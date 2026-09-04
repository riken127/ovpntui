package daemon

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/henriquesilva/ovpntui/internal/config"
	"github.com/henriquesilva/ovpntui/internal/credentials"
	"github.com/henriquesilva/ovpntui/internal/openvpn"
	"github.com/henriquesilva/ovpntui/internal/profile"
)

type fakeBackend struct {
	mu       sync.Mutex
	states   map[string]openvpn.Snapshot
	logs     map[string][]string
	startErr error
	captured credentials.Value
}

func (b *fakeBackend) Start(p profile.Profile, value credentials.Value) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.captured = value
	if b.startErr != nil {
		return b.startErr
	}
	b.states[p.ID] = openvpn.Snapshot{ProfileID: p.ID, Status: openvpn.Connected, PID: 1234, ConnectedAt: time.Now()}
	b.logs[p.ID] = []string{"Initialization Sequence Completed"}
	return nil
}

func TestClientServerPreservesBrowserSSOFlag(t *testing.T) {
	t.Parallel()
	paths := daemonTestPaths(t)
	p := daemonTestProfile(t, paths)
	backend := &fakeBackend{states: make(map[string]openvpn.Snapshot), logs: make(map[string][]string)}
	server := NewServer(paths, backend, fakeProfiles{p.ID: p})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client := waitForClient(t, paths)
	defer client.Close()
	if err := client.Start(p, credentials.Value{BrowserSSO: true}); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	got := backend.captured.BrowserSSO
	backend.mu.Unlock()
	if !got {
		t.Fatal("browser SSO flag was lost across daemon protocol")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestClientPreservesSudoAuthorizationError(t *testing.T) {
	t.Parallel()
	paths := daemonTestPaths(t)
	p := daemonTestProfile(t, paths)
	backend := &fakeBackend{states: make(map[string]openvpn.Snapshot), logs: make(map[string][]string), startErr: openvpn.ErrSudoPasswordRequired}
	server := NewServer(paths, backend, fakeProfiles{p.ID: p})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()
	client := waitForClient(t, paths)
	defer client.Close()
	if err := client.Start(p, credentials.Value{}); !errors.Is(err, openvpn.ErrSudoPasswordRequired) {
		t.Fatalf("Start() error = %v", err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}
func (b *fakeBackend) Stop(id string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.states[id] = openvpn.Snapshot{ProfileID: id, Status: openvpn.Disconnected}
	return nil
}
func (b *fakeBackend) Snapshot(id string) openvpn.Snapshot {
	b.mu.Lock()
	defer b.mu.Unlock()
	if state, ok := b.states[id]; ok {
		return state
	}
	return openvpn.Snapshot{ProfileID: id, Status: openvpn.Disconnected}
}
func (b *fakeBackend) Logs(id string) []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.logs[id]...)
}
func (b *fakeBackend) Shutdown(context.Context) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id := range b.states {
		b.states[id] = openvpn.Snapshot{ProfileID: id, Status: openvpn.Disconnected}
	}
	return nil
}

type fakeProfiles map[string]profile.Profile

func (p fakeProfiles) Get(id string) (profile.Profile, error) { return p[id], nil }

func TestClientServerKeepsStateAcrossClients(t *testing.T) {
	t.Parallel()
	paths := daemonTestPaths(t)
	p := daemonTestProfile(t, paths)
	backend := &fakeBackend{states: make(map[string]openvpn.Snapshot), logs: make(map[string][]string)}
	server := NewServer(paths, backend, fakeProfiles{p.ID: p})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx) }()

	client := waitForClient(t, paths)
	if err := client.Start(p, credentials.Value{}); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	client.Close()

	reopened := NewClient(paths)
	defer reopened.Close()
	state := reopened.Snapshot(p.ID)
	if state.Status != openvpn.Connected || state.PID != 1234 {
		t.Fatalf("reopened Snapshot() = %#v", state)
	}
	if got := reopened.Logs(p.ID); len(got) != 1 {
		t.Fatalf("Logs() = %#v", got)
	}
	if err := reopened.Stop(p.ID); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
	if got := reopened.Snapshot(p.ID).Status; got != openvpn.Disconnected {
		t.Fatalf("status after stop = %s", got)
	}
	if err := reopened.Shutdown(); err != nil {
		t.Fatalf("Shutdown() = %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Serve() = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("server did not stop")
	}
}

func TestServerRejectsSecondInstanceAndCleansStaleCredentials(t *testing.T) {
	t.Parallel()
	paths := daemonTestPaths(t)
	stale := filepath.Join(paths.RuntimeDir, "stale.auth")
	if err := os.WriteFile(stale, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &fakeBackend{states: make(map[string]openvpn.Snapshot), logs: make(map[string][]string)}
	first := NewServer(paths, backend, fakeProfiles{})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- first.Serve(ctx) }()
	client := waitForClient(t, paths)
	client.Close()
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatalf("stale credential still exists: %v", err)
	}
	second := NewServer(paths, backend, fakeProfiles{})
	if err := second.Serve(context.Background()); err == nil {
		t.Fatal("second daemon instance started")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("first server did not stop")
	}
}

func daemonTestPaths(t *testing.T) config.Paths {
	t.Helper()
	root, err := os.MkdirTemp("/tmp", "ovpntui-daemon-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	paths := config.Paths{
		ConfigDir: filepath.Join(root, "config"), ProfilesDir: filepath.Join(root, "config", "profiles"),
		StateDir: filepath.Join(root, "state"), LogsDir: filepath.Join(root, "state", "logs"), RuntimeDir: filepath.Join(root, "runtime"),
	}
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	return paths
}

func daemonTestProfile(t *testing.T, paths config.Paths) profile.Profile {
	t.Helper()
	id := "0123456789abcdef01234567"
	dir := filepath.Join(paths.ProfilesDir, id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, profile.ConfigFilename), []byte("client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return profile.Profile{ID: id, Name: "Test", Dir: dir}
}

func waitForClient(t *testing.T, paths config.Paths) *Client {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		client := NewClient(paths)
		if err := client.Ping(); err == nil {
			return client
		}
		client.Close()
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("daemon did not become ready")
	return nil
}
