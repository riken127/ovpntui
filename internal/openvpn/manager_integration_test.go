package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/riken127/ovpntui/internal/config"
	"github.com/riken127/ovpntui/internal/credentials"
	"github.com/riken127/ovpntui/internal/profile"
)

func TestMain(m *testing.M) {
	if os.Getenv("OVPNTUI_FAKE_SUDO") == "1" {
		fakeSudo()
		return
	}
	if os.Getenv("OVPNTUI_FAKE_OPENVPN") == "1" {
		fakeOpenVPN()
		return
	}
	os.Exit(m.Run())
}

func fakeSudo() {
	if len(os.Args) >= 3 && os.Args[1] == "-n" && os.Args[2] == "true" {
		if os.Getenv("OVPNTUI_SUDO_CACHED") == "1" {
			os.Exit(0)
		}
		os.Exit(1)
	}
	data := make([]byte, 128)
	n, _ := os.Stdin.Read(data)
	if bytes.Equal(data[:n], []byte("correct\n")) {
		os.Exit(0)
	}
	os.Exit(1)
}

func fakeOpenVPN() {
	managementSocket := ""
	managementSignal := false
	remap := ""
	if path := os.Getenv("OVPNTUI_FAKE_ARGS"); path != "" {
		_ = os.WriteFile(path, []byte(strings.Join(os.Args[1:], "\n")), 0o600)
	}
	for i, arg := range os.Args {
		if arg == "--management-signal" {
			managementSignal = true
		}
		if arg == "--remap-usr1" && i+1 < len(os.Args) {
			remap = os.Args[i+1]
		}
		if arg == "--writepid" && i+1 < len(os.Args) {
			_ = os.WriteFile(os.Args[i+1], []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o600)
		}
		if arg == "--management" && i+2 < len(os.Args) && os.Args[i+2] == "unix" {
			managementSocket = os.Args[i+1]
		}
	}
	if managementSocket == "" {
		fmt.Fprintln(os.Stderr, "missing management socket")
		os.Exit(2)
	}
	listener, err := net.Listen("unix", managementSocket)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	defer func() { _ = listener.Close() }()
	if os.Getenv("OVPNTUI_FAKE_SLOW_START") == "1" {
		time.Sleep(100 * time.Millisecond)
	}
	conn, err := listener.Accept()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		if scanner.Text() == "hold release" {
			break
		}
	}
	if os.Getenv("OVPNTUI_FAKE_SSO") == "1" {
		_, _ = fmt.Fprintln(conn, ">STATE:1788541200,AUTH_PENDING,,,,")
		_, _ = fmt.Fprintln(conn, ">INFOMSG:WEB_AUTH:external:https://login.example.test/authorize?state=one-time-secret")
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("TUN/TAP device tun-test opened")
	fmt.Println("net_addr_v4_add: 10.44.0.7/24 dev tun-test")
	if path := os.Getenv("OVPNTUI_FAKE_ROUTES"); path != "" {
		_ = os.WriteFile(path, []byte("0.0.0.0/1\n128.0.0.0/1\nserver/32\n"), 0o600)
		defer func() { _ = os.Remove(path) }()
	}
	fmt.Println("Initialization Sequence Completed")
	if os.Getenv("OVPNTUI_FAKE_EXIT") == "1" {
		os.Exit(7)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	if os.Getenv("OVPNTUI_FAKE_IGNORE_SIGNALS") == "1" {
		signal.Ignore(os.Interrupt, syscall.SIGTERM)
	}
	commands := make(chan string, 8)
	go func() {
		for scanner.Scan() {
			commands <- scanner.Text()
		}
		close(commands)
	}()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-signals:
			return
		case command, ok := <-commands:
			if os.Getenv("OVPNTUI_FAKE_STUCK") == "1" {
				if !ok {
					commands = nil
				}
				continue
			}
			if command == "signal SIGTERM" || (!ok && managementSignal && remap == "SIGTERM") {
				if os.Getenv("OVPNTUI_FAKE_CLEANUP_ERROR") == "1" {
					fmt.Println("ERROR: route deletion failed: Operation not permitted")
				}
				fmt.Println("graceful cleanup completed")
				return
			}
			if !ok {
				commands = nil
			}
		case <-ticker.C:
			if path := os.Getenv("OVPNTUI_FAKE_NETWORK_LOSS"); path != "" {
				if _, err := os.Stat(path); err == nil && remap == "SIGTERM" {
					_, _ = fmt.Fprintln(conn, ">STATE:1788541201,EXITING,ping-restart,,,,,")
					return
				}
			}
		}
	}
}

func TestManagerHandlesBrowserSSO(t *testing.T) {
	t.Setenv("OVPNTUI_FAKE_OPENVPN", "1")
	t.Setenv("OVPNTUI_FAKE_SSO", "1")
	paths, p := integrationFixture(t)
	p.NeedsAuth = true
	manager := NewManager(context.Background(), paths, os.Args[0], PrivilegeNone)
	opened := make(chan string, 1)
	manager.openURL = func(rawURL string) error {
		opened <- rawURL
		return nil
	}
	if err := manager.Start(p, credentials.Value{BrowserSSO: true}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-opened:
		if got != "https://login.example.test/authorize?state=one-time-secret" {
			t.Fatalf("opened URL = %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SSO URL was not opened")
	}
	wantState(t, manager, p.ID, Connected)
	if err := manager.Stop(p.ID); err != nil {
		t.Fatal(err)
	}
	wantState(t, manager, p.ID, Disconnected)
	for _, line := range manager.Logs(p.ID) {
		if strings.Contains(line, "one-time-secret") {
			t.Fatalf("sensitive SSO URL leaked to logs: %q", line)
		}
	}
}

func TestManagerFakeOpenVPNLifecycle(t *testing.T) {
	t.Setenv("OVPNTUI_FAKE_OPENVPN", "1")
	paths, p := integrationFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	manager := NewManager(ctx, paths, os.Args[0], PrivilegeNone)
	if err := manager.Start(p, structCredentials()); err != nil {
		t.Fatalf("Start() = %v", err)
	}
	wantState(t, manager, p.ID, Connected)
	if err := manager.Start(p, structCredentials()); err == nil {
		t.Fatal("duplicate Start() succeeded")
	}
	state := manager.Snapshot(p.ID)
	if state.Interface != "tun-test" || state.IP != "10.44.0.7" || state.PID <= 0 {
		t.Fatalf("connected snapshot = %#v", state)
	}
	if len(manager.Logs(p.ID)) < 3 {
		t.Fatalf("logs = %#v", manager.Logs(p.ID))
	}
	if err := manager.Stop(p.ID); err != nil {
		t.Fatalf("Stop() = %v", err)
	}
	wantState(t, manager, p.ID, Disconnected)
	state = manager.Snapshot(p.ID)
	if state.Interface != "" || state.IP != "" || !state.ConnectedAt.IsZero() {
		t.Fatalf("disconnected snapshot retained session data: %#v", state)
	}
}

func TestManagerDetectsUnexpectedExit(t *testing.T) {
	t.Setenv("OVPNTUI_FAKE_OPENVPN", "1")
	t.Setenv("OVPNTUI_FAKE_EXIT", "1")
	paths, p := integrationFixture(t)
	manager := NewManager(context.Background(), paths, os.Args[0], PrivilegeNone)
	if err := manager.Start(p, structCredentials()); err != nil {
		t.Fatal(err)
	}
	wantState(t, manager, p.ID, Failed)
	if manager.Snapshot(p.ID).Error == "" {
		t.Fatal("unexpected exit did not expose an error")
	}
}

func TestManagerRequestsAndValidatesSudoPassword(t *testing.T) {
	t.Setenv("OVPNTUI_FAKE_SUDO", "1")
	dir := t.TempDir()
	testBinary, err := filepath.Abs(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(testBinary, filepath.Join(dir, "sudo")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	manager := NewManager(context.Background(), config.Paths{}, "", PrivilegeSudo)
	if err := manager.authorizePrivilege(""); !errors.Is(err, ErrSudoPasswordRequired) {
		t.Fatalf("empty password error = %v", err)
	}
	if err := manager.authorizePrivilege("wrong"); !errors.Is(err, ErrSudoPasswordRequired) {
		t.Fatalf("wrong password error = %v", err)
	}
	if err := manager.authorizePrivilege("correct"); err != nil {
		t.Fatalf("correct password error = %v", err)
	}
}

func integrationFixture(t *testing.T) (config.Paths, profile.Profile) {
	t.Helper()
	root := t.TempDir()
	runtimeDir, err := os.MkdirTemp("", "ot-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeDir) })
	paths := config.Paths{ConfigDir: filepath.Join(root, "config"), ProfilesDir: filepath.Join(root, "profiles"), StateDir: filepath.Join(root, "state"), LogsDir: filepath.Join(root, "state", "logs"), RuntimeDir: runtimeDir}
	if err := paths.Ensure(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(paths.ProfilesDir, "fake")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, profile.ConfigFilename), []byte("client\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return paths, profile.Profile{ID: "0123456789abcdef01234567", Name: "Fake", Dir: dir}
}

func wantState(t *testing.T, manager *Manager, id string, want Status) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got := manager.Snapshot(id).Status; got == want {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("state = %s, want %s; snapshot=%#v; logs=%v", manager.Snapshot(id).Status, want, manager.Snapshot(id), manager.Logs(id))
}

func structCredentials() credentials.Value { return credentials.Value{} }

func supervisedFixture(t *testing.T) (*Manager, profile.Profile, string) {
	t.Helper()
	t.Setenv("OVPNTUI_FAKE_OPENVPN", "1")
	// Simulate a root child which the unprivileged daemon cannot signal.
	t.Setenv("OVPNTUI_FAKE_IGNORE_SIGNALS", "1")
	paths, p := integrationFixture(t)
	routes := filepath.Join(paths.RuntimeDir, "routes")
	t.Setenv("OVPNTUI_FAKE_ROUTES", routes)
	m := NewManager(context.Background(), paths, os.Args[0], PrivilegeNone)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := m.Shutdown(ctx); err != nil {
			t.Error(err)
			m.mu.RLock()
			defer m.mu.RUnlock()
			for _, s := range m.sessions {
				_ = s.cmd.Process.Kill()
			}
		}
	})
	return m, p, routes
}

func assertRoutesRemoved(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("simulated routes were not cleaned up: %v", err)
	}
}

func TestStopUsesManagementAndWaitsForCleanup(t *testing.T) {
	m, p, routes := supervisedFixture(t)
	argsPath := filepath.Join(t.TempDir(), "args")
	t.Setenv("OVPNTUI_FAKE_ARGS", argsPath)
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
	if _, err := os.Stat(routes); err != nil {
		t.Fatal(err)
	}
	args, err := os.ReadFile(argsPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--management-signal\n", "--remap-usr1\nSIGTERM\n", "--ping\n0\n", "--ping-restart\n0\n", "--keepalive\n10\n30", "--pull-filter\nignore\nping"} {
		if !strings.Contains(string(args), required) {
			t.Fatalf("missing safety arguments %q", required)
		}
	}
	if err := m.Stop(p.ID); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Disconnected)
	assertRoutesRemoved(t, routes)
	if !strings.Contains(strings.Join(m.Logs(p.ID), "\n"), "graceful cleanup completed") {
		t.Fatal("final cleanup log was lost")
	}
}

func TestStopBeforeManagementIsReady(t *testing.T) {
	m, p, routes := supervisedFixture(t)
	t.Setenv("OVPNTUI_FAKE_SLOW_START", "1")
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(p.ID); err != nil {
		t.Fatal(err)
	}
	if err := m.Stop(p.ID); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Disconnected)
	assertRoutesRemoved(t, routes)
}

func TestNetworkLossCleansRoutesAndAllowsFreshConnection(t *testing.T) {
	m, p, routes := supervisedFixture(t)
	loss := filepath.Join(t.TempDir(), "network-loss")
	t.Setenv("OVPNTUI_FAKE_NETWORK_LOSS", loss)
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
	if err := os.WriteFile(loss, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Failed)
	assertRoutesRemoved(t, routes)
	state := m.Snapshot(p.ID)
	if state.PID != 0 || state.Interface != "" || !state.ConnectedAt.IsZero() || !strings.Contains(state.Error, "ping-restart") {
		t.Fatalf("stale or missing state after network loss: %#v", state)
	}
	if err := os.Remove(loss); err != nil {
		t.Fatal(err)
	}
	// Session filenames must also allow reconnecting within the same second.
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
}

func TestManagementDisconnectCleansRoutes(t *testing.T) {
	m, p, routes := supervisedFixture(t)
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
	m.mu.RLock()
	s := m.sessions[p.ID]
	m.mu.RUnlock()
	s.managementMu.Lock()
	err := s.managementConn.Close()
	s.managementMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Failed)
	assertRoutesRemoved(t, routes)
}

func TestShutdownCleansRoutesAndRejectsNewSessions(t *testing.T) {
	m, p, routes := supervisedFixture(t)
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
	assertRoutesRemoved(t, routes)
	if err := m.Start(p, credentials.Value{}); err == nil {
		t.Fatal("Start succeeded after Shutdown")
	}
}

func TestCleanupErrorIsNotReportedAsDisconnected(t *testing.T) {
	m, p, _ := supervisedFixture(t)
	t.Setenv("OVPNTUI_FAKE_CLEANUP_ERROR", "1")
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := m.Shutdown(ctx); err == nil || !strings.Contains(err.Error(), "route deletion failed") {
		t.Fatalf("Shutdown did not propagate the cleanup failure: %v", err)
	}
	wantState(t, m, p.ID, Failed)
	if !strings.Contains(m.Snapshot(p.ID).Error, "route deletion failed") {
		t.Fatal("cleanup error was discarded")
	}
}

func TestUnresponsiveChildRemainsTracked(t *testing.T) {
	m, p, routes := supervisedFixture(t)
	t.Setenv("OVPNTUI_FAKE_IGNORE_SIGNALS", "0")
	t.Setenv("OVPNTUI_FAKE_STUCK", "1")
	if err := m.Start(p, credentials.Value{}); err != nil {
		t.Fatal(err)
	}
	wantState(t, m, p.ID, Connected)
	m.mu.RLock()
	s := m.sessions[p.ID]
	m.mu.RUnlock()
	defer func() { _ = s.cmd.Process.Signal(syscall.SIGTERM) }()
	if err := m.Stop(p.ID); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for m.Snapshot(p.ID).Error == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	state := m.Snapshot(p.ID)
	if state.Status != Disconnecting || !strings.Contains(state.Error, "routes may still be active") {
		t.Fatalf("unconfirmed shutdown was hidden: %#v", state)
	}
	if _, err := os.Stat(routes); err != nil {
		t.Fatal("child was killed before cleanup")
	}
	if err := m.Start(p, credentials.Value{}); err == nil {
		t.Fatal("a second session was allowed while the old child was still alive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := m.Shutdown(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("shutdown failed to report the live child: %v", err)
	}
}
