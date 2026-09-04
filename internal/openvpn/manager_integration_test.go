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

	"github.com/henriquesilva/ovpntui/internal/config"
	"github.com/henriquesilva/ovpntui/internal/credentials"
	"github.com/henriquesilva/ovpntui/internal/profile"
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
	for i, arg := range os.Args {
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
	defer listener.Close()
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
		fmt.Fprintln(conn, ">STATE:1788541200,AUTH_PENDING,,,,")
		fmt.Fprintln(conn, ">INFOMSG:WEB_AUTH:external:https://login.example.test/authorize?state=one-time-secret")
		time.Sleep(100 * time.Millisecond)
	}
	fmt.Println("TUN/TAP device tun-test opened")
	fmt.Println("net_addr_v4_add: 10.44.0.7/24 dev tun-test")
	fmt.Println("Initialization Sequence Completed")
	if os.Getenv("OVPNTUI_FAKE_EXIT") == "1" {
		os.Exit(7)
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	<-signals
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
	t.Fatalf("state = %s, want %s; snapshot=%#v", manager.Snapshot(id).Status, want, manager.Snapshot(id))
}

func structCredentials() credentials.Value { return credentials.Value{} }
