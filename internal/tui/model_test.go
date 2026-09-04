package tui

import (
	"strings"
	"testing"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/riken127/ovpntui/internal/credentials"
	"github.com/riken127/ovpntui/internal/openvpn"
	"github.com/riken127/ovpntui/internal/profile"
)

type authorizationController struct {
	updates  chan struct{}
	captured credentials.Value
}

func TestStateBadgesHaveStableLabels(t *testing.T) {
	t.Parallel()
	for _, status := range []openvpn.Status{openvpn.Disconnected, openvpn.Connecting, openvpn.Connected, openvpn.Disconnecting, openvpn.Failed} {
		if got := stateBadge(status); !strings.Contains(got, string(status)) {
			t.Errorf("stateBadge(%s) = %q", status, got)
		}
	}
}

func TestCompactHeaderKeepsSessionSummary(t *testing.T) {
	t.Parallel()
	controller := &authorizationController{updates: make(chan struct{}, 1)}
	m := New(profile.NewStore(t.TempDir()), controller, credentials.NewStore())
	m.width = 50
	m.profiles = []profile.Profile{{ID: "0123456789abcdef01234567", Name: "Work"}}
	view := m.headerView()
	if !strings.Contains(view, "ovpntui") || !strings.Contains(view, "1 profiles") || !strings.Contains(view, "\n") {
		t.Fatalf("compact header = %q", view)
	}
}

func (c *authorizationController) Start(_ profile.Profile, value credentials.Value) error {
	c.captured = value
	return nil
}
func (c *authorizationController) Stop(string) error { return nil }
func (c *authorizationController) Snapshot(id string) openvpn.Snapshot {
	return openvpn.Snapshot{ProfileID: id, Status: openvpn.Disconnected}
}
func (c *authorizationController) Logs(string) []string     { return nil }
func (c *authorizationController) Updates() <-chan struct{} { return c.updates }

func TestSudoErrorOpensMaskedAuthorizationForm(t *testing.T) {
	t.Parallel()
	controller := &authorizationController{updates: make(chan struct{}, 1)}
	p := profile.Profile{ID: "0123456789abcdef01234567", Name: "Work"}
	m := New(profile.NewStore(t.TempDir()), controller, credentials.NewStore())
	updated, _ := m.Update(actionMsg{err: openvpn.ErrSudoPasswordRequired, profile: p, credential: credentials.Value{Username: "alice", Password: "vpn-secret"}})
	got := updated.(Model)
	if got.mode != modeElevation || got.password.EchoMode != textinput.EchoPassword {
		t.Fatalf("authorization form mode=%v echo=%v", got.mode, got.password.EchoMode)
	}
	got.password.SetValue("admin-secret")
	updated, cmd := got.Update(tea.KeyMsg{Type: tea.KeyEnter})
	if cmd == nil {
		t.Fatal("authorization submit returned no command")
	}
	_ = updated
	_ = cmd()
	if controller.captured.ElevationPassword != "admin-secret" || controller.captured.Password != "vpn-secret" {
		t.Fatalf("captured credentials = %#v", controller.captured)
	}
}

func TestBrowserSSOShortcutDoesNotCollectPassword(t *testing.T) {
	t.Parallel()
	controller := &authorizationController{updates: make(chan struct{}, 1)}
	p := profile.Profile{ID: "0123456789abcdef01234567", Name: "Work", NeedsAuth: true}
	m := New(profile.NewStore(t.TempDir()), controller, credentials.NewStore())
	m.selected = p
	m.openCredentialForm(p)
	m.input.SetValue("alice")
	m.password.SetValue("must-not-be-sent")
	_, cmd := m.Update(tea.KeyMsg{Type: tea.KeyCtrlO})
	if cmd == nil {
		t.Fatal("SSO shortcut returned no command")
	}
	_ = cmd()
	if !controller.captured.BrowserSSO || controller.captured.Username != "alice" || controller.captured.Password != "" {
		t.Fatalf("captured SSO credentials = %#v", controller.captured)
	}
}
