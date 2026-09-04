package openvpn

import (
	"github.com/henriquesilva/ovpntui/internal/credentials"
	"github.com/henriquesilva/ovpntui/internal/profile"
)

// Controller is implemented by both the local supervisor and the daemon client.
// Keeping this interface at the TUI boundary lets the UI remain unaware of
// process ownership and transport details.
type Controller interface {
	Start(profile.Profile, credentials.Value) error
	Stop(string) error
	Snapshot(string) Snapshot
	Logs(string) []string
	Updates() <-chan struct{}
}
