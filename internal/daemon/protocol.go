package daemon

import (
	"github.com/riken127/ovpntui/internal/credentials"
	"github.com/riken127/ovpntui/internal/openvpn"
)

const (
	protocolVersion = 1

	actionPing     = "ping"
	actionStart    = "start"
	actionStop     = "stop"
	actionSnapshot = "snapshot"
	actionLogs     = "logs"
	actionShutdown = "shutdown"
)

type request struct {
	Action            string            `json:"action"`
	ProfileID         string            `json:"profile_id,omitempty"`
	Credential        credentials.Value `json:"credential,omitempty"`
	ElevationPassword string            `json:"elevation_password,omitempty"`
	BrowserSSO        bool              `json:"browser_sso,omitempty"`
}

type response struct {
	OK       bool             `json:"ok"`
	Version  int              `json:"version,omitempty"`
	Error    string           `json:"error,omitempty"`
	Code     string           `json:"code,omitempty"`
	Snapshot openvpn.Snapshot `json:"snapshot,omitempty"`
	Logs     []string         `json:"logs,omitempty"`
}
