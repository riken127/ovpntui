package profile

import "time"

const (
	ConfigFilename   = "profile.ovpn"
	MetadataFilename = "profile.json"
)

// Profile is the persistent description of an imported OpenVPN profile.
type Profile struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
	NeedsAuth bool      `json:"needs_auth"`
	Dir       string    `json:"-"`
}

func (p Profile) ConfigPath() string { return p.Dir + "/" + ConfigFilename }
