package openvpn

import (
	"errors"
	"time"
)

type Status string

const (
	Disconnected  Status = "disconnected"
	Connecting    Status = "connecting"
	Connected     Status = "connected"
	Disconnecting Status = "disconnecting"
	Failed        Status = "failed"
)

type Snapshot struct {
	ProfileID   string
	Status      Status
	PID         int
	Interface   string
	IP          string
	StartedAt   time.Time
	ConnectedAt time.Time
	Error       string
	LogPath     string
	AuthPending bool
	AuthURL     string
	AuthError   string
}

func (s Snapshot) Duration(now time.Time) time.Duration {
	if s.ConnectedAt.IsZero() || s.Status != Connected {
		return 0
	}
	return now.Sub(s.ConnectedAt).Truncate(time.Second)
}

func validTransition(from, to Status) bool {
	switch from {
	case Disconnected:
		return to == Connecting
	case Connecting:
		return to == Connected || to == Disconnecting || to == Failed
	case Connected:
		return to == Disconnecting || to == Failed
	case Disconnecting:
		return to == Disconnected || to == Failed
	case Failed:
		return to == Connecting || to == Disconnected
	default:
		return false
	}
}

func transition(snapshot *Snapshot, to Status) error {
	if !validTransition(snapshot.Status, to) {
		return errors.New("invalid lifecycle transition: " + string(snapshot.Status) + " -> " + string(to))
	}
	snapshot.Status = to
	return nil
}
