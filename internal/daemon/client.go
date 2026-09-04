package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/riken127/ovpntui/internal/config"
	"github.com/riken127/ovpntui/internal/credentials"
	"github.com/riken127/ovpntui/internal/openvpn"
	"github.com/riken127/ovpntui/internal/profile"
)

// Client implements openvpn.Controller over the daemon Unix socket.
type Client struct {
	socket  string
	updates chan struct{}
}

func NewClient(paths config.Paths) *Client {
	return &Client{socket: SocketPath(paths), updates: make(chan struct{}, 1)}
}

func (c *Client) Ping() error {
	_, err := c.call(request{Action: actionPing}, 2*time.Second)
	return err
}

func (c *Client) Start(p profile.Profile, credential credentials.Value) error {
	elevationPassword := credential.ElevationPassword
	browserSSO := credential.BrowserSSO
	credential.ElevationPassword = ""
	credential.BrowserSSO = false
	_, err := c.call(request{Action: actionStart, ProfileID: p.ID, Credential: credential, ElevationPassword: elevationPassword, BrowserSSO: browserSSO}, 35*time.Second)
	c.notify()
	return err
}

func (c *Client) Stop(profileID string) error {
	_, err := c.call(request{Action: actionStop, ProfileID: profileID}, 12*time.Second)
	c.notify()
	return err
}

func (c *Client) Snapshot(profileID string) openvpn.Snapshot {
	resp, err := c.call(request{Action: actionSnapshot, ProfileID: profileID}, 2*time.Second)
	if err != nil {
		return openvpn.Snapshot{ProfileID: profileID, Status: openvpn.Failed, Error: "ovpntuid unavailable: " + err.Error()}
	}
	return resp.Snapshot
}

func (c *Client) Logs(profileID string) []string {
	resp, err := c.call(request{Action: actionLogs, ProfileID: profileID}, 3*time.Second)
	if err != nil {
		return []string{"ovpntuid unavailable: " + err.Error()}
	}
	return resp.Logs
}

func (c *Client) Updates() <-chan struct{} { return c.updates }

func (c *Client) Shutdown() error {
	_, err := c.call(request{Action: actionShutdown}, 15*time.Second)
	return err
}

func (c *Client) Close() {}

func (c *Client) notify() {
	select {
	case c.updates <- struct{}{}:
	default:
	}
}

func (c *Client) call(req request, timeout time.Duration) (response, error) {
	conn, err := net.DialTimeout("unix", c.socket, timeout)
	if err != nil {
		return response{}, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return response{}, err
	}
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return response{}, fmt.Errorf("send daemon request: %w", err)
	}
	var resp response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return response{}, fmt.Errorf("read daemon response: %w", err)
	}
	if !resp.OK {
		if resp.Error == "" {
			return response{}, errors.New("daemon request failed")
		}
		if resp.Code == "sudo_password_required" {
			if resp.Error == openvpn.ErrSudoPasswordRequired.Error() {
				return response{}, openvpn.ErrSudoPasswordRequired
			}
			return response{}, fmt.Errorf("%w: %s", openvpn.ErrSudoPasswordRequired, resp.Error)
		}
		return response{}, errors.New(resp.Error)
	}
	return resp, nil
}
