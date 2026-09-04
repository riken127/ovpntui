package credentials

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

const service = "ovpntui"

// Value is an OpenVPN username/password pair. It is never written to application config.
type Value struct {
	Username          string `json:"username"`
	Password          string `json:"password"`
	ElevationPassword string `json:"-"`
	BrowserSSO        bool   `json:"-"`
}

// Store uses the desktop Secret Service through secret-tool.
type Store struct {
	binary string
}

func NewStore() *Store {
	binary, _ := exec.LookPath("secret-tool")
	return &Store{binary: binary}
}

func (s *Store) Available() bool { return s.binary != "" }

func (s *Store) Load(ctx context.Context, profileID string) (Value, bool, error) {
	if !s.Available() {
		return Value{}, false, nil
	}
	cmd := exec.CommandContext(ctx, s.binary, "lookup", "service", service, "profile", profileID)
	data, err := cmd.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && len(exitErr.Stderr) == 0 {
			return Value{}, false, nil
		}
		return Value{}, false, fmt.Errorf("read system keyring: %w", err)
	}
	var value Value
	if err := json.Unmarshal(bytes.TrimSpace(data), &value); err != nil {
		return Value{}, false, fmt.Errorf("decode system keyring entry: %w", err)
	}
	return value, true, nil
}

func (s *Store) Save(ctx context.Context, profileID string, value Value) error {
	if !s.Available() {
		return errors.New("secret-tool is not installed; credentials were not saved")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, s.binary, "store", "--label=ovpntui "+profileID, "service", service, "profile", profileID)
	cmd.Stdin = bytes.NewReader(append(data, '\n'))
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("save to system keyring: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (s *Store) Delete(ctx context.Context, profileID string) error {
	if !s.Available() {
		return nil
	}
	cmd := exec.CommandContext(ctx, s.binary, "clear", "service", service, "profile", profileID)
	if output, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("remove system keyring entry: %w: %s", err, strings.TrimSpace(string(output)))
	}
	return nil
}
