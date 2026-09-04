package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// Paths contains every directory used by ovpntui.
type Paths struct {
	ConfigDir   string
	ProfilesDir string
	StateDir    string
	LogsDir     string
	RuntimeDir  string
}

// DefaultPaths resolves directories according to the XDG Base Directory Specification.
func DefaultPaths() (Paths, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve home directory: %w", err)
	}
	configHome := envOr("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	stateHome := envOr("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))
	runtimeHome := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeHome == "" {
		runtimeHome = filepath.Join(os.TempDir(), fmt.Sprintf("ovpntui-%d", os.Getuid()))
	}
	return Paths{
		ConfigDir:   filepath.Join(configHome, "ovpntui"),
		ProfilesDir: filepath.Join(configHome, "ovpntui", "profiles"),
		StateDir:    filepath.Join(stateHome, "ovpntui"),
		LogsDir:     filepath.Join(stateHome, "ovpntui", "logs"),
		RuntimeDir:  filepath.Join(runtimeHome, "ovpntui"),
	}, nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// Ensure creates application directories with private permissions.
func (p Paths) Ensure() error {
	for _, dir := range []string{p.ConfigDir, p.ProfilesDir, p.StateDir, p.LogsDir, p.RuntimeDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		if err := os.Chmod(dir, 0o700); err != nil && !errors.Is(err, os.ErrPermission) {
			return fmt.Errorf("secure %s: %w", dir, err)
		}
	}
	return nil
}
