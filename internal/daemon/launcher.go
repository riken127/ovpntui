package daemon

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"

	"github.com/riken127/ovpntui/internal/config"
	"github.com/riken127/ovpntui/internal/openvpn"
)

// EnsureRunning starts the per-user daemon when it is not already available.
func EnsureRunning(paths config.Paths, openvpnBin string, privilege openvpn.PrivilegeMode) error {
	probe := NewClient(paths)
	if err := probe.Ping(); err == nil {
		probe.Close()
		return nil
	}
	probe.Close()
	daemonBin, err := findDaemonBinary()
	if err != nil {
		return err
	}
	logPath := filepath.Join(paths.LogsDir, "daemon.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open daemon log: %w", err)
	}
	args := []string{"--privilege=" + string(privilege)}
	if openvpnBin != "" {
		args = append(args, "--openvpn="+openvpnBin)
	}
	cmd := exec.Command(daemonBin, args...)
	cmd.Stdin = nil
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = logFile.Close()
		return fmt.Errorf("start ovpntuid: %w", err)
	}
	_ = cmd.Process.Release()
	_ = logFile.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client := NewClient(paths)
		err = client.Ping()
		client.Close()
		if err == nil {
			return nil
		}
		time.Sleep(50 * time.Millisecond)
	}
	return fmt.Errorf("ovpntuid did not become ready: %w; see %s", err, logPath)
}

func findDaemonBinary() (string, error) {
	if configured := os.Getenv("OVPNTUI_DAEMON"); configured != "" {
		path, err := exec.LookPath(configured)
		if err != nil {
			return "", fmt.Errorf("configured ovpntuid not found: %w", err)
		}
		return path, nil
	}
	executable, err := os.Executable()
	if err == nil {
		sibling := filepath.Join(filepath.Dir(executable), "ovpntuid")
		if info, statErr := os.Stat(sibling); statErr == nil && info.Mode().IsRegular() && info.Mode().Perm()&0o111 != 0 {
			return sibling, nil
		}
	}
	path, err := exec.LookPath("ovpntuid")
	if err != nil {
		return "", errors.New("ovpntuid is not installed next to ovpntui or in PATH")
	}
	return path, nil
}
