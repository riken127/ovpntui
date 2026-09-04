package main

import (
	"flag"
	"fmt"
	"os"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/henriquesilva/ovpntui/internal/config"
	"github.com/henriquesilva/ovpntui/internal/credentials"
	"github.com/henriquesilva/ovpntui/internal/daemon"
	"github.com/henriquesilva/ovpntui/internal/openvpn"
	"github.com/henriquesilva/ovpntui/internal/profile"
	"github.com/henriquesilva/ovpntui/internal/tui"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "ovpntui:", err)
		os.Exit(1)
	}
}

func run() error {
	privilege := flag.String("privilege", "auto", "privilege helper: auto, sudo, pkexec, or none")
	openvpnBin := flag.String("openvpn", "", "path to the openvpn binary")
	stopDaemon := flag.Bool("stop-daemon", false, "disconnect all sessions and stop the background daemon")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("ovpntui", version)
		return nil
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("do not run ovpntui as root; use --privilege=auto, sudo, or pkexec from a normal user account")
	}
	mode := openvpn.PrivilegeMode(*privilege)
	if mode != openvpn.PrivilegeAuto && mode != openvpn.PrivilegeSudo && mode != openvpn.PrivilegePKExec && mode != openvpn.PrivilegeNone {
		return fmt.Errorf("invalid --privilege value %q", *privilege)
	}
	paths, err := config.DefaultPaths()
	if err != nil {
		return err
	}
	if err := paths.Ensure(); err != nil {
		return err
	}
	if *stopDaemon {
		client := daemon.NewClient(paths)
		defer client.Close()
		if err := client.Shutdown(); err != nil {
			return fmt.Errorf("stop ovpntuid: %w", err)
		}
		fmt.Println("ovpntuid stopped; active VPN sessions were disconnected")
		return nil
	}
	if err := daemon.EnsureRunning(paths, *openvpnBin, mode); err != nil {
		return err
	}
	client := daemon.NewClient(paths)
	defer client.Close()
	model := tui.New(profile.NewStore(paths.ProfilesDir), client, credentials.NewStore())
	program := tea.NewProgram(model, tea.WithAltScreen())
	_, err = program.Run()
	return err
}
