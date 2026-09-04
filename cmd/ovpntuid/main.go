package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/henriquesilva/ovpntui/internal/config"
	"github.com/henriquesilva/ovpntui/internal/daemon"
	"github.com/henriquesilva/ovpntui/internal/openvpn"
	"github.com/henriquesilva/ovpntui/internal/profile"
)

var version = "dev"

func main() {
	if err := run(); err != nil {
		log.Printf("ovpntuid: %v", err)
		os.Exit(1)
	}
}

func run() error {
	privilege := flag.String("privilege", "auto", "privilege helper: auto, sudo, pkexec, or none")
	openvpnBin := flag.String("openvpn", "", "path to the openvpn binary")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("ovpntuid", version)
		return nil
	}
	if os.Geteuid() == 0 {
		return fmt.Errorf("do not run ovpntuid as root")
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer stop()
	manager := openvpn.NewManager(ctx, paths, *openvpnBin, mode)
	server := daemon.NewServer(paths, manager, profile.NewStore(paths.ProfilesDir))
	serveErr := server.Serve(ctx)
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if err := manager.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("shutdown OpenVPN sessions: %w", err)
	}
	return serveErr
}
