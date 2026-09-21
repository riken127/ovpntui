package daemon

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/riken127/ovpntui/internal/config"
	"github.com/riken127/ovpntui/internal/credentials"
	"github.com/riken127/ovpntui/internal/openvpn"
	"github.com/riken127/ovpntui/internal/profile"
)

const (
	socketFilename = "daemon.sock"
	lockFilename   = "daemon.lock"
)

type backend interface {
	Start(profile.Profile, credentials.Value) error
	Stop(string) error
	Snapshot(string) openvpn.Snapshot
	Logs(string) []string
	Shutdown(context.Context) error
}

type profileLoader interface {
	Get(string) (profile.Profile, error)
}

// Server exposes the OpenVPN supervisor through a private Unix socket.
type Server struct {
	paths    config.Paths
	backend  backend
	profiles profileLoader
	listener net.Listener
	lockFile *os.File
	cancel   context.CancelFunc
	close    sync.Once
}

func NewServer(paths config.Paths, backend backend, profiles profileLoader) *Server {
	return &Server{paths: paths, backend: backend, profiles: profiles}
}

func SocketPath(paths config.Paths) string { return filepath.Join(paths.RuntimeDir, socketFilename) }

func (s *Server) Serve(ctx context.Context) (serveErr error) {
	ctx, s.cancel = context.WithCancel(ctx)
	if err := s.listen(); err != nil {
		return err
	}
	defer func() {
		// Keep the instance lock until the old VPN children have shut down.
		// Otherwise a replacement daemon can overwrite their runtime files.
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if err := s.shutdownBackend(shutdownCtx); err != nil {
			serveErr = errors.Join(serveErr, fmt.Errorf("shutdown OpenVPN sessions: %w", err))
		}
		_ = s.Close()
	}()
	go func() {
		<-ctx.Done()
		_ = s.listener.Close()
	}()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}
			return fmt.Errorf("accept daemon connection: %w", err)
		}
		go s.handle(conn)
	}
}

// A timed out shutdown means a child may still own routes and runtime files.
// Keep the daemon and its instance lock alive until that child exits.
func (s *Server) shutdownBackend(ctx context.Context) error {
	err := s.backend.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return s.backend.Shutdown(context.Background())
	}
	return err
}

func (s *Server) listen() error {
	lockPath := filepath.Join(s.paths.RuntimeDir, lockFilename)
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return fmt.Errorf("open daemon lock: %w", err)
	}
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lockFile.Close()
		return errors.New("another ovpntuid instance is already running")
	}
	s.lockFile = lockFile
	if err := cleanupRuntimeSecrets(s.paths.RuntimeDir); err != nil {
		s.releaseLock()
		return err
	}
	socketPath := SocketPath(s.paths)
	// sockaddr_un paths are limited to roughly 104 bytes on macOS and 108 on
	// Linux. Keep a conservative check so startup fails with an actionable error.
	if len(socketPath) >= 100 {
		s.releaseLock()
		return fmt.Errorf("daemon socket path is too long (%d bytes); set XDG_RUNTIME_DIR to a shorter private directory", len(socketPath))
	}
	if err := removeStaleSocket(socketPath); err != nil {
		s.releaseLock()
		return err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		s.releaseLock()
		return fmt.Errorf("listen on daemon socket: %w", err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(socketPath)
		s.releaseLock()
		return fmt.Errorf("secure daemon socket: %w", err)
	}
	s.listener = listener
	return nil
}

func cleanupRuntimeSecrets(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("scan daemon runtime directory: %w", err)
	}
	for _, entry := range entries {
		if entry.Type().IsRegular() && filepath.Ext(entry.Name()) == ".auth" {
			if err := os.Remove(filepath.Join(dir, entry.Name())); err != nil {
				return fmt.Errorf("remove stale credential file: %w", err)
			}
		}
	}
	return nil
}

func removeStaleSocket(path string) error {
	if _, err := os.Lstat(path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect daemon socket: %w", err)
	}
	conn, err := net.DialTimeout("unix", path, 250*time.Millisecond)
	if err == nil {
		_ = conn.Close()
		return errors.New("daemon socket is already active")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale daemon socket: %w", err)
	}
	return nil
}

func (s *Server) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(35 * time.Second))
	decoder := json.NewDecoder(io.LimitReader(conn, 64*1024))
	decoder.DisallowUnknownFields()
	var req request
	if err := decoder.Decode(&req); err != nil {
		_ = json.NewEncoder(conn).Encode(response{Error: "decode request: " + err.Error()})
		return
	}
	resp := s.dispatch(req)
	_ = json.NewEncoder(conn).Encode(resp)
	if req.Action == actionShutdown && resp.OK && s.cancel != nil {
		s.cancel()
	}
}

func (s *Server) dispatch(req request) response {
	switch req.Action {
	case actionPing:
		return response{OK: true}
	case actionStart:
		p, err := s.profiles.Get(req.ProfileID)
		if err != nil {
			return failed(fmt.Errorf("load profile: %w", err))
		}
		if err := profile.ValidateForExecution(p); err != nil {
			return failed(fmt.Errorf("profile failed security validation: %w", err))
		}
		req.Credential.ElevationPassword = req.ElevationPassword
		req.Credential.BrowserSSO = req.BrowserSSO
		req.ElevationPassword = ""
		if err := s.backend.Start(p, req.Credential); err != nil {
			return failed(err)
		}
		return response{OK: true, Snapshot: s.backend.Snapshot(req.ProfileID)}
	case actionStop:
		if _, err := s.profiles.Get(req.ProfileID); err != nil {
			return failed(fmt.Errorf("load profile: %w", err))
		}
		if err := s.backend.Stop(req.ProfileID); err != nil {
			return failed(err)
		}
		return response{OK: true, Snapshot: s.backend.Snapshot(req.ProfileID)}
	case actionSnapshot:
		return response{OK: true, Snapshot: s.backend.Snapshot(req.ProfileID)}
	case actionLogs:
		return response{OK: true, Logs: s.backend.Logs(req.ProfileID)}
	case actionShutdown:
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
		defer cancel()
		if err := s.backend.Shutdown(ctx); err != nil {
			return failed(fmt.Errorf("disconnect active sessions: %w", err))
		}
		return response{OK: true}
	default:
		return failed(fmt.Errorf("unknown daemon action %q", req.Action))
	}
}

func failed(err error) response {
	resp := response{Error: err.Error()}
	if errors.Is(err, openvpn.ErrSudoPasswordRequired) {
		resp.Code = "sudo_password_required"
	}
	return resp
}

func (s *Server) Close() error {
	var closeErr error
	s.close.Do(func() {
		if s.listener != nil {
			closeErr = s.listener.Close()
		}
		if err := os.Remove(SocketPath(s.paths)); err != nil && !errors.Is(err, os.ErrNotExist) && closeErr == nil {
			closeErr = err
		}
		s.releaseLock()
	})
	return closeErr
}

func (s *Server) releaseLock() {
	if s.lockFile == nil {
		return
	}
	_ = syscall.Flock(int(s.lockFile.Fd()), syscall.LOCK_UN)
	_ = s.lockFile.Close()
	s.lockFile = nil
}
