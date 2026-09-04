package openvpn

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/henriquesilva/ovpntui/internal/config"
	"github.com/henriquesilva/ovpntui/internal/credentials"
	"github.com/henriquesilva/ovpntui/internal/profile"
)

type PrivilegeMode string

var ErrSudoPasswordRequired = errors.New("sudo authorization is required")

const (
	PrivilegeAuto   PrivilegeMode = "auto"
	PrivilegeNone   PrivilegeMode = "none"
	PrivilegeSudo   PrivilegeMode = "sudo"
	PrivilegePKExec PrivilegeMode = "pkexec"
)

type session struct {
	cmd              *exec.Cmd
	pidFile          string
	authFile         string
	managementSocket string
	openedAuthURL    string
	log              *os.File
	done             chan struct{}
	stopping         bool
}

// Manager supervises one OpenVPN child per profile.
type Manager struct {
	ctx        context.Context
	paths      config.Paths
	openvpnBin string
	privilege  PrivilegeMode
	mu         sync.RWMutex
	sessions   map[string]*session
	states     map[string]Snapshot
	logs       map[string][]string
	updates    chan struct{}
	openURL    func(string) error
}

func NewManager(ctx context.Context, paths config.Paths, openvpnBin string, privilege PrivilegeMode) *Manager {
	return &Manager{ctx: ctx, paths: paths, openvpnBin: openvpnBin, privilege: privilege, sessions: make(map[string]*session), states: make(map[string]Snapshot), logs: make(map[string][]string), updates: make(chan struct{}, 1), openURL: openExternalBrowser}
}

func (m *Manager) Updates() <-chan struct{} { return m.updates }

func (m *Manager) Snapshot(profileID string) Snapshot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if state, ok := m.states[profileID]; ok {
		return state
	}
	return Snapshot{ProfileID: profileID, Status: Disconnected}
}

func (m *Manager) Logs(profileID string) []string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return append([]string(nil), m.logs[profileID]...)
}

func (m *Manager) Start(p profile.Profile, credential credentials.Value) error {
	m.mu.RLock()
	if current, ok := m.states[p.ID]; ok && (current.Status == Connecting || current.Status == Connected || current.Status == Disconnecting) {
		m.mu.RUnlock()
		return errors.New("this profile is already running")
	}
	m.mu.RUnlock()
	bin, err := m.resolveOpenVPN()
	if err != nil {
		return err
	}
	if err := m.authorizePrivilege(credential.ElevationPassword); err != nil {
		return err
	}
	credential.ElevationPassword = ""
	m.mu.Lock()
	if current, ok := m.states[p.ID]; ok && (current.Status == Connecting || current.Status == Connected || current.Status == Disconnecting) {
		m.mu.Unlock()
		return errors.New("this profile is already running")
	}
	state := Snapshot{ProfileID: p.ID, Status: Disconnected, StartedAt: time.Now()}
	_ = transition(&state, Connecting)
	m.states[p.ID] = state
	m.logs[p.ID] = nil
	m.mu.Unlock()
	m.notify()

	stamp := time.Now().Format("20060102-150405")
	logPath := filepath.Join(m.paths.LogsDir, p.ID+"-"+stamp+".log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return m.failStart(p.ID, fmt.Errorf("create session log: %w", err))
	}
	pidFile := filepath.Join(m.paths.RuntimeDir, p.ID+".pid")
	_ = os.Remove(pidFile)
	authFile := ""
	if p.NeedsAuth {
		if credential.BrowserSSO {
			if strings.TrimSpace(credential.Username) == "" {
				credential.Username = "ovpntui"
			}
			credential.Password = "ovpntui-sso"
		}
		if credential.Username == "" || credential.Password == "" {
			_ = logFile.Close()
			return m.failStart(p.ID, errors.New("username and password are required by this profile"))
		}
		authFile = filepath.Join(m.paths.RuntimeDir, p.ID+".auth")
		if err := os.WriteFile(authFile, []byte(credential.Username+"\n"+credential.Password+"\n"), 0o600); err != nil {
			_ = logFile.Close()
			return m.failStart(p.ID, fmt.Errorf("create temporary credentials: %w", err))
		}
		if err := os.Chmod(authFile, 0o600); err != nil {
			_ = os.Remove(authFile)
			_ = logFile.Close()
			return m.failStart(p.ID, err)
		}
	}
	managementSocket, err := managementSocketPath(m.paths.RuntimeDir, p.ID)
	if err != nil {
		_ = os.Remove(authFile)
		_ = logFile.Close()
		return m.failStart(p.ID, err)
	}
	_ = os.Remove(managementSocket)
	managementUser, err := currentUsername()
	if err != nil {
		_ = os.Remove(authFile)
		_ = logFile.Close()
		return m.failStart(p.ID, err)
	}
	args := []string{
		"--config", p.ConfigPath(), "--cd", p.Dir, "--writepid", pidFile, "--verb", "3",
		"--management", managementSocket, "unix", "--management-client-user", managementUser,
		"--management-hold", "--setenv", "IV_SSO", "webauth,openurl",
	}
	if authFile != "" {
		args = append(args, "--auth-user-pass", authFile, "--auth-nocache")
	}
	command, commandArgs, err := m.wrapCommand(bin, args)
	if err != nil {
		_ = os.Remove(authFile)
		_ = logFile.Close()
		return m.failStart(p.ID, err)
	}
	// The process is deliberately not tied directly to the UI context. Shutdown
	// sends signals to the whole process group first, which also handles elevated
	// children correctly; CommandContext could kill only the sudo/pkexec wrapper.
	cmd := exec.Command(command, commandArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = os.Remove(authFile)
		_ = logFile.Close()
		return m.failStart(p.ID, err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		_ = os.Remove(authFile)
		_ = logFile.Close()
		return m.failStart(p.ID, err)
	}
	if err := cmd.Start(); err != nil {
		_ = os.Remove(authFile)
		_ = logFile.Close()
		return m.failStart(p.ID, explainStartError(err, m.privilege))
	}
	s := &session{cmd: cmd, pidFile: pidFile, authFile: authFile, managementSocket: managementSocket, log: logFile, done: make(chan struct{})}
	m.mu.Lock()
	m.sessions[p.ID] = s
	state = m.states[p.ID]
	state.PID = cmd.Process.Pid
	state.LogPath = logPath
	m.states[p.ID] = state
	m.mu.Unlock()
	m.notify()
	go m.monitor(p.ID, s, stdout, stderr)
	go m.manage(p.ID, s)
	return nil
}

func (m *Manager) authorizePrivilege(password string) error {
	mode := m.privilege
	if mode == PrivilegeNone || os.Geteuid() == 0 {
		return nil
	}
	if mode == PrivilegePKExec {
		if _, err := exec.LookPath("pkexec"); err != nil {
			return errors.New("pkexec is not installed")
		}
		return nil
	}
	sudo, sudoErr := exec.LookPath("sudo")
	if mode == PrivilegeAuto && sudoErr != nil {
		if _, err := exec.LookPath("pkexec"); err == nil {
			return nil
		}
		return nil
	}
	if sudoErr != nil {
		return errors.New("sudo is not installed")
	}
	check := exec.CommandContext(m.ctx, sudo, "-n", "true")
	if check.Run() == nil {
		return nil
	}
	if mode == PrivilegeAuto && (os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "") {
		if _, err := exec.LookPath("pkexec"); err == nil {
			return nil
		}
	}
	if password == "" {
		return ErrSudoPasswordRequired
	}
	secret := []byte(password + "\n")
	defer func() {
		for i := range secret {
			secret[i] = 0
		}
	}()
	authorize := exec.CommandContext(m.ctx, sudo, "-S", "-p", "", "-v")
	authorize.Stdin = bytes.NewReader(secret)
	if err := authorize.Run(); err != nil {
		return fmt.Errorf("%w: authentication failed or sudo policy denied access", ErrSudoPasswordRequired)
	}
	return nil
}

func (m *Manager) monitor(id string, s *session, stdout, stderr io.Reader) {
	var readers sync.WaitGroup
	readers.Add(2)
	go func() { defer readers.Done(); m.scan(id, s, stdout) }()
	go func() { defer readers.Done(); m.scan(id, s, stderr) }()
	err := s.cmd.Wait()
	readers.Wait()
	_ = s.log.Close()
	_ = os.Remove(s.authFile)
	_ = os.Remove(s.pidFile)
	_ = os.Remove(s.managementSocket)
	m.mu.Lock()
	state := m.states[id]
	state.AuthPending = false
	state.AuthURL = ""
	state.AuthError = ""
	state.Interface = ""
	state.IP = ""
	state.ConnectedAt = time.Time{}
	wasStopping := s.stopping
	delete(m.sessions, id)
	if wasStopping {
		if state.Status != Disconnecting {
			state.Status = Disconnecting
		}
		_ = transition(&state, Disconnected)
		state.Error = ""
		state.PID = 0
	} else {
		if state.Status == Connecting || state.Status == Connected {
			_ = transition(&state, Failed)
		}
		if state.Error == "" {
			if err != nil {
				state.Error = "OpenVPN terminated unexpectedly: " + err.Error()
			} else {
				state.Error = "OpenVPN terminated unexpectedly"
			}
		}
		state.PID = 0
	}
	m.states[id] = state
	close(s.done)
	m.mu.Unlock()
	m.notify()
}

func (m *Manager) scan(id string, s *session, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		_, _ = fmt.Fprintln(s.log, line)
		event := ParseLogLine(line)
		m.mu.Lock()
		lines := append(m.logs[id], line)
		if len(lines) > 2000 {
			lines = append([]string(nil), lines[len(lines)-2000:]...)
		}
		m.logs[id] = lines
		state := m.states[id]
		if event.Interface != "" {
			state.Interface = event.Interface
		}
		if event.IP != "" {
			state.IP = event.IP
		}
		if pid := readPID(s.pidFile); pid > 0 {
			state.PID = pid
		}
		if event.Connected && state.Status == Connecting {
			_ = transition(&state, Connected)
			state.ConnectedAt = time.Now()
			state.AuthPending = false
			state.AuthURL = ""
			state.AuthError = ""
		}
		if event.Failure != "" {
			state.Error = event.Failure
		}
		m.states[id] = state
		m.mu.Unlock()
		m.notify()
	}
}

func (m *Manager) Stop(profileID string) error {
	m.mu.Lock()
	s, ok := m.sessions[profileID]
	if !ok {
		m.mu.Unlock()
		return errors.New("profile is not running")
	}
	state := m.states[profileID]
	if state.Status == Disconnecting {
		m.mu.Unlock()
		return nil
	}
	if err := transition(&state, Disconnecting); err != nil {
		m.mu.Unlock()
		return err
	}
	s.stopping = true
	m.states[profileID] = state
	pid := s.cmd.Process.Pid
	m.mu.Unlock()
	m.notify()
	if err := syscall.Kill(-pid, syscall.SIGINT); err != nil && !errors.Is(err, os.ErrProcessDone) {
		_ = s.cmd.Process.Signal(os.Interrupt)
	}
	go func() {
		select {
		case <-s.done:
		case <-time.After(8 * time.Second):
			_ = syscall.Kill(-pid, syscall.SIGKILL)
			_ = s.cmd.Process.Kill()
		}
	}()
	return nil
}

func (m *Manager) Shutdown(ctx context.Context) error {
	m.mu.RLock()
	ids := make([]string, 0, len(m.sessions))
	for id := range m.sessions {
		ids = append(ids, id)
	}
	m.mu.RUnlock()
	for _, id := range ids {
		_ = m.Stop(id)
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	for {
		m.mu.RLock()
		count := len(m.sessions)
		m.mu.RUnlock()
		if count == 0 {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func (m *Manager) resolveOpenVPN() (string, error) {
	if m.openvpnBin != "" {
		path, err := exec.LookPath(m.openvpnBin)
		if err != nil {
			return "", fmt.Errorf("OpenVPN binary %q not found: %w", m.openvpnBin, err)
		}
		return path, nil
	}
	path, err := exec.LookPath("openvpn")
	if err != nil {
		return "", errors.New("openvpn is not installed or is not in PATH")
	}
	return path, nil
}

func (m *Manager) wrapCommand(bin string, args []string) (string, []string, error) {
	mode := m.privilege
	if mode == PrivilegeAuto {
		if os.Geteuid() == 0 {
			mode = PrivilegeNone
		} else if sudo, err := exec.LookPath("sudo"); err == nil {
			check := exec.CommandContext(m.ctx, sudo, "-n", "true")
			if check.Run() == nil {
				return sudo, append([]string{"-n", "--", bin}, args...), nil
			}
			if pkexec, pkErr := exec.LookPath("pkexec"); pkErr == nil && (os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "") {
				return pkexec, append([]string{bin}, args...), nil
			}
			return sudo, append([]string{"-n", "--", bin}, args...), nil
		} else if pkexec, pkErr := exec.LookPath("pkexec"); pkErr == nil {
			return pkexec, append([]string{bin}, args...), nil
		} else {
			mode = PrivilegeNone
		}
	}
	switch mode {
	case PrivilegeNone:
		return bin, args, nil
	case PrivilegeSudo:
		sudo, err := exec.LookPath("sudo")
		if err != nil {
			return "", nil, errors.New("sudo is not installed")
		}
		return sudo, append([]string{"-n", "--", bin}, args...), nil
	case PrivilegePKExec:
		pkexec, err := exec.LookPath("pkexec")
		if err != nil {
			return "", nil, errors.New("pkexec is not installed")
		}
		return pkexec, append([]string{bin}, args...), nil
	default:
		return "", nil, fmt.Errorf("invalid privilege mode %q", mode)
	}
}

func (m *Manager) failStart(id string, err error) error {
	m.mu.Lock()
	state := m.states[id]
	if state.Status == Connecting {
		_ = transition(&state, Failed)
	}
	state.Error = err.Error()
	m.states[id] = state
	m.mu.Unlock()
	m.notify()
	return err
}

func (m *Manager) notify() {
	select {
	case m.updates <- struct{}{}:
	default:
	}
}

func readPID(path string) int {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return pid
}

func currentUsername() (string, error) {
	current, err := user.Current()
	if err != nil {
		return "", fmt.Errorf("determine user for private management socket: %w", err)
	}
	if current.Username == "" || strings.ContainsAny(current.Username, "\r\n\x00") {
		return "", errors.New("determine user for private management socket: invalid username")
	}
	return current.Username, nil
}

func managementSocketPath(runtimeDir, profileID string) (string, error) {
	shortID := profileID
	if len(shortID) > 20 {
		shortID = shortID[:20]
	}
	path := filepath.Join(runtimeDir, "m-"+shortID)
	if len(path) >= 100 {
		return "", fmt.Errorf("OpenVPN management socket path is too long (%d bytes); set XDG_RUNTIME_DIR to a shorter private directory", len(path))
	}
	return path, nil
}

func signalProcessGroup(pid int) error {
	if err := syscall.Kill(-pid, syscall.SIGINT); err != nil && !errors.Is(err, os.ErrProcessDone) {
		return err
	}
	return nil
}

func explainStartError(err error, mode PrivilegeMode) error {
	message := err.Error()
	if mode == PrivilegeSudo || mode == PrivilegeAuto {
		message += "; if sudo authentication is required, run 'sudo -v' before starting ovpntui or use --privilege=pkexec"
	}
	return errors.New(message)
}
