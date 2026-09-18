package openvpn

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
)

const managementConnectTimeout = 8 * time.Second

type managementEvent struct {
	authPending bool
	authURL     string
	state       string
	detail      string
}

func parseManagementLine(line string) managementEvent {
	event := managementEvent{}
	if strings.HasPrefix(line, ">STATE:") {
		fields := strings.Split(strings.TrimPrefix(line, ">STATE:"), ",")
		if len(fields) > 1 {
			event.state = fields[1]
			event.authPending = fields[1] == "AUTH_PENDING"
		}
		if len(fields) > 2 {
			event.detail = fields[2]
		}
		return event
	}
	payload, ok := strings.CutPrefix(line, ">INFOMSG:")
	if !ok {
		return event
	}
	for _, prefix := range []string{"WEB_AUTH:", "OPEN_URL:"} {
		if !strings.HasPrefix(payload, prefix) {
			continue
		}
		value := strings.TrimPrefix(payload, prefix)
		start := strings.Index(value, "https://")
		if start < 0 {
			return event
		}
		candidate := strings.TrimSpace(value[start:])
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
			return event
		}
		event.authPending = true
		event.authURL = parsed.String()
		return event
	}
	return event
}

func (m *Manager) manage(id string, s *session) {
	conn, err := connectManagement(s.managementSocket, s.done)
	if err != nil {
		if !errors.Is(err, errSessionEnded) {
			m.failManagement(id, s, err)
		}
		return
	}
	defer func() { _ = conn.Close() }()

	s.managementMu.Lock()
	s.managementConn = conn
	// Publish readiness after initialization, so a racing Stop cannot be
	// followed by hold release on the same connection.
	_ = conn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err = fmt.Fprint(conn, "version 5\nstate on\nhold off\nhold release\n")
	close(s.managementReady)
	s.managementMu.Unlock()
	if err != nil {
		m.failManagement(id, s, fmt.Errorf("initialize OpenVPN management channel: %w", err))
		return
	}
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 16*1024), 1024*1024)
	for scanner.Scan() {
		event := parseManagementLine(scanner.Text())
		m.updateManagementState(id, s, event)
		if event.authPending {
			m.setAuthPending(id, s, event.authURL)
		}
	}
	if err := scanner.Err(); err != nil {
		select {
		case <-s.done:
			return
		default:
			m.failManagement(id, s, fmt.Errorf("OpenVPN management channel failed: %w", err))
		}
		return
	}
	select {
	case <-s.done:
		return
	default:
		m.failManagement(id, s, errors.New("OpenVPN management channel closed unexpectedly"))
	}
}

var errSessionEnded = errors.New("OpenVPN session ended")

func connectManagement(socket string, done <-chan struct{}) (net.Conn, error) {
	deadline := time.Now().Add(managementConnectTimeout)
	var lastErr error
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("unix", socket, 250*time.Millisecond)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		select {
		case <-done:
			return nil, errSessionEnded
		case <-time.After(50 * time.Millisecond):
		}
	}
	return nil, fmt.Errorf("connect to OpenVPN management socket: %w", lastErr)
}

func (m *Manager) setAuthPending(id string, s *session, rawURL string) {
	var shouldOpen bool
	m.mu.Lock()
	state := m.states[id]
	current, active := m.sessions[id]
	if active && current == s && !s.stopping {
		state.AuthPending = true
		if rawURL != "" && rawURL != s.openedAuthURL {
			state.AuthURL = rawURL
			state.AuthError = ""
			s.openedAuthURL = rawURL
			shouldOpen = true
		}
		m.states[id] = state
	}
	m.mu.Unlock()
	m.notify()
	if !shouldOpen {
		return
	}
	parsed, _ := url.Parse(rawURL)
	m.appendInternalLog(id, s, "SSO authentication requested for "+parsed.Host)
	if err := m.openURL(rawURL); err != nil {
		m.mu.Lock()
		state := m.states[id]
		state.AuthError = "could not open browser: " + err.Error()
		m.states[id] = state
		m.mu.Unlock()
		m.notify()
	}
}

func (m *Manager) failManagement(id string, s *session, err error) {
	m.mu.Lock()
	current, active := m.sessions[id]
	if !active || current != s || s.stopping {
		m.mu.Unlock()
		return
	}
	state := m.states[id]
	state.Error = err.Error()
	state.Status = Disconnecting
	s.stopping = true
	s.stopError = err.Error()
	m.states[id] = state
	m.mu.Unlock()
	m.appendInternalLog(id, s, err.Error())
	m.notify()
	go m.stopSession(id, s)
}

// The socket is already authorized for the daemon's user, so this works even
// when OpenVPN runs as root and the sudo timestamp has expired.
func (s *session) terminateViaManagement() error {
	s.managementMu.Lock()
	defer s.managementMu.Unlock()
	if s.managementConn == nil {
		return errors.New("OpenVPN management channel is unavailable")
	}
	_ = s.managementConn.SetWriteDeadline(time.Now().Add(time.Second))
	_, err := fmt.Fprint(s.managementConn, "signal SIGTERM\n")
	if err != nil {
		// --management-signal + --remap-usr1 SIGTERM makes EOF another
		// graceful termination path, without signaling an elevated PID.
		_ = s.managementConn.Close()
	}
	return err
}

func (m *Manager) stopSession(id string, s *session) {
	select {
	case <-s.done:
		return
	case <-s.managementReady:
	case <-time.After(managementConnectTimeout):
	}
	if err := s.terminateViaManagement(); err != nil {
		m.appendInternalLog(id, s, "management disconnect: "+err.Error())
		// SIGTERM lets an accessible child (or a cooperating privilege
		// wrapper) clean up. Never SIGKILL the wrapper or claim it cleaned up.
		if signalErr := s.cmd.Process.Signal(syscall.SIGTERM); signalErr != nil {
			m.appendInternalLog(id, s, "termination signal: "+signalErr.Error())
		}
	}
	select {
	case <-s.done:
		return
	case <-time.After(8 * time.Second):
	}
	// Dropping management also requests graceful exit if the command stalled.
	s.managementMu.Lock()
	if s.managementConn != nil {
		_ = s.managementConn.Close()
	}
	s.managementMu.Unlock()
	m.mu.Lock()
	if m.sessions[id] == s {
		state := m.states[id]
		state.Error = "OpenVPN has not confirmed shutdown; VPN routes may still be active"
		m.states[id] = state
	}
	m.mu.Unlock()
	m.notify()
}

func (m *Manager) updateManagementState(id string, s *session, event managementEvent) {
	if event.state != "RECONNECTING" && event.state != "EXITING" {
		return
	}
	m.mu.Lock()
	if m.sessions[id] != s || s.stopping {
		m.mu.Unlock()
		return
	}
	state := m.states[id]
	state.Status = Disconnecting
	state.ConnectedAt = time.Time{}
	state.AuthPending = false
	state.AuthURL = ""
	state.AuthError = ""
	s.stopping = true
	s.stopError = "VPN connection ended (" + event.detail + "); reconnect the profile once the network is available"
	state.Error = s.stopError
	m.states[id] = state
	m.mu.Unlock()
	m.notify()
	go m.stopSession(id, s)
}

func (m *Manager) appendInternalLog(id string, s *session, line string) {
	line = "ovpntui: " + line
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sessions[id] != s {
		return
	}
	_, _ = fmt.Fprintln(s.log, line)
	lines := append(m.logs[id], line)
	if len(lines) > 2000 {
		lines = append([]string(nil), lines[len(lines)-2000:]...)
	}
	m.logs[id] = lines
}

func openExternalBrowser(rawURL string) error {
	var name string
	switch runtime.GOOS {
	case "linux":
		name = "xdg-open"
	case "darwin":
		name = "open"
	default:
		return fmt.Errorf("automatic browser opening is unsupported on %s", runtime.GOOS)
	}
	path, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s is not installed", name)
	}
	cmd := exec.Command(path, rawURL)
	if err := cmd.Start(); err != nil {
		return err
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
