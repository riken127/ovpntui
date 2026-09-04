package tui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/riken127/ovpntui/internal/credentials"
	"github.com/riken127/ovpntui/internal/openvpn"
	"github.com/riken127/ovpntui/internal/profile"
)

type mode int

const (
	modeList mode = iota
	modeImport
	modeRename
	modeDelete
	modeCredentials
	modeElevation
	modeLogs
)

type profileItem struct {
	profile profile.Profile
	state   openvpn.Snapshot
	now     time.Time
}

func (i profileItem) Title() string { return i.profile.Name }
func (i profileItem) Description() string {
	parts := []string{string(i.state.Status)}
	if i.state.AuthPending {
		parts = append(parts, "waiting for browser SSO")
	}
	if duration := i.state.Duration(i.now); duration > 0 {
		parts = append(parts, duration.String())
	}
	if i.state.Interface != "" {
		parts = append(parts, "iface "+i.state.Interface)
	}
	if i.state.IP != "" {
		parts = append(parts, "IP "+i.state.IP)
	}
	if i.state.PID > 0 {
		parts = append(parts, fmt.Sprintf("PID %d", i.state.PID))
	}
	return strings.Join(parts, " • ")
}
func (i profileItem) FilterValue() string { return i.profile.Name }

type profilesMsg struct {
	profiles []profile.Profile
	err      error
}
type actionMsg struct {
	message    string
	err        error
	refresh    bool
	profile    profile.Profile
	credential credentials.Value
}
type credentialMsg struct {
	profile profile.Profile
	value   credentials.Value
	found   bool
	err     error
}
type tickMsg time.Time
type managerMsg struct{}

// Model is the top-level Bubble Tea model.
type Model struct {
	store             *profile.Store
	manager           openvpn.Controller
	credentials       *credentials.Store
	list              list.Model
	input             textinput.Model
	password          textinput.Model
	viewport          viewport.Model
	profiles          []profile.Profile
	mode              mode
	selected          profile.Profile
	pendingCredential credentials.Value
	credentialFocus   int
	width             int
	height            int
	status            string
	statusError       bool
}

func New(store *profile.Store, manager openvpn.Controller, credentialStore *credentials.Store) Model {
	l := list.New(nil, profileDelegate{}, 80, 22)
	l.Title = "Profiles"
	l.Styles.Title = listTitleStyle
	l.Styles.PaginationStyle = mutedStyle
	l.Styles.FilterPrompt = accentStyle
	l.Styles.FilterCursor = accentStyle
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(true)
	l.SetShowHelp(false)
	input := textinput.New()
	input.CharLimit = 4096
	password := textinput.New()
	password.EchoMode = textinput.EchoPassword
	password.EchoCharacter = '•'
	password.CharLimit = 1024
	return Model{store: store, manager: manager, credentials: credentialStore, list: l, input: input, password: password, viewport: viewport.New(80, 18), status: "Ready"}
}

func (m Model) Init() tea.Cmd { return tea.Batch(m.loadProfiles(), tickCmd(), m.waitManager()) }

func (m Model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := message.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.list.SetSize(max(30, msg.Width-6), max(8, msg.Height-11))
		m.viewport.Width = max(30, msg.Width-4)
		m.viewport.Height = max(5, msg.Height-11)
	case profilesMsg:
		if msg.err != nil {
			m.setError(msg.err)
			return m, nil
		}
		m.profiles = msg.profiles
		m.refreshItems(time.Now())
	case tickMsg:
		m.refreshItems(time.Time(msg))
		if m.mode == modeLogs {
			m.refreshLogs()
		}
		return m, tickCmd()
	case managerMsg:
		m.refreshItems(time.Now())
		if p, ok := m.selectedProfile(); ok {
			state := m.manager.Snapshot(p.ID)
			if state.Status == openvpn.Failed && state.Error != "" {
				m.setError(fmt.Errorf("%s: %s", p.Name, state.Error))
			} else if state.AuthError != "" {
				m.status, m.statusError = state.AuthError+" — open manually: "+state.AuthURL, true
			} else if state.AuthPending {
				m.status, m.statusError = "Complete the SSO login in your browser", false
			}
		}
		if m.mode == modeLogs {
			m.refreshLogs()
		}
		return m, m.waitManager()
	case actionMsg:
		if msg.err != nil {
			m.setError(msg.err)
			if errors.Is(msg.err, openvpn.ErrSudoPasswordRequired) {
				m.openElevationForm(msg.profile, msg.credential)
				return m, textinput.Blink
			}
		} else {
			m.status, m.statusError = msg.message, false
		}
		if msg.refresh {
			return m, m.loadProfiles()
		}
	case credentialMsg:
		if msg.err != nil {
			m.setError(msg.err)
			m.openCredentialForm(msg.profile)
			return m, nil
		}
		if msg.found {
			return m, m.startCmd(msg.profile, msg.value)
		}
		m.openCredentialForm(msg.profile)
		return m, nil
	}

	key, ok := message.(tea.KeyMsg)
	if !ok {
		return m.updateComponent(message)
	}
	if key.String() == "ctrl+c" {
		return m, tea.Quit
	}
	if key.String() == "q" && m.mode != modeImport && m.mode != modeRename && m.mode != modeCredentials && m.mode != modeElevation {
		return m, tea.Quit
	}

	switch m.mode {
	case modeList:
		return m.updateList(key)
	case modeImport:
		return m.updateImport(key)
	case modeRename:
		return m.updateRename(key)
	case modeDelete:
		return m.updateDelete(key)
	case modeCredentials:
		return m.updateCredentials(key)
	case modeElevation:
		return m.updateElevation(key)
	case modeLogs:
		if key.String() == "esc" {
			m.mode = modeList
			return m, nil
		}
		var cmd tea.Cmd
		m.viewport, cmd = m.viewport.Update(key)
		return m, cmd
	default:
		return m, nil
	}
}

func (m Model) updateComponent(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch m.mode {
	case modeImport, modeRename:
		m.input, cmd = m.input.Update(msg)
	case modeCredentials, modeElevation:
		if m.credentialFocus == 0 {
			if m.mode == modeElevation {
				m.password, cmd = m.password.Update(msg)
				break
			}
			m.input, cmd = m.input.Update(msg)
		} else {
			m.password, cmd = m.password.Update(msg)
		}
	case modeLogs:
		m.viewport, cmd = m.viewport.Update(msg)
	default:
		m.list, cmd = m.list.Update(msg)
	}
	return m, cmd
}

func (m Model) updateElevation(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.password.SetValue("")
		m.pendingCredential = credentials.Value{}
		m.mode = modeList
		return m, nil
	case "enter":
		if m.password.Value() == "" {
			m.setError(fmt.Errorf("administrator password is required"))
			return m, nil
		}
		value := m.pendingCredential
		value.ElevationPassword = m.password.Value()
		m.password.SetValue("")
		m.pendingCredential = credentials.Value{}
		p := m.selected
		m.mode = modeList
		return m, m.startCmd(p, value)
	}
	var cmd tea.Cmd
	m.password, cmd = m.password.Update(key)
	return m, cmd
}

func (m Model) updateList(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	if m.list.SettingFilter() {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(key)
		return m, cmd
	}
	switch key.String() {
	case "i":
		m.mode = modeImport
		m.input.SetValue("")
		m.input.Placeholder = "/path/to/profile.ovpn"
		m.input.Prompt = "File: "
		m.input.Focus()
		return m, textinput.Blink
	case "enter":
		p, ok := m.selectedProfile()
		if !ok {
			m.status = "No profile selected"
			return m, nil
		}
		state := m.manager.Snapshot(p.ID)
		if state.Status == openvpn.Connecting || state.Status == openvpn.Connected {
			return m, m.stopCmd(p)
		}
		if state.Status == openvpn.Disconnecting {
			m.status = "Disconnect already in progress"
			return m, nil
		}
		if p.NeedsAuth {
			return m, m.loadCredentialCmd(p)
		}
		return m, m.startCmd(p, credentials.Value{})
	case "o":
		p, ok := m.selectedProfile()
		if !ok {
			return m, nil
		}
		state := m.manager.Snapshot(p.ID)
		if state.Status == openvpn.Connecting || state.Status == openvpn.Connected || state.Status == openvpn.Disconnecting {
			m.setError(fmt.Errorf("profile is already running"))
			return m, nil
		}
		if !p.NeedsAuth {
			m.setError(fmt.Errorf("this profile does not request user authentication"))
			return m, nil
		}
		return m, m.startCmd(p, credentials.Value{BrowserSSO: true})
	case "l":
		p, ok := m.selectedProfile()
		if !ok {
			return m, nil
		}
		m.selected = p
		m.mode = modeLogs
		m.refreshLogs()
		m.viewport.GotoBottom()
		return m, nil
	case "r":
		p, ok := m.selectedProfile()
		if !ok {
			return m, nil
		}
		m.selected = p
		m.mode = modeRename
		m.input.SetValue(p.Name)
		m.input.Placeholder = "Profile name"
		m.input.Prompt = "Name: "
		m.input.Focus()
		m.input.CursorEnd()
		return m, textinput.Blink
	case "d":
		p, ok := m.selectedProfile()
		if !ok {
			return m, nil
		}
		state := m.manager.Snapshot(p.ID)
		if state.Status == openvpn.Connecting || state.Status == openvpn.Connected || state.Status == openvpn.Disconnecting {
			m.setError(fmt.Errorf("disconnect the profile before deleting it"))
			return m, nil
		}
		m.selected = p
		m.mode = modeDelete
		return m, nil
	}
	var cmd tea.Cmd
	m.list, cmd = m.list.Update(key)
	return m, cmd
}

func (m Model) updateImport(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.mode = modeList
		m.input.Blur()
		return m, nil
	case "enter":
		path := strings.TrimSpace(m.input.Value())
		if path == "" {
			return m, nil
		}
		m.mode = modeList
		m.status = "Importing " + filepath.Base(path) + "…"
		return m, func() tea.Msg {
			p, err := m.store.Import(path)
			return actionMsg{message: "Imported " + p.Name, err: err, refresh: true}
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(key)
	return m, cmd
}

func (m Model) updateRename(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.mode = modeList
		m.input.Blur()
		return m, nil
	case "enter":
		name := strings.TrimSpace(m.input.Value())
		if name == "" {
			m.setError(fmt.Errorf("profile name cannot be empty"))
			return m, nil
		}
		p := m.selected
		m.mode = modeList
		return m, func() tea.Msg {
			renamed, err := m.store.Rename(p.ID, name)
			return actionMsg{message: "Renamed to " + renamed.Name, err: err, refresh: true}
		}
	}
	var cmd tea.Cmd
	m.input, cmd = m.input.Update(key)
	return m, cmd
}

func (m Model) updateDelete(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch strings.ToLower(key.String()) {
	case "y":
		p := m.selected
		m.mode = modeList
		return m, func() tea.Msg {
			err := m.store.Delete(p.ID)
			if err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = m.credentials.Delete(ctx, p.ID)
			}
			return actionMsg{message: "Deleted " + p.Name, err: err, refresh: true}
		}
	case "n", "esc":
		m.mode = modeList
	}
	return m, nil
}

func (m Model) updateCredentials(key tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "esc":
		m.mode = modeList
		return m, nil
	case "tab", "shift+tab":
		m.credentialFocus = 1 - m.credentialFocus
		if m.credentialFocus == 0 {
			m.password.Blur()
			return m, m.input.Focus()
		}
		m.input.Blur()
		return m, m.password.Focus()
	case "ctrl+o":
		p := m.selected
		value := credentials.Value{Username: strings.TrimSpace(m.input.Value()), BrowserSSO: true}
		m.password.SetValue("")
		m.mode = modeList
		return m, m.startCmd(p, value)
	case "enter", "ctrl+s":
		if m.credentialFocus == 0 {
			m.credentialFocus = 1
			m.input.Blur()
			return m, m.password.Focus()
		}
		value := credentials.Value{Username: m.input.Value(), Password: m.password.Value()}
		if value.Username == "" || value.Password == "" {
			m.setError(fmt.Errorf("username and password are required"))
			return m, nil
		}
		p := m.selected
		save := key.String() == "ctrl+s"
		m.mode = modeList
		if save {
			return m, func() tea.Msg {
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				if err := m.credentials.Save(ctx, p.ID, value); err != nil {
					return actionMsg{err: err}
				}
				if err := m.manager.Start(p, value); err != nil {
					return actionMsg{err: err, profile: p, credential: value}
				}
				return actionMsg{message: "Connecting to " + p.Name + " (credentials saved securely)"}
			}
		}
		return m, m.startCmd(p, value)
	}
	var cmd tea.Cmd
	if m.credentialFocus == 0 {
		m.input, cmd = m.input.Update(key)
	} else {
		m.password, cmd = m.password.Update(key)
	}
	return m, cmd
}

func (m Model) View() string {
	if m.width == 0 {
		return "Starting ovpntui…"
	}
	header := m.headerView()
	content := ""
	switch m.mode {
	case modeImport:
		content = m.formView("Import profile", "Copy an OpenVPN profile and its local assets.", m.input.View(), "enter import  •  esc cancel")
	case modeRename:
		content = m.formView("Rename profile", m.selected.Name, m.input.View(), "enter save  •  esc cancel")
	case modeDelete:
		content = m.formView("Delete profile", "This removes the imported profile and its copied files.", fmt.Sprintf("Delete %s?", accentStyle.Render(m.selected.Name)), "y confirm  •  n/esc cancel")
	case modeCredentials:
		fields := m.input.View() + "\n" + m.password.View()
		content = m.formView("VPN credentials", m.selected.Name, fields, "tab switch  •  enter connect once  •  ctrl+s save  •  ctrl+o browser SSO  •  esc cancel")
	case modeElevation:
		content = m.formView("Administrator authorization", "OpenVPN needs elevated network permissions. The password is never stored.", m.password.View(), "enter authorize once  •  esc cancel")
	case modeLogs:
		state := m.manager.Snapshot(m.selected.ID)
		logsHeader := lipgloss.JoinHorizontal(lipgloss.Center, sectionTitleStyle.Render("Session logs"), "  ", stateBadge(state.Status), "  ", mutedStyle.Render(m.selected.Name))
		content = panelStyle.Width(m.contentWidth()).Render(logsHeader+"\n\n"+m.viewport.View()) + "\n" + footerStyle.Render("↑/↓ scroll  •  esc back  •  q close TUI")
	default:
		content = m.list.View() + "\n" + m.shortcutsView()
	}
	status := m.statusView()
	body := lipgloss.JoinVertical(lipgloss.Left, header, content, status)
	return frameStyle.Width(max(1, m.width-2)).Height(max(1, m.height-2)).Render(body)
}

func (m Model) headerView() string {
	connected, active := 0, 0
	for _, p := range m.profiles {
		status := m.manager.Snapshot(p.ID).Status
		if status == openvpn.Connected {
			connected++
		}
		if status == openvpn.Connecting || status == openvpn.Connected || status == openvpn.Disconnecting {
			active++
		}
	}
	brand := brandStyle.Render("◆ ovpntui")
	summary := mutedStyle.Render(fmt.Sprintf("%d profiles  ·  %d active  ·  %d connected", len(m.profiles), active, connected))
	if m.contentWidth() < 64 {
		return headerStyle.Render(brand + "\n" + summary)
	}
	gap := max(2, m.contentWidth()-lipgloss.Width(brand)-lipgloss.Width(summary))
	return headerStyle.Width(m.contentWidth()).Render(brand + strings.Repeat(" ", gap) + summary)
}

func (m Model) formView(title, description, fields, help string) string {
	heading := sectionTitleStyle.Render(title)
	if description != "" {
		heading += "\n" + mutedStyle.Render(description)
	}
	return panelStyle.Width(m.contentWidth()).Render(heading+"\n\n"+fields) + "\n" + footerStyle.Render(help)
}

func (m Model) shortcutsView() string {
	help := "↵ connect  •  o SSO  •  i import  •  l logs  •  r rename  •  d delete  •  / filter  •  q quit"
	if m.width < 88 {
		help = "↵ connect  •  o SSO  •  i import  •  l logs  •  q quit"
	}
	return footerStyle.Render(help)
}

func (m Model) statusView() string {
	icon := "✓"
	style := statusOKStyle
	if m.statusError {
		icon = "!"
		style = statusErrorStyle
	}
	return style.Width(m.contentWidth()).Render(icon + "  " + m.status)
}

func (m Model) contentWidth() int { return max(28, m.width-6) }

func (m *Model) refreshItems(now time.Time) {
	selectedID := ""
	if p, ok := m.selectedProfile(); ok {
		selectedID = p.ID
	}
	items := make([]list.Item, 0, len(m.profiles))
	selectedIndex := 0
	for i, p := range m.profiles {
		items = append(items, profileItem{profile: p, state: m.manager.Snapshot(p.ID), now: now})
		if p.ID == selectedID {
			selectedIndex = i
		}
	}
	m.list.SetItems(items)
	m.list.Title = fmt.Sprintf("Profiles  %s", mutedStyle.Render(fmt.Sprintf("%d total", len(items))))
	if len(items) > 0 {
		m.list.Select(selectedIndex)
	}
}

func (m *Model) refreshLogs() {
	lines := m.manager.Logs(m.selected.ID)
	state := m.manager.Snapshot(m.selected.ID)
	if len(lines) == 0 {
		if state.LogPath != "" {
			m.viewport.SetContent("No output yet.\nPersistent log: " + state.LogPath)
		} else {
			m.viewport.SetContent("No session logs yet.")
		}
		return
	}
	m.viewport.SetContent(strings.Join(lines, "\n"))
}

func (m *Model) selectedProfile() (profile.Profile, bool) {
	item, ok := m.list.SelectedItem().(profileItem)
	if !ok {
		return profile.Profile{}, false
	}
	return item.profile, true
}

func (m *Model) setError(err error) { m.status, m.statusError = err.Error(), true }

func (m *Model) openCredentialForm(p profile.Profile) {
	m.selected = p
	m.mode = modeCredentials
	m.credentialFocus = 0
	m.input.SetValue("")
	m.input.Prompt = "Username: "
	m.input.Placeholder = "username"
	m.input.Focus()
	m.password.SetValue("")
	m.password.Prompt = "Password: "
	m.password.Placeholder = "password"
	m.password.Blur()
}

func (m *Model) openElevationForm(p profile.Profile, value credentials.Value) {
	value.ElevationPassword = ""
	m.selected = p
	m.pendingCredential = value
	m.mode = modeElevation
	m.credentialFocus = 0
	m.password.SetValue("")
	m.password.Prompt = "Administrator password: "
	m.password.Placeholder = "sudo password"
	m.password.Focus()
}

func (m Model) loadProfiles() tea.Cmd {
	return func() tea.Msg { profiles, err := m.store.List(); return profilesMsg{profiles: profiles, err: err} }
}
func (m Model) startCmd(p profile.Profile, value credentials.Value) tea.Cmd {
	return func() tea.Msg {
		err := m.manager.Start(p, value)
		value.ElevationPassword = ""
		return actionMsg{message: "Connecting to " + p.Name, err: err, profile: p, credential: value}
	}
}
func (m Model) stopCmd(p profile.Profile) tea.Cmd {
	return func() tea.Msg {
		err := m.manager.Stop(p.ID)
		return actionMsg{message: "Disconnecting " + p.Name, err: err}
	}
}
func (m Model) loadCredentialCmd(p profile.Profile) tea.Cmd {
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		value, found, err := m.credentials.Load(ctx, p.ID)
		return credentialMsg{profile: p, value: value, found: found, err: err}
	}
}
func (m Model) waitManager() tea.Cmd {
	return func() tea.Msg { <-m.manager.Updates(); return managerMsg{} }
}
func tickCmd() tea.Cmd { return tea.Tick(time.Second, func(t time.Time) tea.Msg { return tickMsg(t) }) }

var (
	primaryColor   = lipgloss.AdaptiveColor{Light: "#4F46E5", Dark: "#8B80F9"}
	secondaryColor = lipgloss.AdaptiveColor{Light: "#0369A1", Dark: "#67D7F5"}
	mutedColor     = lipgloss.AdaptiveColor{Light: "#64748B", Dark: "#8993A4"}
	panelColor     = lipgloss.AdaptiveColor{Light: "#CBD5E1", Dark: "#30394A"}
	successColor   = lipgloss.AdaptiveColor{Light: "#047857", Dark: "#5FE3A1"}
	warningColor   = lipgloss.AdaptiveColor{Light: "#B45309", Dark: "#F9C56A"}
	dangerColor    = lipgloss.AdaptiveColor{Light: "#BE123C", Dark: "#FF6B8A"}

	frameStyle               = lipgloss.NewStyle().Padding(0, 1)
	headerStyle              = lipgloss.NewStyle().MarginBottom(1)
	brandStyle               = lipgloss.NewStyle().Bold(true).Foreground(primaryColor)
	sectionTitleStyle        = lipgloss.NewStyle().Bold(true).Foreground(primaryColor)
	listTitleStyle           = lipgloss.NewStyle().Bold(true).Foreground(primaryColor).Padding(0, 1)
	profileCardStyle         = lipgloss.NewStyle().PaddingLeft(2)
	selectedProfileCardStyle = lipgloss.NewStyle().BorderLeft(true).BorderStyle(lipgloss.ThickBorder()).BorderForeground(primaryColor).PaddingLeft(1)
	profileNameStyle         = lipgloss.NewStyle().Foreground(lipgloss.AdaptiveColor{Light: "#1E293B", Dark: "#E2E8F0"})
	selectedProfileNameStyle = lipgloss.NewStyle().Bold(true).Foreground(primaryColor)
	panelStyle               = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(panelColor).Padding(1, 2)
	footerStyle              = lipgloss.NewStyle().Foreground(mutedColor).MarginTop(1)
	accentStyle              = lipgloss.NewStyle().Bold(true).Foreground(secondaryColor)
	mutedStyle               = lipgloss.NewStyle().Foreground(mutedColor)
	statusOKStyle            = lipgloss.NewStyle().Foreground(successColor).BorderLeft(true).BorderForeground(successColor).PaddingLeft(1).MarginTop(1)
	statusErrorStyle         = lipgloss.NewStyle().Foreground(dangerColor).BorderLeft(true).BorderForeground(dangerColor).PaddingLeft(1).MarginTop(1)
	disconnectedBadgeStyle   = lipgloss.NewStyle().Foreground(mutedColor)
	connectingBadgeStyle     = lipgloss.NewStyle().Bold(true).Foreground(warningColor)
	connectedBadgeStyle      = lipgloss.NewStyle().Bold(true).Foreground(successColor)
	disconnectingBadgeStyle  = lipgloss.NewStyle().Foreground(warningColor)
	failedBadgeStyle         = lipgloss.NewStyle().Bold(true).Foreground(dangerColor)
)
