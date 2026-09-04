package tui

import (
	"fmt"
	"io"
	"strings"

	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/henriquesilva/ovpntui/internal/openvpn"
)

type profileDelegate struct{}

func (profileDelegate) Height() int  { return 3 }
func (profileDelegate) Spacing() int { return 0 }
func (profileDelegate) Update(tea.Msg, *list.Model) tea.Cmd {
	return nil
}

func (profileDelegate) Render(writer io.Writer, model list.Model, index int, raw list.Item) {
	item, ok := raw.(profileItem)
	if !ok {
		return
	}

	selected := index == model.Index()
	name := profileNameStyle.Render(item.profile.Name)
	if selected {
		name = selectedProfileNameStyle.Render(item.profile.Name)
	}

	details := profileDetails(item)
	content := lipgloss.JoinVertical(lipgloss.Left, name, stateBadge(item.state.Status)+"  "+details)
	style := profileCardStyle
	if selected {
		style = selectedProfileCardStyle
	}
	_, _ = fmt.Fprint(writer, style.Width(max(1, model.Width()-4)).Render(content))
}

func profileDetails(item profileItem) string {
	parts := make([]string, 0, 4)
	if item.state.AuthPending {
		parts = append(parts, "browser login required")
	}
	if duration := item.state.Duration(item.now); duration > 0 {
		parts = append(parts, duration.String())
	}
	if item.state.Interface != "" {
		parts = append(parts, item.state.Interface)
	}
	if item.state.IP != "" {
		parts = append(parts, item.state.IP)
	}
	if item.state.PID > 0 {
		parts = append(parts, fmt.Sprintf("pid %d", item.state.PID))
	}
	if len(parts) == 0 {
		return mutedStyle.Render("ready")
	}
	return mutedStyle.Render(strings.Join(parts, "  ·  "))
}

func stateBadge(status openvpn.Status) string {
	label := string(status)
	style := disconnectedBadgeStyle
	switch status {
	case openvpn.Connecting:
		style = connectingBadgeStyle
	case openvpn.Connected:
		style = connectedBadgeStyle
	case openvpn.Disconnecting:
		style = disconnectingBadgeStyle
	case openvpn.Failed:
		style = failedBadgeStyle
	}
	return style.Render(label)
}
