//go:build linux

package tui

import (
	"syscall"

	"charm.land/lipgloss/v2"
)

var (
	titleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("39"))

	dimStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))

	headerStyle = lipgloss.NewStyle().
			Bold(true).
			Underline(true).
			Foreground(lipgloss.Color("103"))

	selStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15")).
			Background(lipgloss.Color("60"))

	helpStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("241"))

	noteOKStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("42"))

	noteErrStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("203"))

	fieldLabel = lipgloss.NewStyle().
			Foreground(lipgloss.Color("74")).
			PaddingRight(1)

	labelStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("222"))

	modalTitleStyle = lipgloss.NewStyle().
			Bold(true).
			Foreground(lipgloss.Color("15"))

	boxStyle = lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("61")).
			Padding(1, 3)

	modalBoxStyle = lipgloss.NewStyle().
			Border(lipgloss.DoubleBorder()).
			BorderForeground(lipgloss.Color("203")).
			Padding(1, 3)
)

// signalHint explains what each offered signal does.
func signalHint(sig Signal) string {
	switch sig {
	case syscall.SIGTERM:
		return "ask it to exit gracefully"
	case syscall.SIGKILL:
		return "terminate immediately, no cleanup"
	case syscall.SIGINT:
		return "same as pressing ctrl+c"
	case syscall.SIGHUP:
		return "often triggers a config reload"
	case syscall.SIGQUIT:
		return "exit with a core dump"
	case syscall.SIGSTOP:
		return "suspend until SIGCONT"
	default:
		return ""
	}
}
