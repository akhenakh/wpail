//go:build linux

package tui

import (
	"fmt"
	"strings"
	"syscall"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Signal mirrors syscall.Signal so callers can wire stdlib signals directly.
type Signal = syscall.Signal

const defaultRefresh = 2 * time.Second

const (
	exitErr = 1 // Run failed before drawing anything usable
)

type mode int

const (
	modeList mode = iota
	modeDetail
	modeSignal
)

type (
	tickMsg    struct{}
	scanMsg    struct{ items []Item }
	scanErrMsg struct{ err error }
)

type detailMsg struct {
	pid int
	d   *Detail
	err error
}

type killMsg struct {
	pid  int
	sig  Signal
	err  error
	item Item // what the status row pointed at when signaling
}

type signalTarget struct {
	pid   int
	label string
	port  uint16
}

var signalChoices = []struct {
	name string
	sig  Signal
}{
	{"SIGTERM", syscall.SIGTERM},
	{"SIGKILL", syscall.SIGKILL},
	{"SIGINT", syscall.SIGINT},
	{"SIGHUP", syscall.SIGHUP},
	{"SIGQUIT", syscall.SIGQUIT},
	{"SIGSTOP", syscall.SIGSTOP},
}

func signalName(sig Signal) string {
	for _, c := range signalChoices {
		if c.sig == sig {
			return c.name
		}
	}
	return fmt.Sprintf("signal %d", int(sig))
}

type Model struct {
	cfg    Config
	items  []Item
	cursor int
	loaded bool

	mode      mode
	detail    *Detail
	detailPID int
	detailErr error

	sigTarget signalTarget
	sigSel    int

	note    string
	noteErr bool

	width, height int
}

func newModel(cfg Config) Model {
	return Model{cfg: cfg, width: 80, height: 24}
}

func (m Model) Init() tea.Cmd {
	return tea.Batch(m.rescanCmd(), tickCmd(m.cfg.Refresh))
}

func tickCmd(every time.Duration) tea.Cmd {
	return tea.Tick(every, func(time.Time) tea.Msg { return tickMsg{} })
}

func (m Model) rescanCmd() tea.Cmd {
	fn := m.cfg.Listen
	port := m.cfg.Port
	return func() tea.Msg {
		items, err := fn(port)
		if err != nil {
			return scanErrMsg{err}
		}
		return scanMsg{items}
	}
}

func (m Model) detailCmd(pid int) tea.Cmd {
	inspect := m.cfg.Inspect
	return func() tea.Msg {
		d, err := inspect(pid)
		return detailMsg{pid: pid, d: d, err: err}
	}
}

func (m Model) signalCmd(t signalTarget, sig Signal) tea.Cmd {
	send := m.cfg.Signal
	return func() tea.Msg {
		err := send(t.pid, sig)
		return killMsg{pid: t.pid, sig: sig, err: err}
	}
}

func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if key, ok := msg.(tea.KeyPressMsg); ok && key.String() == "ctrl+c" {
		return m, tea.Quit
	}
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
	case tickMsg:
		return m, tea.Batch(m.rescanCmd(), tickCmd(m.cfg.Refresh))
	case scanErrMsg:
		m.loaded = true
		m.note, m.noteErr = "scan failed: "+msg.err.Error(), true
	case scanMsg:
		m.loaded = true
		m.note, m.noteErr = "", false
		m.applyItems(msg.items)
	case detailMsg:
		if m.mode == modeDetail && m.detailPID == msg.pid {
			if msg.err != nil {
				m.detail, m.detailErr = msg.d, msg.err
			} else {
				m.detail, m.detailErr = msg.d, nil
			}
		}
	case killMsg:
		if msg.err != nil {
			m.note, m.noteErr = msg.err.Error(), true
		} else {
			lbl := describeTarget(msg.item, msg.pid)
			m.note, m.noteErr = fmt.Sprintf("sent %s to %s", signalName(msg.sig), lbl), false
		}
		return m, m.rescanCmd()
	case tea.KeyPressMsg:
		return m.handleKey(msg)
	}
	return m, nil
}

// describeTarget prefers the fresher scan snapshot over stale item data.
func describeTarget(item Item, pid int) string {
	if item.Owner() == pid {
		return item.Label()
	}
	return fmt.Sprintf("pid %d", pid)
}

// applyItems swaps in a fresh scan while keeping the user's selection
// anchored on the same (port, owner) row when it survives the refresh.
func (m *Model) applyItems(items []Item) {
	if len(m.items) == 0 {
		m.items = items
		m.clampCursor()
		return
	}
	it := m.items[min(m.cursor, len(m.items)-1)]
	prev := [2]int{int(it.Port), it.Owner()}
	m.items = items
	for i, it := range items {
		if [2]int{int(it.Port), it.Owner()} == prev {
			m.cursor = i
			return
		}
	}
	m.clampCursor()
}

func (m *Model) clampCursor() {
	switch {
	case len(m.items) == 0:
		m.cursor = 0
	case m.cursor >= len(m.items):
		m.cursor = len(m.items) - 1
	case m.cursor < 0:
		m.cursor = 0
	}
}

func (m Model) current() (Item, bool) {
	if len(m.items) == 0 || m.cursor < 0 || m.cursor >= len(m.items) {
		return Item{}, false
	}
	return m.items[m.cursor], true
}

func (m Model) handleKey(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.mode {
	case modeList:
		return m.listKey(key)
	case modeDetail:
		return m.detailKey(key)
	default:
		return m.modalKey(key)
	}
}

func (m Model) listKey(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "q":
		return m, tea.Quit
	case "down", "j":
		m.cursor++
		m.clampCursor()
	case "up", "p":
		m.cursor--
		m.clampCursor()
	case "g":
		m.cursor = 0
	case "G":
		m.cursor = max(len(m.items)-1, 0)
	case "enter", "i":
		return m.openDetail()
	case "k":
		return m.openSignal()
	case "r":
		return m, m.rescanCmd()
	case "esc":
		m.note = ""
	}
	return m, nil
}

func (m Model) openDetail() (tea.Model, tea.Cmd) {
	item, ok := m.current()
	if !ok {
		return m, nil
	}
	pid := item.Owner()
	if pid == 0 {
		m.note, m.noteErr = fmt.Sprintf("owner of port %d unknown — try running wpail as root", item.Port), true
		return m, nil
	}
	m.mode = modeDetail
	m.detailPID = pid
	m.detail = nil
	m.detailErr = nil
	m.note = ""
	return m, m.detailCmd(pid)
}

func (m Model) openSignal() (tea.Model, tea.Cmd) {
	item, ok := m.current()
	if !ok {
		return m, nil
	}
	pid := item.Owner()
	if pid == 0 {
		m.note, m.noteErr = fmt.Sprintf("cannot signal: owner of port %d is unknown", item.Port), true
		return m, nil
	}
	m.sigTarget = signalTarget{pid: pid, label: item.Label(), port: item.Port}
	m.sigSel = 0
	m.mode = modeSignal
	m.note = ""
	return m, nil
}

func (m Model) detailKey(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch key.String() {
	case "q":
		return m, tea.Quit
	case "esc", "enter":
		m.mode = modeList
		m.detail = nil
	case "k":
		if m.detail == nil || m.detail.Error != "" {
			return m, nil
		}
		m.sigTarget = signalTarget{
			pid:   m.detail.PID,
			label: fmt.Sprintf("%s (%d)", shortenCommand(m.detail.Cmdline, m.detail.UID == 0), m.detail.PID),
		}
		m.sigSel = 0
		m.mode = modeSignal
		m.note = ""
	}
	return m, nil
}

func (m Model) modalKey(key tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	last := len(signalChoices) - 1
	switch key.String() {
	case "esc", "q":
		m.mode = modeList
	case "up", "left":
		m.sigSel--
		if m.sigSel < 0 {
			m.sigSel = last
		}
	case "down", "right", "tab", "j":
		m.sigSel++
		if m.sigSel > last {
			m.sigSel = 0
		}
	case "enter":
		sig := signalChoices[m.sigSel].sig
		t := m.sigTarget
		m.mode = modeList
		return m, m.signalCmd(t, sig)
	}
	return m, nil
}

// shortenCommand renders a human-friendly process label: command basename,
// falling back to the kernel comm name. Root-owned processes get marked.
func shortenCommand(cmdline string, privileged bool) string {
	cmd := cmdline
	if fields := strings.Fields(cmd); len(fields) > 0 {
		cmd = fields[0]
		if i := strings.LastIndexByte(cmd, '/'); i >= 0 {
			cmd = cmd[i+1:]
		}
	}
	out := "unknown"
	switch {
	case cmd != "":
		out = cmd
	case cmdline != "":
		out = cmdline
	}
	if privileged {
		out += " (root)"
	}
	return out
}
