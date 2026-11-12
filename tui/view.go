//go:build linux || freebsd || (darwin && arm64)

package tui

import (
	"fmt"
	"strings"
	"unicode/utf8"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

const colGap = 2

func (m Model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	v.WindowTitle = "wpail"
	v.MouseMode = tea.MouseModeCellMotion
	return v
}

func (m Model) render() string {
	switch m.mode {
	case modeDetail:
		return m.renderDetail()
	case modeSignal:
		return m.renderModal()
	default:
		return m.renderList()
	}
}

// colSpec holds computed column widths for the listener table.
type colSpec struct{ port, proto, addr, conns, pid, user, proc int }

func calcCols(width int) colSpec {
	c := colSpec{port: 8, proto: 12, addr: 20, conns: 6, pid: 9, user: 12, proc: 24}
	fixedSum := c.port + c.proto + c.conns + c.pid + c.user + 6*colGap
	extra := width - fixedSum - c.addr - c.proc - 2
	switch {
	case extra > 40:
		c.proc += extra * 2 / 3
		c.addr += extra / 3
	case extra > 0:
		c.proc += extra / 2
		c.addr += extra / 4
	case extra < -12:
		shrink := min(-extra, c.addr-10+c.proc-10)
		takeAddr := min(shrink/2, c.addr-10)
		c.addr -= takeAddr
		c.proc -= shrink - takeAddr
		if c.proc < 10 || c.addr < 10 {
			c.addr += takeAddr
			c.proto = 6
			c.user = 8
			c.conns = 5
		}
	}
	return c
}

func (c colSpec) widths() []int {
	return []int{c.port, c.proto, c.addr, c.conns, c.pid, c.user, c.proc}
}

var listHeaders = []string{"PORT", "PROTO", "ADDRESS", "CONNS", "PID", "USER", "PROCESS"}

func (m Model) renderList() string {
	title := titleStyle.Render("wpail")
	subtitle := " — listeners & sessions"
	if m.cfg.Port != 0 {
		subtitle += fmt.Sprintf(" (filtered :%d)", m.cfg.Port)
	}
	if m.filter != "" {
		subtitle += fmt.Sprintf(" (filter: %s)", m.filter)
	}
	lines := []string{title + dimStyle.Render(subtitle), ""}

	switch {
	case !m.loaded:
		lines = append(lines, dimStyle.Render("scanning listening sockets…"))
	case len(m.items) == 0 && m.filter != "":
		lines = append(lines,
			dimStyle.Render(fmt.Sprintf("no listeners match %q", m.filter)),
			dimStyle.Render("esc clears the filter"))
	case len(m.items) == 0:
		lines = append(lines,
			dimStyle.Render("no listening sockets found"),
			dimStyle.Render("(run as root to see every user's listeners)"))
	default:
		lines = append(lines, m.renderTable()...)
	}
	lines = append(lines, "", m.renderFooter())
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderTable() []string {
	spec := calcCols(m.width)
	widths := spec.widths()

	head := make([]string, len(listHeaders))
	for i, h := range listHeaders {
		head[i] = headerStyle.Render(cell(h, widths[i]))
	}
	rows := []string{strings.Join(head, strings.Repeat(" ", colGap))}

	start, end, budget := m.listWindow()

	for i := start; i < end; i++ {
		item := m.items[i]
		row := strings.Join([]string{
			cell(fmt.Sprintf("%d", item.Port), widths[0]),
			cell(item.Proto, widths[1]),
			cell(item.Addr, widths[2]),
			cell(connsDisplay(item), widths[3]),
			cell(pidsDisplay(item), widths[4]),
			cell(ownerUser(item), widths[5]),
			cell(item.Name, widths[6]),
		}, strings.Repeat(" ", colGap))
		if i == m.cursor {
			rows = append(rows, selStyle.Render(row))
		} else {
			rows = append(rows, row)
		}
	}
	for range budget - (end - start) { // stable height while scrolling
		rows = append(rows, "")
	}
	if end < len(m.items) {
		rows = append(rows, dimStyle.Render(fmt.Sprintf("… %d more", len(m.items)-end)))
	}
	return rows
}

func connsDisplay(i Item) string {
	if i.Conns == 0 {
		return "—"
	}
	return fmt.Sprintf("%d", i.Conns)
}

func pidsDisplay(i Item) string {
	if i.Owner() == 0 {
		return "—"
	}
	out := fmt.Sprintf("%d", i.PIDs[0])
	if n := len(i.PIDs); n > 1 {
		out += fmt.Sprintf(" +%d", n-1)
	}
	return out
}

func ownerUser(i Item) string {
	if i.Owner() == 0 {
		return "?"
	}
	return i.User
}

func clampWindow(cursor, budget, total int) int {
	start := max(cursor-budget/2, 0)
	if start+budget > total {
		start = max(total-budget, 0)
	}
	return start
}

// listWindow returns the visible slice of the item table: [start, end) item
// indices and the row budget. Rendering and mouse hit-testing both use it so
// clicks always land on the row the user sees.
func (m Model) listWindow() (start, end, budget int) {
	budget = max(m.height-7, 1)
	start = clampWindow(m.cursor, budget, len(m.items))
	end = min(start+budget, len(m.items))
	return start, end, budget
}

// listDataRow is the screen row of the first table row in list view:
// title, blank line, then the header row sit above it.
const listDataRow = 3

// rowAt maps a screen row onto the item index shown there. ok is false when
// the row falls outside the rendered table rows (title, header, filler,
// footer) or the list is not showing a table at all.
func (m Model) rowAt(y int) (int, bool) {
	if m.mode != modeList || !m.loaded || len(m.items) == 0 {
		return 0, false
	}
	start, end, _ := m.listWindow()
	if i := start + y - listDataRow; i >= start && i < end {
		return i, true
	}
	return 0, false
}

func (m Model) renderFooter() string {
	if m.mode == modeFilter {
		query := truncate(m.filter, max(m.width-38, 8))
		return labelStyle.Render("filter: "+query) + dimStyle.Render("▏") +
			"   " + helpStyle.Render("enter apply · esc cancel · ctrl+u clear")
	}
	var hints string
	switch m.mode {
	case modeDetail:
		hints = "esc back · k send signal · q quit"
		if m.detailMaxScroll() > 0 {
			hints = "↑/↓ scroll · " + hints
		}
	case modeSignal:
		hints = "↑/↓ select signal · enter send · esc cancel"
	default:
		hints = "↓/↑ move · enter details · / filter · k kill · r refresh · q quit"
	}
	line := helpStyle.Render(hints)
	if m.note != "" && m.mode != modeSignal {
		style := noteOKStyle
		if m.noteErr {
			style = noteErrStyle
		}
		noteLine := style.Render(truncate(m.note, max(m.width-len(hints)-8, 8)))
		line = lipgloss.JoinHorizontal(lipgloss.Top, noteLine, "   ", line)
	}
	return line
}

// detailBody renders the process panel contents. Rendering and scrolling use
// it so both agree on the line count.
func (m Model) detailBody() string {
	switch {
	case m.detail != nil:
		return m.detailText(m.detail)
	case m.detailErr != nil:
		return noteErrStyle.Render("detail failed: " + m.detailErr.Error())
	default:
		return dimStyle.Render("loading process detail…")
	}
}

func (m Model) detailLines() []string { return strings.Split(m.detailBody(), "\n") }

// detailVisibleLines is how many body lines fit between the title, the box
// chrome (border + padding) and the footer. renderDetail keeps the layout at
// exactly m.height rows.
func (m Model) detailVisibleLines() int { return max(m.height-7, 1) }

// detailMaxScroll is the largest offset that still fills the window.
func (m Model) detailMaxScroll() int {
	return max(len(m.detailLines())-m.detailVisibleLines(), 0)
}

func (m Model) renderDetail() string {
	lines := m.detailLines()
	visible := m.detailVisibleLines()
	maxScroll := max(len(lines)-visible, 0)
	start := min(max(m.detailScroll, 0), maxScroll)
	end := min(start+visible, len(lines))
	window := strings.Join(lines[start:end], "\n")

	title := titleStyle.Render("wpail — process detail")
	if maxScroll > 0 {
		title += dimStyle.Render(fmt.Sprintf("  lines %d–%d/%d", start+1, end, len(lines)))
	}
	box := boxStyle.Render(window)
	screen := lipgloss.Place(m.width, max(m.height-3, 1),
		lipgloss.Center, lipgloss.Center, box)
	return lipgloss.JoinVertical(lipgloss.Left,
		title, screen, "", m.renderFooter())
}

func (m Model) detailText(d *Detail) string {
	lines := []string{
		fieldLabel.Render("Command") + truncate(fallback(d.Cmdline, "—"), max(m.width-24, 16)),
		fieldLabel.Render("Exe") + truncate(fallback(d.Exe, "—"), max(m.width-24, 16)),
		fieldLabel.Render("PID") + fmt.Sprintf("%d", d.PID),
		fieldLabel.Render("User") + d.User + dimStyle.Render(fmt.Sprintf(" (%d)", d.UID)),
		fieldLabel.Render("Memory") + fallback(d.Memory, "n/a"),
	}
	if d.Error != "" {
		lines = append(lines, "", noteErrStyle.Render(d.Error))
	}
	if len(d.Parents) > 0 {
		lines = append(lines, "", fieldLabel.Render("Ancestry"))
		for i, p := range d.Parents {
			indent := strings.Repeat("   ", i)
			prefix := ""
			if i > 0 {
				prefix = "└─ "
			}
			label := truncate(fmt.Sprintf("%s (%d)", p.Name, p.PID), max(m.width-24, 16))
			lines = append(lines, indent+prefix+label)
		}
		leaf := fmt.Sprintf("this process (%d)", d.PID)
		lines = append(lines, strings.Repeat("   ", len(d.Parents))+
			"└─ "+dimStyle.Render(truncate(leaf, max(m.width-24, 16))))
	}
	if len(d.Build) > 0 {
		lines = append(lines, "", fieldLabel.Render("Build"))
		for _, kv := range d.Build {
			lines = append(lines, "  "+dimStyle.Render(pad(kv[0], 9))+
				truncate(kv[1], max(m.width-16, 20)))
		}
	}
	if len(d.Conns) > 0 {
		lines = append(lines, "", fieldLabel.Render("Connections"))
		for _, c := range d.Conns {
			line := fmt.Sprintf("%-6s %-13s %s → %s", c.Proto, c.State, c.Local, c.Remote)
			if c.Peer != "" {
				line += "  " + c.Peer
			}
			lines = append(lines, "  "+truncate(line, max(m.width-16, 20)))
		}
	}
	if len(d.Ports) > 0 {
		lines = append(lines, "", fieldLabel.Render("Listening on"))
		for _, p := range d.Ports {
			lines = append(lines, "  "+dimStyle.Render(pad(p.Proto, 6))+
				fmt.Sprintf("%s:%d", p.Addr, p.Port))
		}
	} else {
		lines = append(lines, "", fieldLabel.Render("Ports")+dimStyle.Render("none observed"))
	}
	if !d.CanKill {
		lines = append(lines, "", helpStyle.Render(
			fmt.Sprintf("owned by %s — sending signals needs root", d.User)))
	}
	return lipgloss.JoinVertical(lipgloss.Left, lines...)
}

func (m Model) renderModal() string {
	target := describeSignalTarget(m.sigTarget)
	opts := make([]string, 0, len(signalChoices))
	for i, c := range signalChoices {
		text := pad(c.name, 9) + signalHint(c.sig)
		if i == m.sigSel {
			opts = append(opts, selStyle.Render(pointer+" "+text))
		} else {
			opts = append(opts, "  "+text)
		}
	}
	body := strings.Join(append([]string{
		modalTitleStyle.Render("Send signal to process"),
		"",
		labelStyle.Render(target),
		"",
	}, opts...), "\n")

	box := modalBoxStyle.Render(body)
	screen := lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, box)
	return screen
}

// --- small formatting helpers -------------------------------------------

const pointer = "▸"

func describeSignalTarget(t signalTarget) string {
	if t.label != "" {
		return t.label
	}
	return fmt.Sprintf("pid %d", t.pid)
}

func fallback(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// cell truncates and pads a single value to exactly w display columns.
func cell(s string, w int) string {
	if utf8.RuneCountInString(s) > w {
		return truncate(s, w)
	}
	return pad(s, w)
}

func pad(s string, w int) string {
	if n := w - utf8.RuneCountInString(s); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
}

func truncate(s string, w int) string {
	if w <= 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	if w == 1 {
		return string(r[:1])
	}
	return string(r[:w-1]) + "…"
}
