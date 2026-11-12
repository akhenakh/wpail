//go:build linux || freebsd || (darwin && arm64)

package tui

import (
	"errors"
	"regexp"
	"strings"
	"syscall"
	"testing"

	tea "charm.land/bubbletea/v2"
)

func fixtureItems() []Item {
	return []Item{
		{Port: 80, Proto: "tcp+tcp6", Addr: "0.0.0.0,[::]", Conns: 2, PIDs: []int{100}, Name: "nginx", User: "root"},
		{Port: 5432, Proto: "tcp", Addr: "127.0.0.1", PIDs: []int{200}, Name: "postgres", User: "pg"},
	}
}

type harness struct {
	m    Model
	sent []struct {
		pid int
		sig Signal
	}
	signalErr error
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{}
	h.m = newModel(Config{
		Listen: func(uint16) ([]Item, error) { return fixtureItems(), nil },
		Inspect: func(pid int) (*Detail, error) {
			return &Detail{
				PID: pid, UID: 1000, User: "nginx", Cmdline: "/usr/sbin/nginx -g",
				Exe: "/usr/sbin/nginx", Memory: "12.5 MB",
				Ports:   []BoundPort{{Proto: "tcp", Addr: "0.0.0.0", Port: 80}},
				CanKill: true,
			}, nil
		},
		Signal: func(pid int, sig Signal) error {
			if h.signalErr != nil {
				return h.signalErr
			}
			h.sent = append(h.sent, struct {
				pid int
				sig Signal
			}{pid, sig})
			return nil
		},
	})
	if h.m.Init() == nil {
		t.Fatal("Init must schedule the first scan")
	}
	h.feed(scanMsg{items: fixtureItems()})
	return h
}

// feed funnels a message through Update and keeps the model by value:
// Bubble Tea models are immutable snapshots, so every step must reassign.
func (h *harness) feed(msg tea.Msg) tea.Cmd {
	next, cmd := h.m.Update(msg)
	m, ok := next.(Model)
	if !ok {
		panic("Update returned non-Model")
	}
	h.m = m
	return cmd
}

func (h *harness) press(key tea.KeyPressMsg) tea.Cmd { return h.feed(key) }

// typeString feeds one printable key press per rune, as a terminal would.
func (h *harness) typeString(s string) {
	for _, r := range s {
		h.press(keyChar(r))
	}
}

func keyChar(c rune) tea.KeyPressMsg { return tea.KeyPressMsg{Code: c, Text: string(c)} }

func named(name string) tea.KeyPressMsg {
	switch name {
	case "enter":
		return tea.KeyPressMsg{Code: tea.KeyEnter}
	case "esc":
		return tea.KeyPressMsg{Code: tea.KeyEscape}
	case "up":
		return tea.KeyPressMsg{Code: tea.KeyUp}
	case "down":
		return tea.KeyPressMsg{Code: tea.KeyDown}
	case "tab":
		return tea.KeyPressMsg{Code: tea.KeyTab}
	default:
		panic("unknown test key " + name)
	}
}

func TestScanLoadsAndMovesCursor(t *testing.T) {
	h := newHarness(t)
	if !h.m.loaded || len(h.m.items) != 2 || h.m.cursor != 0 {
		t.Fatalf("initial state wrong: loaded=%v n=%d cur=%d",
			h.m.loaded, len(h.m.items), h.m.cursor)
	}

	h.press(keyChar('j'))
	if h.m.cursor != 1 {
		t.Fatalf("cursor = %d after j, want 1", h.m.cursor)
	}

	h.press(named("down"))
	if h.m.cursor != 1 {
		t.Fatalf("cursor moved past last row: %d", h.m.cursor)
	}

	h.press(keyChar('j')) // already at end, clamped again
	if h.m.cursor != 1 {
		t.Fatalf("clamp failed: cursor=%d", h.m.cursor)
	}
}

func TestSelectionSurvivesRefresh(t *testing.T) {
	h := newHarness(t)
	h.press(named("down")) // postgres selected

	h.feed(scanMsg{items: fixtureItems()}) // same rows reordered? identical here
	if h.m.items[h.m.cursor].Name != "postgres" {
		t.Fatalf("refresh lost selection on %s", h.m.items[h.m.cursor].Name)
	}

	shrunk := []Item{h.m.items[0]} // postgres disappeared
	h.feed(scanMsg{items: shrunk})
	if h.m.cursor != 0 || h.m.items[0].Name != "nginx" {
		t.Fatalf("shrinking list misclamped cursor: %+v", h.m.items)
	}
}

func TestEnterOpensDetailThenKillsFromDetail(t *testing.T) {
	h := newHarness(t)

	cmd := h.press(tea.KeyPressMsg{Code: tea.KeyEnter})
	if h.m.mode != modeDetail || h.m.detail != nil {
		t.Fatalf("enter must switch to loading detail; mode=%v detail=%+v", h.m.mode, h.m.detail)
	}
	dmsg := cmd()
	if dmsg, ok := dmsg.(detailMsg); ok && dmsg.pid != 100 {
		t.Fatalf("detail requested for pid %d, want 100", dmsg.pid)
	} else if !ok {
		t.Fatalf("expected detailMsg, got %T", cmd())
	}
	h.feed(dmsg)
	if h.m.detail == nil || h.m.detail.PID != 100 || h.m.detail.Memory != "12.5 MB" {
		t.Fatalf("detail not populated: %+v", h.m.detail)
	}
	if !h.m.detail.CanKill {
		t.Fatal("CanKill expected true for stub owner")
	}

	h.press(keyChar('k'))
	if h.m.mode != modeSignal || h.m.sigSel != 0 ||
		h.m.sigTarget.pid != 100 || h.m.sigTarget.label == "" {
		t.Fatalf("k from detail must open signal modal: %+v target=%+v",
			h.m.sigSel, h.m.sigTarget)
	}

	h.press(named("down"))
	if h.m.sigSel >= len(signalChoices) || signalChoices[h.m.sigSel].name != "SIGKILL" {
		t.Fatalf("sigSel %d should point at SIGKILL", h.m.sigSel)
	}

	kcmd := h.press(tea.KeyPressMsg{Code: tea.KeyEnter})
	if h.m.mode != modeList {
		t.Fatalf("confirm returns to list, got mode %v", h.m.mode)
	}
	km, ok := kcmd().(killMsg)
	if !ok {
		t.Fatalf("expected killMsg, got %T", kcmd())
	}
	h.feed(km)

	if len(h.sent) != 1 || h.sent[0].pid != 100 || h.sent[0].sig != syscall.SIGKILL {
		t.Fatalf("Signal callback invocations = %+v", h.sent)
	}
	if h.m.noteErr {
		t.Fatalf("unexpected error note: %q", h.m.note)
	}
	if !strings.Contains(h.m.note, "SIGKILL") || !strings.Contains(h.m.note, "100") {
		t.Errorf("note = %q, want 'sent SIGKILL to nginx (100)'", h.m.note)
	}
	if km.pid != 100 || km.sig != syscall.SIGKILL {
		t.Errorf("kill message payload pid=%d sig=%v", km.pid, km.sig)
	}
}

func TestModalSelectionWrapsAround(t *testing.T) {
	h := newHarness(t)
	h.press(keyChar('k'))

	for range 2 {
		h.press(named("down"))
	}
	if h.m.sigSel != 2 {
		t.Fatalf("after two downs sigSel = %d", h.m.sigSel)
	}
	h.press(named("up"))
	if h.m.sigSel != 1 {
		t.Fatalf("up should decrement: sigSel = %d", h.m.sigSel)
	}

	h.press(named("up")) // from index 1 wraps? no: lands on 0
	if h.m.sigSel != 0 {
		t.Fatalf("decrement to zero failed: sigSel = %d", h.m.sigSel)
	}
	h.press(named("up")) // wrap below zero
	if h.m.sigSel != len(signalChoices)-1 {
		t.Fatalf("wrap below zero failed: sigSel = %d", h.m.sigSel)
	}

	h.press(named("tab")) // wrap past end
	if h.m.sigSel != 0 {
		t.Fatalf("wrap past end failed: sigSel = %d", h.m.sigSel)
	}

	h.press(named("esc"))
	if h.m.mode != modeList {
		t.Fatal("esc must return to list")
	}
	if len(h.sent) != 0 {
		t.Fatalf("cancel must not send signals: %+v", h.sent)
	}
}

func TestPermissionErrorSurfacesInNote(t *testing.T) {
	h := newHarness(t)
	h.signalErr = errors.New(
		"not permitted: nginx (100) runs as root — you are not the owner")

	h.press(keyChar('k'))
	kcmd := h.press(tea.KeyPressMsg{Code: tea.KeyEnter})
	if kcmd == nil {
		t.Fatal("enter should still dispatch even when permission is missing")
	}
	h.feed(kcmd())

	if !h.m.noteErr {
		t.Fatalf("error note flag missing: note=%q", h.m.note)
	}
	if !strings.Contains(h.m.note, "not permitted") {
		t.Errorf("note = %q", h.m.note)
	}
}

func TestUnownedPortBlockedFromKillAndDetail(t *testing.T) {
	h := newHarness(t)
	lonely := Item{Port: 9999, Proto: "udp", Addr: "0.0.0.0"}
	h.feed(scanMsg{items: []Item{lonely}})

	h.press(tea.KeyPressMsg{Code: tea.KeyEnter})
	if h.m.mode != modeList {
		t.Fatalf("unknown owner must stay on list; mode=%v", h.m.mode)
	}
	if h.m.note == "" || !h.m.noteErr {
		t.Fatalf("expected explanatory error note, got %q", h.m.note)
	}

	h.press(keyChar('k'))
	if h.m.mode != modeList {
		t.Fatalf("k on an unknown owner must stay on the list, got mode %v", h.m.mode)
	}
	if !h.m.noteErr || !strings.Contains(h.m.note, "cannot signal") {
		t.Errorf("expected cannot-signal note, got %q (err=%v)", h.m.note, h.m.noteErr)
	}
}

func TestViewRendersTableAndFilteredTitle(t *testing.T) {
	h := newHarness(t)
	h.feed(tea.WindowSizeMsg{Width: 120, Height: 30})

	content := plain(h.m.View().Content)
	for _, want := range []string{"wpail", "PORT", "CONNS", "PROCESS", "nginx"} {
		if !strings.Contains(content, want) {
			t.Errorf("list view missing %q in:\n%s", want, content)
		}
	}
	if !strings.Contains(content, "80") || !strings.Contains(content, "tcp+tcp6") {
		t.Errorf("table rows incomplete:\n%s", content)
	}

	filtered := newModel(Config{Port: 5432})
	next, _ := filtered.Update(scanMsg{items: fixtureItems()[1:]})
	fm := next.(Model)
	if !strings.Contains(plain(fm.View().Content), "(filtered :5432)") {
		t.Error("filtered title lost the port")
	}
}

// plain strips ANSI escapes so assertions see rendered text rather than
// lipgloss's per-grapheme style runs.
var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`)

func plain(s string) string { return ansiRe.ReplaceAllString(s, "") }

func TestShortenCommand(t *testing.T) {
	tests := []struct{ in string }{{"/usr/sbin/nginx -g daemon off;"}, {"plain"}, {""}}
	want := []string{"nginx", "plain", "unknown"}
	for i, tt := range tests {
		if got := shortenCommand(tt.in, false); got != want[i] {
			t.Errorf("shortenCommand(%q) = %q, want %q", tt.in, got, want[i])
		}
	}
	if got := shortenCommand("", true); got != "unknown (root)" {
		t.Errorf("privileged fallback = %q", got)
	}
}

func TestMouseClickActivatesRow(t *testing.T) {
	h := newHarness(t)

	// Rows sit below title, blank line and header: Y=3 is nginx, Y=4 postgres.
	cmd := h.feed(tea.MouseClickMsg{Button: tea.MouseLeft, Y: listDataRow + 1})
	if h.m.cursor != 1 || h.m.mode != modeDetail {
		t.Fatalf("click must select row 2 and open detail: cursor=%d mode=%v",
			h.m.cursor, h.m.mode)
	}
	dmsg, ok := cmd().(detailMsg)
	if !ok || dmsg.pid != 200 {
		t.Fatalf("click activation must request detail for pid 200, got %T %+v", cmd(), cmd())
	}
}

func TestMouseClickOutsideRowsIgnored(t *testing.T) {
	h := newHarness(t)

	for _, y := range []int{0, 2, listDataRow + 5, listDataRow + 30} {
		if cmd := h.feed(tea.MouseClickMsg{Button: tea.MouseLeft, Y: y}); cmd != nil {
			t.Errorf("click at y=%d must be ignored, got cmd %T", y, cmd)
		}
		if h.m.cursor != 0 || h.m.mode != modeList {
			t.Fatalf("click at y=%d changed state: cursor=%d mode=%v",
				y, h.m.cursor, h.m.mode)
		}
	}

	if cmd := h.feed(tea.MouseClickMsg{Button: tea.MouseRight, Y: listDataRow}); cmd != nil {
		t.Errorf("right click must be ignored, got cmd %T", cmd)
	}
	if h.m.mode != modeList {
		t.Fatalf("right click changed mode to %v", h.m.mode)
	}
}

func TestMouseClickIgnoredOutsideListMode(t *testing.T) {
	h := newHarness(t)
	h.feed(tea.KeyPressMsg{Code: tea.KeyEnter}) // detail mode, loading
	if h.m.mode != modeDetail {
		t.Fatalf("precondition: mode=%v", h.m.mode)
	}

	if cmd := h.feed(tea.MouseClickMsg{Button: tea.MouseLeft, Y: listDataRow}); cmd != nil {
		t.Errorf("click in detail mode must be ignored, got cmd %T", cmd)
	}
	if h.m.mode != modeDetail {
		t.Fatalf("click must not leave detail mode, got %v", h.m.mode)
	}
}

func TestMouseWheelScrollsList(t *testing.T) {
	h := newHarness(t)

	h.feed(tea.MouseWheelMsg{Button: tea.MouseWheelDown})
	if h.m.cursor != 1 {
		t.Fatalf("wheel down = cursor %d, want 1", h.m.cursor)
	}
	h.feed(tea.MouseWheelMsg{Button: tea.MouseWheelDown}) // clamps at the last row
	if h.m.cursor != 1 {
		t.Fatalf("wheel down must clamp: cursor=%d", h.m.cursor)
	}
	h.feed(tea.MouseWheelMsg{Button: tea.MouseWheelUp})
	if h.m.cursor != 0 {
		t.Fatalf("wheel up = cursor %d, want 0", h.m.cursor)
	}
	h.feed(tea.MouseWheelMsg{Button: tea.MouseWheelUp}) // clamps at the first row
	if h.m.cursor != 0 {
		t.Fatalf("wheel up must clamp: cursor=%d", h.m.cursor)
	}
}

func TestSlashFiltersListLive(t *testing.T) {
	h := newHarness(t)

	h.press(keyChar('/'))
	if h.m.mode != modeFilter {
		t.Fatalf("/ must enter filter mode, got %v", h.m.mode)
	}

	h.press(keyChar('n'))
	if h.m.filter != "n" || len(h.m.items) != 1 || h.m.items[0].Name != "nginx" {
		t.Fatalf("live filter failed: q=%q items=%+v", h.m.filter, h.m.items)
	}

	h.press(keyChar('g'))
	if h.m.filter != "ng" || len(h.m.items) != 1 {
		t.Fatalf("narrowing failed: q=%q items=%+v", h.m.filter, h.m.items)
	}

	h.press(keyChar('x'))
	if len(h.m.items) != 0 {
		t.Fatalf("query with no match must empty the list, got %+v", h.m.items)
	}

	h.press(tea.KeyPressMsg{Code: tea.KeyBackspace})
	if h.m.filter != "ng" || len(h.m.items) != 1 {
		t.Fatalf("backspace failed: q=%q items=%+v", h.m.filter, h.m.items)
	}

	h.press(keyChar('q')) // q is text while filtering, not quit
	if h.m.filter != "ngq" || h.m.mode != modeFilter {
		t.Fatalf("q must be typed into the filter, mode=%v q=%q", h.m.mode, h.m.filter)
	}

	h.press(named("enter"))
	if h.m.mode != modeList || h.m.filter != "ngq" {
		t.Fatalf("enter must keep the query and return to the list, mode=%v q=%q",
			h.m.mode, h.m.filter)
	}
}

func TestFilterEscRestoresPreviousQuery(t *testing.T) {
	h := newHarness(t)

	h.press(keyChar('/'))
	h.typeString("post")
	h.press(named("enter"))
	if h.m.filter != "post" || len(h.m.items) != 1 || h.m.items[0].Name != "postgres" {
		t.Fatalf("precondition: q=%q items=%+v", h.m.filter, h.m.items)
	}

	h.press(keyChar('/'))
	h.typeString("x") // no match
	if len(h.m.items) != 0 {
		t.Fatalf("precondition: expected empty list, got %+v", h.m.items)
	}
	h.press(named("esc"))
	if h.m.mode != modeList || h.m.filter != "post" || len(h.m.items) != 1 {
		t.Fatalf("esc must restore the previous query: mode=%v q=%q items=%+v",
			h.m.mode, h.m.filter, h.m.items)
	}
}

func TestEscClearsAppliedFilter(t *testing.T) {
	h := newHarness(t)
	h.press(keyChar('/'))
	h.typeString("post")
	h.press(named("enter"))

	h.press(named("esc"))
	if h.m.filter != "" || len(h.m.items) != 2 {
		t.Fatalf("esc in list must clear the filter: q=%q items=%+v",
			h.m.filter, h.m.items)
	}
}

func TestFilterSurvivesRefresh(t *testing.T) {
	h := newHarness(t)
	h.press(keyChar('/'))
	h.typeString("post")
	h.press(named("enter"))

	h.feed(scanMsg{items: fixtureItems()})
	if h.m.filter != "post" || len(h.m.items) != 1 || h.m.items[0].Name != "postgres" {
		t.Fatalf("refresh dropped the filter: q=%q items=%+v", h.m.filter, h.m.items)
	}
}

func TestFilteredRowOpensDetail(t *testing.T) {
	h := newHarness(t)
	h.press(keyChar('/'))
	h.typeString("post")
	h.press(named("enter"))

	cmd := h.press(named("enter"))
	if h.m.mode != modeDetail {
		t.Fatalf("enter on filtered row must open detail, mode=%v", h.m.mode)
	}
	dmsg, ok := cmd().(detailMsg)
	if !ok || dmsg.pid != 200 {
		t.Fatalf("filtered selection must request pid 200, got %T %+v", cmd(), cmd())
	}
}

func TestItemMatches(t *testing.T) {
	postgres := fixtureItems()[1]
	for _, q := range []string{"postgres", "POST", "5432", "200", "pg", "tcp", "127"} {
		if !itemMatches(postgres, q) {
			t.Errorf("itemMatches(postgres, %q) = false, want true", q)
		}
	}
	for _, q := range []string{"nginx", "80", "100", "udp"} {
		if itemMatches(postgres, q) {
			t.Errorf("itemMatches(postgres, %q) = true, want false", q)
		}
	}
	if !itemMatches(postgres, "") {
		t.Error("empty query must match every row")
	}
}

func TestViewShowsFilterPromptAndEmptyState(t *testing.T) {
	h := newHarness(t)
	h.feed(tea.WindowSizeMsg{Width: 120, Height: 30})
	h.press(keyChar('/'))
	h.typeString("post")

	content := plain(h.m.View().Content)
	if !strings.Contains(content, "filter: post") {
		t.Errorf("filter prompt missing from footer:\n%s", content)
	}
	if !strings.Contains(content, "postgres") || strings.Contains(content, "nginx") {
		t.Errorf("table must show only matching rows:\n%s", content)
	}

	h.press(keyChar('x')) // nothing matches
	content = plain(h.m.View().Content)
	if !strings.Contains(content, `no listeners match "postx"`) {
		t.Errorf("empty filtered state missing:\n%s", content)
	}
}

func TestViewEnablesMouse(t *testing.T) {
	m := newModel(Config{})
	if v := m.View(); v.MouseMode != tea.MouseModeCellMotion {
		t.Fatalf("MouseMode = %v, want MouseModeCellMotion", v.MouseMode)
	}
}
