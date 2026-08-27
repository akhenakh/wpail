//go:build linux || (darwin && arm64)

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
		{Port: 80, Proto: "tcp+tcp6", Addr: "0.0.0.0,[::]", PIDs: []int{100}, Name: "nginx", User: "root"},
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
	for _, want := range []string{"wpail", "PORT", "PROCESS", "nginx"} {
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
