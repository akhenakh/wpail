//go:build linux || freebsd || (darwin && arm64)

package tui

import (
	"fmt"
	"strings"
	"testing"
)

func TestDetailRendersBuildBlock(t *testing.T) {
	m := newModel(Config{})
	d := &Detail{
		PID:     42,
		Build:   [][2]string{{"Artifact", "go run"}, {"Module", "example.com/you/myproj"}},
		CanKill: true,
	}
	out := m.detailText(d)
	for _, want := range []string{"Build", "Artifact", "go run", "Module", "example.com/you/myproj"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q in:\n%s", want, out)
		}
	}
	empty := m.detailText(&Detail{PID: 42})
	if strings.Contains(empty, "Build") {
		t.Errorf("build block must be absent without metadata:\n%s", empty)
	}
}

func TestDetailRendersConnections(t *testing.T) {
	m := newModel(Config{})
	conns := make([]ConnRef, 3)
	for i := range conns {
		conns[i] = ConnRef{
			Proto:  "tcp",
			State:  "ESTABLISHED",
			Local:  "127.0.0.1:8080",
			Remote: fmt.Sprintf("10.0.0.%d:5555", i),
			Peer:   "curl (200)",
		}
	}
	out := m.detailText(&Detail{PID: 42, Conns: conns})
	for _, want := range []string{
		"Connections", "ESTABLISHED", "127.0.0.1:8080", "10.0.0.0:5555",
		"10.0.0.2:5555", "curl (200)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(m.detailText(&Detail{PID: 42}), "Connections") {
		t.Error("connections block must be absent without sessions")
	}
}

func TestDetailScrollsLongContent(t *testing.T) {
	m := newModel(Config{})
	m.width, m.height = 100, 20
	m.mode = modeDetail
	m.detail = &Detail{PID: 42}
	for i := range 40 {
		m.detail.Conns = append(m.detail.Conns, ConnRef{
			Proto:  "tcp",
			State:  "ESTABLISHED",
			Local:  "127.0.0.1:8080",
			Remote: fmt.Sprintf("10.0.0.%d:5555", i),
		})
	}

	first := plain(m.renderDetail())
	if !strings.Contains(first, "lines 1–") {
		t.Fatalf("long detail must show a scroll window:\n%s", first)
	}
	if strings.Contains(first, "10.0.0.39:5555") {
		t.Errorf("last session must not fit the first page:\n%s", first)
	}

	for range 3 {
		next, _ := m.Update(named("pgdown"))
		m = next.(Model)
	}
	if m.detailScroll == 0 {
		t.Fatal("pgdown must move the detail viewport")
	}
	last := plain(m.renderDetail())
	if !strings.Contains(last, "10.0.0.39:5555") {
		t.Errorf("last page must reach the final session:\n%s", last)
	}
	next, _ := m.Update(named("end"))
	m = next.(Model)
	if got := m.detailScroll; got != m.detailMaxScroll() {
		t.Errorf("end scroll = %d, want %d", got, m.detailMaxScroll())
	}
	next, _ = m.Update(named("home"))
	m = next.(Model)
	if m.detailScroll != 0 {
		t.Errorf("home scroll = %d, want 0", m.detailScroll)
	}
}

func TestDetailRendersAncestryTree(t *testing.T) {
	m := newModel(Config{})
	d := &Detail{
		PID: 300,
		Parents: []ProcRef{
			{PID: 1, Name: "systemd"},
			{PID: 100, Name: "zsh"},
			{PID: 200, Name: "go run"},
		},
	}
	out := m.detailText(d)
	for _, want := range []string{"Ancestry", "systemd (1)", "zsh (100)", "go run (200)", "this process (300)"} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q in:\n%s", want, out)
		}
	}
	// Indentation grows with depth; the leaf carries the └─ connector.
	if !strings.Contains(out, "└─ zsh (100)") || !strings.Contains(out, "   └─ go run (200)") {
		t.Errorf("tree connectors missing:\n%s", out)
	}
	empty := m.detailText(&Detail{PID: 42})
	if strings.Contains(empty, "Ancestry") {
		t.Errorf("ancestry block must be absent without parents:\n%s", empty)
	}
}
