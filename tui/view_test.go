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
	conns := make([]ConnRef, maxDetailConns+2)
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
		"curl (200)", "… 2 more",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("detail view missing %q in:\n%s", want, out)
		}
	}
	if strings.Contains(m.detailText(&Detail{PID: 42}), "Connections") {
		t.Error("connections block must be absent without sessions")
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
