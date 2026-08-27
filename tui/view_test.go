//go:build linux || (darwin && arm64)

package tui

import (
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
