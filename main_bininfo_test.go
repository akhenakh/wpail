//go:build linux || (darwin && arm64)

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akhenakh/wpail/bininfo"
	"github.com/akhenakh/wpail/listen"
)

func TestRelabelRowMarksDevBuilds(t *testing.T) {
	cache := newBinCache()
	stub := func(pid int) (*listen.Process, error) {
		return &listen.Process{PID: pid, Exe: "/tmp/go-build123/b001/exe/myproj"}, nil
	}
	r := &listen.Row{Port: 8080, PIDs: []int{7}, Names: []string{"/tmp/go-build123/b001/exe/myproj"}}
	relabelRow(r, stub, cache)
	if got := r.Names[0]; got != "myproj (go run)" {
		t.Errorf("Names[0] = %q, want %q", got, "myproj (go run)")
	}

	// A go.mod next to the process cwd upgrades the label to the module path.
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/akhenakh/myproj\n"), 0o644)
	modStub := func(pid int) (*listen.Process, error) {
		return &listen.Process{PID: pid, Exe: "/tmp/go-build123/b001/exe/myproj", CWD: dir}, nil
	}
	cache2 := newBinCache()
	r1 := &listen.Row{Port: 8080, PIDs: []int{7}, Names: []string{"/tmp/go-build123/b001/exe/myproj"}}
	relabelRow(r1, modStub, cache2)
	if got := r1.Names[0]; got != "github.com/akhenakh/myproj (go run)" {
		t.Errorf("Names[0] = %q, want module path label", got)
	}

	// Uninspectable process keeps the original name.
	r2 := &listen.Row{Port: 8080, PIDs: []int{7}, Names: []string{"unknown"}}
	relabelRow(r2, func(int) (*listen.Process, error) {
		return nil, errors.New("gone")
	}, cache)
	if r2.Names[0] != "unknown" {
		t.Errorf("uninspectable process must keep its name, got %q", r2.Names[0])
	}

	// Regular binaries are never relabeled.
	r3 := &listen.Row{Port: 443, PIDs: []int{7}, Names: []string{"/usr/sbin/nginx"}}
	relabelRow(r3, func(int) (*listen.Process, error) {
		return &listen.Process{PID: 7, Exe: "/usr/sbin/nginx"}, nil
	}, cache)
	if r3.Names[0] != "/usr/sbin/nginx" {
		t.Errorf("regular binary must keep its name, got %q", r3.Names[0])
	}
}

func TestDevLabel(t *testing.T) {
	tests := []struct {
		bi   bininfo.Info
		want string
	}{
		{bininfo.Info{Project: "myproj", Kind: "go run"}, "myproj (go run)"},
		{bininfo.Info{Project: "myproj", Kind: "go test"}, "myproj (go test)"},
		{bininfo.Info{Project: "server", Kind: "cargo run"}, "server (cargo run)"},
		{bininfo.Info{Project: "hello"}, "hello"},
		// Full module path wins when it fits…
		{bininfo.Info{Module: "github.com/akhenakh/listener", Project: "listener", Kind: "go run"},
			"github.com/akhenakh/listener (go run)"},
		// …and the short name takes over when it would overflow.
		{bininfo.Info{Module: "example.com/some/very/deeply/nested/org/repo/name", Project: "name", Kind: "go run"},
			"name (go run)"},
	}
	for _, tt := range tests {
		if got := devLabel(&tt.bi); got != tt.want {
			t.Errorf("devLabel(%+v) = %q, want %q", tt.bi, got, tt.want)
		}
	}
}

func TestVCSShort(t *testing.T) {
	tests := []struct {
		bi   bininfo.Info
		want string
	}{
		{bininfo.Info{}, "-"},
		{bininfo.Info{VCSRev: "b784ce5e2d4ac10f034b13addfe51e0f7d7f0e5a"}, "b784ce5"},
		{bininfo.Info{VCSRev: "b784ce5e2d4a", VCSDirty: true}, "b784ce5*"},
		{bininfo.Info{VCSRev: "b784ce5e2d4a", VCSBranch: "main"}, "main b784ce5"},
	}
	for _, tt := range tests {
		if got := vcsShort(&tt.bi); got != tt.want {
			t.Errorf("vcsShort(%+v) = %q, want %q", tt.bi, got, tt.want)
		}
	}
}

func TestBuildRowsOrderAndGaps(t *testing.T) {
	rows := buildRows(&bininfo.Info{
		Kind: "go run", Lang: "go", Runtime: "go1.27.0",
		Module: "example.com/you/myproj", Project: "myproj", Dir: "/home/u/myproj",
		VCSRev: "b784ce5e2d4a", VCSBranch: "main", VCSDirty: true,
	})
	want := [][2]string{
		{"Artifact", "go run"},
		{"Language", "go"},
		{"Runtime", "go1.27.0"},
		{"Module", "example.com/you/myproj"},
		{"Project", "myproj"},
		{"Dir", "/home/u/myproj"},
		{"VCS", "main b784ce5*"},
	}
	if len(rows) != len(want) {
		t.Fatalf("got %d rows, want %d: %v", len(rows), len(want), rows)
	}
	for i, r := range want {
		if rows[i] != r {
			t.Errorf("row %d = %v, want %v", i, rows[i], r)
		}
	}
	rows = buildRows(&bininfo.Info{})
	if len(rows) != 0 {
		t.Errorf("empty info must yield no rows, got %v", rows)
	}
}

func TestPrintVerboseLayout(t *testing.T) {
	var buf bytes.Buffer
	if err := printVerbose(&buf, []int{999999999}); err != nil {
		t.Fatalf("printVerbose: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("want header + one row, got %q", buf.String())
	}
	if !strings.HasPrefix(lines[0], "PID") || !strings.Contains(lines[0], "VCS") ||
		!strings.Contains(lines[0], "DIR") {
		t.Errorf("header missing columns: %q", lines[0])
	}
	// Uninspectable pid renders placeholders in aligned columns.
	if !strings.Contains(lines[1], "?") || !strings.Contains(lines[1], "-") {
		t.Errorf("placeholder row missing: %q", lines[1])
	}
	if len(lines[0]) != len(lines[1]) {
		t.Errorf("columns not aligned: %q vs %q", lines[0], lines[1])
	}
}

func TestFlagCombinations(t *testing.T) {
	tests := []struct {
		args []string
		code int
	}{
		{[]string{"-u", "-v", "80"}, 2},
		{[]string{"-t", "-v", "80"}, 2},
		{[]string{"-t", "-u", "80"}, 2},
	}
	for _, tt := range tests {
		if code := run(tt.args); code != tt.code {
			t.Errorf("run(%v) = %d, want %d", tt.args, code, tt.code)
		}
	}
}
