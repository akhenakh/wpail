//go:build linux || (darwin && arm64)

package bininfo

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestClassifyPath(t *testing.T) {
	tests := []struct {
		exe     string
		dev     bool
		kind    string
		lang    string
		project string // from path when non-empty (deps hash stripping)
	}{
		{exe: "/tmp/go-build123456/b001/exe/main", dev: true, kind: "go run", lang: "go"},
		{exe: "/var/folders/x9/T/GoLand/go-build42/b003/exe/myproj", dev: true, kind: "go run", lang: "go"},
		{exe: "/tmp/go-build777/b002/exe/mypkg.test", dev: true, kind: "go test", lang: "go"},
		{exe: "/home/u/.cache/go-build/ab/abb10ebfdfb327628c1cc4b0900ff7db90dc226a87fe9090c6b5948c18092982-d/listener", dev: true, kind: "go run", lang: "go"},
		{exe: "/Users/u/Library/Caches/go-build/9c/9c11ffaa00bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22aa33bb44cc-d/server", dev: true, kind: "go run", lang: "go"},
		{exe: "/home/u/.cache/go-build/ab/abb10ebfdfb327628c1cc4b0900ff7db90dc226a87fe9090c6b5948c18092982-d/mypkg.test", dev: true, kind: "go test", lang: "go"},
		{exe: "/home/u/proj/target/debug/server", dev: true, kind: "cargo run", lang: "rust", project: "server"},
		{exe: "/home/u/proj/target/debug/deps/cli-1a2b3c4d5e6f7a8b", dev: true, kind: "cargo run", lang: "rust", project: "cli"},
		{exe: "/home/u/proj/target/release/server", dev: false, kind: "", lang: "rust", project: "server"},
		{exe: "/home/u/proj/zig-out/bin/zigprobe", dev: true, kind: "zig build", lang: "zig", project: "zigprobe"},
		{exe: "/home/u/.cache/zig/o/8eb789cf65c4162f7bb2c12ad87b3975/hello", dev: true, kind: "zig run", lang: "zig", project: "hello"},
		{exe: "/usr/bin/nginx"},
		{exe: "/home/u/proj/target", dev: false, kind: "", lang: ""},
	}
	for _, tt := range tests {
		got := ClassifyPath(tt.exe)
		if got.dev != tt.dev || got.kind != tt.kind || got.lang != tt.lang {
			t.Errorf("ClassifyPath(%q) = %+v, want dev=%v kind=%q lang=%q",
				tt.exe, got, tt.dev, tt.kind, tt.lang)
		}
		if tt.project != "" && got.lang == "rust" {
			if name := cargoBinName(tt.exe); name != tt.project {
				t.Errorf("cargoBinName(%q) = %q, want %q", tt.exe, name, tt.project)
			}
		}
	}
}

func TestLangFromComment(t *testing.T) {
	tests := []struct {
		entries []string
		lang    string
		version string
	}{
		{[]string{"rustc version 1.95.0 (59807616e 2026-04-14)", "Linker: LLD 22.1.2"},
			"rust", "rustc 1.95.0 (59807616e 2026-04-14)"},
		{[]string{"Linker: LLD 21.1.8", "zig 0.16.0"},
			"zig", "zig 0.16.0"},
		{[]string{"GCC: (GNU) 16.2.1", "Linker: LLD 22.1.2"}, "", ""},
		{nil, "", ""},
	}
	for _, tt := range tests {
		lang, version := langFromComment(tt.entries)
		if lang != tt.lang || version != tt.version {
			t.Errorf("langFromComment(%v) = %q, %q; want %q, %q",
				tt.entries, lang, version, tt.lang, tt.version)
		}
	}
}

func TestGoModProject(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/you/myproj\n\ngo 1.27\n"), 0o644)
	if got := goModProject(dir); got != "example.com/you/myproj" {
		t.Errorf("goModProject = %q", got)
	}
	if got := goModProject(t.TempDir()); got != "" {
		t.Errorf("missing go.mod should yield \"\", got %q", got)
	}
}

func TestCargoManifestName(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Cargo.toml"), []byte(
		"[package]\nname = \"mycrate\"\nversion = \"0.1.0\"\n\n[dependencies]\n"), 0o644)
	if got := cargoManifestName(dir); got != "mycrate" {
		t.Errorf("cargoManifestName = %q", got)
	}
	ws := t.TempDir()
	os.WriteFile(filepath.Join(ws, "Cargo.toml"), []byte(
		"[workspace]\nmembers = [\"crates/a\"]\n"), 0o644)
	if got := cargoManifestName(ws); got != "" {
		t.Errorf("workspace manifest must yield \"\", got %q", got)
	}
}

// --- fixture binary parsing ----------------------------------------------

var (
	fixtureOnce  sync.Once
	fixtureBin   string
	fixtureError error
)

// buildFixture compiles a tiny module on first use so readGoBuildInfo and
// Analyze are tested against a real binary; tests skip when no toolchain
// is available.
func buildFixture(t *testing.T) string {
	t.Helper()
	fixtureOnce.Do(func() {
		dir, err := os.MkdirTemp("", "bininfo-fixture")
		if err != nil {
			fixtureError = err
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "go.mod"),
			[]byte("module example.com/fixtures/hello\n\ngo 1.27\n"), 0o644); err != nil {
			fixtureError = err
			return
		}
		if err := os.WriteFile(filepath.Join(dir, "main.go"),
			[]byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
			fixtureError = err
			return
		}
		bin := filepath.Join(dir, "hello")
		cmd := exec.Command("go", "build", "-o", bin, ".")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			fixtureError = err
			t.Logf("fixture build output: %s", out)
		}
		fixtureBin = bin
	})
	if fixtureError != nil {
		t.Skipf("no fixture binary: %v", fixtureError)
	}
	return fixtureBin
}

func TestAnalyzeGoFixture(t *testing.T) {
	bin := buildFixture(t)
	info := Analyze(bin, 0, "")
	if info.Lang != "go" {
		t.Fatalf("Lang = %q, want go", info.Lang)
	}
	if info.Module != "example.com/fixtures/hello" {
		t.Errorf("Module = %q", info.Module)
	}
	if info.Project != "hello" {
		t.Errorf("Project = %q", info.Project)
	}
	if info.Runtime == "" {
		t.Errorf("Runtime empty; want the building toolchain version")
	}
	if info.Dev {
		t.Errorf("a regular build must not be marked dev")
	}
}

func TestAnalyzeGoTempPathUsesBuildInfo(t *testing.T) {
	bin := buildFixture(t)
	fake := "/tmp/go-build123/b001/exe/hello"
	// pid 0: file lookup uses the path; the fixture exists there under a
	// different path, so exercise classify + go fallback via Dir only.
	info := Analyze(fake, 0, filepath.Dir(bin))
	if !info.Dev || info.Kind != "go run" || info.Lang != "go" {
		t.Fatalf("Analyze = %+v", info)
	}
	if info.Module != "example.com/fixtures/hello" && info.Project != "hello" {
		t.Errorf("project identity missing: %+v", info)
	}
	if !strings.Contains(info.Dir, "bininfo-fixture") {
		t.Errorf("Dir = %q", info.Dir)
	}
}

func TestAnalyzeRustFixture(t *testing.T) {
	rustc, err := exec.LookPath("rustc")
	if err != nil {
		t.Skip("rustc not installed")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "hello")
	src := filepath.Join(dir, "hello.rs")
	os.WriteFile(src, []byte("fn main() {}\n"), 0o644)
	if out, err := exec.Command(rustc, "-o", bin, src).CombinedOutput(); err != nil {
		t.Skipf("rustc build failed: %v: %s", err, out)
	}
	info := Analyze(bin, 0, "")
	if info.Lang != "rust" {
		t.Fatalf("Lang = %q, want rust", info.Lang)
	}
	if !strings.HasPrefix(info.Runtime, "rustc ") {
		t.Errorf("Runtime = %q, want rustc version", info.Runtime)
	}
	if info.Project != "hello" {
		t.Errorf("Project = %q", info.Project)
	}
}

func TestAnalyzeUnknownBinary(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "sh")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	info := Analyze(bin, 0, "")
	if info.Lang != "" || info.Dev || info.Kind != "" {
		t.Errorf("Analyze = %+v, want empty language/kind", info)
	}
	if info.Project != "sh" {
		t.Errorf("Project fallback = %q, want sh", info.Project)
	}
}
