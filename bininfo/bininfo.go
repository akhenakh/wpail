//go:build linux || (darwin && arm64)

// Package bininfo extracts build metadata from a process' binary and its
// surrounding context, so ephemeral developer builds ("go run .", "cargo
// run", "zig run") can be identified and labeled like first-class citizens.
//
// Everything is agentless: Go binaries carry a buildinfo blob (module path,
// toolchain, VCS state) that survives stripping; Rust and Zig binaries
// embed their compiler version in the ELF ".comment" section. Language
// fallbacks use stable path conventions: go-build temp dirs, cargo
// target/{debug,release} trees, zig-out/bin and the zig run cache.
package bininfo

import (
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
)

// Info is the best-effort build metadata collected for one process.
// Zero-value fields mean "unknown".
type Info struct {
	Dev       bool   // ephemeral or developer-workspace artifact
	Kind      string // "go run", "go test", "cargo run", "zig run", "zig build"
	Lang      string // "go", "rust", "zig"
	Module    string // Go main module path, e.g. github.com/you/myproj
	Version   string // module version, typically "(devel)"
	Runtime   string // "go1.27.0", "rustc 1.95.0", "zig 0.16.0"
	VCSRev    string
	VCSBranch string
	VCSDirty  bool
	Project   string // short project name
	Dir       string // project or working directory
}

// classify describes what the executable path alone reveals.
type classify struct {
	dev  bool
	kind string
	lang string
}

var (
	// go run executes temp binaries from two layouts: the classic
	// /tmp/go-buildNNN/bNNN/exe/ staging dir, and (Go 1.24+) directly
	// from the build cache, e.g. ~/.cache/go-build/ab/<hash>-d/name
	// (~/Library/Caches/go-build on macOS — hence the case folding).
	goRunPath  = regexp.MustCompile(`(?i)(/go-build[0-9]+/b[0-9]+/exe/|[/.]caches?/go-build/[0-9a-f]{2}/[0-9a-f]+-d/)([^/]+)$`)
	cargoPath  = regexp.MustCompile(`/target/(debug|release)(?:/deps)?/([^/]+)$`)
	zigOutPath = regexp.MustCompile(`/zig-out/bin/([^/]+)$`)
	zigRunPath = regexp.MustCompile(`[/.]cache/zig/o/[0-9a-f]+/([^/]+)$`)
	goTestExe  = regexp.MustCompile(`\.test$`)

	rustCommentRe = regexp.MustCompile(`rustc version (\S+) \(([^)]+)\)`)
	zigCommentRe  = regexp.MustCompile(`^zig (\d\S*)$`)
)

// ClassifyPath inspects an executable path for toolchain conventions.
// It never touches the filesystem, so it is safe on hot refresh paths.
func ClassifyPath(exe string) classify {
	switch {
	case goRunPath.MatchString(exe):
		kind := "go run"
		if goTestExe.MatchString(exe) {
			kind = "go test"
		}
		return classify{dev: true, kind: kind, lang: "go"}
	case zigRunPath.MatchString(exe):
		return classify{dev: true, kind: "zig run", lang: "zig"}
	case zigOutPath.MatchString(exe):
		return classify{dev: true, kind: "zig build", lang: "zig"}
	}
	if m := cargoPath.FindStringSubmatch(exe); m != nil {
		kind := ""
		if m[1] == "debug" {
			kind = "cargo run" // release artifacts are ordinary binaries
		}
		return classify{dev: m[1] == "debug", kind: kind, lang: "rust"}
	}
	return classify{}
}

// Analyze collects everything known about a process' binary. exePath is the
// resolved executable path (may end in " (deleted)"), pid the process id and
// cwd its working directory. Results are best effort: unknown aspects stay
// empty. The returned Info is never nil.
func Analyze(exePath string, pid int, cwd string) *Info {
	info := &Info{Dir: cwd}
	cls := ClassifyPath(exePath)
	info.Dev, info.Kind, info.Lang = cls.dev, cls.kind, cls.lang

	if f := openBinary(exePath, pid); f != nil {
		defer f.Close()
		if gi, err := readGoBuildInfo(f); err == nil {
			info.applyGo(gi)
		} else {
			applyCommentInfo(f, info)
		}
	}

	// Project identity, most specific source wins.
	switch {
	case info.Project != "":
	case info.Lang == "go":
		if info.Module == "" {
			info.Module = goModProject(info.Dir)
		}
		if info.Module != "" {
			info.Project = moduleShortName(info.Module)
		}
	case info.Lang == "rust":
		info.Project = cargoProject(exePath, cwd, info)
	}
	if info.Project == "" {
		info.Project = exeName(exePath)
	}
	if info.Dir == "" {
		info.Dir = fallbackDir(exePath)
	}
	return info
}

// applyGo merges stdlib buildinfo data into info.
func (info *Info) applyGo(gi *goBuildInfo) {
	info.Lang = "go"
	info.Runtime = gi.goVersion
	info.Module = gi.module
	info.Version = gi.version
	info.VCSRev = gi.vcsRev
	info.VCSBranch = gi.vcsBranch
	info.VCSDirty = gi.vcsDirty
}

// openBinary opens the running binary, preferring the live /proc/<pid>/exe
// inode on Linux: go run unlinks its temp binary, and a same-path cargo
// artifact may already hold newer code than the running process.
func openBinary(exePath string, pid int) *os.File {
	if runtime.GOOS == "linux" && pid > 0 {
		if f, err := os.Open("/proc/" + itoa(pid) + "/exe"); err == nil {
			return f
		}
	}
	if exePath == "" {
		return nil
	}
	if f, err := os.Open(strings.TrimSuffix(exePath, " (deleted)")); err == nil {
		return f
	}
	return nil
}

// goBuildInfo is the subset of debug.BuildInfo we surface.
type goBuildInfo struct {
	goVersion, module, version string
	vcsRev, vcsBranch          string
	vcsDirty                   bool
}

// readGoBuildInfo parses the embedded buildinfo blob. Binaries keep it even
// when built with -s -w; a non-Go binary yields an error.
func readGoBuildInfo(r io.ReaderAt) (*goBuildInfo, error) {
	bi, err := buildinfoRead(r)
	if err != nil {
		return nil, err
	}
	out := &goBuildInfo{goVersion: bi.GoVersion}
	if bi.Main.Path != "" && bi.Main.Path != "command-line-arguments" {
		out.module = bi.Main.Path
		out.version = bi.Main.Version
	}
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			out.vcsRev = s.Value
		case "vcs.branch", "vcs.tag":
			out.vcsBranch = s.Value
		case "vcs.modified":
			out.vcsDirty = s.Value == "true"
		}
	}
	return out, nil
}

// applyCommentInfo identifies Rust or Zig binaries through their ELF
// ".comment" section (e.g. "rustc version 1.95.0 (...)", "zig 0.16.0").
// It is a no-op for other formats.
func applyCommentInfo(f io.ReaderAt, info *Info) {
	lang, version := langFromComment(commentStrings(f))
	if lang == "" {
		return
	}
	info.Lang = lang
	info.Runtime = version
}

func moduleShortName(module string) string {
	if i := strings.LastIndexByte(module, '/'); i >= 0 {
		return module[i+1:]
	}
	return module
}

// fallbackDir derives a project directory when the process cwd is unknown:
// cargo artifacts live under <project>/target, zig build output under
// <project>/zig-out.
func fallbackDir(exePath string) string {
	for _, marker := range []string{"/target/", "/zig-out/"} {
		if i := strings.LastIndex(exePath, marker); i > 0 {
			return exePath[:i]
		}
	}
	return ""
}

func exeName(exePath string) string {
	if exePath == "" {
		return ""
	}
	base := exePath
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	return strings.TrimSuffix(base, " (deleted)")
}

func itoa(pid int) string {
	if pid < 0 {
		return ""
	}
	var b [20]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + pid%10)
		pid /= 10
		if pid == 0 {
			break
		}
	}
	return string(b[i:])
}
