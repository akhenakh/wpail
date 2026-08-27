//go:build linux || (darwin && arm64)

package bininfo

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// cargoProject names a Rust project for a target/ artifact. The exe
// basename is authoritative for cargo binaries (package name == bin name,
// minus the hash cargo appends under deps/); Cargo.toml is consulted as a
// fallback for workspace setups where the crate name differs.
func cargoProject(exePath, cwd string, info *Info) string {
	if name := cargoBinName(exePath); name != "" {
		return name
	}
	if pkg := cargoManifestName(projectRoot(exePath, cwd)); pkg != "" {
		return pkg
	}
	return exeName(exePath)
}

// cargoBinName strips cargo's hash suffix from deps artifacts:
// .../target/debug/deps/mybin-1a2b3c4d5e6f7g8h -> mybin.
func cargoBinName(exePath string) string {
	m := cargoPath.FindStringSubmatch(exePath)
	if m == nil {
		return exeName(exePath)
	}
	name := m[2]
	if strings.HasSuffix(filepath.Dir(exePath), "deps") {
		if i := strings.LastIndexByte(name, '-'); i > 0 {
			name = name[:i]
		}
	}
	return strings.TrimSuffix(name, ".exe")
}

// projectRoot picks the directory most likely to hold the Cargo.toml of a
// target/ artifact: its parent (…/myproj/target/...), else the cwd.
func projectRoot(exePath, cwd string) string {
	if i := strings.LastIndex(exePath, "/target/"); i > 0 {
		return exePath[:i]
	}
	return cwd
}

var (
	goModRe     = regexp.MustCompile(`(?m)^module\s+(\S+)`)
	sectionRe   = regexp.MustCompile(`(?m)^\[([^\]]+)\]`)
	cargoNameRe = regexp.MustCompile(`(?m)^name\s*=\s*"([^"]+)"`)
)

// goModProject parses the module path of dir/go.mod, "" when absent.
func goModProject(dir string) string {
	if dir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return ""
	}
	if m := goModRe.FindSubmatch(data); m != nil {
		return string(m[1])
	}
	return ""
}

// cargoManifestName parses the [package] name of root/Cargo.toml. Workspace
// manifests (no [package] section) yield "" — member crates own the names.
func cargoManifestName(root string) string {
	if root == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(root, "Cargo.toml"))
	if err != nil {
		return ""
	}
	inPkg := false
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if m := sectionRe.FindStringSubmatch(line); m != nil {
			inPkg = m[1] == "package"
			continue
		}
		if inPkg {
			if m := cargoNameRe.FindStringSubmatch(line); m != nil {
				return m[1]
			}
		}
	}
	return ""
}
