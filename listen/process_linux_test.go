//go:build linux

package listen

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetailReadsCWD(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "4242")
	if err := os.MkdirAll(pidDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pidDir, "status"),
		[]byte("Name:\tselftest\nUid:\t1000\t1000\t1000\t1000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	proj := filepath.Join(root, "myproject")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(proj, filepath.Join(pidDir, "cwd")); err != nil {
		t.Fatal(err)
	}

	p, err := detailAt(root, 4242)
	if err != nil {
		t.Fatal(err)
	}
	if p.CWD != proj {
		t.Errorf("CWD = %q, want %q", p.CWD, proj)
	}
}

func TestDetailMissingCWDIsEmpty(t *testing.T) {
	root := t.TempDir()
	pidDir := filepath.Join(root, "9")
	os.MkdirAll(pidDir, 0o755)
	os.WriteFile(filepath.Join(pidDir, "status"), []byte("Name:\tx\nUid:\t0\t0\t0\t0\n"), 0o644)
	p, err := detailAt(root, 9)
	if err != nil {
		t.Fatal(err)
	}
	if p.CWD != "" {
		t.Errorf("CWD = %q, want empty", p.CWD)
	}
}
