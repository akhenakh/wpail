//go:build linux

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/akhenakh/wpail/listen"
)

func TestParsePort(t *testing.T) {
	tests := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"6666", 6666, false},
		{":80", 80, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"-5", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parsePort(tt.in)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("parsePort(%q) = %d, %v; want %d, err=%v",
					tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestPrintUsersAligned(t *testing.T) {
	self := os.Getpid()
	var buf bytes.Buffer
	if err := printUsers(&buf, []int{self, self}); err != nil {
		t.Fatalf("printUsers: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected one line per pid, got %q", buf.String())
	}
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) != 2 {
			t.Fatalf("want two columns (pid user), got %q", ln)
		}
		if fields[0] != fmt.Sprintf("%d", self) {
			t.Fatalf("wrong pid column: %q", ln)
		}
	}
	if lines[0] != lines[1] {
		t.Errorf("same pid must render identically: %q vs %q", lines[0], lines[1])
	}
}

func TestMutuallyExclusiveFlags(t *testing.T) {
	if code := run([]string{"-t", "-u", "80"}); code != 2 {
		t.Errorf("-t -u combo = %d, want 2", code)
	}
}

const procTableHeader = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"

// writeProcFixture creates a minimal fake /proc: net tables plus optional
// rows. Rows are "ADDRHEX:PORTHEX st inode uid" tuples; no process dirs are
// created unless owned rows are supplied.
func writeProcFixture(t *testing.T, tcpRows ...string) string {
	t.Helper()
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}
	tcp := procTableHeader
	for _, r := range tcpRows {
		tcp += r + "\n"
	}
	for _, name := range []string{"tcp", "tcp6", "udp", "udp6"} {
		body := procTableHeader
		if name == "tcp" {
			body = tcp
		}
		if err := os.WriteFile(filepath.Join(netDir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// 631 is the CUPS port — a realistic foreign-owned listener.
const foreignRow631 = "   0: 00000000:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999\n"

func TestForeignPortMessageTakesPriorityOverEmpty(t *testing.T) {
	root := writeProcFixture(t, foreignRow631)
	snap, err := listen.ScanAt(root)
	if err != nil {
		t.Fatal(err)
	}

	var out, errW bytes.Buffer
	code := renderCLI(&out, &errW, snap, 631, false)

	if code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	msg := errW.String()
	switch {
	case strings.Contains(msg, "nothing is listening"):
		t.Errorf("foreign sockets must not be reported as 'nothing is listening': %q", msg)
	case !strings.Contains(msg, "owned by another user"):
		t.Errorf("missing ownership explanation: %q", msg)
	case !strings.Contains(msg, "rerun as root"):
		t.Errorf("missing sudo hint: %q", msg)
	}
	if out.Len() != 0 {
		t.Errorf("stdout should stay clean on failure: %q", out.String())
	}
}

func TestTrulyEmptyPortMessage(t *testing.T) {
	root := writeProcFixture(t) // header only
	snap, err := listen.ScanAt(root)
	if err != nil {
		t.Fatal(err)
	}

	var out, errW bytes.Buffer
	code := renderCLI(&out, &errW, snap, 631, false)

	if code != 1 || !strings.Contains(errW.String(), "nothing is listening on port 631") {
		t.Fatalf("code=%d message=%q", code, errW.String())
	}
}

func TestRenderCLIPrintsOwnedPIDsAndFlagStrangers(t *testing.T) {
	root := writeProcFixture(t,
		foreignRow631,
		// *:8080 LISTEN, inode 777, ours via pid 4242
		"   1: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 777\n",
		// second *:8080 listener, inode 888, linked by nobody (SO_REUSEPORT-style)
		"   2: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 888\n",
	)
	pidDir := filepath.Join(root, "4242")
	fdDir := filepath.Join(pidDir, "fd")
	if err := os.MkdirAll(fdDir, 0o755); err != nil {
		t.Fatal(err)
	}
	status := "Name:\tselftest\nUid:\t1000\t1000\t1000\t1000\n"
	if err := os.WriteFile(filepath.Join(pidDir, "status"), []byte(status), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("socket:[777]", filepath.Join(fdDir, "3")); err != nil {
		t.Fatal(err)
	}

	snap, err := listen.ScanAt(root)
	if err != nil {
		t.Fatal(err)
	}

	var out, errW bytes.Buffer
	code := renderCLI(&out, &errW, snap, 8080, true)
	if code != 0 {
		t.Fatalf("code=%d stderr=%q", code, errW.String())
	}
	if !strings.Contains(out.String(), "4242") {
		t.Errorf("pid column missing: %q", out.String())
	}
	if !strings.Contains(errW.String(), "additional socket(s)") {
		t.Errorf("coexisting foreign socket must be flagged: %q", errW.String())
	}
}

func TestBareInvocationDefaultsToTUI(t *testing.T) {
	// Non-TTY stdin makes the TUI exit with an error immediately; what matters
	// is that it dispatched to TUI (exit 1) instead of usage (2).
	code := run([]string{})
	if code != 1 {
		t.Errorf("bare run() = %d, want 1 (TUI attempted)", code)
	}
}
