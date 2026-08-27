//go:build darwin && arm64

package listen

import (
	"encoding/binary"
	"net"
	"os"
	"slices"
	"strings"
	"testing"
)

func buildProcArgs(exe string, args []string) []byte {
	var b []byte
	b = binary.NativeEndian.AppendUint32(b, uint32(len(args)))
	b = append(b, exe...)
	for len(b)%8 != 0 { // alignment padding before argv
		b = append(b, 0)
	}
	for _, a := range args {
		b = append(b, a...)
		b = append(b, 0)
	}
	return b
}

func TestParseProcArgs(t *testing.T) {
	tests := []struct {
		name     string
		buf      []byte
		wantExe  string
		wantArgs []string
	}{
		{
			name:     "path with padding and three args",
			buf:      buildProcArgs("/usr/local/bin/inserve\x00", []string{"/usr/local/bin/inserve", "--listen", ":8080"}),
			wantExe:  "/usr/local/bin/inserve",
			wantArgs: []string{"/usr/local/bin/inserve", "--listen", ":8080"},
		},
		{name: "no padding needed", buf: buildProcArgs("a\x00", []string{"a", "b"}), wantExe: "a", wantArgs: []string{"a", "b"}},
		{name: "empty buffer", buf: nil, wantExe: "", wantArgs: nil},
		{name: "short buffer", buf: []byte{1, 2}, wantExe: "", wantArgs: nil},
		{name: "zero argc", buf: binary.NativeEndian.AppendUint32(nil, 0), wantExe: "", wantArgs: nil},
		{
			name:     "truncated argv list",
			buf:      append(buildProcArgs("p\x00", []string{"only"}), 0),
			wantExe:  "p",
			wantArgs: []string{"only"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exe, argv := parseProcArgs(tt.buf)
			if exe != tt.wantExe {
				t.Errorf("exe = %q, want %q", exe, tt.wantExe)
			}
			if !slices.Equal(argv, tt.wantArgs) {
				t.Errorf("argv = %v, want %v", argv, tt.wantArgs)
			}
		})
	}
}

// TestScanFindsOwnSockets binds real sockets in this process and asserts the
// libproc scanner attributes them to us.
func TestScanFindsOwnSockets(t *testing.T) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer func() { _ = lis.Close() }()
	tcpPort := uint16(lis.Addr().(*net.TCPAddr).Port)

	udpSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind udp: %v", err)
	}
	defer func() { _ = udpSock.Close() }()
	udpPort := uint16(udpSock.LocalAddr().(*net.UDPAddr).Port)

	self := os.Getpid()
	snap, err := Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	if !slices.Contains(snap.PIDs(tcpPort), self) {
		t.Fatalf("PIDs(%d) = %v, missing self %d", tcpPort, snap.PIDs(tcpPort), self)
	}
	if !slices.Contains(snap.PIDs(udpPort), self) {
		t.Errorf("PIDs(%d) = %v, missing self %d (udp)", udpPort, snap.PIDs(udpPort), self)
	}
	row, ok := findRow(snap.Rows(tcpPort), tcpPort)
	if !ok {
		t.Fatalf("no row aggregated for port %d", tcpPort)
	}
	if !slices.ContainsFunc(row.Protos, func(p string) bool { return strings.HasPrefix(p, "tcp") }) {
		t.Errorf("row protos %v lack tcp", row.Protos)
	}
}

func findRow(rows []Row, port uint16) (Row, bool) {
	for _, r := range rows {
		if r.Port == port {
			return r, true
		}
	}
	return Row{}, false
}

// TestDetailRootOwnedAncestor verifies Detail works unprivileged on
// root-owned processes such as launchd: proc_pidinfo answers EPERM there,
// and the ancestry walk terminates early with "unknown" placeholders if the
// sysctl fallback did not fill the gap.
func TestDetailRootOwnedAncestor(t *testing.T) {
	p, err := Detail(1)
	if err != nil {
		t.Fatalf("Detail(1): %v", err)
	}
	if p.PPID != 0 {
		t.Errorf("Detail(1).PPID = %d, want 0", p.PPID)
	}
	if p.Comm != "launchd" {
		t.Errorf("Detail(1).Comm = %q, want launchd", p.Comm)
	}
	if p.User != "root" {
		t.Errorf("Detail(1).User = %q, want root", p.User)
	}
}

// TestCommString verifies fixed-size kernel comm buffers truncate at the
// first NUL; the kernel leaves stale bytes beyond it.
func TestCommString(t *testing.T) {
	tests := []struct {
		buf  []byte
		want string
	}{
		{[]byte("launchd\x00ask\x00"), "launchd"},
		{[]byte("zsh\x00"), "zsh"},
		{[]byte("exactly16ch"), "exactly16ch"},
		{nil, ""},
	}
	for _, tt := range tests {
		if got := commString(tt.buf); got != tt.want {
			t.Errorf("commString(%q) = %q, want %q", tt.buf, got, tt.want)
		}
	}
}

// TestDetailSelf verifies Detail works on the live test process.
func TestDetailSelf(t *testing.T) {
	p, err := Detail(os.Getpid())
	if err != nil {
		t.Fatalf("Detail(self): %v", err)
	}
	if p.Comm == "" && p.Cmdline == "" {
		t.Error("neither comm nor cmdline resolved for self")
	}
	if p.Exe == "" {
		t.Error("executable path missing for self")
	}
	if p.User == "" {
		t.Error("user unresolved for self")
	}
}
