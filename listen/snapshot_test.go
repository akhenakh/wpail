//go:build linux

package listen

import (
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const fixtureStatus1234 = "Name:\tinserve\nUid:\t1000\t1000\t1000\t1000\nVmRSS:\t2048 kB\n"

// writeFixtureProc builds a fake /proc tree. Real system processes appear in
// ownersAt scans of the tempdir too? No — the scanner only reads the given
// root, so only our fixture dirs are visible there.
func writeFixtureProc(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	netDir := filepath.Join(root, "net")
	if err := os.MkdirAll(netDir, 0o755); err != nil {
		t.Fatal(err)
	}

	writeFile := func(rel, body string) {
		path := filepath.Join(root, rel)
		if dir := filepath.Dir(path); dir != root {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	const hdr = "  sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n"
	var b strings.Builder
	b.WriteString(hdr)
	b.WriteString("   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 100\n") // *:8080       -> pid 1234
	b.WriteString("   1: 00000000:1B58 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 110\n") // *:7000 REUSEPORT -> pids 1234,2345
	b.WriteString("   2: 00000000:2382 0100007F:0011 01 00000000:00000000 00:00000000 00000000  1000        0 111\n") // :9090 established, must be ignored
	b.WriteString("   3: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 999\n") // :3000 unmapped owner
	writeFile("net/tcp", b.String())

	writeFile("net/tcp6", hdr+"   0: "+strings.Repeat("0", 32)+":1F90 "+strings.Repeat("0", 32)+":0000 0A 00000000:00000000 00:00000000 00000000  1000        0 101\n") // [::]:8080 -> pid 1234
	writeFile("net/udp", hdr+"   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 300\n")                                        // *:5353 -> pid 3456
	writeFile("net/udp6", hdr)

	linkFD := func(pid int, files map[string]string) {
		pidDir := filepath.Join(root, strconv.Itoa(pid))
		for rel, body := range files {
			path := filepath.Join(pidDir, rel)
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if after, ok := strings.CutPrefix(body, "@symlink:"); ok {
				target := after
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
				continue
			}
			if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}

	status2345 := "Name:\tsidecar\nUid:\t0\t0\t0\t0\n"
	status3456 := "Name:\tdnsbridge\nUid:\t33\t33\t33\t33\nVmRSS:\t512 kB\n"

	linkFD(1234, map[string]string{
		"status":  fixtureStatus1234,
		"cmdline": "inserve\x00--listen\x00:8080",
		"exe":     "@symlink:/usr/bin/inserve",
		"fd/3":    "@symlink:socket:[100]",
		"fd/4":    "@symlink:socket:[101]",
		"fd/7":    "@symlink:socket:[110]",
		"fd/8":    "@symlink:socket:[999]", // links the :3000 socket too
	})
	linkFD(2345, map[string]string{
		"status":  status2345,
		"cmdline": "",
		"fd/2":    "@symlink:socket:[110]",
	})
	linkFD(3456, map[string]string{
		"status":  status3456,
		"cmdline": "",
		"fd/5":    "@symlink:socket:[300]",
	})

	return root
}

func TestScanFixtureAggregatesPorts(t *testing.T) {
	root := writeFixtureProc(t)
	snap, err := scanAt(root)
	if err != nil {
		t.Fatal(err)
	}

	if got := snap.PIDs(8080); !slices.Equal(got, []int{1234}) {
		t.Errorf("PIDs(8080) = %v, want [1234]", got)
	}
	if got := snap.PIDs(7000); !slices.Equal(got, []int{1234, 2345}) {
		t.Errorf("PIDs(7000) shared/reuseport = %v, want [1234 2345]", got)
	}
	if got := snap.PIDs(9090); len(got) != 0 {
		t.Errorf("established sockets leaked into PIDs(9090): %v", got)
	}
	if got := snap.Unresolved(3000); got != 0 {
		t.Errorf("Unresolved(3000) = %d, want 0 (pid 1234 links inode 999)", got)
	}
	if got := snap.Unresolved(9090); got != 0 {
		t.Errorf("non-listen rows must never count as unresolved: %d", got)
	}

	row8080, found := findRow(snap.Rows(0), 8080)
	if !found {
		t.Fatal("row for :8080 missing")
	}
	if got := row8080.Protos; !slices.Equal(got, []string{"tcp", "tcp6"}) {
		t.Errorf("Protos = %v, want [tcp tcp6]", got)
	}
	if len(row8080.Addrs) != 2 || row8080.Addrs[0] != "0.0.0.0" {
		t.Errorf("Addrs = %v, want sorted [0.0.0.0 [::]]", row8080.Addrs)
	}
	if row8080.Owner() != 1234 {
		t.Errorf("Owner = %d, want 1234", row8080.Owner())
	}
	if len(row8080.Names) != 1 || row8080.Names[0] != "inserve --listen :8080" {
		t.Errorf("Names = %#v, want joined cmdline", row8080.Names)
	}

	rowUdp, _ := findRow(snap.Rows(0), 5353)
	if got := rowUdp.Users; len(got) == 0 || strings.TrimSpace(got[0]) == "" {
		t.Errorf("Users missing for udp row: %#v", got)
	}
	if filtered := snap.Rows(8080); len(filtered) != 1 || filtered[0].Port != 8080 {
		t.Fatalf("Rows(8080) filter failed: %+v", filtered)
	}

	gotPorts := make([]uint16, 0, len(snap.Sockets))
	for _, r := range snap.Rows(0) {
		gotPorts = append(gotPorts, r.Port)
	}
	want := []uint16{3000, 5353, 7000, 8080} // sorted ascending
	if !slices.Equal(gotPorts, want) {
		t.Errorf("Rows(0) ports = %v, want sorted %v", gotPorts, want)
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

func TestDetailFromFixture(t *testing.T) {
	root := writeFixtureProc(t)
	proc, err := detailAt(root, 1234)
	if err != nil {
		t.Fatal(err)
	}
	switch {
	case proc.Name() != "inserve --listen :8080":
		t.Errorf("Name = %q", proc.Name())
	case proc.UID != 1000:
		t.Errorf("UID = %d", proc.UID)
	case proc.RSSKB != 2048:
		t.Errorf("RSSKB = %d", proc.RSSKB)
	case proc.Memory() != "2.0 MB":
		t.Errorf("Memory = %q", proc.Memory())
	case proc.Exe != "/usr/bin/inserve":
		t.Errorf("Exe = %q", proc.Exe)
	case proc.User == "":
		t.Error("uid 1000 must resolve to some username (numeric fallback)")
	}

	sidecar, err := detailAt(root, 2345)
	if err != nil {
		t.Fatal(err)
	}
	if sidecar.Name() != "sidecar" || sidecar.Memory() != "n/a" {
		t.Errorf("sidecar Name/Memory = %q/%q", sidecar.Name(), sidecar.Memory())
	}

	if _, err := detailAt(root, 40404); err == nil {
		t.Error("detailAt must fail for unknown pids")
	}
}

func TestSnapshotIgnoresForeignInodesWhenUnmapped(t *testing.T) {
	root := writeFixtureProc(t)
	// remove pid 1234's link to the :3000 socket so inode 999 becomes orphaned
	fdPath := filepath.Join(root, "1234", "fd", "8")
	if err := os.Remove(fdPath); err != nil {
		t.Fatal(err)
	}
	snap, err := scanAt(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := snap.Unresolved(3000); got != 1 {
		t.Errorf("Unresolved(3000) = %d, want 1", got)
	}
	if got := snap.PIDs(3000); len(got) != 0 {
		t.Errorf("PIDs(3000) = %v, want none", got)
	}
}

// TestScanFindsOwnSockets runs against the machine's real /proc and asserts
// wpail discovers sockets this very test binds, including under an
// unprivileged user where other users' fds are unreadable.
func TestScanFindsOwnSockets(t *testing.T) {
	tcpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer func() { _ = tcpListener.Close() }()
	tcpPort := uint16(tcpListener.Addr().(*net.TCPAddr).Port)

	udpSock, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind udp: %v", err)
	}
	defer func() { _ = udpSock.Close() }()
	udpPort := uint16(udpSock.LocalAddr().(*net.UDPAddr).Port)

	self := os.Getpid()
	snap, err := Scan()
	if err != nil {
		t.Fatalf("real Scan failed: %v", err)
	}

	for _, tc := range []struct {
		name  string
		port  uint16
		proto string
	}{
		{"own tcp listener", tcpPort, "tcp"},
		{"own udp socket", udpPort, "udp"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pids := snap.PIDs(tc.port)
			if !slices.Contains(pids, self) {
				t.Fatalf("PIDs(%d) = %v, want to contain self pid %d", tc.port, pids, self)
			}
			var found bool
			for _, sk := range snap.Owned(self) {
				if sk.Port == tc.port && strings.HasPrefix(sk.Proto, tc.proto) {
					found = true
				}
			}
			if !found {
				t.Errorf("Owned(%d) misses %s socket on %d", self, tc.proto, tc.port)
			}
			row, ok := findRow(snap.Rows(tc.port), tc.port)
			if !ok {
				t.Fatalf("no row aggregated for port %d", tc.port)
			}
			hasProto := slices.ContainsFunc(row.Protos, func(p string) bool {
				return strings.HasPrefix(p, tc.proto)
			})
			if !hasProto {
				t.Errorf("row protos %v lack %s", row.Protos, tc.proto)
			}
		})
	}
}
