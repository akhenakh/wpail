//go:build freebsd

package listen

import (
	"net"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestParseNullArgs(t *testing.T) {
	tests := []struct {
		name string
		raw  []byte
		want []string
	}{
		{"three args", []byte("/usr/local/bin/inserve\x00--listen\x00:8080\x00"), []string{"/usr/local/bin/inserve", "--listen", ":8080"}},
		{"no trailing nul", []byte("daemon\x00--fg"), []string{"daemon", "--fg"}},
		{"empty", nil, nil},
		{"only nuls", []byte{0, 0, 0}, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseNullArgs(tt.raw); !slices.Equal(got, tt.want) {
				t.Errorf("parseNullArgs(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestParseNullString(t *testing.T) {
	if got := parseNullString([]byte("/bin/sh\x00garbage")); got != "/bin/sh" {
		t.Errorf("parseNullString = %q, want /bin/sh", got)
	}
	if got := parseNullString([]byte("-\x00")); got != "" {
		t.Errorf("placeholder '-' must yield empty, got %q", got)
	}
}

func TestScanFindsOwnSockets(t *testing.T) {
	tcpLis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind tcp: %v", err)
	}
	defer func() { _ = tcpLis.Close() }()
	tcpPort := uint16(tcpLis.Addr().(*net.TCPAddr).Port)

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

	var foundTCP, foundUDP bool
	for _, sk := range snap.Owned(self) {
		if sk.Port == tcpPort && strings.HasPrefix(sk.Proto, "tcp") {
			foundTCP = true
		}
		if sk.Port == udpPort && strings.HasPrefix(sk.Proto, "udp") {
			foundUDP = true
		}
	}
	if !foundTCP || !foundUDP {
		t.Errorf("Owned(%d) incomplete: tcp=%v udp=%v", self, foundTCP, foundUDP)
	}

	row, ok := findRow(snap.Rows(tcpPort), tcpPort)
	if !ok {
		t.Fatalf("no row aggregated for port %d", tcpPort)
	}
	if !slices.ContainsFunc(row.Protos, func(p string) bool { return strings.HasPrefix(p, "tcp") }) {
		t.Errorf("row protos %v lack tcp", row.Protos)
	}
}

func TestScanFindsOwnSessions(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot bind: %v", err)
	}
	defer func() { _ = ln.Close() }()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skipf("cannot dial: %v", err)
	}
	defer func() { _ = client.Close() }()
	server, err := ln.Accept()
	if err != nil {
		t.Skipf("cannot accept: %v", err)
	}
	defer func() { _ = server.Close() }()

	self := os.Getpid()
	snap, err := Scan()
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	var found *Connection
	for _, c := range snap.Connections(port) {
		if c.State == "ESTABLISHED" && c.PID == self {
			found = &c
			break
		}
	}
	if found == nil {
		t.Fatalf("no established session owned by pid %d on port %d: %+v",
			self, port, snap.Connections(port))
	}
	if found.PeerPID != self {
		t.Errorf("peer PID = %d, want %d (client runs in this process)", found.PeerPID, self)
	}
	if found.RemotePort == 0 {
		t.Error("session has no remote endpoint")
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

func TestDetailSelfAndParent(t *testing.T) {
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
	if p.CWD == "" {
		t.Error("CWD missing for self")
	}
	if p.User == "" {
		t.Error("user unresolved for self")
	}
	if p.RSSKB == 0 {
		t.Error("RSSKB = 0 for self")
	}

	if ppid := os.Getppid(); ppid > 0 {
		parent, err := Detail(ppid)
		if err != nil {
			t.Fatalf("Detail(ppid=%d): %v", ppid, err)
		}
		if parent.PID != ppid {
			t.Errorf("parent.PID = %d, want %d", parent.PID, ppid)
		}
	}

	for _, bad := range []int{0, -1, 999999999} {
		if _, err := Detail(bad); err == nil {
			t.Errorf("Detail(%d) succeeded, want error", bad)
		}
	}
}
