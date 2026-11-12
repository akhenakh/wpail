package listen

import (
	"net"
	"testing"
)

func si(proto, family, state string, local net.IP, lport uint16, remote net.IP, rport, inode uint64) socketInfo {
	return socketInfo{
		Proto: proto, Local: local, Port: lport, Key: inode,
		Family:     family,
		State:      state,
		Remote:     remote,
		RemotePort: uint16(rport),
	}
}

func TestBuildConnectionsMatchesDualStackPeers(t *testing.T) {
	lo4 := net.IPv4(127, 0, 0, 1)
	lo6mapped := net.ParseIP("::ffff:127.0.0.1")
	socks := []socketInfo{
		si("tcp6", "tcp", "ESTABLISHED", lo6mapped, 8080, lo6mapped, 40000, 100),
		si("tcp", "tcp", "ESTABLISHED", lo4, 40000, lo4, 8080, 200),
	}
	owner := map[uint64]int{100: 10, 200: 20}

	conns := buildConnections(socks, owner)
	if len(conns) != 2 {
		t.Fatalf("got %d sessions, want 2", len(conns))
	}
	for _, c := range conns {
		switch c.LocalPort {
		case 8080:
			if c.PID != 10 || c.PeerPID != 20 || c.PeerKey != 200 {
				t.Errorf("server side resolved to pid %d peer %d key %d", c.PID, c.PeerPID, c.PeerKey)
			}
		case 40000:
			if c.PID != 20 || c.PeerPID != 10 || c.PeerKey != 100 {
				t.Errorf("client side resolved to pid %d peer %d key %d", c.PID, c.PeerPID, c.PeerKey)
			}
		}
	}
}

func TestBuildConnectionsKeepsTimeWaitWithoutOwner(t *testing.T) {
	lo4 := net.IPv4(127, 0, 0, 1)
	socks := []socketInfo{
		si("tcp", "tcp", "TIME_WAIT", lo4, 8080, lo4, 40000, 0),
	}
	conns := buildConnections(socks, nil)
	if len(conns) != 1 {
		t.Fatalf("got %d sessions, want 1", len(conns))
	}
	if conns[0].State != "TIME_WAIT" || conns[0].PID != 0 || conns[0].PeerPID != 0 {
		t.Errorf("unexpected TIME_WAIT session: %+v", conns[0])
	}
}

func TestBuildConnectionsResolvesWildcardUDPPeers(t *testing.T) {
	any4 := net.IPv4zero
	lo4 := net.IPv4(127, 0, 0, 1)
	socks := []socketInfo{
		si("udp", "udp", "ESTABLISHED", lo4, 5353, lo4, 40000, 300),
		si("udp", "udp", "ESTABLISHED", any4, 40000, lo4, 5353, 400),
	}
	owner := map[uint64]int{300: 30, 400: 40}

	conns := buildConnections(socks, owner)
	if len(conns) != 2 {
		t.Fatalf("got %d sessions, want 2", len(conns))
	}
	for _, c := range conns {
		if c.PID == 30 && c.PeerPID != 40 {
			t.Errorf("server peer = %d, want 40", c.PeerPID)
		}
		if c.PID == 40 && c.PeerPID != 30 {
			t.Errorf("client peer = %d, want 30", c.PeerPID)
		}
	}
}
