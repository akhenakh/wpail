package listen

import "net"

// socketInfo is one row of a kernel socket table: a listening socket, an
// accepted or connected session, or an already-closed socket the kernel still
// tracks. Backends fill it in and the shared session code pairs the two ends
// of loopback connections through their mirrored 4-tuples.
type socketInfo struct {
	Socket
	Family     string // tcp or udp, shared by the IPv4 and IPv6 variants
	State      string // ESTABLISHED, LISTEN, TIME_WAIT, …
	Remote     net.IP
	RemotePort uint16
}

// isListener reports whether the socket belongs in the listening table: TCP
// only in LISTEN state, UDP whenever bound (it has no listen state at all).
func (s socketInfo) isListener() bool {
	return s.Family == "udp" || s.State == "LISTEN"
}

// hasPeer reports whether the row describes a session with a remote endpoint.
func (s socketInfo) hasPeer() bool { return s.RemotePort != 0 }
