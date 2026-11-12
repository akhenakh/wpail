package listen

import "net"

// endpoint is an address normalized for 4-tuple matching: IPv4 addresses are
// widened into their IPv4-mapped IPv6 form so a tcp client and the tcp6
// dual-stack listener it talks to produce the same key.
type endpoint struct {
	addr [16]byte
	port uint16
}

type connKey struct {
	local  endpoint
	remote endpoint
	family string
}

// portPair identifies a session by ports only; it backs the fallback lookup
// for sockets whose local address is still the wildcard (connected UDP).
type portPair struct {
	family     string
	localPort  uint16
	remotePort uint16
}

func endpointOf(ip net.IP, port uint16) endpoint {
	var e endpoint
	e.port = port
	if v4 := ip.To4(); v4 != nil {
		e.addr[10], e.addr[11] = 0xff, 0xff
		copy(e.addr[12:], v4)
	} else if v16 := ip.To16(); v16 != nil {
		copy(e.addr[:], v16)
	}
	return e
}

func (s socketInfo) key() connKey {
	return connKey{
		local:  endpointOf(s.Local, s.Port),
		remote: endpointOf(s.Remote, s.RemotePort),
		family: s.Family,
	}
}

// mirrorKey is the same session seen from the other end.
func (s socketInfo) mirrorKey() connKey {
	return connKey{
		local:  endpointOf(s.Remote, s.RemotePort),
		remote: endpointOf(s.Local, s.Port),
		family: s.Family,
	}
}

func (s socketInfo) pair() portPair {
	return portPair{family: s.Family, localPort: s.Port, remotePort: s.RemotePort}
}

// buildConnections turns the raw socket rows into sessions and resolves the
// local process on each end. The kernel exposes both halves of a loopback
// connection (server accepted socket and client connected socket) as separate
// rows; matching each row's mirrored 4-tuple against the table yields the
// peer's inode, and the fd scan yields its PID.
func buildConnections(socks []socketInfo, ownerOf map[uint64]int) []Connection {
	byKey := make(map[connKey][]int, len(socks))
	byPorts := make(map[portPair][]int, len(socks))
	for i, si := range socks {
		if !si.hasPeer() {
			continue
		}
		byKey[si.key()] = append(byKey[si.key()], i)
		byPorts[si.pair()] = append(byPorts[si.pair()], i)
	}

	out := make([]Connection, 0, len(byKey))
	for i, si := range socks {
		if !si.hasPeer() {
			continue
		}
		c := Connection{
			Proto:      si.Proto,
			State:      si.State,
			Local:      si.Local,
			LocalPort:  si.Port,
			Remote:     si.Remote,
			RemotePort: si.RemotePort,
			Key:        si.Key,
			PID:        ownerOf[si.Key],
		}
		if j := pickMirror(byKey[si.mirrorKey()], i, ownerOf, socks); j >= 0 {
			c.PeerKey, c.PeerPID = socks[j].Key, ownerOf[socks[j].Key]
		} else if j := pickMirror(byPorts[si.mirrorPorts()], i, ownerOf, socks); j >= 0 {
			c.PeerKey, c.PeerPID = socks[j].Key, ownerOf[socks[j].Key]
		}
		out = append(out, c)
	}
	return out
}

// mirrorPorts flips the endpoints of s so the fallback lookup can find a
// session whose 4-tuple is only distinguishable by ports (wildcard locals).
func (s socketInfo) mirrorPorts() portPair {
	return portPair{family: s.Family, localPort: s.RemotePort, remotePort: s.Port}
}

// pickMirror prefers a candidate owned by a live process over a TIME_WAIT row
// whose inode the kernel already released.
func pickMirror(candidates []int, self int, ownerOf map[uint64]int, socks []socketInfo) int {
	fallback := -1
	for _, j := range candidates {
		if j == self {
			continue
		}
		if ownerOf[socks[j].Key] != 0 {
			return j
		}
		if fallback < 0 {
			fallback = j
		}
	}
	return fallback
}
