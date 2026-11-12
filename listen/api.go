//go:build linux || freebsd || (darwin && arm64)

// Package listen discovers which processes are listening on TCP/UDP ports by
// reading kernel tables directly, without shelling out to lsof or ss.
//
// Linux reads procfs (/proc/net/{tcp,tcp6,udp,udp6} plus per-process fd
// symlinks); FreeBSD reads the kernel PCB and file tables through sysctl;
// macOS walks process file descriptors through libproc.
package listen

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"strconv"
	"strings"
)

// Socket is one listening entry reported by the platform backend.
type Socket struct {
	Proto string // tcp, tcp6, udp, udp6
	Local net.IP
	Port  uint16
	Key   uint64 // opaque socket identity, unique within one Snapshot
	UID   uint32
}

// Connection is one session observed in the kernel socket tables: the local
// endpoint, the remote peer, the transport state, and — best effort — the
// processes holding each end. Key and PID describe the local socket; PeerKey
// and PeerPID describe the mirrored socket when the peer runs on this host.
type Connection struct {
	Proto      string // tcp, tcp6, udp, udp6
	State      string // ESTABLISHED, CLOSE_WAIT, TIME_WAIT, …
	Local      net.IP
	LocalPort  uint16
	Remote     net.IP
	RemotePort uint16
	Key        uint64
	PeerKey    uint64
	PID        int
	PeerPID    int
}

// LocalAddr renders the local endpoint as host:port.
func (c Connection) LocalAddr() string {
	return net.JoinHostPort(c.Local.String(), strconv.Itoa(int(c.LocalPort)))
}

// RemoteAddr renders the remote endpoint as host:port.
func (c Connection) RemoteAddr() string {
	return net.JoinHostPort(c.Remote.String(), strconv.Itoa(int(c.RemotePort)))
}

// String renders the socket as proto://ip:port, bracketing IPv6 addresses.
func (s Socket) String() string {
	return fmt.Sprintf("%s://%s:%d", s.Proto, FormatIP(s.Local), s.Port)
}

// FormatIP renders ip for display, wrapping IPv6 addresses in brackets.
func FormatIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return "[" + ip.String() + "]"
}

// Process describes an OS process, used for detail views and CLI reporting.
type Process struct {
	PID     int
	PPID    int // parent PID; 0 when unavailable
	UID     uint32
	User    string
	Comm    string
	Cmdline string
	Exe     string
	CWD     string // working directory; empty when unavailable
	RSSKB   uint64 // resident set size in KB; 0 when unavailable
}

// Name prefers the full command line over the bare executable name.
func (p Process) Name() string {
	if c := strings.TrimSpace(p.Cmdline); c != "" {
		return c
	}
	return p.Comm
}

// Memory renders the resident set size in human readable units.
func (p Process) Memory() string {
	switch kb := p.RSSKB; {
	case kb == 0:
		return "n/a"
	case kb < 1024:
		return fmt.Sprintf("%d KB", kb)
	case kb < 1024*1024:
		return fmt.Sprintf("%.1f MB", float64(kb)/1024)
	default:
		return fmt.Sprintf("%.2f GB", float64(kb)/(1024*1024))
	}
}

var protoRank = map[string]int{"tcp": 0, "tcp6": 1, "udp": 2, "udp6": 3}

func compareProto(a, b string) int { return protoRank[a] - protoRank[b] }

func sortSockets(s []Socket) {
	slices.SortFunc(s, func(a, b Socket) int {
		if a.Port != b.Port {
			return cmp.Compare(a.Port, b.Port)
		}
		return strings.Compare(a.Proto, b.Proto)
	})
}

func sortConnections(c []Connection) {
	slices.SortFunc(c, func(a, b Connection) int {
		if n := cmp.Compare(a.LocalPort, b.LocalPort); n != 0 {
			return n
		}
		if n := strings.Compare(a.Proto, b.Proto); n != 0 {
			return n
		}
		if n := bytes.Compare(a.Remote.To16(), b.Remote.To16()); n != 0 {
			return n
		}
		if n := cmp.Compare(a.RemotePort, b.RemotePort); n != 0 {
			return n
		}
		return strings.Compare(a.State, b.State)
	})
}

// Row aggregates every listening socket sharing one port. Multiple processes
// can share a port via SO_REUSEPORT, so owners are reported as parallel
// slices: PIDs[i] runs as Users[i] answering to Names[i].
type Row struct {
	Port        uint16
	Protos      []string // unique, canonical order tcp, tcp6, udp, udp6
	Addrs       []string // unique formatted local addresses, sorted
	Connections int      // accepted sessions currently attached to this port
	PIDs        []int    // sorted ascending; empty when the owner is unresolvable
	Names       []string // aligned with PIDs; "?" entries for unknown
	Users       []string // aligned with PIDs
}

// Owner returns the representative PID or 0 when unknown.
func (r Row) Owner() int {
	if len(r.PIDs) > 0 && r.PIDs[0] > 0 {
		return r.PIDs[0]
	}
	return 0
}

// Snapshot is one point-in-time view of listening sockets, their owners, and
// the sessions currently attached to them.
type Snapshot struct {
	Sockets []Socket
	conns   []Connection
	owners  map[int][]Socket                // pid -> owned listening sockets
	detail  func(pid int) (*Process, error) // platform process resolver
}

func newSnapshot(sockets []Socket, conns []Connection, owners map[int][]Socket,
	detail func(pid int) (*Process, error)) *Snapshot {
	if detail == nil {
		detail = func(int) (*Process, error) { return nil, errors.New("process detail unsupported") }
	}
	if owners == nil {
		owners = map[int][]Socket{}
	}
	sortConnections(conns)
	return &Snapshot{Sockets: sockets, conns: conns, owners: owners, detail: detail}
}

// Connections returns the sessions whose local port is port, sorted by local
// port, protocol and remote endpoint. A zero port returns every session.
func (s *Snapshot) Connections(port uint16) []Connection {
	if port == 0 {
		return slices.Clone(s.conns)
	}
	var out []Connection
	for _, c := range s.conns {
		if c.LocalPort == port {
			out = append(out, c)
		}
	}
	return out
}

// ConnectionsOf returns the sessions held locally by pid, as either the
// accepting server or the connecting client.
func (s *Snapshot) ConnectionsOf(pid int) []Connection {
	var out []Connection
	for _, c := range s.conns {
		if c.PID == pid {
			out = append(out, c)
		}
	}
	return out
}

// ConnectionCount counts the sessions attached to a listening port.
func (s *Snapshot) ConnectionCount(port uint16) int {
	n := 0
	for _, c := range s.conns {
		if c.LocalPort == port {
			n++
		}
	}
	return n
}

// SessionsFor returns the sessions shown for pid in the detail view: every
// session attached to a port it listens on (the accepting worker may be a
// different PID), plus any session pid holds as a client. The result is
// de-duplicated and sorted like Connections.
func (s *Snapshot) SessionsFor(pid int) []Connection {
	ports := make(map[uint16]bool)
	for _, sk := range s.owners[pid] {
		ports[sk.Port] = true
	}

	seen := make(map[connKey]bool)
	out := make([]Connection, 0, len(ports))
	add := func(c Connection) {
		k := connKey{
			local:  endpointOf(c.Local, c.LocalPort),
			remote: endpointOf(c.Remote, c.RemotePort),
			family: strings.TrimSuffix(c.Proto, "6"),
		}
		if seen[k] {
			return
		}
		seen[k] = true
		out = append(out, c)
	}
	for port := range ports {
		for _, c := range s.Connections(port) {
			add(c)
		}
	}
	for _, c := range s.ConnectionsOf(pid) {
		add(c)
	}
	sortConnections(out)
	return out
}

// Owned returns every listening socket held open by pid.
func (s *Snapshot) Owned(pid int) []Socket { return s.owners[pid] }

// PIDs reports every process listening on port, sorted and de-duplicated.
func (s *Snapshot) PIDs(port uint16) []int {
	var pids []int
	for pid, socks := range s.owners {
		if slices.ContainsFunc(socks, func(sk Socket) bool { return sk.Port == port }) {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	return pids
}

// Unresolved counts listening sockets on port whose owner could not be
// identified, typically because they belong to another user.
func (s *Snapshot) Unresolved(port uint16) int {
	resolved := make(map[uint64]bool)
	for _, socks := range s.owners {
		for _, sk := range socks {
			if sk.Port == port {
				resolved[sk.Key] = true
			}
		}
	}
	n := 0
	for _, sk := range s.Sockets {
		if sk.Port == port && !resolved[sk.Key] {
			n++
		}
	}
	return n
}

// Rows aggregates sockets into one row per listening port, optionally
// filtered to port when it is non-zero. Process identity is resolved best
// effort; rows may be empty of PIDs when foreign-owned processes are hidden
// from us.
func (s *Snapshot) Rows(filter uint16) []Row {
	type agg struct {
		protos map[string]bool
		addrs  map[string]bool
		inodes map[uint64]bool
	}
	order := make([]uint16, 0, 8)
	slots := make(map[uint16]*agg)

	slotFor := func(port uint16) *agg {
		a, ok := slots[port]
		if !ok {
			a = &agg{protos: map[string]bool{}, addrs: map[string]bool{}, inodes: map[uint64]bool{}}
			slots[port] = a
			order = append(order, port)
		}
		return a
	}

	for _, sk := range s.Sockets {
		if filter != 0 && sk.Port != filter {
			continue
		}
		a := slotFor(sk.Port)
		a.protos[sk.Proto] = true
		a.addrs[FormatIP(sk.Local)] = true
		a.inodes[sk.Key] = true
	}

	counts := make(map[uint16]int, len(order))
	for _, c := range s.conns {
		counts[c.LocalPort]++
	}

	rows := make([]Row, 0, len(order))
	for _, port := range order {
		a := slots[port]

		row := Row{Port: port,
			Connections: counts[port],
			Protos:      make([]string, 0, len(a.protos))}
		for proto := range a.protos {
			row.Protos = append(row.Protos, proto)
		}
		slices.SortFunc(row.Protos, compareProto)
		row.Addrs = slices.Sorted(maps.Keys(a.addrs))

		pidSet := map[int]bool{}
		for pid, socks := range s.owners {
			if slices.ContainsFunc(socks, func(sk Socket) bool { return a.inodes[sk.Key] }) {
				pidSet[pid] = true
			}
		}
		for pid := range pidSet {
			row.PIDs = append(row.PIDs, pid)
		}
		slices.Sort(row.PIDs)

		row.Names = make([]string, len(row.PIDs))
		row.Users = make([]string, len(row.PIDs))
		for i, pid := range row.PIDs {
			if proc, err := s.detail(pid); err == nil {
				row.Names[i] = proc.Name()
				row.Users[i] = proc.User
			} else {
				row.Names[i], row.Users[i] = "?", "?"
			}
		}
		rows = append(rows, row)
	}
	slices.SortFunc(rows, func(a, b Row) int { return cmp.Compare(a.Port, b.Port) })
	return rows
}
