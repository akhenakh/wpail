//go:build linux || (darwin && arm64)

// Package listen discovers which processes are listening on TCP/UDP ports by
// reading kernel tables directly, without shelling out to lsof or ss.
//
// Linux reads procfs (/proc/net/{tcp,tcp6,udp,udp6} plus per-process fd
// symlinks); macOS walks process file descriptors through libproc.
package listen

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
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

// Row aggregates every listening socket sharing one port. Multiple processes
// can share a port via SO_REUSEPORT, so owners are reported as parallel
// slices: PIDs[i] runs as Users[i] answering to Names[i].
type Row struct {
	Port   uint16
	Protos []string // unique, canonical order tcp, tcp6, udp, udp6
	Addrs  []string // unique formatted local addresses, sorted
	PIDs   []int    // sorted ascending; empty when the owner is unresolvable
	Names  []string // aligned with PIDs; "?" entries for unknown
	Users  []string // aligned with PIDs
}

// Owner returns the representative PID or 0 when unknown.
func (r Row) Owner() int {
	if len(r.PIDs) > 0 && r.PIDs[0] > 0 {
		return r.PIDs[0]
	}
	return 0
}

// Snapshot is one point-in-time view of listening sockets and their owners.
type Snapshot struct {
	Sockets []Socket
	owners  map[int][]Socket                // pid -> owned listening sockets
	detail  func(pid int) (*Process, error) // platform process resolver
}

func newSnapshot(sockets []Socket, owners map[int][]Socket,
	detail func(pid int) (*Process, error)) *Snapshot {
	if detail == nil {
		detail = func(int) (*Process, error) { return nil, errors.New("process detail unsupported") }
	}
	return &Snapshot{Sockets: sockets, owners: owners, detail: detail}
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

	rows := make([]Row, 0, len(order))
	for _, port := range order {
		a := slots[port]

		row := Row{Port: port,
			Protos: make([]string, 0, len(a.protos))}
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
