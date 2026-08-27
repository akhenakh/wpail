//go:build linux

package listen

import (
	"cmp"
	"maps"
	"slices"
)

const procFS = "/proc"

var protoRank = map[string]int{"tcp": 0, "tcp6": 1, "udp": 2, "udp6": 3}

func compareProto(a, b string) int { return protoRank[a] - protoRank[b] }

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
	owners  map[int][]Socket // pid -> owned listening sockets
	root    string           // procfs root this snapshot came from
}

// Scan snapshots the system's listening sockets by reading /proc.
func Scan() (*Snapshot, error) { return scanAt(procFS) }

// ScanAt works like Scan but reads an alternative procfs root. It exists for
// testing and for embedding scenarios.
func ScanAt(root string) (*Snapshot, error) { return scanAt(root) }

func scanAt(root string) (*Snapshot, error) {
	socks, err := readSockets(root)
	if err != nil {
		return nil, err
	}
	return &Snapshot{Sockets: socks, owners: ownersAt(root, socks), root: root}, nil
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
				resolved[sk.Inode] = true
			}
		}
	}
	n := 0
	for _, sk := range s.Sockets {
		if sk.Port == port && !resolved[sk.Inode] {
			n++
		}
	}
	return n
}

// Rows aggregates sockets into one row per listening port, optionally
// filtered to port when it is non-zero. Process identity is resolved best
// effort; rows may be empty of PIDs when /proc is not readable enough.
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
		a.inodes[sk.Inode] = true
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
			if slices.ContainsFunc(socks, func(sk Socket) bool { return a.inodes[sk.Inode] }) {
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
			if proc, err := detailAt(s.root, pid); err == nil {
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
