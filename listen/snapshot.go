//go:build linux

package listen

const procFS = "/proc"

// Scan snapshots the system's listening sockets and the sessions attached to
// them by reading /proc.
func Scan() (*Snapshot, error) { return scanAt(procFS) }

// ScanAt works like Scan but reads an alternative procfs root. It exists for
// testing and for embedding scenarios.
func ScanAt(root string) (*Snapshot, error) { return scanAt(root) }

func scanAt(root string) (*Snapshot, error) {
	socks, err := readSockets(root)
	if err != nil {
		return nil, err
	}

	byPID := ownersAt(root, socks)

	// Everyone holding an inode: used to attach a PID to each half of a
	// session. When forked processes share a socket, the lowest PID wins so
	// the report is stable across scans.
	ownerOf := make(map[uint64]int, len(socks))
	listeners := make([]Socket, 0, len(socks))
	for _, si := range socks {
		if si.isListener() {
			listeners = append(listeners, si.Socket)
		}
	}
	owners := make(map[int][]Socket, len(byPID))
	for pid, owned := range byPID {
		seen := make(map[uint64]bool, len(owned))
		for _, si := range owned {
			if si.Key == 0 {
				continue
			}
			if prev, ok := ownerOf[si.Key]; !ok || pid < prev {
				ownerOf[si.Key] = pid
			}
			if !si.isListener() || seen[si.Key] {
				continue // a duplicated fd must not duplicate the row
			}
			seen[si.Key] = true
			owners[pid] = append(owners[pid], si.Socket)
		}
		sortSockets(owners[pid])
	}

	return newSnapshot(listeners, buildConnections(socks, ownerOf), owners,
		func(pid int) (*Process, error) {
			return detailAt(root, pid)
		}), nil
}
