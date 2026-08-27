//go:build linux

package listen

const procFS = "/proc"

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
	return newSnapshot(socks, ownersAt(root, socks), func(pid int) (*Process, error) {
		return detailAt(root, pid)
	}), nil
}
