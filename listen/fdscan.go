//go:build linux

package listen

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// owners maps every listening socket to the processes holding it open by
// walking /proc/[pid]/fd and resolving socket:[inode] symlinks. Directories
// of processes we lack permission to read are skipped silently, matching
// lsof/ss behaviour for unprivileged users.
func ownersAt(root string, socks []Socket) map[int][]Socket {
	byInode := make(map[uint64][]Socket, len(socks))
	for _, s := range socks {
		byInode[s.Inode] = append(byInode[s.Inode], s)
	}

	res := make(map[int][]Socket)
	dirs, err := os.ReadDir(root)
	if err != nil {
		return res
	}
	for _, d := range dirs {
		pid, err := strconv.Atoi(d.Name())
		if err != nil || !d.IsDir() {
			continue
		}
		fdDir := filepath.Join(root, d.Name(), "fd")
		fds, err := os.ReadDir(fdDir)
		if err != nil {
			continue // not ours: /proc/<pid> inaccessible
		}
		for _, fd := range fds {
			link, err := os.Readlink(filepath.Join(fdDir, fd.Name()))
			if err != nil {
				continue
			}
			inode, ok := socketInode(link)
			if !ok {
				continue
			}
			res[pid] = append(res[pid], byInode[inode]...)
		}
	}
	for pid := range res {
		sortSockets(res[pid])
	}
	return res
}

func sortSockets(s []Socket) {
	slices.SortFunc(s, func(a, b Socket) int {
		if a.Port != b.Port {
			return int(a.Port) - int(b.Port)
		}
		return strings.Compare(a.Proto, b.Proto)
	})
}

// socketInode parses "socket:[12345]" into 12345.
func socketInode(link string) (uint64, bool) {
	rest, ok := strings.CutPrefix(link, "socket:[")
	if !ok {
		return 0, false
	}
	body, ok := strings.CutSuffix(rest, "]")
	if !ok {
		return 0, false
	}
	inode, err := strconv.ParseUint(body, 10, 64)
	if err != nil || inode == 0 {
		return 0, false
	}
	return inode, true
}
