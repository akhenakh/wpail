//go:build linux

package listen

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Detail loads information about a live process from /proc.
func Detail(pid int) (*Process, error) { return detailAt(procFS, pid) }

func detailAt(root string, pid int) (*Process, error) {
	dir := filepath.Join(root, strconv.Itoa(pid))
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("process %d: %w", pid, err)
	}

	p := &Process{PID: pid}
	raw, err := os.ReadFile(filepath.Join(dir, "status"))
	if os.IsNotExist(err) {
		raw = nil // kernel threads and some pseudo processes have no status
	} else if err != nil {
		return nil, fmt.Errorf("process %d status: %w", pid, err)
	}
	if raw != nil {
		parseStatus(string(raw), p)
	}
	if p.UID != 0 || p.Comm != "" {
		p.User = UserName(p.UID)
	}

	data, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(data), "\x00", " "))
	}

	if exe, err := os.Readlink(filepath.Join(dir, "exe")); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if cwd, err := os.Readlink(filepath.Join(dir, "cwd")); err == nil {
		p.CWD = cwd
	}
	return p, nil
}

func parseStatus(raw string, p *Process) {
	for line := range strings.SplitSeq(raw, "\n") {
		switch {
		case strings.HasPrefix(line, "Name:"):
			p.Comm = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Uid:"):
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				if v, err := strconv.ParseUint(fields[0], 10, 32); err == nil {
					p.UID = uint32(v)
				}
			}
		case strings.HasPrefix(line, "VmRSS:"):
			fields := strings.Fields(strings.TrimPrefix(line, "VmRSS:"))
			if len(fields) >= 1 {
				if v, err := strconv.ParseUint(fields[0], 10, 64); err == nil {
					p.RSSKB = v
				}
			}
		}
	}
}
