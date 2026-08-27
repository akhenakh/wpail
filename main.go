//go:build linux

// Command wpail reports which application is listening on a TCP/UDP port.
//
//	wpail PORT           print the PIDs listening on PORT
//	wpail -u PORT        print PID and owning user per line
//	wpail -t [PORT]      open the interactive UI (optionally filtered to PORT)
package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/akhenakh/wpail/listen"
	"github.com/akhenakh/wpail/tui"
)

const usageText = `wpail finds what application is listening on a TCP/UDP port.

usage:
  wpail                  interactive TUI over all listening ports
  wpail -t [PORT]        same TUI, optionally filtered to PORT
  wpail [-u] PORT        print PID(s) listening on PORT (-u adds the owner column)

exit codes:
  0  found / success     1  nothing found or scan error     2  usage error
`

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	fs := flag.NewFlagSet("wpail", flag.ExitOnError)
	tuiFlag := fs.Bool("t", false, "open the interactive terminal UI")
	userFlag := fs.Bool("u", false, "report the owning user next to each PID")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch {
	case *tuiFlag && *userFlag:
		fmt.Fprintln(os.Stderr, "wpail: -u and -t are mutually exclusive")
		fs.Usage()
		return 2
	case *tuiFlag, fs.NArg() == 0 && !*userFlag:
		// -t wins; bare wpail defaults to the interactive UI.
		return tuiMode(fs)
	default:
		if fs.NArg() != 1 {
			fs.Usage()
			return 2
		}
		port, err := parsePort(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "wpail: %v\n", err)
			fs.Usage()
			return 2
		}
		return runCLI(port, *userFlag)
	}
}

// tuiMode parses the optional port argument and launches the TUI.
func tuiMode(fs *flag.FlagSet) int {
	var port uint16
	switch {
	case fs.NArg() == 0:
	case fs.NArg() == 1:
		p, err := parsePort(fs.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "wpail: %v\n", err)
			fs.Usage()
			return 2
		}
		port = p
	default:
		fs.Usage()
		return 2
	}
	return startTUI(port)
}

func parsePort(s string) (uint16, error) {
	v, err := strconv.ParseUint(strings.TrimPrefix(s, ":"), 10, 32)
	switch {
	case err != nil || v < 1 || v > 65535:
		return 0, fmt.Errorf("invalid port %q", s)
	}
	return uint16(v), nil
}

func runCLI(port uint16, showUsers bool) int {
	snap, err := listen.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wpail: %v\n", err)
		return 1
	}
	return renderCLI(os.Stdout, os.Stderr, snap, port, showUsers)
}

func renderCLI(out, errW io.Writer, snap *listen.Snapshot, port uint16, showUsers bool) int {
	pids := snap.PIDs(port)
	if len(pids) == 0 {
		if n := snap.Unresolved(port); n > 0 {
			// The sockets are real, they just are not ours to inspect.
			warnf(errW,
				"wpail: %d listening socket(s) on port %d are owned by another user — rerun as root\n",
				n, port)
		} else {
			warnf(errW, "wpail: nothing is listening on port %d\n", port)
		}
		return 1
	}
	if !showUsers {
		for _, pid := range pids {
			if _, err := fmt.Fprintln(out, pid); err != nil {
				warnf(errW, "wpail: writing output: %v\n", err)
				return 1
			}
		}
	} else if err := printUsers(out, pids); err != nil {
		warnf(errW, "wpail: writing output: %v\n", err)
		return 1
	}
	if n := snap.Unresolved(port); n > 0 {
		warnf(errW,
			"wpail: %d additional socket(s) on this port belong to another user — rerun as root\n", n)
	}
	return 0
}

// warnf writes a diagnostic to errW. Write failures are deliberately
// discarded: there is nowhere left to report problems with stderr itself.
func warnf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

func printUsers(w io.Writer, pids []int) error {
	rows := make([][2]string, len(pids))
	pw, uw := len("PID"), len("USER")
	for i, pid := range pids {
		user := "?"
		if proc, err := listen.Detail(pid); err == nil && proc.User != "" {
			user = proc.User
		}
		name := strconv.Itoa(pid)
		rows[i] = [2]string{name, user}
		pw = max(pw, len(name))
		uw = max(uw, len(user))
	}
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "%*s %*s\n", pw, r[0], uw, r[1]); err != nil {
			return err
		}
	}
	return nil
}

func startTUI(port uint16) int {
	selfUID := uint32(os.Geteuid())

	var mu sync.Mutex
	var lastSnap *listen.Snapshot

	cfg := tui.Config{
		Port:    port,
		Refresh: 2 * time.Second,
		SelfUID: selfUID,

		Listen: func(filter uint16) ([]tui.Item, error) {
			snap, err := listen.Scan()
			if err != nil {
				return nil, err
			}
			mu.Lock()
			lastSnap = snap
			mu.Unlock()
			rows := snap.Rows(filter)
			items := make([]tui.Item, len(rows))
			for i, r := range rows {
				items[i] = tui.Item{
					Port:  r.Port,
					Proto: strings.Join(r.Protos, "+"),
					Addr:  strings.Join(r.Addrs, ", "),
					PIDs:  r.PIDs,
					Name:  firstNonEmpty(r.Names, "?"),
					User:  firstNonEmpty(r.Users, "?"),
				}
			}
			return items, nil
		},

		Inspect: func(pid int) (*tui.Detail, error) {
			proc, err := listen.Detail(pid)
			if err != nil {
				return nil, err
			}
			d := &tui.Detail{
				PID:     pid,
				User:    proc.User,
				UID:     proc.UID,
				Cmdline: proc.Name(),
				Exe:     proc.Exe,
				Memory:  proc.Memory(),
				CanKill: selfUID == 0 || selfUID == proc.UID,
			}
			snap := func() *listen.Snapshot {
				mu.Lock()
				defer mu.Unlock()
				return lastSnap
			}()
			socks := []listen.Socket{}
			switch {
			case snap != nil:
				socks = snap.Owned(pid)
			default:
				if fresh, ferr := listen.Scan(); ferr == nil {
					socks = fresh.Owned(pid)
				}
			}
			for _, sk := range socks {
				d.Ports = append(d.Ports, tui.BoundPort{
					Proto: sk.Proto,
					Addr:  listen.FormatIP(sk.Local),
					Port:  sk.Port,
				})
			}
			sortPorts(d.Ports)
			return d, nil
		},

		Signal: func(pid int, sig syscall.Signal) error {
			proc, err := listen.Detail(pid)
			if err != nil {
				return fmt.Errorf("process %d already exited", pid)
			}
			if proc.UID != selfUID && selfUID != 0 {
				return fmt.Errorf(
					"not permitted: %s (%d) runs as %s — you are not the owner (try sudo)",
					shortLabel(proc), pid, proc.User)
			}
			if err := syscall.Kill(pid, sig); err != nil {
				switch {
				case errors.Is(err, os.ErrPermission):
					return fmt.Errorf(
						"not permitted: %s (%d) runs as %s — you are not the owner (try sudo)",
						shortLabel(proc), pid, proc.User)
				case errors.Is(err, syscall.ESRCH):
					return fmt.Errorf("process %d already exited", pid)
				default:
					return fmt.Errorf("sending signal to pid %d: %w", pid, err)
				}
			}
			return nil
		},
	}
	return tui.Run(cfg)
}

func sortPorts(ports []tui.BoundPort) {
	slices.SortFunc(ports, func(a, b tui.BoundPort) int {
		if c := cmp.Compare(a.Port, b.Port); c != 0 {
			return c
		}
		return strings.Compare(a.Proto, b.Proto)
	})
}

func firstNonEmpty(ss []string, def string) string {
	for _, s := range ss {
		if s != "" && s != "?" {
			return s
		}
	}
	return def
}

// shortLabel renders the process for status messages: bare command name.
func shortLabel(p *listen.Process) string {
	fields := strings.Fields(p.Name())
	name := p.Comm
	if len(fields) > 0 {
		name = filepath.Base(fields[0])
	}
	return name
}
