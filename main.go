//go:build linux || (darwin && arm64)

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

	"github.com/akhenakh/wpail/bininfo"
	"github.com/akhenakh/wpail/listen"
	"github.com/akhenakh/wpail/tui"
)

const usageText = `wpail finds what application is listening on a TCP/UDP port.

usage:
  wpail                  interactive TUI over all listening ports
  wpail -t [PORT]        same TUI, optionally filtered to PORT
  wpail [-u] PORT        print PID(s) listening on PORT (-u adds the owner column)
  wpail -v PORT          verbose: PID, owner, build metadata per listener

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
	verboseFlag := fs.Bool("v", false, "report build metadata (module, toolchain, VCS) per PID")
	fs.Usage = func() {
		fmt.Fprint(os.Stderr, usageText)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}

	switch {
	case *tuiFlag && *userFlag, *tuiFlag && *verboseFlag:
		fmt.Fprintln(os.Stderr, "wpail: -t cannot be combined with -u or -v")
		fs.Usage()
		return 2
	case *userFlag && *verboseFlag:
		fmt.Fprintln(os.Stderr, "wpail: -u and -v are mutually exclusive")
		fs.Usage()
		return 2
	case *tuiFlag, fs.NArg() == 0 && !*userFlag && !*verboseFlag:
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
		switch {
		case *verboseFlag:
			return runCLI(port, verbose)
		case *userFlag:
			return runCLI(port, users)
		default:
			return runCLI(port, pidsOnly)
		}
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

// cliMode selects the PID report layout.
type cliMode int

const (
	pidsOnly cliMode = iota
	users
	verbose
)

func runCLI(port uint16, mode cliMode) int {
	snap, err := listen.Scan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wpail: %v\n", err)
		return 1
	}
	return renderCLI(os.Stdout, os.Stderr, snap, port, mode)
}

func renderCLI(out, errW io.Writer, snap *listen.Snapshot, port uint16, mode cliMode) int {
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
	var err error
	switch mode {
	case pidsOnly:
		err = printPIDs(out, pids)
	case users:
		err = printUsers(out, pids)
	case verbose:
		err = printVerbose(out, pids)
	}
	if err != nil {
		warnf(errW, "wpail: writing output: %v\n", err)
		return 1
	}
	if n := snap.Unresolved(port); n > 0 {
		warnf(errW,
			"wpail: %d additional socket(s) on this port belong to another user — rerun as root\n", n)
	}
	return 0
}

func printPIDs(w io.Writer, pids []int) error {
	for _, pid := range pids {
		if _, err := fmt.Fprintln(w, pid); err != nil {
			return err
		}
	}
	return nil
}

// binCache memoizes binary metadata per executable path so periodic
// rescans do not re-read binaries. Entries live for the session; temp
// build dirs are unique per run, so stale entries are harmless and the
// map is reset when it grows past a sane bound.
type binCache struct {
	mu sync.Mutex
	m  map[string]*bininfo.Info
}

func newBinCache() *binCache { return &binCache{m: map[string]*bininfo.Info{}} }

func (c *binCache) probe(p *listen.Process) *bininfo.Info {
	key := p.Exe
	if key == "" {
		key = strconv.Itoa(p.PID)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if info, ok := c.m[key]; ok {
		return info
	}
	info := bininfo.Analyze(p.Exe, p.PID, p.CWD)
	if len(c.m) >= 1024 {
		c.m = map[string]*bininfo.Info{}
	}
	c.m[key] = info
	return info
}

// maxDevLabelLen caps the module path shown in list-view labels; longer
// paths fall back to the short project name so rows stay readable.
const maxDevLabelLen = 32

// devLabel renders a developer build as "<name> (<kind>)" so a
// /tmp/go-build…/exe/main row reads like "github.com/you/myproj (go run)".
// The full module path is preferred when it fits; longer ones (and
// languages without one) use the short project name.
func devLabel(bi *bininfo.Info) string {
	name := bi.Project
	if bi.Module != "" && len(bi.Module) <= maxDevLabelLen {
		name = bi.Module
	}
	if bi.Kind != "" {
		name += " (" + bi.Kind + ")"
	}
	return name
}

// relabelRow replaces cryptic temp-path process names with dev labels:
// /tmp/go-build123/b001/exe/main becomes "myproj (go run)". Processes we
// cannot inspect keep the scan-resolved name.
func relabelRow(r *listen.Row, detail func(int) (*listen.Process, error), cache *binCache) {
	for j, pid := range r.PIDs {
		proc, err := detail(pid)
		if err != nil {
			continue
		}
		if bi := cache.probe(proc); bi.Dev {
			r.Names[j] = devLabel(bi)
		}
	}
}

// maxAncestry bounds the parent walk; real chains are shallow, the cap is
// a defensive guard against corrupt PPid data.
const maxAncestry = 16

// ancestry walks the parent chain of self up to init, ordered root first
// (nearest parent last). Unreadable ancestors terminate the walk with a
// placeholder entry; cycles are detected and stopped.
func ancestry(self *listen.Process, detail func(int) (*listen.Process, error)) []tui.ProcRef {
	var chain []tui.ProcRef
	seen := map[int]bool{self.PID: true}
	for ppid, depth := self.PPID, 0; ppid > 0 && depth < maxAncestry; depth++ {
		if seen[ppid] {
			break
		}
		p, err := detail(ppid)
		if err != nil {
			chain = append(chain, tui.ProcRef{PID: ppid, Name: "unknown"})
			break
		}
		seen[ppid] = true
		chain = append(chain, tui.ProcRef{PID: ppid, Name: procLabel(p)})
		ppid = p.PPID
	}
	slices.Reverse(chain)
	return chain
}

// procLabel renders a short process name for the ancestry tree: the first
// command line words ("go run"), falling back to the kernel comm name.
func procLabel(p *listen.Process) string {
	fields := strings.Fields(p.Name())
	switch {
	case len(fields) >= 2:
		return filepath.Base(fields[0]) + " " + fields[1]
	case len(fields) == 1:
		return filepath.Base(fields[0])
	default:
		return p.Comm
	}
}

// warnf writes a diagnostic to errW. Write failures are deliberately
// discarded: there is nowhere left to report problems with stderr itself.
func warnf(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, format, args...)
}

// printVerbose reports one aligned row per PID: owner, dev-build kind,
// project, toolchain runtime, VCS state and project directory when known.
// Processes we cannot inspect render as "?" columns.
func printVerbose(w io.Writer, pids []int) error {
	headers := []string{"PID", "USER", "BUILD", "PROJECT", "RUNTIME", "VCS", "DIR"}
	rows := make([][]string, len(pids))
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}
	for i, pid := range pids {
		uid, user, exe, cwd := "?", "?", "", ""
		if proc, err := listen.Detail(pid); err == nil {
			uid, user = strconv.Itoa(pid), proc.User
			exe, cwd = proc.Exe, proc.CWD
		}
		bi := bininfo.Analyze(exe, pid, cwd)
		row := []string{
			uid,
			user,
			firstNonEmpty([]string{bi.Kind, bi.Lang, "-"}, "-"),
			firstNonEmpty([]string{bi.Project, "-"}, "-"),
			firstNonEmpty([]string{bi.Runtime, "-"}, "-"),
			vcsShort(bi),
			firstNonEmpty([]string{bi.Dir, "-"}, "-"),
		}
		rows[i] = row
		for c, v := range row {
			widths[c] = max(widths[c], len([]rune(v)))
		}
	}
	hcells := make([]string, len(headers))
	for i, h := range headers {
		hcells[i] = pad(h, widths[i])
	}
	if _, err := fmt.Fprintln(w, strings.Join(hcells, "  ")); err != nil {
		return err
	}
	for _, row := range rows {
		cells := make([]string, len(row))
		for i, v := range row {
			cells[i] = pad(v, widths[i])
		}
		if _, err := fmt.Fprintln(w, strings.Join(cells, "  ")); err != nil {
			return err
		}
	}
	return nil
}

// buildRows turns binary metadata into the detail view's key/value block.
func buildRows(bi *bininfo.Info) [][2]string {
	var rows [][2]string
	add := func(k, v string) {
		if v != "" {
			rows = append(rows, [2]string{k, v})
		}
	}
	if bi.Kind != "" {
		add("Artifact", bi.Kind)
	}
	add("Language", bi.Lang)
	add("Runtime", bi.Runtime)
	add("Module", bi.Module)
	add("Version", bi.Version)
	add("Project", bi.Project)
	add("Dir", bi.Dir)
	if bi.VCSRev != "" {
		add("VCS", vcsShort(bi))
	}
	return rows
}

// vcsShort renders "branch rev-short" with "*" marking a dirty tree.
func vcsShort(bi *bininfo.Info) string {
	if bi.VCSRev == "" {
		return "-"
	}
	rev := bi.VCSRev
	if len(rev) > 7 {
		rev = rev[:7]
	}
	if bi.VCSDirty {
		rev += "*"
	}
	if bi.VCSBranch != "" {
		return bi.VCSBranch + " " + rev
	}
	return rev
}

// pad right-pads s with spaces to width w (display-width naive, CLI use).
func pad(s string, w int) string {
	if n := w - len([]rune(s)); n > 0 {
		return s + strings.Repeat(" ", n)
	}
	return s
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

// prevRow remembers the dev labels resolved for one port's owner set so
// periodic rescans skip re-reading process details and binaries unless the
// set of listening processes changed (a new app showed up).
type prevRow struct {
	pids  []int
	names []string
}

// startTUI is a var so tests can stub the interactive UI out; running the
// real one inside a test would take over the terminal and hang the run.
var startTUI = func(port uint16) int {
	selfUID := uint32(os.Geteuid())
	cache := newBinCache()

	var mu sync.Mutex
	var lastSnap *listen.Snapshot
	prevRows := map[uint16]prevRow{}

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
			current := make(map[uint16]bool, len(rows))
			for i := range rows {
				current[rows[i].Port] = true
				if prev, ok := prevRows[rows[i].Port]; ok && slices.Equal(prev.pids, rows[i].PIDs) {
					// Same app(s) as the last scan: reuse the already
					// resolved labels instead of reprocessing binaries.
					copy(rows[i].Names, prev.names)
					continue
				}
				relabelRow(&rows[i], listen.Detail, cache)
				if !slices.Contains(rows[i].Names, "?") {
					prevRows[rows[i].Port] = prevRow{
						pids:  slices.Clone(rows[i].PIDs),
						names: slices.Clone(rows[i].Names),
					}
				}
			}
			for port := range prevRows {
				if !current[port] {
					delete(prevRows, port)
				}
			}
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
				Build:   buildRows(cache.probe(proc)),
				Parents: ancestry(proc, listen.Detail),
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
