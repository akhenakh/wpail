//go:build linux || (darwin && arm64)

// Package tui renders the wpail interactive UI on Bubble Tea v2.
package tui

import (
	"fmt"
	"os"
	"strconv"
	"time"

	tea "charm.land/bubbletea/v2"
)

// Item is one row of the listener table: a port plus every protocol and
// process bound to it.
type Item struct {
	Port  uint16
	Proto string // e.g. "tcp+tcp6"
	Addr  string // e.g. "0.0.0.0,[::]"
	PIDs  []int  // sorted ascending; shared ports may have several owners
	Name  string
	User  string
}

// Owner returns the representative PID or 0 when unknown.
func (i Item) Owner() int {
	if len(i.PIDs) > 0 && i.PIDs[0] > 0 {
		return i.PIDs[0]
	}
	return 0
}

// Label renders "name (pid)" suitable for statuses and kill dialogs.
func (i Item) Label() string {
	if o := i.Owner(); o != 0 {
		return i.Name + " (" + strconv.Itoa(o) + ")"
	}
	return i.Name
}

// BoundPort is one socket a process keeps open.
type BoundPort struct {
	Proto string
	Addr  string
	Port  uint16
}

// Detail backs the Enter overlay: everything known about one process.
type Detail struct {
	PID     int
	User    string
	UID     uint32
	Cmdline string
	Exe     string
	Memory  string
	Ports   []BoundPort
	Build   [][2]string // build metadata key/value pairs, render order
	CanKill bool
	Error   string // non-empty when inspection failed
}

// Config wires the UI to the system scanner and executor. All callbacks are
// required; Run reports a configuration panic early otherwise.
type Config struct {
	Port    uint16 // optional port filter applied by the caller
	Refresh time.Duration
	SelfUID uint32 // caller's effective uid, used for CanKill decisions
	Listen  func(port uint16) ([]Item, error)
	Inspect func(pid int) (*Detail, error)
	Signal  func(pid int, sig Signal) error
}

// Run starts the program and blocks until the user quits.
// It returns a process exit code.
func Run(cfg Config) int {
	if cfg.Refresh <= 0 {
		cfg.Refresh = defaultRefresh
	}
	p := tea.NewProgram(newModel(cfg))
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "wpail:", err)
		return exitErr
	}
	return 0
}
