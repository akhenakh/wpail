package listen

import (
	"net"
	"testing"
)

// TestSessionsForIncludesPortSessions covers servers whose accepted sockets
// live in worker PIDs: the listening process must still see them.
func TestSessionsForIncludesPortSessions(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	listeners := []Socket{{Proto: "tcp", Local: lo, Port: 8080, Key: 100}}
	conns := []Connection{
		{
			Proto: "tcp", State: "ESTABLISHED",
			Local: lo, LocalPort: 8080, Remote: lo, RemotePort: 40000,
			Key: 200, PID: 500,
		},
		{
			Proto: "tcp", State: "ESTABLISHED",
			Local: lo, LocalPort: 40000, Remote: lo, RemotePort: 8080,
			Key: 300, PID: 501,
		},
	}
	snap := newSnapshot(listeners, conns, map[int][]Socket{42: listeners}, nil)

	got := snap.SessionsFor(42)
	if len(got) != 1 || got[0].Key != 200 {
		t.Errorf("SessionsFor(listener) = %+v, want the worker-held session", got)
	}
	if got := snap.SessionsFor(501); len(got) != 1 || got[0].Key != 300 {
		t.Errorf("SessionsFor(client) = %+v, want its own outgoing session", got)
	}
	if got := snap.SessionsFor(999); len(got) != 0 {
		t.Errorf("SessionsFor(unrelated) = %+v, want none", got)
	}
}

func TestSessionsForDeduplicates(t *testing.T) {
	lo := net.IPv4(127, 0, 0, 1)
	listeners := []Socket{{Proto: "tcp", Local: lo, Port: 8080, Key: 100}}
	conns := []Connection{{
		Proto: "tcp", State: "ESTABLISHED",
		Local: lo, LocalPort: 8080, Remote: lo, RemotePort: 40000,
		Key: 200, PID: 42,
	}}
	snap := newSnapshot(listeners, conns, map[int][]Socket{42: listeners}, nil)

	if got := snap.SessionsFor(42); len(got) != 1 {
		t.Errorf("SessionsFor(self) = %+v, want one de-duplicated session", got)
	}
}
