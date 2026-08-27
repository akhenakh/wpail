//go:build linux

package listen

import (
	"net"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestHexIP(t *testing.T) {
	tests := []struct {
		name string
		hex  string
		want string   // expected FormatIP output
		raw  []string // optional: expected exact 16-byte form as hex pairs
	}{
		{"ipv4 any", "00000000", "0.0.0.0", nil},
		{"ipv4 loopback", "0100007F", "127.0.0.1", nil},
		{"ipv4 broadcast", "FFFFFFFF", "255.255.255.255", nil},
		{"ipv6 any", strings.Repeat("0", 32), "[::]", nil},
		{
			// kernel prints four little-endian words; words 2..3 encode the
			// ::ffff: prefix plus loopback. FormatIP collapses v4-mapped forms
			// for readability, so verify the decoded bytes explicitly here.
			"ipv4-mapped loopback",
			"0000000000000000FFFF00000100007F",
			"127.0.0.1",
			[]string{"00", "00", "00", "00", "00", "00", "00", "00",
				"00", "00", "ff", "ff", "7f", "00", "00", "01"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := hexIP(tt.hex)
			if got := FormatIP(ip); got != tt.want {
				t.Fatalf("FormatIP(hexIP(%q)) = %q, want %q", tt.hex, got, tt.want)
			}
			if len(tt.raw) > 0 {
				got16 := ip.To16()
				want16 := make([]byte, 0, len(tt.raw))
				for _, b := range tt.raw {
					v, err := strconv.ParseUint(b, 16, 8)
					if err != nil {
						t.Fatalf("bad fixture byte %q: %v", b, err)
					}
					want16 = append(want16, byte(v))
				}
				if !slices.Equal(got16, want16) {
					t.Fatalf("decoded bytes = %#x, want %#x", got16, want16)
				}
			}
			if _, err := net.ResolveIPAddr("ip", strings.Trim(tt.want, "[]")); err != nil {
				t.Fatalf("unexpected unparsable result %q: %v", tt.want, err)
			}
		})
	}
}

func TestParseTableTCPKeepsListenersOnly(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 100
   1: 0100007F:1F91 0100007F:1F92 01 00000000:00000000 00:00000000 00000000  1000        0 101
   2: 00000000:2382 00000000:0000 08 00000000:00000000 00:00000000 00000000     0        0 102
   3: garbage line with too few fields
   4: 00000000:0BB8 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 0
`
	got, err := parseTable(strings.NewReader(table), "tcp", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected only the LISTEN row with an inode, got %+v", got)
	}
	s := got[0]
	switch {
	case s.Port != 8080:
		t.Errorf("Port = %d, want 8080", s.Port)
	case s.Key != 100:
		t.Errorf("Key = %d, want 100", s.Key)
	case s.UID != 1000:
		t.Errorf("UID = %d, want 1000", s.UID)
	case s.Proto != "tcp":
		t.Errorf("Proto = %q, want tcp", s.Proto)
	case !s.Local.To4().Equal(net.IPv4zero):
		t.Errorf("Local = %v, want 0.0.0.0", s.Local)
	}
}

func TestParseTableUDPKeepsAllStates(t *testing.T) {
	const table = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000   105        0 300
`
	got, err := parseTable(strings.NewReader(table), "udp", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Proto != "udp" || got[0].Key != 300 || got[0].UID != 105 {
		t.Fatalf("unexpected parse result: %+v (err=%v)", got, err)
	}
}

func TestSocketStringBracketsIPv6(t *testing.T) {
	s := Socket{Proto: "tcp6", Local: hexIP(strings.Repeat("0", 32)), Port: 443}
	if got := s.String(); got != "tcp6://[::]:443" {
		t.Fatalf("String() = %q", got)
	}
	v4 := Socket{Proto: "tcp", Local: hexIP("0100007F"), Port: 80}
	if got := v4.String(); got != "tcp://127.0.0.1:80" {
		t.Fatalf("String() = %q", got)
	}
}
