//go:build linux

// Package listen discovers which processes are listening on TCP/UDP ports by
// reading procfs directly, without shelling out to lsof or ss.
package listen

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Socket is one listening entry reported by /proc/net/{tcp,tcp6,udp,udp6}.
type Socket struct {
	Proto string // tcp, tcp6, udp, udp6
	Local net.IP
	Port  uint16
	Inode uint64
	UID   uint32
}

// String renders the socket as proto://ip:port, bracketing IPv6 addresses.
func (s Socket) String() string {
	return fmt.Sprintf("%s://%s:%d", s.Proto, FormatIP(s.Local), s.Port)
}

// FormatIP renders ip for display, wrapping IPv6 addresses in brackets.
func FormatIP(ip net.IP) string {
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return "[" + ip.String() + "]"
}

type netTable struct {
	file       string
	proto      string
	listenOnly bool // TCP keeps state == LISTEN; UDP has no listen state.
}

var netTables = []netTable{
	{"tcp", "tcp", true},
	{"tcp6", "tcp6", true},
	{"udp", "udp", false},
	{"udp6", "udp6", false},
}

const listenStateHex = "0A"

func readSockets(root string) ([]Socket, error) {
	var out []Socket
	for _, t := range netTables {
		path := filepath.Join(root, "net", t.file)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		socks, err := parseTable(f, t.proto, t.listenOnly)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, fmt.Errorf("closing %s: %w", path, closeErr)
		}
		out = append(out, socks...)
	}
	return out, nil
}

func parseTable(r io.Reader, proto string, listenOnly bool) ([]Socket, error) {
	out := make([]Socket, 0, 16)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024)
	first := true
	for sc.Scan() {
		line := sc.Text()
		if first {
			first = false // header line
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		if listenOnly && fields[3] != listenStateHex {
			continue
		}
		ipHex, portHex, ok := strings.Cut(fields[1], ":")
		if !ok {
			continue
		}
		port, err := strconv.ParseUint(portHex, 16, 16)
		if err != nil {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil || inode == 0 {
			continue
		}
		out = append(out, Socket{
			Proto: proto,
			Local: hexIP(ipHex),
			Port:  uint16(port),
			Inode: inode,
			UID:   uint32(uid),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parsing %s table: %w", proto, err)
	}
	return out, nil
}

// hexIP decodes a procfs hex address. The kernel prints IP addresses as an
// array of uint32 words in host (little-endian) byte order, so every group of
// eight hex chars decodes into four bytes via LittleEndian.
func hexIP(s string) net.IP {
	b := make([]byte, len(s)/2)
	for i := 0; i+8 <= len(s); i += 8 {
		w, err := strconv.ParseUint(s[i:i+8], 16, 32)
		if err != nil {
			return net.IP(b[:len(s)/2])
		}
		binary.LittleEndian.PutUint32(b[i/2:], uint32(w))
	}
	return net.IP(b[:len(s)/2])
}
