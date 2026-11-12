//go:build linux

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

type netTable struct {
	file  string
	proto string
	tcp   bool
}

var netTables = []netTable{
	{"tcp", "tcp", true},
	{"tcp6", "tcp6", true},
	{"udp", "udp", false},
	{"udp6", "udp6", false},
}

// socketInfo is one row of a /proc/net table: a listening socket, an accepted
// or connected session, or an already-closed socket the kernel still tracks
// (TIME_WAIT entries carry no inode because no process owns them anymore).
type socketInfo struct {
	Socket
	Family     string // tcp or udp, shared by the IPv4 and IPv6 variants
	State      string // ESTABLISHED, LISTEN, TIME_WAIT, …
	Remote     net.IP
	RemotePort uint16
}

// isListener reports whether the socket belongs in the listening table: TCP
// only in LISTEN state, UDP whenever bound (it has no listen state at all).
func (s socketInfo) isListener() bool {
	return s.Family == "udp" || s.State == "LISTEN"
}

// hasPeer reports whether the row describes a session with a remote endpoint.
func (s socketInfo) hasPeer() bool { return s.RemotePort != 0 }

func readSockets(root string) ([]socketInfo, error) {
	var out []socketInfo
	for _, t := range netTables {
		path := filepath.Join(root, "net", t.file)
		f, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", path, err)
		}
		socks, err := parseTable(f, t.proto, t.tcp)
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

// stateName maps the kernel's two-hex-digit socket state onto the name used
// by ss/lsof. TCP and UDP reuse the same numbers with different meanings.
func stateName(tcp bool, hex string) string {
	if !tcp {
		switch hex {
		case "01":
			return "ESTABLISHED"
		case "07":
			return "UNCONN"
		default:
			return "STATE_" + hex
		}
	}
	if name, ok := tcpStateNames[hex]; ok {
		return name
	}
	return "STATE_" + hex
}

var tcpStateNames = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
	"0C": "NEW_SYN_RECV",
}

func parseTable(r io.Reader, proto string, tcp bool) ([]socketInfo, error) {
	family := strings.TrimSuffix(proto, "6")
	out := make([]socketInfo, 0, 16)
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
		local, localPort, ok := parseEndpoint(fields[1])
		if !ok {
			continue
		}
		remote, remotePort, ok := parseEndpoint(fields[2])
		if !ok {
			continue
		}
		uid, err := strconv.ParseUint(fields[7], 10, 32)
		if err != nil {
			continue
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			continue
		}
		if inode == 0 && remotePort == 0 {
			continue // neither an owner nor a peer: nothing to report
		}
		out = append(out, socketInfo{
			Proto:      proto,
			Local:      local,
			Port:       localPort,
			Key:        inode,
			UID:        uint32(uid),
			Family:     family,
			State:      stateName(tcp, fields[3]),
			Remote:     remote,
			RemotePort: remotePort,
		})
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parsing %s table: %w", proto, err)
	}
	return out, nil
}

func parseEndpoint(s string) (net.IP, uint16, bool) {
	ipHex, portHex, ok := strings.Cut(s, ":")
	if !ok {
		return nil, 0, false
	}
	port, err := strconv.ParseUint(portHex, 16, 16)
	if err != nil {
		return nil, 0, false
	}
	return hexIP(ipHex), uint16(port), true
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
