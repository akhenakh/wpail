//go:build freebsd

package listen

/*
#include <sys/param.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysctl.h>
#include <sys/file.h>
#include <sys/user.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_var.h>
#include <arpa/inet.h>
#include <stddef.h>
#include <string.h>

// fbsd_pcb is the cgo-friendly view of one PCB row: identity, both endpoints,
// and the TCP state. It keeps Go out of the kernel structs' unions.
struct fbsd_pcb {
	uint64_t key;		// kernel struct socket pointer, 0 for orphans
	uint32_t uid;
	uint16_t lport;
	uint16_t fport;
	int is_v6;
	int state;		// TCP FSM state; 0 for UDP
	unsigned char laddr[16];
	unsigned char faddr[16];
};

// Accessors copy out of raw sysctl byte buffers to avoid alignment and union issues.

static size_t fbsd_xfile_size(const void *b) {
	struct xfile xf;
	memcpy(&xf, b, sizeof(xf));
	return xf.xf_size;
}

static int fbsd_xfile_is_socket(const void *b) {
	struct xfile xf;
	memcpy(&xf, b, sizeof(xf));
	return xf.xf_type == DTYPE_SOCKET;
}

static int fbsd_xfile_pid(const void *b) {
	struct xfile xf;
	memcpy(&xf, b, sizeof(xf));
	return (int)xf.xf_pid;
}

static uint64_t fbsd_xfile_data(const void *b) {
	struct xfile xf;
	memcpy(&xf, b, sizeof(xf));
	return (uint64_t)xf.xf_data;
}

static size_t fbsd_xig_len(const void *b) {
	struct xinpgen xig;
	memcpy(&xig, b, sizeof(xig));
	return xig.xig_len;
}

static uint64_t fbsd_xig_gen(const void *b) {
	struct xinpgen xig;
	memcpy(&xig, b, sizeof(xig));
	return (uint64_t)xig.xig_gen;
}

static int fbsd_fill_pcb(const struct xinpcb *xi, uint64_t maxgen, struct fbsd_pcb *out) {
	if ((uint64_t)xi->inp_gencnt > maxgen) {
		return 0;
	}
	uint16_t lport = ntohs(xi->inp_inc.inc_ie.ie_lport);
	if (lport == 0) {
		return 0;
	}
	memset(out, 0, sizeof(*out));
	if ((xi->inp_vflag & INP_IPV6) != 0) {
		out->is_v6 = 1;
		memcpy(out->laddr, &xi->inp_inc.inc_ie.ie6_laddr, 16);
		memcpy(out->faddr, &xi->inp_inc.inc_ie.ie6_faddr, 16);
	} else if ((xi->inp_vflag & INP_IPV4) != 0) {
		memcpy(out->laddr, &xi->inp_inc.inc_ie.ie_laddr, 4);
		memcpy(out->faddr, &xi->inp_inc.inc_ie.ie_faddr, 4);
	} else {
		return 0;
	}
	out->key = (uint64_t)xi->xi_socket.xso_so;
	out->uid = (uint32_t)xi->xi_socket.so_uid;
	out->lport = lport;
	out->fport = ntohs(xi->inp_inc.inc_ie.ie_fport);
	return 1;
}

// Returns 1 if a TCP PCB was extracted, 0 to skip, -1 on struct mismatch.
static int fbsd_tcp_pcb(const void *b, size_t avail, uint64_t maxgen,
	struct fbsd_pcb *out) {
	struct xtcpcb xt;
	if (avail < sizeof(xt)) {
		return -1;
	}
	memcpy(&xt, b, sizeof(xt));
	if (xt.xt_len != sizeof(xt)) {
		return -1;
	}
	if (fbsd_fill_pcb(&xt.xt_inp, maxgen, out) == 0) {
		return 0;
	}
	out->state = (int)xt.t_state;
	return 1;
}

// Returns 1 if a UDP PCB was extracted, 0 to skip, -1 on struct mismatch.
static int fbsd_udp_pcb(const void *b, size_t avail, uint64_t maxgen,
	struct fbsd_pcb *out) {
	struct xinpcb xi;
	if (avail < sizeof(xi)) {
		return -1;
	}
	memcpy(&xi, b, sizeof(xi));
	if (xi.xi_len != sizeof(xi)) {
		return -1;
	}
	return fbsd_fill_pcb(&xi, maxgen, out);
}

static const char *fbsd_tcp_state_name(int state) {
	switch (state) {
	case TCPS_CLOSED:		return "CLOSED";
	case TCPS_LISTEN:		return "LISTEN";
	case TCPS_SYN_SENT:		return "SYN_SENT";
	case TCPS_SYN_RECEIVED:		return "SYN_RECV";
	case TCPS_ESTABLISHED:		return "ESTABLISHED";
	case TCPS_CLOSE_WAIT:		return "CLOSE_WAIT";
	case TCPS_FIN_WAIT_1:		return "FIN_WAIT1";
	case TCPS_CLOSING:		return "CLOSING";
	case TCPS_LAST_ACK:		return "LAST_ACK";
	case TCPS_FIN_WAIT_2:		return "FIN_WAIT2";
	case TCPS_TIME_WAIT:		return "TIME_WAIT";
	default:			return "UNKNOWN";
	}
}

static int fbsd_kinfo_proc(const void *b, size_t avail,
	uint32_t *uid, int *ppid, int64_t *rss_pages, char *comm, size_t commsz) {
	struct kinfo_proc kp;
	if (avail < sizeof(kp)) {
		return -1;
	}
	memcpy(&kp, b, sizeof(kp));
	if (kp.ki_structsize != sizeof(kp)) {
		return -1;
	}
	*uid = (uint32_t)kp.ki_uid;
	*ppid = (int)kp.ki_ppid;
	*rss_pages = (int64_t)kp.ki_rssize;
	size_t n = sizeof(kp.ki_comm);
	if (n > commsz) {
		n = commsz;
	}
	memcpy(comm, kp.ki_comm, n);
	if (commsz > 0) {
		comm[commsz - 1] = '\0';
	}
	return 0;
}

// KERN_PROC_CWD returns a packed struct kinfo_file whose kf_path holds the cwd.
static int fbsd_proc_cwd(int pid, char *out, size_t outsz) {
	int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_CWD, pid };
	struct kinfo_file kif;
	size_t len = sizeof(kif);
	if (sysctl(mib, 4, &kif, &len, NULL, 0) != 0) {
		return -1;
	}
	size_t off = offsetof(struct kinfo_file, kf_path);
	if (len <= off || outsz == 0) {
		return -1;
	}
	size_t avail = len - off;
	if (avail > sizeof(kif.kf_path)) {
		avail = sizeof(kif.kf_path);
	}
	size_t slen = strnlen(kif.kf_path, avail);
	if (slen == 0) {
		return -1;
	}
	if (slen >= outsz) {
		slen = outsz - 1;
	}
	memcpy(out, kif.kf_path, slen);
	out[slen] = '\0';
	return (int)slen;
}
*/
import "C"

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

var (
	sizeofXfile     = int(unsafe.Sizeof(C.struct_xfile{}))
	sizeofXinpgen   = int(unsafe.Sizeof(C.struct_xinpgen{}))
	sizeofKinfoProc = int(unsafe.Sizeof(C.struct_kinfo_proc{}))
)

// Scan snapshots the system's listening sockets on FreeBSD by reading the
// kernel PCB lists and matching socket pointers against kern.file.
func Scan() (*Snapshot, error) { return scanSysctl() }

func scanSysctl() (*Snapshot, error) {
	bySocket, err := socketOwners()
	if err != nil {
		return nil, err
	}
	tcpSocks, err := readPCBList("net.inet.tcp.pcblist", true)
	if err != nil {
		return nil, err
	}
	udpSocks, err := readPCBList("net.inet.udp.pcblist", false)
	if err != nil {
		return nil, err
	}

	all := make([]socketInfo, 0, len(tcpSocks)+len(udpSocks))
	all = append(all, tcpSocks...)
	all = append(all, udpSocks...)

	// Only listening sockets make up the port table; every PCB still feeds
	// session pairing so local clients can be named.
	sockets := make([]Socket, 0, len(all))
	ownerOf := make(map[uint64]int, len(bySocket))
	for key, pids := range bySocket {
		if len(pids) > 0 {
			ownerOf[key] = slices.Min(pids)
		}
	}
	for _, si := range all {
		if si.isListener() {
			sockets = append(sockets, si.Socket)
		}
	}

	owners := make(map[int][]Socket)
	for _, sk := range sockets {
		for _, pid := range bySocket[sk.Key] {
			owners[pid] = append(owners[pid], sk)
		}
	}
	for pid := range owners {
		sortSockets(owners[pid])
	}
	return newSnapshot(sockets, buildConnections(all, ownerOf), owners, Detail), nil
}

// sysctlRawRetry reads a variable-length sysctl, retrying if the table grows
// between the size query and the read.
func sysctlRawRetry(name string) ([]byte, error) {
	for range 5 {
		raw, err := unix.SysctlRaw(name)
		if errors.Is(err, unix.ENOMEM) {
			continue
		}
		return raw, err
	}
	return unix.SysctlRaw(name)
}

// socketOwners maps each kernel struct socket pointer to the PIDs holding it open.
func socketOwners() (map[uint64][]int, error) {
	raw, err := sysctlRawRetry("kern.file")
	if err != nil {
		return nil, fmt.Errorf("reading kern.file: %w", err)
	}
	bySocket := make(map[uint64][]int)
	for off := 0; off+sizeofXfile <= len(raw); off += sizeofXfile {
		base := unsafe.Pointer(&raw[off])
		if int(C.fbsd_xfile_size(base)) != sizeofXfile {
			return nil, errors.New("kern.file: struct xfile size mismatch")
		}
		if C.fbsd_xfile_is_socket(base) == 0 {
			continue
		}
		pid := int(C.fbsd_xfile_pid(base))
		key := uint64(C.fbsd_xfile_data(base))
		if pid <= 0 || key == 0 {
			continue
		}
		if !slices.Contains(bySocket[key], pid) {
			bySocket[key] = append(bySocket[key], pid)
		}
	}
	return bySocket, nil
}

func readPCBList(mibName string, isTCP bool) ([]socketInfo, error) {
	var (
		raw     []byte
		headLen int
		tailOff int
		headGen uint64
	)
	for attempt := range 5 {
		b, err := sysctlRawRetry(mibName)
		if errors.Is(err, unix.ENOENT) {
			return nil, nil
		}
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", mibName, err)
		}
		if len(b) < 2*sizeofXinpgen {
			return nil, nil
		}
		tOff := len(b) - sizeofXinpgen
		hLen := int(C.fbsd_xig_len(unsafe.Pointer(&b[0])))
		tLen := int(C.fbsd_xig_len(unsafe.Pointer(&b[tOff])))
		if hLen != sizeofXinpgen || tLen != sizeofXinpgen {
			return nil, fmt.Errorf("%s: struct xinpgen size mismatch", mibName)
		}
		hGen := uint64(C.fbsd_xig_gen(unsafe.Pointer(&b[0])))
		tGen := uint64(C.fbsd_xig_gen(unsafe.Pointer(&b[tOff])))

		raw, headLen, tailOff, headGen = b, hLen, tOff, hGen
		if hGen == tGen || attempt == 4 {
			break
		}
	}

	var pc C.struct_fbsd_pcb
	out := make([]socketInfo, 0, 32)
	for off := headLen; off+sizeofXinpgen <= tailOff; {
		base := unsafe.Pointer(&raw[off])
		step := int(C.fbsd_xig_len(base))
		if step <= sizeofXinpgen || off+step > tailOff {
			break
		}
		var rc C.int
		if isTCP {
			rc = C.fbsd_tcp_pcb(base, C.size_t(tailOff-off), C.uint64_t(headGen), &pc)
		} else {
			rc = C.fbsd_udp_pcb(base, C.size_t(tailOff-off), C.uint64_t(headGen), &pc)
		}
		if rc < 0 {
			return nil, fmt.Errorf("%s: pcb struct size mismatch", mibName)
		}
		if rc > 0 {
			proto, addrLen := pcbProto(isTCP, pc.is_v6 != 0)
			state := "UNCONN"
			switch {
			case isTCP:
				state = C.GoString(C.fbsd_tcp_state_name(pc.state))
			case pc.fport != 0:
				state = "ESTABLISHED"
			}
			out = append(out, socketInfo{
				Proto:      proto,
				Local:      net.IP(C.GoBytes(unsafe.Pointer(&pc.laddr[0]), C.int(addrLen))),
				Port:       uint16(pc.lport),
				Key:        uint64(pc.key),
				UID:        uint32(pc.uid),
				Family:     strings.TrimSuffix(proto, "6"),
				State:      state,
				Remote:     net.IP(C.GoBytes(unsafe.Pointer(&pc.faddr[0]), C.int(addrLen))),
				RemotePort: uint16(pc.fport),
			})
		}
		off += step
	}
	return out, nil
}

func pcbProto(isTCP, isV6 bool) (proto string, addrLen int) {
	switch {
	case isTCP && isV6:
		return "tcp6", 16
	case isTCP:
		return "tcp", 4
	case isV6:
		return "udp6", 16
	default:
		return "udp", 4
	}
}

// Detail loads information about a live process on FreeBSD via kern.proc.* sysctls.
func Detail(pid int) (*Process, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("process %d: %w", pid, os.ErrProcessDone)
	}
	raw, err := unix.SysctlRaw("kern.proc.pid", pid)
	if err != nil || len(raw) < sizeofKinfoProc {
		return nil, fmt.Errorf("process %d: %w", pid, os.ErrProcessDone)
	}

	var (
		uid      C.uint32_t
		ppid     C.int
		rssPages C.int64_t
		commBuf  [32]byte
	)
	if C.fbsd_kinfo_proc(unsafe.Pointer(&raw[0]), C.size_t(len(raw)),
		&uid, &ppid, &rssPages, (*C.char)(unsafe.Pointer(&commBuf[0])), C.size_t(len(commBuf))) != 0 {
		return nil, fmt.Errorf("process %d: struct kinfo_proc size mismatch", pid)
	}

	p := &Process{
		PID:  pid,
		PPID: max(int(ppid), 0),
		UID:  uint32(uid),
		User: UserName(uint32(uid)),
		Comm: parseNullString(commBuf[:]),
	}
	if rssPages > 0 {
		p.RSSKB = uint64(rssPages) * uint64(os.Getpagesize()) / 1024
	}
	if exeRaw, err := unix.SysctlRaw("kern.proc.pathname", pid); err == nil {
		p.Exe = parseNullString(exeRaw)
	}
	if argsRaw, err := unix.SysctlRaw("kern.proc.args", pid); err == nil {
		p.Cmdline = strings.Join(parseNullArgs(argsRaw), " ")
	}
	cwdBuf := make([]byte, C.PATH_MAX)
	if n := C.fbsd_proc_cwd(C.int(pid), (*C.char)(unsafe.Pointer(&cwdBuf[0])), C.size_t(len(cwdBuf))); n > 0 {
		p.CWD = string(cwdBuf[:n])
	}
	return p, nil
}

func parseNullString(raw []byte) string {
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	s := string(raw)
	if s == "-" {
		return ""
	}
	return s
}

func parseNullArgs(raw []byte) []string {
	var args []string
	for len(raw) > 0 {
		i := bytes.IndexByte(raw, 0)
		if i < 0 {
			args = append(args, string(raw))
			break
		}
		if i > 0 {
			args = append(args, string(raw[:i]))
		}
		raw = raw[i+1:]
	}
	return args
}
