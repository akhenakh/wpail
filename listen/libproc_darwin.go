//go:build darwin && arm64

package listen

/*
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/proc_info.h>
#include <libproc.h>

typedef struct socket_fdinfo sfdi_t;

// Accessors keep Go away from the C structs' unions and nested arrays.

static int lpf_family(const void *b) { return ((const sfdi_t *)b)->psi.soi_family; }
static int lpf_type(const void *b)   { return ((const sfdi_t *)b)->psi.soi_type; }

static uint64_t lpf_pcb(const void *b) { return ((const sfdi_t *)b)->psi.soi_pcb; }

static uint16_t lpf_lport(const void *b) {
	const sfdi_t *s = b;
	switch (s->psi.soi_type) {
	case SOCK_STREAM:
		return ntohs((uint16_t)s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_lport);
	case SOCK_DGRAM:
		return ntohs((uint16_t)s->psi.soi_proto.pri_in.insi_lport);
	default:
		return 0;
	}
}

static int lpf_tcp_state(const void *b) {
	const sfdi_t *s = b;
	if (s->psi.soi_type != SOCK_STREAM) return -1;
	return s->psi.soi_proto.pri_tcp.tcpsi_state;
}

// lpf_laddr copies the local address into out; returns 4, 16 or 0 bytes.
static int lpf_laddr(const void *b, unsigned char out[16]) {
	const sfdi_t *s = b;
	const unsigned char *a;
	switch (s->psi.soi_type) {
	case SOCK_STREAM:
		a = (const unsigned char *)&s->psi.soi_proto.pri_tcp.tcpsi_ini.insi_laddr;
		break;
	case SOCK_DGRAM:
		a = (const unsigned char *)&s->psi.soi_proto.pri_in.insi_laddr;
		break;
	default:
		return 0;
	}
	switch (s->psi.soi_family) {
	case AF_INET:
		memcpy(out, a, 4);
		return 4;
	case AF_INET6:
		memcpy(out, a, 16);
		return 16;
	default:
		return 0;
	}
}

static long long lpf_fds_size(int pid) {
	return (long long)proc_pidinfo(pid, PROC_PIDLISTFDS, 0, NULL, 0);
}
static int lpf_fds(int pid, void *out, size_t bytes) {
	return (int)proc_pidinfo(pid, PROC_PIDLISTFDS, 0, out, bytes);
}
static int lpf_fdinfo(int pid, int fd, void *out, size_t bytes) {
	return (int)proc_pidfdinfo(pid, fd, PROC_PIDFDSOCKETINFO, out, bytes);
}
static int lpf_fd_of(const void *b) { return ((const struct proc_fdinfo *)b)->proc_fd; }
static int lpf_fdtype_of(const void *b) {
	return (int)((const struct proc_fdinfo *)b)->proc_fdtype;
}

static int lpf_allpids(void *out, int bytes) { return proc_listallpids(out, bytes); }

static int lpf_bsdinfo(int pid, void *out, size_t bytes) {
	return (int)proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, out, bytes);
}
static int lpf_taskinfo(int pid, void *out, size_t bytes) {
	return (int)proc_pidinfo(pid, PROC_PIDTASKINFO, 0, out, bytes);
}

static unsigned int lpb_uid(const void *b) { return ((const struct proc_bsdinfo *)b)->pbi_uid; }

// pbi_comm is a fixed MAXCOMLEN array, not always NUL terminated.
static void lpb_comm(const void *b, unsigned char out[16]) {
	memcpy(out, ((const struct proc_bsdinfo *)b)->pbi_comm, 16);
}

static uint64_t lpt_rss(const void *b) { return ((const struct proc_taskinfo *)b)->pti_resident_size; }
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// tcpListenState is the inpcb state reported by proc_pidfdinfo for TCP
// sockets that are accepting connections.
const tcpListenState = int(C.TSI_S_LISTEN)

const socketFdType = int(C.PROX_FDTYPE_SOCKET)

var (
	sizeofSocketFDInfo = unsafe.Sizeof(C.struct_socket_fdinfo{})
	sizeofProcFDInfo   = unsafe.Sizeof(C.struct_proc_fdinfo{})
)

// Scan snapshots the system's listening sockets on macOS by walking every
// accessible process's file descriptors with libproc. Processes running as
// another user are skipped silently, mirroring the unprivileged procfs view
// on Linux; rerunning with sudo reveals them.
func Scan() (*Snapshot, error) { return scanLibproc() }

func scanLibproc() (*Snapshot, error) {
	pids, err := allPIDs()
	if err != nil {
		return nil, err
	}

	var sockets []Socket
	owners := make(map[int][]Socket)
	uids := map[int]uint32{}
	addr := [16]byte{}
	fdinfo := make([]byte, sizeofSocketFDInfo)

	for i := range pids {
		pid := int(pids[i])
		fds := pidFileDescriptors(pid)
		if len(fds) == 0 {
			continue // dead, EPERM, or no fds at all
		}
		for off := 0; off+int(sizeofProcFDInfo) <= len(fds); off += int(sizeofProcFDInfo) {
			entry := unsafe.Pointer(&fds[off])
			fd, fdtype := int(C.lpf_fd_of(entry)), int(C.lpf_fdtype_of(entry))
			if fdtype != socketFdType {
				continue
			}
			sk, ok := socketOfFD(pid, fd, fdinfo, addr[:])
			if !ok {
				continue
			}
			uid, known := uids[pid]
			if !known {
				uid, _, _ = pidBSDInfo(pid)
				uids[pid] = uid
			}
			sk.UID = uid
			sockets = append(sockets, sk)
			owners[pid] = append(owners[pid], sk)
		}
	}
	for pid := range owners {
		sortSockets(owners[pid])
	}
	return newSnapshot(sockets, owners, Detail), nil
}

// allPIDs lists every process on the system via proc_listallpids.
func allPIDs() ([]int32, error) {
	n, err := C.lpf_allpids(nil, 0)
	if err != nil || n <= 0 {
		return nil, fmt.Errorf("enumerating processes: %w", err)
	}
	buf := make([]C.int, n+1)
	r, err := C.lpf_allpids(unsafe.Pointer(&buf[0]), C.int(len(buf)*int(unsafe.Sizeof(buf[0]))))
	if err != nil || r <= 0 {
		return nil, fmt.Errorf("enumerating processes: %w", err)
	}
	out := make([]int32, r)
	for i := range out {
		out[i] = int32(buf[i])
	}
	return out, nil
}

// pidFileDescriptors returns the raw fd table of pid as packed records of
// sizeof(struct proc_fdinfo); empty when the process is gone or its table is
// not readable.
func pidFileDescriptors(pid int) []byte {
	n, err := C.lpf_fds_size(C.int(pid))
	if err != nil || n <= 0 {
		return nil
	}
	buf := make([]byte, int(n)+int(sizeofProcFDInfo)) // one slot of slack
	r, err := C.lpf_fds(C.int(pid), unsafe.Pointer(&buf[0]), C.size_t(len(buf)))
	if err != nil || r <= 0 {
		return nil
	}
	return buf[:r]
}

// socketOfFD resolves one descriptor to a listening Socket entry using the
// caller-provided scratch buffers. TCP keeps only sockets in listen state;
// UDP has no such state and is kept whenever it carries a bound local port,
// matching the procfs table contents on Linux.
func socketOfFD(pid, fd int, info, ip []byte) (Socket, bool) {
	if len(info) != int(sizeofSocketFDInfo) || len(ip) != 16 {
		return Socket{}, false
	}
	base := unsafe.Pointer(&info[0])
	r, err := C.lpf_fdinfo(C.int(pid), C.int(fd), base, C.size_t(len(info)))
	if err != nil || r != C.int(sizeofSocketFDInfo) {
		return Socket{}, false // closed meanwhile or alien descriptor type
	}

	typ := int(C.lpf_type(base))
	var proto string
	switch typ {
	case int(C.SOCK_STREAM):
		switch family := int(C.lpf_family(base)); family {
		case int(C.AF_INET):
			proto = "tcp"
		case int(C.AF_INET6):
			proto = "tcp6"
		default:
			return Socket{}, false
		}
		if int(C.lpf_tcp_state(base)) != tcpListenState {
			return Socket{}, false
		}
	case int(C.SOCK_DGRAM):
		switch family := int(C.lpf_family(base)); family {
		case int(C.AF_INET):
			proto = "udp"
		case int(C.AF_INET6):
			proto = "udp6"
		default:
			return Socket{}, false // unix domain datagrams, netgraph, ...
		}
	default:
		return Socket{}, false
	}

	port := int(C.lpf_lport(base))
	if port == 0 {
		return Socket{}, false // unnamed socket, not a listener
	}
	n := int(C.lpf_laddr(base, (*C.uchar)(unsafe.Pointer(&ip[0]))))
	if n != 4 && n != 16 {
		return Socket{}, false
	}

	return Socket{
		Proto: proto,
		Local: net.IP(append([]byte(nil), ip[:n]...)),
		Port:  uint16(port),
		Key:   uint64(C.lpf_pcb(base)),
	}, true
}

// Detail loads information about a live process through libproc and
// kern.procargs2, mirroring the /proc based Linux backend best effort.
func Detail(pid int) (*Process, error) {
	p := &Process{PID: pid}
	uid, comm, ok := pidBSDInfo(pid)
	if !ok {
		return nil, fmt.Errorf("process %d: %w", pid, os.ErrProcessDone)
	}
	p.UID = uid
	p.User = UserName(uid)
	p.Comm = strings.TrimRight(comm, "\x00")
	exe, argv := procArgs(pid)
	p.Exe, p.Cmdline = exe, strings.Join(argv, " ")

	if raw := taskInfoBytes(pid); raw != nil {
		p.RSSKB = uint64(C.lpt_rss(unsafe.Pointer(&raw[0]))) / 1024
	}
	return p, nil
}

// taskInfoBytes fetches struct proc_taskinfo bytes for pid, nil on failure.
func taskInfoBytes(pid int) []byte {
	raw := make([]byte, unsafe.Sizeof(C.struct_proc_taskinfo{}))
	r, err := C.lpf_taskinfo(C.int(pid), unsafe.Pointer(&raw[0]), C.size_t(len(raw)))
	if err != nil || r <= 0 {
		return nil
	}
	return raw[:r]
}

// pidBSDInfo returns (uid, comm, ok) from PROC_PIDTBSDINFO.
func pidBSDInfo(pid int) (uint32, string, bool) {
	raw := make([]byte, unsafe.Sizeof(C.struct_proc_bsdinfo{}))
	r, err := C.lpf_bsdinfo(C.int(pid), unsafe.Pointer(&raw[0]), C.size_t(len(raw)))
	if err != nil || r != C.int(len(raw)) {
		return 0, "", false
	}
	base := unsafe.Pointer(&raw[0])
	comm := make([]byte, 16)
	C.lpb_comm(base, (*C.uchar)(unsafe.Pointer(&comm[0])))
	return uint32(C.lpb_uid(base)), string(comm), true
}

// procArgs resolves the executable path and argument vector of pid via the
// kern.procargs2 sysctl.
func procArgs(pid int) (string, []string) {
	raw, err := unix.SysctlRaw("kern.procargs2", pid)
	if err != nil {
		return "", nil
	}
	return parseProcArgs(raw)
}
