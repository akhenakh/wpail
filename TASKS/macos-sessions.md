# Handoff: session tracking on macOS (arm64)

## Goal

Port the session/peer tracking already shipped for Linux and FreeBSD to the
macOS `libproc` backend, so these work on Apple Silicon:

- `wpail -c PORT` — active sessions with local/remote endpoints, state and the
  local peer program.
- `CONNS` column in the listener table.
- `Connections` block in the process detail overlay (scrollable).
- `Snapshot.Connections`, `ConnectionsOf`, `SessionsFor` populated on macOS.

Everything above the backend is already platform-neutral. The macOS backend is
the only missing producer of `[]Connection`.

## Current model (landed in `86b4f3a` and `8d757c4`)

Read these first:

- `listen/session.go` — `socketInfo` (embeds `Socket`, adds `Family`, `State`,
  `Remote`, `RemotePort`), `isListener()`, `hasPeer()`.
- `listen/conns.go` — `buildConnections(socks []socketInfo, ownerOf map[uint64]int) []Connection`.
  Matches mirrored 4-tuples, normalizes IPv4-mapped IPv6, falls back to ports
  for wildcard-local UDP, prefers a live mirror over a `TIME_WAIT` row.
- `listen/api.go` — `Connection`, `Snapshot.Connections/ConnectionsOf/
  ConnectionCount/SessionsFor`, `Row.Connections`, `newSnapshot(sockets,
  conns, owners, detail)`.
- `listen/sysctl_freebsd.go` — the reference port; mirror its `scanSysctl`
  shape almost line for line.
- `listen/netinfo.go` — the Linux producer of `socketInfo`.

`SessionsFor(pid)` unions every session attached to the ports `pid` listens on
with the sessions `pid` holds as a client. This matters: accepted sockets can
live in worker PIDs, and some are not attributable to a PID at all while still
belonging to the port.

## What the macOS backend does today

`listen/libproc_darwin.go`:

1. `Scan()` → `scanLibproc()` enumerates all PIDs (`allPIDs`), each PID's fd
   table (`pidFileDescriptors`), and resolves socket fds with `socketOfFD`.
2. The cgo preamble exposes: `lpf_family`, `lpf_type`, `lpf_pcb`
   (`psi.soi_pcb`), `lpf_lport`, `lpf_laddr`, `lpf_tcp_state`
   (`pri_tcp.tcpsi_state`).
3. `socketOfFD` keeps TCP only in `TSI_S_LISTEN`; UDP is kept whenever it has
   a bound local port. It returns `Socket{Proto, Local, Port, Key=soi_pcb}`.
4. `scanLibproc` appends every kept socket to `owners[pid]` and calls
   `newSnapshot(sockets, nil, owners, Detail)`.

`listen/libproc_darwin_test.go` covers the listener-only behaviour with real
sockets.

## Required changes

### 1. Extend the C preamble

Add accessors for the foreign endpoint and TCP state name. Follow the existing
`lpf_laddr`/`lpf_lport` family switch. Expected fields in
`struct in_sockinfo` (verify against the installed SDK's
`<sys/proc_info.h>`; the accessor layer isolates any spelling differences):

- TCP: `psi.soi_proto.pri_tcp.tcpsi_ini.insi_fport` / `insi_faddr`
- UDP: `psi.soi_proto.pri_in.insi_fport` / `insi_faddr`

Ports are network order (`ntohs`). Addresses are network-order bytes; copy 4
bytes for `AF_INET`, 16 for `AF_INET6`, exactly like `lpf_laddr`.

Add `lpf_tcp_state_name(int)` returning the same names used by the other
backends (`ESTABLISHED`, `CLOSE_WAIT`, `TIME_WAIT`, …), switching over the
`TSI_S_*` constants:

```
TSI_S_CLOSED, TSI_S_LISTEN, TSI_S_SYN_SENT, TSI_S_SYN_RECEIVED,
TSI_S_ESTABLISHED, TSI_S_CLOSE_WAIT, TSI_S_FIN_WAIT_1, TSI_S_CLOSING,
TSI_S_LAST_ACK, TSI_S_FIN_WAIT_2, TSI_S_TIME_WAIT
```

Use C constants rather than hardcoded numbers. `fbsd_tcp_state_name` in
`listen/sysctl_freebsd.go` is the template.

**cgo warning:** the preamble is a Go `/* … */` comment. Do not use `/* … */`
comments inside it; any inner `*/` terminates the Go comment and cgo fails.
Use `//` comments only.

### 2. Make `socketOfFD` return full rows

Change it to `(socketInfo, bool)`:

- Remove the `lpf_tcp_state != tcpListenState` filter.
- Keep every TCP state and every bound UDP socket (`port != 0`).
- Populate `Family` (`tcp`/`udp`), `State`, `Remote`, `RemotePort`.
- UDP state: `ESTABLISHED` when `fport != 0`, else `UNCONN`.
- `Key` stays `soi_pcb`; skip sockets with `soi_pcb == 0` (unusable identity).
- Keep the existing `AF_INET`/`AF_INET6` and `SOCK_STREAM`/`SOCK_DGRAM`
  filtering; unix-domain and other families stay out.

### 3. Build the snapshot

In `scanLibproc`, mirror `scanSysctl` (`listen/sysctl_freebsd.go`):

- Collect `all []socketInfo` across all PIDs.
- Build `ownerOf map[uint64]int` (PCB → lowest PID; sockets can be shared by
  fork/dup).
- `sockets` and `owners` must contain listeners only:
  `if si.isListener() { sockets = append(sockets, si.Socket); owners[pid] = append(owners[pid], si.Socket) }`,
  de-duplicating by `Key` per PID (duplicated fds are common).
- Return `newSnapshot(sockets, buildConnections(all, ownerOf), owners, Detail)`.

### 4. Enable the feature flag

- `sessions_supported.go`: build tag `linux || freebsd || darwin`, const
  `connectionsSupported = true`.
- `sessions_other.go`: `!linux && !freebsd && !darwin`.

`main.go` and `tui/` need no changes.

### 5. Tests

Add to `listen/libproc_darwin_test.go` (copy the FreeBSD one from
`listen/sysctl_freebsd_test.go`):

```go
func TestScanFindsOwnSessions(t *testing.T) {
    ln, _ := net.Listen("tcp", "127.0.0.1:0")
    // dial, accept, keep both open
    // Scan(); find Connections(port) with State == "ESTABLISHED",
    // PID == os.Getpid(), PeerPID == os.Getpid(), RemotePort != 0
}
```

Also assert that `Row.Connections` is non-zero while connected, and keep the
existing listener tests green — `PIDs`, `Rows` and `Owned` must still only
contain listeners (TCP LISTEN + bound UDP).

Optional: a `socketOfFD` test on a socket owned by the test process (bind a
TCP socket and pass its fd), checking state/endpoints.

### 6. Verification (on macOS arm64, cgo enabled)

```sh
go vet ./...
golangci-lint run ./...
modernize -diff ./...      # or: go fix -diff ./...
go test -count=1 ./...
CGO_ENABLED=1 go build -trimpath -ldflags "-s -w" -o bin/wpail .
```

Manual checks:

- `nc -l 18099` / a dev server plus a local client, then
  `./bin/wpail -c 18099` — peer name and PID correct.
- TUI: `CONNS` column, Enter shows `Connections`, scrolling with
  `↑/↓`, `pgup/pgdn`, `home/end`, wheel.
- IPv6 listener (`nc -6 -l ::1`) and a v4-mapped case if the host allows
  `net.inet6` dual-stack; the shared matcher normalizes `::ffff:`.
- Unprivileged run sees only readable processes; `sudo` for the full table.

## Acceptance criteria

- `wpail -c PORT` on macOS reports local/remote endpoints, state, and the peer
  program for loopback sessions when the peer's fds are readable.
- `CONNS` and the detail `Connections` block agree with the snapshot, including
  sessions accepted by worker PIDs (`SessionsFor`).
- TCP IPv4, TCP IPv6 and IPv4-mapped matches work; bound UDP stays in the
  listener table; connected UDP peers resolve when their PCB is visible.
- No regressions on Linux/FreeBSD, no new dependencies, `CGO_ENABLED=1`
  remains the only macOS build requirement.
- vet, golangci-lint, modernize and tests pass; existing `errcheck` findings in
  `bininfo` are pre-existing and not part of this task.

## Gotchas

- `PROC_PIDLISTFDS` / `PROC_PIDFDSOCKETINFO` fail with EPERM for other users;
  skip silently.
- `proc_pidfdinfo` can race with `close(2)`; ignore failures.
- Keep `sizeofSocketFDInfo` / `sizeofProcFDInfo` checks.
- `soi_pcb` is the socket identity; without it neither ownership nor mirror
  matching works, so skip zero.
- The macOS backend only builds under `darwin && arm64`; do not widen the
  build tags.
- The task runner (`task check`) covers vet/test/build but not lint/modernize;
  run those explicitly.

## Reference commits

- `86b4f3a listen: track active sessions and local peers per port`
- `8d757c4 freebsd: track sessions and scroll the process detail`
