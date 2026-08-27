//go:build darwin && arm64

package listen

import (
	"bytes"
	"encoding/binary"
)

// parseProcArgs decodes a kern.procargs2 blob:
//
//	int32 argc, exec path (NUL terminated), [padding NULs], argv entries
//	(NUL terminated each), then the environment strings.
//
// Only argc argv strings are collected; anything after them is ignored.
func parseProcArgs(buf []byte) (exe string, argv []string) {
	if len(buf) < 4 {
		return "", nil
	}
	n := int(binary.NativeEndian.Uint32(buf[:4]))
	if n <= 0 || n > 4096 {
		return "", nil // no argv recorded or corrupt buffer
	}
	b := buf[4:]

	i := 0
	for i < len(b) && b[i] == 0 { // tolerate alignment padding
		i++
	}
	start := i
	for i < len(b) && b[i] != 0 {
		i++
	}
	exe = string(b[start:i])
	if i >= len(b) {
		return exe, nil
	}
	b = b[i+1:]

	for len(argv) < n && len(b) > 0 {
		j := bytes.IndexByte(b, 0)
		if j < 0 {
			break
		}
		if j > 0 {
			argv = append(argv, string(b[:j]))
		}
		b = b[j+1:]
	}
	return exe, argv
}
