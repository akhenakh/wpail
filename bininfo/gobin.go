//go:build linux || (darwin && arm64)

package bininfo

import "debug/buildinfo"

// buildinfoRead wraps debug/buildinfo.Read so callers can pass an
// *os.File (e.g. the live /proc/<pid>/exe inode) or any io.ReaderAt.
func buildinfoRead(r interface {
	ReadAt([]byte, int64) (int, error)
}) (*buildinfo.BuildInfo, error) {
	return buildinfo.Read(r)
}
