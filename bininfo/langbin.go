//go:build linux || (darwin && arm64)

package bininfo

import (
	"debug/elf"
	"io"
)

// commentStrings returns the NUL-separated strings of the ELF ".comment"
// section, nil when the reader is not an ELF image or has no comment
// section (Mach-O binaries have none; Rust detection there falls back to
// path conventions).
func commentStrings(f io.ReaderAt) []string {
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil
	}
	defer ef.Close()
	sec := ef.Section(".comment")
	if sec == nil {
		return nil
	}
	data, err := sec.Data()
	if err != nil {
		return nil
	}
	var out []string
	start := 0
	for i, b := range data {
		if b == 0 {
			if i > start {
				out = append(out, string(data[start:i]))
			}
			start = i + 1
		}
	}
	if start < len(data) {
		out = append(out, string(data[start:]))
	}
	return out
}

// langFromComment matches compiler marks inside a ".comment" dump. Entries
// look like "rustc version 1.95.0 (hash date)" or "zig 0.16.0"; GCC and
// LLVM entries are ignored.
func langFromComment(entries []string) (lang, version string) {
	for _, entry := range entries {
		if m := rustCommentRe.FindStringSubmatch(entry); m != nil {
			return "rust", "rustc " + m[1] + " (" + m[2] + ")"
		}
		if m := zigCommentRe.FindStringSubmatch(entry); m != nil {
			return "zig", "zig " + m[1]
		}
	}
	return "", ""
}
