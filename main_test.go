package main

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestParsePort(t *testing.T) {
	tests := []struct {
		in      string
		want    uint16
		wantErr bool
	}{
		{"6666", 6666, false},
		{":80", 80, false},
		{"1", 1, false},
		{"65535", 65535, false},
		{"0", 0, true},
		{"65536", 0, true},
		{"-5", 0, true},
		{"abc", 0, true},
		{"", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got, err := parsePort(tt.in)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Fatalf("parsePort(%q) = %d, %v; want %d, err=%v",
					tt.in, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestPrintUsersAligned(t *testing.T) {
	self := os.Getpid()
	var buf bytes.Buffer
	if err := printUsers(&buf, []int{self, self}); err != nil {
		t.Fatalf("printUsers: %v", err)
	}
	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected one line per pid, got %q", buf.String())
	}
	for _, ln := range lines {
		fields := strings.Fields(ln)
		if len(fields) != 2 {
			t.Fatalf("want two columns (pid user), got %q", ln)
		}
		if fields[0] != fmt.Sprintf("%d", self) {
			t.Fatalf("wrong pid column: %q", ln)
		}
	}
	if lines[0] != lines[1] {
		t.Errorf("same pid must render identically: %q vs %q", lines[0], lines[1])
	}
}

func TestMutuallyExclusiveFlags(t *testing.T) {
	if code := run([]string{"-t", "-u", "80"}); code != 2 {
		t.Errorf("-t -u combo = %d, want 2", code)
	}
}
