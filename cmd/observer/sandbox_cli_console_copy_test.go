//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"testing/iotest"
)

// TestCopyConsoleOutputStripsOSC52 (WINFIX4 audit finding 2): the CLI host
// console's copy removes an OSC 52 set and query even when every read
// returns one byte, and copies everything unfiltered when not asked.
func TestCopyConsoleOutputStripsOSC52(t *testing.T) {
	in := "before\x1b]52;c;aGVsbG8=\x07mid\x1b]52;c;?\x1b\\after\x1b]0;title\x07"
	var out bytes.Buffer
	seen := 0
	if err := copyConsoleOutput(&out, iotest.OneByteReader(bytes.NewReader([]byte(in))), true, func() { seen++ }); !errors.Is(err, io.EOF) {
		t.Fatalf("copy: %v", err)
	}
	if got, want := out.String(), "beforemidafter\x1b]0;title\x07"; got != want {
		t.Fatalf("stripped: %q, want %q", got, want)
	}
	if seen != len(in) {
		t.Fatalf("seen %d reads, want %d", seen, len(in))
	}
	out.Reset()
	_ = copyConsoleOutput(&out, iotest.HalfReader(bytes.NewReader([]byte(in))), false, func() {})
	if out.String() != in {
		t.Fatalf("an unfiltered copy changed the stream: %q", out.String())
	}
}
