package termfilter

import (
	"bytes"
	"testing"
)

// run feeds input split at every position in splits and returns the output.
func run(input string, splits []int) string {
	var s OSC52Stripper
	var out bytes.Buffer
	prev := 0
	for _, at := range append(splits, len(input)) {
		out.Write(s.Write([]byte(input[prev:at])))
		prev = at
	}
	out.Write(s.Flush())
	return out.String()
}

// TestOSC52StrippedWhereverTheReadsSplit (WINFIX4 audit finding 2): an OSC
// 52 set or query is removed whether it arrives in one read or split at any
// byte, with BEL, ST or 8-bit ST, and every other sequence (a title, a
// colour, a CSI) passes byte for byte.
func TestOSC52StrippedWhereverTheReadsSplit(t *testing.T) {
	cases := []struct{ in, want string }{
		{"before\x1b]52;c;aGVsbG8=\x07after", "beforeafter"},
		{"a\x1b]52;c;?\x07b", "ab"},
		{"a\x1b]52;c;aGk=\x1b\\b", "ab"},
		{"a\x1b]52;p;aGk=\x9cb", "ab"},
		{"\x1b]0;title\x07x", "\x1b]0;title\x07x"},
		{"\x1b]520;x\x07", "\x1b]520;x\x07"},
		{"\x1b]5;x\x07", "\x1b]5;x\x07"},
		{"\x1b[31mred\x1b[0m", "\x1b[31mred\x1b[0m"},
		{"\x1b\x1b]52;c;x\x07z", "\x1bz"},
		{"x\x1b]52;c;never ended", "x"},
		{"x\x1b]52;c;abc\x1b[1mbold", "x\x1b[1mbold"},
		{"x\x1b]52;c;abc\x18y", "xy"},
		{"tail\x1b", "tail\x1b"},
		{"tail\x1b]5", "tail\x1b]5"},
	}
	for _, c := range cases {
		if got := run(c.in, nil); got != c.want {
			t.Errorf("one read %q: %q, want %q", c.in, got, c.want)
		}
		for i := 1; i < len(c.in); i++ {
			if got := run(c.in, []int{i}); got != c.want {
				t.Fatalf("split at %d of %q: %q, want %q", i, c.in, got, c.want)
			}
		}
		every := make([]int, 0, len(c.in))
		for i := 1; i < len(c.in); i++ {
			every = append(every, i)
		}
		if got := run(c.in, every); got != c.want {
			t.Errorf("byte by byte %q: %q, want %q", c.in, got, c.want)
		}
	}
}

// TestOSC52StripperPassesPlainBytes: a stream with no ESC comes out
// unchanged and nothing is held.
func TestOSC52StripperPassesPlainBytes(t *testing.T) {
	var s OSC52Stripper
	in := []byte("plain text \xe2\x9d\x9d utf-8 and \x07 bells")
	if got := s.Write(in); !bytes.Equal(got, in) {
		t.Fatalf("%q", got)
	}
	if f := s.Flush(); len(f) != 0 {
		t.Fatalf("held %q", f)
	}
}
