package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
)

// TestPrintProbeNeverWritesControlCharacters pins that the connect/test
// output, whose account id and display come from a vendor response, never
// writes a control or bidi character to the terminal.
func TestPrintProbeNeverWritesControlCharacters(t *testing.T) {
	rlo := string(rune(0x202e)) // RIGHT-TO-LEFT OVERRIDE, a bidi control
	var b bytes.Buffer
	printProbe(&b, cloudagentssvc.ProbeResult{
		Connector: "cursor-cloud", OK: true,
		AccountID: "user:42\x1b[2J",
		Display:   "dev\x1b]0;pwned\x07@corp.example" + rlo,
	})
	out := b.String()
	for _, bad := range []string{"\x1b", "\x07", rlo} {
		if strings.Contains(out, bad) {
			t.Fatalf("printProbe wrote %q: %q", bad, out)
		}
	}
	if !strings.Contains(out, "reachable as dev?]0;pwned?@corp.example? (user:42?[2J)") {
		t.Fatalf("unexpected output %q", out)
	}
}
