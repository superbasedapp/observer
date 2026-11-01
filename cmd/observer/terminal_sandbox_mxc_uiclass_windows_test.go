//go:build windows && !sbo_omit_terminals_sandbox_mxc && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"
	"testing"
)

// TestMXCUnrecognisedBoxExitsBeforeTheTool (WINFIX4 audit finding 4): a
// process whose environment names a box directory but that does not
// recognise the box (here: no AppContainer token) sets the start refusal
// main exits 125 with before any command runs. Before, it only noted why,
// and only the launcher's launch gate stopped the tool, with exit 1.
func TestMXCUnrecognisedBoxExitsBeforeTheTool(t *testing.T) {
	oldRefusal, oldNote := boxStartRefusal, boxDetectNote
	t.Cleanup(func() { boxStartRefusal, boxDetectNote = oldRefusal, oldNote })
	boxStartRefusal, boxDetectNote = "", ""
	t.Setenv(sandboxInnerLogEnv, "")
	t.Setenv(mxcBoxDirEnv, t.TempDir())
	mxcDetectBox()
	if boxStartRefusal == "" || !strings.Contains(boxStartRefusal, "did not recognise") {
		t.Fatalf("start refusal %q", boxStartRefusal)
	}
	if boxInsideByToken {
		t.Fatal("an unrecognised box was taken as recognised")
	}
}
