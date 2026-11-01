//go:build !sbo_omit_adapter_cursor

package hook

import (
	"bytes"
	"io"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// TestCursorAllowSeamRunsBeforeReply is decision log P-078 ruling 3 (lane
// SEC-F2B): the Cursor gate's allow seam runs after the decision and before
// the reply, on the before* permission events and on preToolUse, and never
// on a deny.
func TestCursorAllowSeamRunsBeforeReply(t *testing.T) {
	g := conformanceGuard(t, "enforce")
	preTool := []byte(`{"conversation_id":"s","generation_id":"g","hook_event_name":"preToolUse","tool_name":"Shell","tool_input":{"command":"ls"},"workspace_roots":["/r"],"cwd":"/r"}`)
	cases := []struct {
		name, event string
		body        []byte
		want        bool
	}{
		{"before shell allowed", "beforeShellExecution", loadFixture(t, "cursor", "before_shell_benign.json"), true},
		{"before shell denied", "beforeShellExecution", loadFixture(t, "cursor", "before_shell_rmrf.json"), false},
		{"preToolUse allowed", "preToolUse", preTool, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ran := false
			w := &seamWriter{ran: &ran}
			HandleCursorEventGated(c.event, g, nil, nil, func() { ran = true }, &fakeSink{outcomeRows: 1}, scrub.New(),
				bytes.NewReader(c.body), false, w, io.Discard, 0)
			if !w.wrote {
				t.Fatal("no reply written")
			}
			if ran != c.want || w.ranAtWrite != c.want {
				t.Fatalf("seam ran=%v (at reply %v), want %v; reply %s", ran, w.ranAtWrite, c.want, w.buf.String())
			}
		})
	}
}
