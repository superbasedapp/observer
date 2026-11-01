package hook

import (
	"bytes"
	"encoding/json"
	"io"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// seamWriter records whether the allow seam had run when the reply was
// first written: what the host reads must find the marker in place.
type seamWriter struct {
	ran        *bool
	wrote      bool
	ranAtWrite bool
	buf        bytes.Buffer
}

func (w *seamWriter) Write(p []byte) (int, error) {
	if !w.wrote {
		w.wrote, w.ranAtWrite = true, *w.ran
	}
	return w.buf.Write(p)
}

// TestPluginAllowSeamRunsBeforeReply is P-078 ruling 4: the plugin shim's
// allow seam runs before the allow reply (the old call after it raced the
// plugin), and never on a deny.
func TestPluginAllowSeamRunsBeforeReply(t *testing.T) {
	body, _ := json.Marshal(map[string]any{
		"host": "opencode", "event": "tool.execute.before", "session_id": "s1", "cwd": "/w",
		"tool_name": "bash", "tool_input": map[string]any{"command": "git commit -m x"}, "call_id": "c1",
	})
	for _, c := range []struct {
		name string
		ev   stubEvaluator
		want bool
	}{
		{"allow", stubEvaluator{v: verdictWith(policy.DecisionAllow, "")}, true},
		{"deny", stubEvaluator{v: verdictWith(policy.DecisionDeny, "S-791"), worthy: true}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			ran := false
			w := &seamWriter{ran: &ran}
			HandlePluginToolGateAllow("opencode", "tool.execute.before", body, PluginToolGateCaps(false), true, c.ev, nil, nil, func() { ran = true }, w, io.Discard)
			if ran != c.want || w.ranAtWrite != c.want {
				t.Fatalf("seam ran=%v (at reply %v), want %v", ran, w.ranAtWrite, c.want)
			}
		})
	}
}
