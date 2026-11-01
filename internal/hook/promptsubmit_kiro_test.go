package hook

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/guard"
)

// TestHandlePromptSubmitGuarded_KiroCLI pins Kiro CLI's context-only
// userPromptSubmit dialect (gfiD, 2026-10-15): the hook cannot block, an
// exit-0 stdout reaches the MODEL as text, so a finding is one plain-text
// line (never JSON, never a block claim) and an allow is an empty stdout.
func TestHandlePromptSubmitGuarded_KiroCLI(t *testing.T) {
	t.Parallel()
	body := []byte(`{"hook_event_name":"userPromptSubmit","cwd":"/w","session_id":"k1","prompt":"use x"}`)
	warnLine := "observer: pii (forwarded; see `observer guard prompt status`).\n"
	for _, tc := range []struct {
		name    string
		verdict guard.PromptVerdict
		want    string
	}{
		{"warn is one plain-text line", warnVerdict("pii"), warnLine},
		{"ask cannot stop the prompt: a model warning", askVerdict("pii"), warnLine},
		{"allow is an empty stdout", allowVerdict(), ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stub := &stubPromptEvaluator{verdict: tc.verdict}
			var out bytes.Buffer
			handled, _, code := HandlePromptSubmitGuarded("kiro-cli", PromptDialectKiroCLI, "userPromptSubmit", body, false, stub, nil, &out, io.Discard)
			if !handled || code != 0 {
				t.Fatalf("handled=%v code=%d (the hook never blocks)", handled, code)
			}
			if out.String() != tc.want {
				t.Fatalf("stdout\n got %q\nwant %q", out.String(), tc.want)
			}
			if strings.HasPrefix(out.String(), "{") {
				t.Fatal("Kiro adds stdout to the model context as text: no JSON")
			}
			if stub.lastEvent.SessionID != "k1" {
				t.Fatalf("session id %q", stub.lastEvent.SessionID)
			}
		})
	}
	var out bytes.Buffer
	HandlePromptAllow(PromptDialectKiroCLI, "kiro-cli:userPromptSubmit", strings.NewReader("{}"), &out, io.Discard)
	if out.Len() != 0 {
		t.Fatalf("kiro allow must be empty, got %q", out.String())
	}
	if CanFailClosed(PromptDialectKiroCLI) {
		t.Fatal("kiro-cli is warn-only (exit 2 does not block): it must stay fail-open")
	}
}
