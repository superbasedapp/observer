package proxy

import (
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// TestResolveAPITurnSessionIDRelayRun (live run 2, finding N5: relayed
// api_turns rows from a hosted sandbox box had session_id NULL): a request
// the home side of a hosted run's relay names the run on lands on the run's
// re-keyed session (the box's session re-keyed like its pulled transcripts,
// or the run's own key when it names none), an id that is not run-shaped is
// ignored, and the header never reaches the upstream.
func TestResolveAPITurnSessionIDRelayRun(t *testing.T) {
	p, err := New(Options{
		AnthropicUpstream: "http://127.0.0.1:1",
		OpenAIUpstream:    "http://127.0.0.1:1",
		ChatGPTUpstream:   "http://127.0.0.1:1",
		Sink:              &fakeSink{},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range []struct {
		name    string
		headers map[string]string
		want    string
	}{
		{"named session re-keyed", map[string]string{sandboxvocab.RelayRunHeader: "run-7", "X-Session-Id": "abc"}, "rsbx-run-7-abc"},
		{"no session: the run's own key", map[string]string{sandboxvocab.RelayRunHeader: "run-7"}, "rsbx-run-7"},
		{"not run-shaped: ignored", map[string]string{sandboxvocab.RelayRunHeader: "run 7/../x", "X-Session-Id": "abc"}, "abc"},
		{"no header: unchanged", map[string]string{"X-Session-Id": "abc"}, "abc"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, "http://test/v1/messages", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			if got := p.resolveAPITurnSessionID(req, models.ProviderAnthropic, []byte(`{}`)); got != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
	src := http.Header{}
	src.Set(sandboxvocab.RelayRunHeader, "run-7")
	src.Set("Anthropic-Version", "2023-06-01")
	dst := http.Header{}
	p.copyRequestHeaders(dst, src)
	if dst.Get(sandboxvocab.RelayRunHeader) != "" || dst.Get("Anthropic-Version") == "" {
		t.Errorf("upstream headers %v", dst)
	}
}
