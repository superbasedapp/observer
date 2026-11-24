package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// pipelineCompressor adapts the real conversation pipeline to the proxy's
// Compressor seam, the way cmd/observer's pipelineAdapter does.
type pipelineCompressor struct {
	p       *conversation.Pipeline
	dropped *int // when set, records the last run's DroppedCount
}

func (c pipelineCompressor) Compress(ctx context.Context, provider string, body []byte) CompressionResult {
	return c.CompressInSession(ctx, provider, body, "")
}

func (c pipelineCompressor) CompressInSession(ctx context.Context, provider string, body []byte, sessionID string) CompressionResult {
	r := c.p.RunInSessionContext(ctx, provider, body, sessionID)
	if c.dropped != nil {
		*c.dropped = r.DroppedCount
	}
	return CompressionResult{
		Body:              r.Body,
		Skipped:           r.Skipped,
		MessagePrefixHash: r.MessagePrefixHash,
		OriginalBytes:     r.OriginalBytes,
		CompressedBytes:   r.CompressedBytes,
		CompressedCount:   r.CompressedCount,
		DroppedCount:      r.DroppedCount,
		MarkerCount:       r.MarkerCount,
	}
}

// Fernet-shaped (urlsafe base64) encrypted_content values as OpenAI returns
// them with include=["reasoning.encrypted_content"]; each carries a run the
// api_key_prefixed scrub row matches (`-ak-`, `Sk_`).
const (
	followUpTok1 = "gAAAAABpQx7Rk3Lw-ak-Zq9VvYb2aXc1Yt0uTsR8pQoNmLkJiHgFeDcBa_ZyXwVuTsRqPoNm=="
	followUpTok2 = "gAAAAABpQx8aZyXwVuTsRqPoNm_Sk_LkJiHgFeDcBa9Zq9VvYb2aXc1Yt0uTsR8pQoNmLk=="
)

// followUpSentinel is the secret the sandbox recheck printed as the last
// line of a tool output; with compression on, the forward scrub must
// redact it.
const followUpSentinel = "sbx-sentinel-0123456789"

var followUpReasoning = []string{
	`{"type":"reasoning","id":"rs_01","summary":[{"type":"summary_text","text":"**Checking the sandbox env** <env> & keys"}],"encrypted_content":"` + followUpTok1 + `"}`,
	`{"type":"reasoning","id":"rs_02","summary":[],"encrypted_content":"` + followUpTok2 + `"}`,
}

// codexFollowUpBody is turn 2 of a Codex session as it reaches the proxy:
// the full history with the prior turn's reasoning items, store=false, and
// a tool output whose LAST line is an env assignment (the sandbox recheck
// printed the run's sentinel key). That last line is what pushed the old
// ScrubForward onto its value-by-value fallback, which scrubbed the
// encrypted_content values out of their key's sight.
func codexFollowUpBody() []byte {
	input := []string{
		`{"type":"message","role":"developer","content":[{"type":"input_text","text":"<permissions instructions>Filesystem sandboxing: workspace-write.</permissions instructions>"}]}`,
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"<environment_context>\n  <cwd>/work/app</cwd>\n  <shell>bash</shell>\n</environment_context>"}]}`,
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"which OpenAI key does this box see?"}]}`,
		followUpReasoning[0],
		`{"type":"function_call","name":"exec_command","arguments":"{\"cmd\":\"env | grep OPENAI\"}","call_id":"call_01"}`,
		`{"type":"function_call_output","call_id":"call_01","output":"Exit code: 0\nWall time: 0.1 seconds\nOutput:\nOPENAI_API_KEY=` + followUpSentinel + `"}`,
		followUpReasoning[1],
		`{"type":"message","role":"assistant","content":[{"type":"output_text","text":"The box only holds the sandbox sentinel key."}]}`,
		`{"type":"message","role":"user","content":[{"type":"input_text","text":"good, now list the workspace"}]}`,
	}
	return []byte(`{"model":"gpt-5.1-codex-mini","instructions":"You are Codex, a coding agent.","input":[` +
		strings.Join(input, ",") +
		`],"tools":[{"type":"function","name":"exec_command","description":"Run a command","parameters":{"type":"object","properties":{"cmd":{"type":"string"}},"required":["cmd"]}}],` +
		`"tool_choice":"auto","parallel_tool_calls":false,"reasoning":{"effort":"low","summary":"auto"},"store":false,"stream":false,` +
		`"include":["reasoning.encrypted_content"],"prompt_cache_key":"0193f0a2-5c3e-7d41-9a7e-2b1c4d5e6f70"}`)
}

// TestProxyForwardsEncryptedReasoningByteExact reproduces lane
// sr-openai-n2 through the proxy's own request path: a Codex follow-up
// turn with prior reasoning items must reach the upstream with every
// reasoning item byte-exact, with conversation compression OFF and ON
// (shipped defaults). Before the fix the ON case forwarded
// `…-[REDACTED:api_key_prefixed]==` inside encrypted_content, and OpenAI
// answered every follow-up with HTTP 400 "encrypted content could not be
// verified".
func TestProxyForwardsEncryptedReasoningByteExact(t *testing.T) {
	var pressureDrops int
	cases := []struct {
		name      string
		comp      Compressor
		wantDrops bool
	}{
		{name: "compression off"},
		{name: "compression on (shipped defaults)", comp: pipelineCompressor{p: conversation.NewPipeline(conversation.PipelineConfig{
			Enabled:       true,
			Mode:          conversation.ModeCacheAware,
			TargetRatio:   0.85,
			PreserveLastN: 5,
			CompressTypes: []string{"json", "logs", "code"},
		}, conversation.DefaultRegistry(), scrub.New())}},
		{name: "compression on (drop pressure)", comp: pipelineCompressor{p: conversation.NewPipeline(conversation.PipelineConfig{
			Enabled:       true,
			Mode:          conversation.ModeToken,
			TargetRatio:   0.2,
			PreserveLastN: 1,
			CompressTypes: []string{"json", "logs", "code"},
		}, conversation.DefaultRegistry(), scrub.New()), dropped: &pressureDrops}, wantDrops: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seen []byte
			oai := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				mu.Lock()
				seen = b
				mu.Unlock()
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","model":"gpt-5.1-codex-mini","output":[],"usage":{"input_tokens":120,"output_tokens":4}}`))
			})
			anth := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("anthropic upstream hit") })
			anthUp, oaiUp := httptest.NewServer(anth), httptest.NewServer(oai)
			defer anthUp.Close()
			defer oaiUp.Close()
			p, err := New(Options{AnthropicUpstream: anthUp.URL, OpenAIUpstream: oaiUp.URL, Sink: &fakeSink{}, Compressor: tc.comp})
			if err != nil {
				t.Fatalf("proxy.New: %v", err)
			}
			srv := httptest.NewServer(p.Handler())
			defer srv.Close()

			body := codexFollowUpBody()
			req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/responses", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer sk-test-not-a-real-key")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d", resp.StatusCode)
			}

			mu.Lock()
			got := seen
			mu.Unlock()
			if !json.Valid(got) {
				t.Fatalf("upstream body is not valid JSON: %s", got)
			}
			for _, item := range followUpReasoning {
				if !bytes.Contains(got, []byte(item)) {
					t.Errorf("reasoning item not forwarded byte-exact:\nwant %s\n got %s", item, got)
				}
			}
			var v struct {
				Input []map[string]any `json:"input"`
			}
			if err := json.Unmarshal(got, &v); err != nil {
				t.Fatalf("decode upstream body: %v", err)
			}
			want := map[string]string{"rs_01": followUpTok1, "rs_02": followUpTok2}
			for _, it := range v.Input {
				if id, _ := it["id"].(string); want[id] != "" {
					if it["encrypted_content"] != want[id] {
						t.Errorf("%s encrypted_content = %v, want %s", id, it["encrypted_content"], want[id])
					}
					delete(want, id)
				}
			}
			if len(want) != 0 {
				t.Errorf("reasoning items missing upstream: %v", want)
			}
			if tc.wantDrops && pressureDrops == 0 {
				t.Errorf("precondition: the drop pass did not fire")
			}
			// With compression on, the pipeline's forward scrub must still
			// have run: keeping the reasoning items byte-exact may not cost
			// the scrub. (With compression off this path forwards the
			// client's body without the pipeline, so there is no scrub to
			// assert.)
			if tc.comp != nil {
				if bytes.Contains(got, []byte(followUpSentinel)) {
					t.Errorf("sentinel secret %q reached the upstream unscrubbed:\n%s", followUpSentinel, got)
				}
				var out string
				found := false
				for _, it := range v.Input {
					if it["call_id"] == "call_01" && it["type"] == "function_call_output" {
						out, _ = it["output"].(string)
						found = true
					}
				}
				// Under drop pressure the output item may be evicted; when
				// it survives (always with shipped defaults) its last line
				// must carry the redaction in place.
				if (found || !tc.wantDrops) && !strings.HasSuffix(out, "OPENAI_API_KEY="+scrub.Redacted) {
					t.Errorf("call_01 output not redacted in place: %q", out)
				}
			}
		})
	}
}
