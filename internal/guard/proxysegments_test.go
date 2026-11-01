package guard

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/testsupport/latencygate"
)

// TestExtractLatestUserPromptText pins the per-provider latest-user-turn
// extraction (contract §3.2) the prompt-submit intervention PROXY LANE
// depends on: only the LAST role:"user" entry counts, tool_result blocks
// are excluded, and content-parts arrays flatten to plain text.
func TestExtractLatestUserPromptText(t *testing.T) {
	t.Parallel()
	type m = map[string]any

	tests := []struct {
		name     string
		provider string
		body     any
		wantText string
		wantOK   bool
	}{
		{
			name:     "anthropic plain string content",
			provider: models.ProviderAnthropic,
			body: m{"model": "claude-opus-4-8", "messages": []any{
				m{"role": "user", "content": "my key is sk-ant-api03-xxxx"},
			}},
			wantText: "my key is sk-ant-api03-xxxx",
			wantOK:   true,
		},
		{
			name:     "anthropic skips tool_result, keeps only text blocks",
			provider: models.ProviderAnthropic,
			body: m{"model": "claude-opus-4-8", "messages": []any{
				m{"role": "user", "content": "start"},
				m{"role": "assistant", "content": []any{
					m{"type": "tool_use", "id": "tu1", "name": "Bash", "input": m{"command": "cat .env"}},
				}},
				m{"role": "user", "content": []any{
					m{"type": "tool_result", "tool_use_id": "tu1", "content": "AWS_SECRET=deadbeefdeadbeefdeadbeefdeadbeef"},
					m{"type": "text", "text": "here is a card 4242 4242 4242 4242"},
				}},
			}},
			wantText: "here is a card 4242 4242 4242 4242",
			wantOK:   true,
		},
		{
			name:     "anthropic multi-turn — only the LAST user message counts",
			provider: models.ProviderAnthropic,
			body: m{"model": "claude-opus-4-8", "messages": []any{
				m{"role": "user", "content": "first secret sk-ant-api03-OLDOLDOLD"},
				m{"role": "assistant", "content": "ok"},
				m{"role": "user", "content": "second message, no secret here"},
			}},
			wantText: "second message, no secret here",
			wantOK:   true,
		},
		{
			name:     "openai chat completions string content",
			provider: models.ProviderOpenAI,
			body: m{"model": "gpt-5", "messages": []any{
				m{"role": "system", "content": "be terse"},
				m{"role": "user", "content": "ssn 219-09-1234"},
			}},
			wantText: "ssn 219-09-1234",
			wantOK:   true,
		},
		{
			name:     "openai chat completions content-parts array",
			provider: models.ProviderOpenAI,
			body: m{"model": "gpt-5", "messages": []any{
				m{"role": "user", "content": []any{
					m{"type": "text", "text": "part one"},
					m{"type": "text", "text": "part two"},
				}},
			}},
			wantText: "part one\npart two",
			wantOK:   true,
		},
		{
			name:     "openai responses api bare string input",
			provider: models.ProviderOpenAI,
			body:     m{"model": "gpt-5", "input": "the whole prompt as a string"},
			wantText: "the whole prompt as a string",
			wantOK:   true,
		},
		{
			name:     "openai responses api item array — last user item wins",
			provider: models.ProviderOpenAI,
			body: m{"model": "gpt-5", "input": []any{
				m{"type": "message", "role": "user", "content": []any{
					m{"type": "input_text", "text": "first"},
				}},
				m{"type": "message", "role": "assistant", "content": []any{
					m{"type": "output_text", "text": "reply"},
				}},
				m{"type": "message", "role": "user", "content": []any{
					m{"type": "input_text", "text": "second"},
				}},
			}},
			wantText: "second",
			wantOK:   true,
		},
		{
			name:     "gemini generateContent — last user content, model turns excluded",
			provider: models.ProviderGoogle,
			body: m{"contents": []any{
				m{"role": "user", "parts": []any{m{"text": "first turn"}}},
				m{"role": "model", "parts": []any{m{"text": "assistant reply"}}},
				m{"role": "user", "parts": []any{m{"text": "second turn"}, m{"text": "more text"}}},
			}},
			wantText: "second turn\nmore text",
			wantOK:   true,
		},
		{
			// F4 (phase-3b review): generateContent allows a single-turn
			// request to omit `role` entirely — the API defaults it to
			// "user". A role-less entry must not be silently skipped.
			name:     "gemini generateContent — role omitted defaults to user (F4)",
			provider: models.ProviderGoogle,
			body: m{"contents": []any{
				m{"parts": []any{m{"text": "role-less single turn, sk-ant-api03-xxxx"}}},
			}},
			wantText: "role-less single turn, sk-ant-api03-xxxx",
			wantOK:   true,
		},
		{
			// F3 (phase-3b review): a role:"tool" message AFTER the last
			// role:"user" message means this request is mid-tool-loop,
			// re-sending the SAME original prompt — must not re-extract
			// (and re-fire an already-resolved interrupt against) stale
			// text on every subsequent turn of the loop.
			name:     "openai chat completions — mid-tool-loop continuation skipped (F3)",
			provider: models.ProviderOpenAI,
			body: m{"model": "gpt-5", "messages": []any{
				m{"role": "user", "content": "original prompt with sk-ant-api03-xxxx"},
				m{"role": "assistant", "content": nil, "tool_calls": []any{
					m{"id": "call_1", "function": m{"name": "Bash", "arguments": "{}"}},
				}},
				m{"role": "tool", "tool_call_id": "call_1", "content": "tool output"},
			}},
			wantOK: false,
		},
		{
			// F3's Responses-API row: a function_call_output item after
			// the last role:"user" item is the same continuation shape.
			name:     "openai responses api — mid-tool-loop continuation skipped (F3)",
			provider: models.ProviderOpenAI,
			body: m{"model": "gpt-5", "input": []any{
				m{"type": "message", "role": "user", "content": []any{
					m{"type": "input_text", "text": "original prompt with sk-ant-api03-xxxx"},
				}},
				m{"type": "function_call", "call_id": "call_1", "name": "Bash"},
				m{"type": "function_call_output", "call_id": "call_1", "output": "tool output"},
			}},
			wantOK: false,
		},
		{
			name:     "unsupported provider yields ok=false",
			provider: "cohere",
			body:     m{"messages": []any{m{"role": "user", "content": "hi"}}},
			wantOK:   false,
		},
		{
			name:     "no user turn at all",
			provider: models.ProviderAnthropic,
			body:     m{"model": "claude-opus-4-8", "messages": []any{}},
			wantOK:   false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body, err := json.Marshal(tc.body)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			text, ok := extractLatestUserPromptText(tc.provider, body)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (text=%q)", ok, tc.wantOK, text)
			}
			if ok && text != tc.wantText {
				t.Errorf("text = %q, want %q", text, tc.wantText)
			}
		})
	}
}

// TestExtractLatestUserPromptText_MalformedBodyNeverErrors pins the
// "tolerant, never an error" contract every parser in this file shares:
// garbage input yields ok=false, never a panic.
func TestExtractLatestUserPromptText_MalformedBodyNeverErrors(t *testing.T) {
	t.Parallel()
	for _, provider := range []string{models.ProviderAnthropic, models.ProviderOpenAI, models.ProviderGoogle} {
		if _, ok := extractLatestUserPromptText(provider, []byte("not json at all")); ok {
			t.Errorf("provider %s: ok=true for garbage input", provider)
		}
		if _, ok := extractLatestUserPromptText(provider, nil); ok {
			t.Errorf("provider %s: ok=true for nil body", provider)
		}
	}
}

// oneMiBPromptBody builds a ~1 MiB Anthropic Messages body — many
// tool-result round-trips (never scanned by the latest-user-turn
// extractor) followed by a short final user message — the shape
// contract §3's "benchmark on a 1 MiB body" calls for.
func oneMiBPromptBody() []byte {
	type m = map[string]any
	filler := strings.Repeat("ordinary tool output with no secrets in it, just filler text.\n", 800) // ~50KB
	msgs := []any{m{"role": "user", "content": "start"}}
	for i := 0; i < 20; i++ {
		msgs = append(msgs,
			m{"role": "assistant", "content": []any{m{"type": "tool_use", "id": "t", "name": "Bash", "input": m{"command": "go test"}}}},
			m{"role": "user", "content": []any{m{"type": "tool_result", "tool_use_id": "t", "content": filler}}},
		)
	}
	msgs = append(msgs, m{"role": "user", "content": "final short message with a card 4242 4242 4242 4242"})
	body, _ := json.Marshal(m{"model": "claude-opus-4-8", "messages": msgs})
	return body
}

// extractLatencyBudget is the per-call ceiling BenchmarkExtractLatestUserPromptText_1MiB
// and its CI-visible sibling assert — extraction is a bounded prefix of
// the §17.9 whole-request ≤10ms budget (proxyguard_test.go's
// scanProxyRequestBudget), since it is only one part of scanPrompt.
const extractLatencyBudget = 5 * time.Millisecond

// BenchmarkExtractLatestUserPromptText_1MiB measures the extraction
// cost alone (never the detector pass) on a ~1MiB body.
func BenchmarkExtractLatestUserPromptText_1MiB(b *testing.B) {
	body := oneMiBPromptBody()
	b.SetBytes(int64(len(body)))
	start := time.Now()
	for i := 0; i < b.N; i++ {
		extractLatestUserPromptText(models.ProviderAnthropic, body)
	}
	elapsed := time.Since(start)
	if b.N > 0 {
		if perOp := elapsed / time.Duration(b.N); perOp > extractLatencyBudget {
			b.Fatalf("extractLatestUserPromptText: %v/op exceeds the %v budget", perOp, extractLatencyBudget)
		}
	}
}

// extractLatencyTestHeadroom scales extractLatencyBudget up for
// TestExtractLatestUserPromptText_LatencyRegression's own ceiling —
// matching TestScanProxyRequest_LatencyRegression's ratio of its own
// CI-visible ceiling to its underlying budget (scanProxyRequestTestCeiling
// / scanProxyRequestBudget ≈ 6x): a handful of cold iterations with no
// testing.B-style warmup runs meaningfully hotter than the steady-state
// -bench measurement the declared budget was set against.
const extractLatencyTestHeadroom = 6

// TestExtractLatestUserPromptText_LatencyRegression is the CI-visible
// sibling of BenchmarkExtractLatestUserPromptText_1MiB (`go test -race
// ./...` never runs `-bench`, mirroring TestScanProxyRequest_LatencyRegression's
// own rationale). Skipped under -short.
//
// F6 (phase-3b review): the ceiling used to be a hardcoded 50ms with no
// documented relationship to extractLatencyBudget (the actual declared
// 5ms budget the benchmark above enforces) at all — a real regression
// could blow the declared budget 10x over and still pass CI silently.
// Tightened to extractLatencyBudget * extractLatencyTestHeadroom
// (still scaled by raceLatencyMultiplier for headroom under -race) so
// the ceiling is now DERIVED from the declared budget instead of a
// disconnected magic number.
func TestExtractLatestUserPromptText_LatencyRegression(t *testing.T) {
	latencygate.Gate(t) // listed, and skipped under -short and in a loaded CI shard
	if raceDetectorOn {
		t.Skip("wall-clock latency ceiling is not measurable under the race detector; ci.yml's static go job runs this without -race")
	}
	body := oneMiBPromptBody()
	const iterations = 7
	ceiling := extractLatencyBudget * extractLatencyTestHeadroom * raceLatencyMultiplier
	// T-527: the extraction and a reference workload (json.Valid over the
	// SAME body, the cheapest possible full pass over it) are timed
	// interleaved, and each keeps its fastest sample. A loaded host slows
	// both alike, so their ratio stays put while the absolute number moves.
	extractMin, refMin := time.Duration(math.MaxInt64), time.Duration(math.MaxInt64)
	for i := 0; i < iterations; i++ {
		start := time.Now()
		text, ok := extractLatestUserPromptText(models.ProviderAnthropic, body)
		if d := time.Since(start); d < extractMin {
			extractMin = d
		}
		if !ok || !strings.Contains(text, "4242 4242 4242 4242") {
			t.Fatalf("extraction result = %q/%v, want the final short message", text, ok)
		}
		start = time.Now()
		if !json.Valid(body) {
			t.Fatal("reference body is not valid JSON")
		}
		if d := time.Since(start); d < refMin {
			refMin = d
		}
	}
	if msg, fail := extractLatencyVerdict(extractMin, refMin, ceiling, extractLatencyMaxRatio); fail {
		t.Fatal(msg)
	} else {
		t.Log(msg)
	}
}

// extractLatencyMaxRatio bounds the extraction against the json.Valid
// reference pass over the same body. Measured 4.4 to 4.8 on the lane VM
// (2026-10-06, 15 ms against 3.2 ms); 10 is about 2x headroom, the same
// headroom the absolute ceiling (30 ms against a 15 ms steady state) has.
const extractLatencyMaxRatio = 10.0

// extractLatencyVerdict is the T-527 load-tolerant regression rule. It
// fails only when BOTH bounds are exceeded: the absolute ceiling (the
// original signal, still decisive on a quiet machine) AND the ratio to
// the reference pass measured in the same process (the signal that
// survives host load, because contention inflates both timings alike).
// A host at load 12 pushes the extraction to 47 to 71 ms but the
// reference rises with it, so the ratio holds and the test passes; a
// real regression (extra decodes, a quadratic walk) moves the ratio and
// fails on any host. The returned message carries every number either way.
func extractLatencyVerdict(extract, ref, ceiling time.Duration, maxRatio float64) (string, bool) {
	ratio := math.Inf(1)
	if ref > 0 {
		ratio = float64(extract) / float64(ref)
	}
	overCeiling := extract > ceiling
	overRatio := ratio > maxRatio
	msg := fmt.Sprintf("extractLatestUserPromptText: best %v/op (ceiling %v), json.Valid reference best %v/op, ratio %.2f (max %.1f)",
		extract, ceiling, ref, ratio, maxRatio)
	return msg, overCeiling && overRatio
}

// TestExtractLatencyVerdict pins the T-527 rule with the numbers that
// motivated it. The "loaded host" row is the flake: under the old
// absolute-only rule (extract > ceiling) it failed.
func TestExtractLatencyVerdict(t *testing.T) {
	t.Parallel()
	const ceiling = 30 * time.Millisecond
	ms := func(f float64) time.Duration { return time.Duration(f * float64(time.Millisecond)) }
	tests := []struct {
		name      string
		extract   time.Duration
		ref       time.Duration
		wantFail  bool
		oldWouldF bool
	}{
		{"quiet host, steady state", ms(15), ms(3.2), false, false},
		{"loaded host (load ~12), both timings inflated", ms(71), ms(15), false, true},
		{"loaded host, worst observed sample", ms(71), ms(9), false, true},
		{"real regression on a quiet host", ms(45), ms(3.2), true, true},
		{"real regression on a loaded host", ms(160), ms(15), true, true},
		{"ratio drift but still inside the absolute budget", ms(28), ms(2), false, false},
		{"zero reference reading never excuses an over-ceiling run", ms(45), 0, true, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.extract > ceiling; got != tc.oldWouldF {
				t.Fatalf("old absolute rule = %v, row says %v", got, tc.oldWouldF)
			}
			msg, fail := extractLatencyVerdict(tc.extract, tc.ref, ceiling, extractLatencyMaxRatio)
			if fail != tc.wantFail {
				t.Fatalf("verdict fail=%v, want %v (%s)", fail, tc.wantFail, msg)
			}
		})
	}
}
