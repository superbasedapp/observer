package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// genFixture is testdata/codex/rollout-gen-timing.jsonl, modelled on a live
// codex 0.154 rollout (2026-09-22): each inference's token_usage_record is
// followed by tool execution and only THEN by the token_count the adapter
// emits, so the token_count timestamp is not the inference end. The fourth
// inference has no token_usage_record (older build shape) and must stay
// unstamped.
const genFixture = "../../../testdata/codex/rollout-gen-timing.jsonl"

// wantGen is keyed by each token_count's OutputTokens (net of reasoning):
// inference 1 = 351-99, inference 2 = 299-175, inference 3 = 200-50.
var wantGen = map[int64]int64{
	252: 16300, // user message 21:55:14.158 -> token_usage_record 21:55:30.458
	124: 20772, // world_state 21:55:31.053 -> token_usage_record 21:55:51.825
	// Live 0.154 ordering: the previous inference's token_count is written
	// AFTER the tool output that is this inference's input, and no other
	// input follows - the token_count must not end the walk.
	150: 4681, // custom_tool_call_output 21:55:52.329 -> token_usage_record 21:55:57.010
}

func genByOutput(t *testing.T, evs []models.TokenEvent) map[int64]int64 {
	t.Helper()
	got := map[int64]int64{}
	for _, ev := range evs {
		if ev.GenMs > 0 {
			if ev.GenBasis != models.GenBasisTranscript || ev.GenTimingV != codexGenTimingV {
				t.Errorf("%s: basis=%q v=%d", ev.SourceEventID, ev.GenBasis, ev.GenTimingV)
			}
			got[ev.OutputTokens] = ev.GenMs
		}
	}
	return got
}

func TestCodexGenTiming_WholeFile(t *testing.T) {
	res, err := New().ParseSessionFile(context.Background(), genFixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.TokenEvents) != 4 {
		t.Fatalf("want 4 token events, got %d", len(res.TokenEvents))
	}
	got := genByOutput(t, res.TokenEvents)
	if len(got) != len(wantGen) {
		t.Fatalf("stamped %v, want %v", got, wantGen)
	}
	for out, ms := range wantGen {
		if got[out] != ms {
			t.Errorf("output %d: gen_ms=%d, want %d", out, got[out], ms)
		}
	}
}

// TestCodexGenTiming_SplitReplay re-parses the fixture split at EVERY 2-way
// and 3-way line boundary the way the watcher parses a growing rollout. The
// store keeps the first stamped gen_ms per row at a parser version, so the
// replay does too: every stored value must equal the whole-file span or be
// absent.
func TestCodexGenTiming_SplitReplay(t *testing.T) {
	data, err := os.ReadFile(genFixture)
	if err != nil {
		t.Fatal(err)
	}
	var bounds []int
	for i, b := range data {
		if b == '\n' {
			bounds = append(bounds, i+1)
		}
	}
	replay := func(cuts []int) {
		path := filepath.Join(t.TempDir(), "rollout-2026-09-22T21-54-52-"+"01a0cb1d-0000-7000-a000-00000000gen1.jsonl")
		stored := map[string]int64{}
		outBy := map[string]int64{}
		var off int64
		prev := 0
		for _, cut := range append(append([]int{}, cuts...), len(data)) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = f.Write(data[prev:cut])
			f.Close()
			prev = cut
			res, err := New().ParseSessionFile(context.Background(), path, off)
			if err != nil {
				t.Fatal(err)
			}
			off = res.NewOffset
			for _, ev := range res.TokenEvents {
				outBy[ev.SourceEventID] = ev.OutputTokens
				if ev.GenMs > 0 {
					if _, ok := stored[ev.SourceEventID]; !ok {
						stored[ev.SourceEventID] = ev.GenMs
					}
				}
			}
		}
		for id, ms := range stored {
			if want, ok := wantGen[outBy[id]]; !ok || ms != want {
				t.Errorf("cuts %v: %s stored gen_ms=%d, want %d (or absent)", cuts, id, ms, want)
			}
		}
		if len(cuts) == 1 && len(stored) != len(wantGen) {
			// With the look-back, one split never loses a span.
			t.Errorf("cuts %v: stored %d spans, want %d", cuts, len(stored), len(wantGen))
		}
	}
	// Default first look-back step, then a 256-byte one that forces the
	// backward doubling path through every split.
	for _, step := range []int64{codexGenLookbackFirstBytes, 256} {
		saved := codexGenLookbackFirstBytes
		codexGenLookbackFirstBytes = step
		for i := 0; i < len(bounds)-1; i++ {
			replay([]int{bounds[i]})
			for j := i + 1; j < len(bounds)-1; j++ {
				replay([]int{bounds[i], bounds[j]})
			}
		}
		codexGenLookbackFirstBytes = saved
	}
}
