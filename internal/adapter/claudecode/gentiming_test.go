package claudecode

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// genFixture is testdata/claudecode/gen-timing.jsonl: the current Claude
// Code shape where one API message (msg_A) streams tool execution INSIDE
// itself (tool_result records between its blocks), a legacy interleaved
// sidechain record (msg_S), a message completed by the next message
// (msg_A by msg_B), one completed by a stop_hook_summary system record
// (msg_B), and a tail message with no completion evidence (msg_C).
const genFixture = "../../../testdata/claudecode/gen-timing.jsonl"

// wantGen is the whole-file span per message: start = the first block's
// parent record, end = the last block. msg_S (no provable first block) and
// msg_C (no completion evidence) are never stamped.
var wantGen = map[string]int64{
	"msg_A": 19950, // 20:55:00.050 (attachment a1) -> 20:55:20.000 (block bA3)
	"msg_B": 4000,  // 20:55:21.000 (tool_result r2) -> 20:55:25.000 (block bB1)
}

// genDeferredFixture is testdata/claudecode/gen-timing-deferred.jsonl: the
// Claude Code shape first seen live on 2026-09-26, where a
// deferred_tools_record attachment is written WITH the response - stamped at
// the first block's own millisecond (or 1 ms after it) and parented between
// the request's real input and that block. Built from the structure of two
// live messages (lane BL4, 2026-09-27), which the v1 span rule timed from
// the deferred record and showed at 382 and 316 tok/s instead of ~75.
const genDeferredFixture = "../../../testdata/claudecode/gen-timing-deferred.jsonl"

// wantGenDeferred: one case per defect row.
//   - msg_A: deferred record at the first block's ms -> start = the input
//     before it (a1). v1 timed 10:00:08.000 -> 10:00:10.000 = 2000 ms
//     (900 tokens at 450 tok/s instead of 90).
//   - msg_B: deferred record 1 ms AFTER the first block -> start = a2. v1
//     rejected the span (start after the first block) and left it unmeasured.
//   - msg_C: an UNKNOWN attachment at the first block's ms -> not stamped:
//     a request cannot return its first block in the millisecond it was
//     sent, so an equal-ms start is unproven (v1 accepted it: 1500 ms, the
//     first-block-to-last-block gap).
//   - msg_D: deferred record directly under a prompt -> start = the prompt.
var wantGenDeferred = map[string]int64{
	"msg_A": 9990, // 10:00:00.010 (attachment a1) -> 10:00:10.000 (block bA2)
	"msg_B": 4000, // 10:00:11.000 (attachment a2) -> 10:00:15.000 (block bB1)
	"msg_D": 2000, // 10:02:00.000 (prompt u3)     -> 10:02:02.000 (block bD1)
}

// genFixtures is every span fixture the whole-file and split-replay tests
// run over.
var genFixtures = []struct {
	name string
	path string
	want map[string]int64
}{
	{"streamed-tools", genFixture, wantGen},
	{"deferred-tools-record", genDeferredFixture, wantGenDeferred},
}

func TestGenTiming_WholeFile(t *testing.T) {
	for _, fx := range genFixtures {
		t.Run(fx.name, func(t *testing.T) {
			res, err := New().ParseSessionFile(context.Background(), fx.path, 0)
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]int64{}
			for _, ev := range res.TokenEvents {
				if ev.GenMs > 0 {
					if ev.GenBasis != models.GenBasisTranscript || ev.GenTimingV != ccGenTimingV {
						t.Errorf("%s: basis=%q v=%d", ev.SourceEventID, ev.GenBasis, ev.GenTimingV)
					}
					got[ev.SourceEventID] = ev.GenMs
				}
			}
			if len(got) != len(fx.want) {
				t.Fatalf("stamped %v, want %v", got, fx.want)
			}
			for id, ms := range fx.want {
				if got[id] != ms {
					t.Errorf("%s: gen_ms=%d, want %d", id, got[id], ms)
				}
			}
		})
	}
}

// TestGenTiming_ClassifyAttachment pins the attachment classification table:
// a response-side type is never a request start; every other attachment
// (including an unknown one and a non-object value) stays request input.
func TestGenTiming_ClassifyAttachment(t *testing.T) {
	cases := []struct {
		name string
		line string
		want ccLineKind
	}{
		{"deferred_tools_record is response-side", `{"type":"attachment","uuid":"x","attachment":{"type":"deferred_tools_record","entries":[]}}`, ccKindResponseSide},
		{"hook_success is input", `{"type":"attachment","uuid":"x","attachment":{"type":"hook_success"}}`, ccKindInput},
		{"total_tokens_reminder is input", `{"type":"attachment","uuid":"x","attachment":{"type":"total_tokens_reminder"}}`, ccKindInput},
		{"unknown type is input", `{"type":"attachment","uuid":"x","attachment":{"type":"some_future_record"}}`, ccKindInput},
		{"missing body is input", `{"type":"attachment","uuid":"x"}`, ccKindInput},
		{"non-object body is input and decodes", `{"type":"attachment","uuid":"x","attachment":"text"}`, ccKindInput},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var line rawLine
			if err := json.Unmarshal([]byte(tc.line), &line); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if got := classifyRecord(line, true).Kind; got != tc.want {
				t.Errorf("kind = %d, want %d", got, tc.want)
			}
		})
	}
}

// TestGenTiming_SplitReplay re-parses the fixture split at EVERY 2-way and
// 3-way line boundary, the way the watcher parses a growing transcript
// (append, parse from the previous NewOffset). The store keeps the FIRST
// stamped gen_ms per row at a given parser version, so the replay does too.
// Every stored value must be the whole-file span or absent - a window split
// may cost coverage but may never shorten or lengthen a span.
func TestGenTiming_SplitReplay(t *testing.T) {
	for _, fx := range genFixtures {
		t.Run(fx.name, func(t *testing.T) { genSplitReplay(t, fx.path, fx.want) })
	}
}

func genSplitReplay(t *testing.T, fixture string, want map[string]int64) {
	data, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	var bounds []int
	for i, b := range data {
		if b == '\n' {
			bounds = append(bounds, i+1)
		}
	}
	replay := func(t *testing.T, cuts []int) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "sess-gen.jsonl")
		stored := map[string]int64{}
		var off int64
		prev := 0
		for _, cut := range append(append([]int{}, cuts...), len(data)) {
			f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.Write(data[prev:cut]); err != nil {
				t.Fatal(err)
			}
			f.Close()
			prev = cut
			res, err := New().ParseSessionFile(context.Background(), path, off)
			if err != nil {
				t.Fatal(err)
			}
			off = res.NewOffset
			for _, ev := range res.TokenEvents {
				if ev.GenMs > 0 {
					if _, ok := stored[ev.SourceEventID]; !ok {
						stored[ev.SourceEventID] = ev.GenMs
					}
				}
			}
		}
		for id, ms := range stored {
			if w, ok := want[id]; !ok || ms != w {
				t.Errorf("cuts %v: %s stored gen_ms=%d, want %d (or absent)", cuts, id, ms, want[id])
			}
		}
	}
	// Default first look-back step (reaches the file start at once on this
	// small fixture), then a 256-byte first step that forces the backward
	// doubling path through every split.
	for _, step := range []int64{genLookbackFirstBytes, 256} {
		saved := genLookbackFirstBytes
		genLookbackFirstBytes = step
		for i := 0; i < len(bounds)-1; i++ {
			replay(t, []int{bounds[i]})
			for j := i + 1; j < len(bounds)-1; j++ {
				replay(t, []int{bounds[i], bounds[j]})
			}
		}
		genLookbackFirstBytes = saved
	}
}

// TestGenTiming_SplitReplayCoverage pins that the look-back makes the
// common incremental shape still measurable: with the window cut right
// after each message's last block (the next message not yet written),
// both completed messages are still stamped by the NEXT parse.
func TestGenTiming_SplitReplayCoverage(t *testing.T) {
	data, err := os.ReadFile(genFixture)
	if err != nil {
		t.Fatal(err)
	}
	cutAfter := func(uuid string) int {
		i := bytes.Index(data, []byte(`"uuid":"`+uuid+`"`))
		return i + bytes.IndexByte(data[i:], '\n') + 1
	}
	saved := genLookbackFirstBytes
	genLookbackFirstBytes = 256 // force the backward doubling path
	defer func() { genLookbackFirstBytes = saved }()
	path := filepath.Join(t.TempDir(), "sess-gen.jsonl")
	stored := map[string]int64{}
	var off int64
	prev := 0
	for _, cut := range []int{cutAfter("bA3"), cutAfter("bB1"), len(data)} {
		f, _ := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		_, _ = f.Write(data[prev:cut])
		f.Close()
		prev = cut
		res, err := New().ParseSessionFile(context.Background(), path, off)
		if err != nil {
			t.Fatal(err)
		}
		off = res.NewOffset
		for _, ev := range res.TokenEvents {
			if ev.GenMs > 0 {
				if _, ok := stored[ev.SourceEventID]; !ok {
					stored[ev.SourceEventID] = ev.GenMs
				}
			}
		}
	}
	for id, ms := range wantGen {
		if stored[id] != ms {
			t.Errorf("%s: stored %d, want %d (look-back must recover the tail message)", id, stored[id], ms)
		}
	}
}
