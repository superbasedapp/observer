package claudecode

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// genRealFixture is testdata/claudecode/gen-timing-real.jsonl: an anonymised
// 322-line slice (lines 1-322, the session header records through the 15th
// API message) of a live proxy-routed claude-code session (2026-09-02,
// session 74977661-ec73-4c1f-86c2-152a21bc5bab). It carries 15 real API
// messages with parallel tool_use/tool_result blocks; 14 have provable
// completion evidence in-window. The one gap - msg_011CeeXk4tdsq2Y57Mv1xwzm
// (5 parallel tool_use blocks) - is a genuine, non-bug limitation of the
// span rule's "last visible block" heuristic: its LAST block's own
// tool_result (uuid e19ddfca -> ef4610cb -> df16540b) dead-ends without
// reaching the next message, while an EARLIER sibling block's tool_result
// chain is the one that actually continues into msg6 - tool completion can
// arrive out of file order. That is a coverage cost, not a correctness bug
// (msg5 simply stays unstamped, same fail-closed behaviour as an unprovable
// synthetic case), so it is left undisturbed here. All free text
// (thinking/text/signatures, tool inputs and outputs, prompts, titles,
// paths, branch names) is replaced with short placeholders; every
// structural field the span rule reads (type, uuid, parentUuid,
// isSidechain, timestamp, message.id/model/usage, content block type,
// tool_use id/name, tool_use_id) is untouched.
const genRealFixture = "../../../testdata/claudecode/gen-timing-real.jsonl"

// genRealProxyTSV holds the SAME session's proxy-measured request durations
// (`<msg_id> <total_response_ms>`), captured independently of the
// transcript, for the 15 messages in the fixture's window.
const genRealProxyTSV = "../../../testdata/claudecode/gen-timing-real.proxy.tsv"

func loadRealProxyTSV(t *testing.T, path string) map[string]int64 {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[string]int64{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		id, ms, ok := parseTSVLine(line)
		if !ok {
			t.Fatalf("bad proxy tsv line %q", line)
		}
		out[id] = ms
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// parseTSVLine splits a TAB-separated "<id>\t<ms>" line without pulling in
// an extra dependency.
func parseTSVLine(line string) (id string, ms int64, ok bool) {
	for i := 0; i < len(line); i++ {
		if line[i] == '\t' {
			id = line[:i]
			var v int64
			for _, c := range line[i+1:] {
				if c < '0' || c > '9' {
					return "", 0, false
				}
				v = v*10 + int64(c-'0')
			}
			return id, v, true
		}
	}
	return "", 0, false
}

func median(vals []float64) float64 {
	if len(vals) == 0 {
		return 0
	}
	sorted := append([]float64(nil), vals...)
	sort.Float64s(sorted)
	mid := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[mid]
	}
	return (sorted[mid-1] + sorted[mid]) / 2
}

// realStamped runs ParseSessionFile whole-file and returns the stamped
// GenMs by SourceEventID (message id).
func realStamped(t *testing.T) map[string]int64 {
	t.Helper()
	res, err := New().ParseSessionFile(context.Background(), genRealFixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, ev := range res.TokenEvents {
		if ev.GenMs > 0 {
			if ev.GenBasis != models.GenBasisTranscript || ev.GenTimingV != ccGenTimingV {
				t.Errorf("%s: basis=%q v=%d, want %q/%d", ev.SourceEventID, ev.GenBasis, ev.GenTimingV, models.GenBasisTranscript, ccGenTimingV)
			}
			got[ev.SourceEventID] = ev.GenMs
		}
	}
	return got
}

// TestGenTimingReal_WholeFile validates the span rule against a live proxy
// measurement: the transcript-derived span must never UNDER-state the
// proxy's measured request duration by more than 5% (a small margin for the
// two clocks / rounding), matching the doc comment's live finding that the
// transcript span runs long (client pre-send time) far more often than
// short. It also pins whole-file coverage: exactly how many of the 15
// messages in the window get a proven span, and that at least 8 of the
// stamped ones cross-reference a real proxy row.
func TestGenTimingReal_WholeFile(t *testing.T) {
	proxy := loadRealProxyTSV(t, genRealProxyTSV)
	stamped := realStamped(t)

	// Pinned coverage: 14 of the window's 15 messages have completion
	// evidence in-window. msg_011CeeXk4tdsq2Y57Mv1xwzm (msg5) is the one
	// gap - see the fixture doc comment above for why (out-of-order
	// parallel tool_use completion, not a bug).
	const wantStamped = 14
	if len(stamped) != wantStamped {
		t.Fatalf("stamped %d messages, want %d: %v", len(stamped), wantStamped, stamped)
	}

	var ratios []float64
	matched := 0
	for id, ms := range stamped {
		proxyMs, ok := proxy[id]
		if !ok {
			continue
		}
		matched++
		ratio := float64(ms) / float64(proxyMs)
		ratios = append(ratios, ratio)
		if ratio < 0.95 {
			t.Errorf("%s: gen_ms=%d is %.1f%% of proxy_ms=%d (%.3fx) - transcript span materially UNDER-states the real request duration", id, ms, ratio*100, proxyMs, ratio)
		}
	}
	if matched < 8 {
		t.Fatalf("only %d stamped events cross-referenced a proxy row, want >= 8", matched)
	}

	sorted := append([]float64(nil), ratios...)
	sort.Float64s(sorted)
	t.Logf("whole-file: n=%d stamped=%d matched=%d min_ratio=%.3f median_ratio=%.3f max_ratio=%.3f",
		len(stamped), len(stamped), matched, sorted[0], median(ratios), sorted[len(sorted)-1])
}

// TestGenTimingReal_SplitReplay re-parses the real fixture split at EVERY
// 2-way line boundary (append part 1, parse from 0, then append part 2 and
// parse from NewOffset), the way the watcher parses a growing transcript.
// The store keeps the FIRST stamped gen_ms per row at a given parser
// version, so the replay does too: every stored value must equal the
// whole-file value or be absent - a window split may cost coverage but must
// never shorten or lengthen a proven span.
func TestGenTimingReal_SplitReplay(t *testing.T) {
	whole := realStamped(t)
	if len(whole) == 0 {
		t.Fatal("whole-file produced no stamped events; nothing to validate replay against")
	}

	data, err := os.ReadFile(genRealFixture)
	if err != nil {
		t.Fatal(err)
	}
	var bounds []int
	for i, b := range data {
		if b == '\n' {
			bounds = append(bounds, i+1)
		}
	}
	// Drop the final boundary (EOF): splitting there isn't a 2-way split.
	if n := len(bounds); n > 0 && bounds[n-1] == len(data) {
		bounds = bounds[:n-1]
	}

	minCoverage := 1.0
	minCut := -1
	for _, cut := range bounds {
		path := filepath.Join(t.TempDir(), "sess-gen-real.jsonl")
		if err := os.WriteFile(path, data[:cut], 0o600); err != nil {
			t.Fatal(err)
		}
		res1, err := New().ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("cut %d: first parse: %v", cut, err)
		}
		f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write(data[cut:]); err != nil {
			t.Fatal(err)
		}
		f.Close()
		res2, err := New().ParseSessionFile(context.Background(), path, res1.NewOffset)
		if err != nil {
			t.Fatalf("cut %d: second parse: %v", cut, err)
		}

		stored := map[string]int64{}
		for _, ev := range append(append([]models.TokenEvent(nil), res1.TokenEvents...), res2.TokenEvents...) {
			if ev.GenMs > 0 {
				if _, ok := stored[ev.SourceEventID]; !ok {
					stored[ev.SourceEventID] = ev.GenMs
				}
			}
		}
		for id, ms := range stored {
			want, ok := whole[id]
			if !ok || ms != want {
				t.Errorf("cut %d: %s stored gen_ms=%d, want %d (or absent)", cut, id, ms, whole[id])
			}
		}
		coverage := float64(len(stored)) / float64(len(whole))
		if coverage < minCoverage {
			minCoverage = coverage
			minCut = cut
		}
	}

	// Pinned floor from a live run of this fixture (2026-09-23): every
	// 2-way split still recovers the FULL whole-file stamped set via the
	// one-shot look-back (min_coverage=1.000 measured across all 321
	// boundaries). A regression that drops below this floor is a real
	// coverage loss, not fixture noise.
	const wantMinCoverage = 1.0
	t.Logf("split-replay: whole=%d min_coverage=%.3f at cut=%d (%d boundaries checked)", len(whole), minCoverage, minCut, len(bounds))
	if minCoverage < wantMinCoverage-1e-9 {
		t.Errorf("split-replay coverage floor regressed: got %.3f, want >= %.3f", minCoverage, wantMinCoverage)
	}
}
