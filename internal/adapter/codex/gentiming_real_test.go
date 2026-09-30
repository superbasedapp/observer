package codex

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// genRealFixture is testdata/codex/rollout-gen-timing-real.jsonl: an
// anonymised 80-line slice (lines 1-80: the session header through the 9th
// inference's token_count) of a live proxy-routed codex rollout (2026-09-23,
// thread 01a0cbe2-f675-7112-b631-6772c77b20c1, codex 0.154.0). It carries 9
// complete inferences, each a token_usage_record immediately followed by
// its event_msg/token_count, matching the live 0.154 ordering the parser
// targets. All free text (instructions, commands, tool arguments/outputs,
// git info, cwd) is replaced with short placeholders; token_usage_record
// and event_msg/token_count payloads are BYTE-IDENTICAL to the source
// (minus git/cwd, which don't appear there) because the span rule binds a
// token_count to its nearest preceding token_usage_record by exact
// usage-counter equality, and the test binds a stamped event to a proxy row
// by walking these SAME real records (see responseIDsByLine below), not by
// a hand-maintained id list.
const genRealFixture = "../../../testdata/codex/rollout-gen-timing-real.jsonl"

// genRealProxyTSV holds the SAME rollout's proxy-measured request durations
// (`<response_id> <total_response_ms>`) for the 9 inferences in the
// fixture's window.
const genRealProxyTSV = "../../../testdata/codex/rollout-gen-timing-real.proxy.tsv"

func loadRealCodexProxyTSV(t *testing.T, path string) map[string]int64 {
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
		parts := strings.Split(line, "\t")
		if len(parts) != 2 {
			t.Fatalf("bad proxy tsv line %q", line)
		}
		ms, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			t.Fatalf("bad proxy tsv line %q: %v", line, err)
		}
		out[parts[0]] = ms
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// responseIDsByLine reads the RAW rollout file (independent of the
// adapter's own parsing) and returns, for every event_msg/token_count
// line's 1-based line number, the response_id of the nearest PRECEDING
// token_usage_record - the same binding the span rule itself proves before
// stamping. This lets the test cross-reference a stamped TokenEvent to a
// proxy row purely from its SourceEventID (which embeds the token_count's
// own absolute line number as "tk:<basename>:L<lineNum>"), without
// depending on TokenEvents slice order or any unexported adapter helper.
func responseIDsByLine(t *testing.T, path string) map[int]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	out := map[int]string{}
	lastResp := ""
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	lineNum := 0
	for sc.Scan() {
		lineNum++
		raw := sc.Bytes()
		if len(raw) == 0 {
			continue
		}
		var line struct {
			Type    string          `json:"type"`
			Payload json.RawMessage `json:"payload"`
		}
		if json.Unmarshal(raw, &line) != nil {
			continue
		}
		switch line.Type {
		case "token_usage_record":
			var r struct {
				ResponseID string `json:"response_id"`
			}
			if json.Unmarshal(line.Payload, &r) == nil && r.ResponseID != "" {
				lastResp = r.ResponseID
			}
		case "event_msg":
			var p struct {
				Type string `json:"type"`
			}
			if json.Unmarshal(line.Payload, &p) == nil && p.Type == "token_count" {
				out[lineNum] = lastResp
			}
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// lineFromSourceEventID extracts the absolute line number embedded in a
// codex token TokenEvent's SourceEventID ("tk:<basename>:L<lineNum>", see
// applyCodexGenTiming's perEventID in adapter.go).
func lineFromSourceEventID(id string) (int, bool) {
	i := strings.LastIndex(id, ":L")
	if i < 0 {
		return 0, false
	}
	n, err := strconv.Atoi(id[i+2:])
	if err != nil {
		return 0, false
	}
	return n, true
}

func realCodexStamped(t *testing.T) (all []models.TokenEvent, stamped map[string]int64) {
	t.Helper()
	res, err := New().ParseSessionFile(context.Background(), genRealFixture, 0)
	if err != nil {
		t.Fatal(err)
	}
	stamped = map[string]int64{}
	for _, ev := range res.TokenEvents {
		if ev.GenMs > 0 {
			if ev.GenBasis != models.GenBasisTranscript || ev.GenTimingV != codexGenTimingV {
				t.Errorf("%s: basis=%q v=%d, want %q/%d", ev.SourceEventID, ev.GenBasis, ev.GenTimingV, models.GenBasisTranscript, codexGenTimingV)
			}
			stamped[ev.SourceEventID] = ev.GenMs
		}
	}
	return res.TokenEvents, stamped
}

func codexMedian(vals []float64) float64 {
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

// TestCodexGenTimingReal_WholeFile validates the span rule against a live
// proxy measurement of the SAME rollout: every stamped span must never
// UNDER-state the proxy's measured request duration by more than 5%. It
// pins whole-file coverage (all 9 inferences in the window get a proven
// span) and that at least 8 of them cross-reference a real proxy row via
// their nearest-preceding token_usage_record's response_id.
func TestCodexGenTimingReal_WholeFile(t *testing.T) {
	proxy := loadRealCodexProxyTSV(t, genRealProxyTSV)
	byLine := responseIDsByLine(t, genRealFixture)
	all, stamped := realCodexStamped(t)

	const wantTotal = 9
	if len(all) != wantTotal {
		t.Fatalf("got %d token events, want %d", len(all), wantTotal)
	}
	const wantStamped = 9
	if len(stamped) != wantStamped {
		t.Fatalf("stamped %d events, want %d: %v", len(stamped), wantStamped, stamped)
	}

	var ratios []float64
	matched := 0
	for id, ms := range stamped {
		line, ok := lineFromSourceEventID(id)
		if !ok {
			t.Errorf("%s: could not parse a line number out of the SourceEventID", id)
			continue
		}
		respID, ok := byLine[line]
		if !ok || respID == "" {
			t.Errorf("%s (line %d): no preceding token_usage_record found in the raw fixture", id, line)
			continue
		}
		proxyMs, ok := proxy[respID]
		if !ok {
			continue
		}
		matched++
		ratio := float64(ms) / float64(proxyMs)
		ratios = append(ratios, ratio)
		if ratio < 0.95 {
			t.Errorf("%s (%s): gen_ms=%d is %.1f%% of proxy_ms=%d (%.3fx) - transcript span materially UNDER-states the real request duration", id, respID, ms, ratio*100, proxyMs, ratio)
		}
	}
	if matched < 8 {
		t.Fatalf("only %d stamped events cross-referenced a proxy row, want >= 8", matched)
	}

	sorted := append([]float64(nil), ratios...)
	sort.Float64s(sorted)
	t.Logf("whole-file: total=%d stamped=%d matched=%d min_ratio=%.3f median_ratio=%.3f max_ratio=%.3f",
		len(all), len(stamped), matched, sorted[0], codexMedian(ratios), sorted[len(sorted)-1])
}

// TestCodexGenTimingReal_SplitReplay re-parses the real fixture split at
// EVERY 2-way line boundary (append part 1, parse from 0, then append part
// 2 and parse from NewOffset), the way the watcher parses a growing
// rollout. The store keeps the FIRST stamped gen_ms per row at a given
// parser version, so the replay does too: every stored value must equal the
// whole-file value or be absent.
func TestCodexGenTimingReal_SplitReplay(t *testing.T) {
	_, whole := realCodexStamped(t)
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
	if n := len(bounds); n > 0 && bounds[n-1] == len(data) {
		bounds = bounds[:n-1]
	}

	minCoverage := 1.0
	minCut := -1
	for _, cut := range bounds {
		// Same basename as genRealFixture: codex's perEventID embeds
		// filepath.Base(path), so the SourceEventID must match the
		// whole-file run's for the `whole` map lookup below to line up.
		path := filepath.Join(t.TempDir(), filepath.Base(genRealFixture))
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
	// one-shot look-back (min_coverage=1.000 measured across all 79
	// boundaries). A regression that drops below this floor is a real
	// coverage loss, not fixture noise.
	const wantMinCoverage = 1.0
	t.Logf("split-replay: whole=%d min_coverage=%.3f at cut=%d (%d boundaries checked)", len(whole), minCoverage, minCut, len(bounds))
	if minCoverage < wantMinCoverage-1e-9 {
		t.Errorf("split-replay coverage floor regressed: got %.3f, want >= %.3f", minCoverage, wantMinCoverage)
	}
}
