package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ---------------------------------------------------------------------------
// Pure-layer tests: the comparator table.
// ---------------------------------------------------------------------------

func i64p(v int64) *int64     { return &v }
func f64p(v float64) *float64 { return &v }

// seqsOf resolves a permutation back to the chronological ordinals it selects,
// which is what every ordering assertion below is written against.
func seqsOf(fields []messageSortField, perm []int) []int {
	out := make([]int, len(perm))
	for i, p := range perm {
		out[i] = fields[p].Seq
	}
	return out
}

// TestMessageSortOrder_PerKey walks the sort allow-list one row at a time:
// each case supplies three rows that differ ONLY in the column under test and
// asserts the ascending and descending permutations. One case per
// messageSortKeys entry — TestMessageSortKeys_AllColumnsCovered pins that the
// table and this test stay in lock-step.
func TestMessageSortOrder_PerKey(t *testing.T) {
	// mk builds three rows carrying seq 1/2/3 with the column under test
	// pre-set by the case's mutator, so "want" is expressed as seq order.
	tests := []struct {
		key      string
		set      func(f *messageSortField, i int)
		wantAsc  []int
		wantDesc []int
	}{
		{
			key:      "seq",
			set:      func(f *messageSortField, i int) { _ = i },
			wantAsc:  []int{1, 2, 3},
			wantDesc: []int{3, 2, 1},
		},
		{
			key: "timestamp",
			set: func(f *messageSortField, i int) {
				f.Timestamp = []string{
					"2026-04-28T06:50:02Z", "2026-04-28T06:50:00Z", "2026-04-28T06:50:01Z",
				}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key: "message_id",
			set: func(f *messageSortField, i int) {
				f.MessageID = []string{"msg_c", "msg_A", "msg_b"}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key: "role",
			set: func(f *messageSortField, i int) {
				f.Role = []string{"user", "assistant", "tool"}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key: "model",
			set: func(f *messageSortField, i int) {
				f.Model = []string{"gpt-5.6", "claude-opus-5", "gemini-3.1-pro"}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			// Effort sorts by INTENSITY, not alphabetically: low < medium < high.
			key: "effort_level",
			set: func(f *messageSortField, i int) {
				f.EffortLevel = []string{"high", "low", "medium"}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "input",
			set:      func(f *messageSortField, i int) { f.Input = []int64{300, 100, 200}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "cache_read",
			set:      func(f *messageSortField, i int) { f.CacheRead = []int64{300, 100, 200}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "cache_creation",
			set:      func(f *messageSortField, i int) { f.CacheWrite = []int64{300, 100, 200}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "output",
			set:      func(f *messageSortField, i int) { f.Output = []int64{300, 100, 200}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key: "elapsed_ms",
			set: func(f *messageSortField, i int) {
				f.ElapsedMs = []*int64{i64p(3000), i64p(1000), i64p(2000)}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key: "tokens_per_sec",
			set: func(f *messageSortField, i int) {
				f.TokensPerSec = []*float64{f64p(90.5), f64p(10.25), f64p(50)}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "tool_call_count",
			set:      func(f *messageSortField, i int) { f.ToolCalls = []int{7, 1, 4}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "ai_cost_usd",
			set:      func(f *messageSortField, i int) { f.AICostUSD = []float64{0.3, 0.1, 0.2}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "tool_cost_usd",
			set:      func(f *messageSortField, i int) { f.ToolCostUSD = []float64{0.03, 0.01, 0.02}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key:      "cost_usd",
			set:      func(f *messageSortField, i int) { f.CostUSD = []float64{0.33, 0.11, 0.22}[i] },
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
		{
			key: "content",
			set: func(f *messageSortField, i int) {
				f.Content = []string{"Write file · z.go", "Edit file · a.go", "Read file · m.go"}[i]
			},
			wantAsc:  []int{2, 3, 1},
			wantDesc: []int{1, 3, 2},
		},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			fields := make([]messageSortField, 3)
			for i := range fields {
				fields[i].Seq = i + 1
				tc.set(&fields[i], i)
			}
			if got := seqsOf(fields, messageSortOrder(fields, tc.key, false)); !reflect.DeepEqual(got, tc.wantAsc) {
				t.Errorf("asc: got seq order %v, want %v", got, tc.wantAsc)
			}
			if got := seqsOf(fields, messageSortOrder(fields, tc.key, true)); !reflect.DeepEqual(got, tc.wantDesc) {
				t.Errorf("desc: got seq order %v, want %v", got, tc.wantDesc)
			}
		})
	}
}

// TestMessageSortKeys_AllColumnsCovered pins the allow-list against the 17
// columns the Messages table renders — a new column must land as a table row
// here AND a case in TestMessageSortOrder_PerKey, never as a new conditional.
func TestMessageSortKeys_AllColumnsCovered(t *testing.T) {
	want := []string{
		"seq", "timestamp", "message_id", "role", "account", "model", "effort_level",
		"input", "cache_read", "cache_creation", "output", "elapsed_ms",
		"tokens_per_sec", "tool_call_count", "ai_cost_usd", "tool_cost_usd",
		"cost_usd", "content",
	}
	if len(messageSortKeys) != len(want) {
		t.Fatalf("messageSortKeys has %d entries, want %d", len(messageSortKeys), len(want))
	}
	for _, k := range want {
		if _, ok := messageSortKeys[k]; !ok {
			t.Errorf("messageSortKeys missing key %q", k)
		}
	}
}

// TestMessageSortOrder_NullSink pins that an absent value sorts LAST in BOTH
// directions for every nullable column — flipping direction must never drag
// the "—" rows to the top of the table.
func TestMessageSortOrder_NullSink(t *testing.T) {
	tests := []struct {
		key string
		set func(f *messageSortField, i int)
	}{
		{"elapsed_ms", func(f *messageSortField, i int) {
			f.ElapsedMs = []*int64{i64p(200), nil, i64p(100), nil}[i]
		}},
		{"tokens_per_sec", func(f *messageSortField, i int) {
			f.TokensPerSec = []*float64{f64p(200), nil, f64p(100), nil}[i]
		}},
		// Empty effort_level is the MAJORITY value on real data (every
		// adapter without an effort knob), so it gets the same null-sink
		// treatment — including whitespace-only, which trims to empty.
		{"effort_level", func(f *messageSortField, i int) {
			f.EffortLevel = []string{"high", "", "low", "  "}[i]
		}},
	}
	for _, tc := range tests {
		t.Run(tc.key, func(t *testing.T) {
			fields := make([]messageSortField, 4)
			for i := range fields {
				fields[i].Seq = i + 1
				tc.set(&fields[i], i)
			}
			// seq 2 and 4 are the null rows; they sink to the end in both
			// directions, and among themselves stay in seq order.
			for _, c := range []struct {
				desc bool
				want []int
			}{
				{false, []int{3, 1, 2, 4}},
				{true, []int{1, 3, 2, 4}},
			} {
				got := seqsOf(fields, messageSortOrder(fields, tc.key, c.desc))
				if !reflect.DeepEqual(got, c.want) {
					t.Errorf("desc=%v: got seq order %v, want %v", c.desc, got, c.want)
				}
			}
		})
	}
}

// TestMessageEffortRank pins the effort ladder itself: the known vocabulary
// ranks by intensity, and an unrecognised NON-EMPTY value ranks BELOW the
// whole ladder (not above it — "unplaceable" is not "more than high").
func TestMessageEffortRank(t *testing.T) {
	ladder := []string{"none", "minimal", "low", "medium", "high", "max"}
	for i := 1; i < len(ladder); i++ {
		if messageEffortRank(ladder[i-1]) >= messageEffortRank(ladder[i]) {
			t.Fatalf("%q must rank below %q", ladder[i-1], ladder[i])
		}
	}
	if got, want := messageEffortRank("HIGH"), messageEffortRank("  high  "); got != want {
		t.Fatalf("case/space normalisation: %d != %d", got, want)
	}
	for _, unknown := range []string{"turbo", "ultrathink", "3", "-"} {
		if r := messageEffortRank(unknown); r >= messageEffortRank("none") {
			t.Fatalf("unrecognised %q ranked %d, want below the ladder (%d)",
				unknown, r, messageEffortRank("none"))
		}
	}
}

// TestMessageSortOrder_EffortUnknownBelowLadder pins the ORDERING consequence
// of the rank change: descending — the direction an operator actually uses to
// find the expensive turns — opens with "high", not with an unplaceable
// value, and the empty rows sink in both directions.
func TestMessageSortOrder_EffortUnknownBelowLadder(t *testing.T) {
	vals := []string{"high", "turbo", "low", "", "medium"}
	fields := make([]messageSortField, len(vals))
	for i := range fields {
		fields[i].Seq = i + 1
		fields[i].EffortLevel = vals[i]
	}
	for _, c := range []struct {
		desc bool
		want []int
	}{
		// asc: turbo(unknown) < low < medium < high, then the empty null-sink.
		{false, []int{2, 3, 5, 1, 4}},
		// desc: high > medium > low > turbo, and the empty row STILL last.
		{true, []int{1, 5, 3, 2, 4}},
	} {
		got := seqsOf(fields, messageSortOrder(fields, "effort_level", c.desc))
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("desc=%v: got seq order %v, want %v", c.desc, got, c.want)
		}
	}
}

// TestMessageSortOrder_StableSeqTieBreak pins that equal values resolve on the
// chronological ordinal ASCENDING in BOTH directions. Without this a 4s
// auto-refresh poll could visibly reshuffle equal rows.
func TestMessageSortOrder_StableSeqTieBreak(t *testing.T) {
	fields := make([]messageSortField, 5)
	for i := range fields {
		fields[i].Seq = i + 1
		fields[i].Output = 100 // every row identical on the sort column
	}
	fields[2].Output = 999 // one distinct row to prove direction still applies
	for _, c := range []struct {
		desc bool
		want []int
	}{
		{false, []int{1, 2, 4, 5, 3}},
		{true, []int{3, 1, 2, 4, 5}},
	} {
		got := seqsOf(fields, messageSortOrder(fields, "output", c.desc))
		if !reflect.DeepEqual(got, c.want) {
			t.Fatalf("desc=%v: got seq order %v, want %v", c.desc, got, c.want)
		}
	}
	// Order-independence: the same field values in a shuffled input slice
	// produce the same seq ordering (the tie-break, not the incoming order,
	// decides). This is what makes the result poll-stable.
	shuffled := []messageSortField{fields[3], fields[0], fields[4], fields[2], fields[1]}
	if got := seqsOf(shuffled, messageSortOrder(shuffled, "output", false)); !reflect.DeepEqual(got, []int{1, 2, 4, 5, 3}) {
		t.Fatalf("shuffled input: got seq order %v, want [1 2 4 5 3]", got)
	}
}

// TestMessageSortOrder_UnknownKeyFallsBackToSeqComparator pins the fail-open
// contract: an unrecognised column falls back to the seq COMPARATOR
// (chronological order) rather than panicking. That is deliberately NOT the
// identity permutation — input in seq order 3,1,2 comes back permuted to
// [1 2 0], not [0 1 2].
func TestMessageSortOrder_UnknownKeyFallsBackToSeqComparator(t *testing.T) {
	fields := []messageSortField{{Seq: 3}, {Seq: 1}, {Seq: 2}}
	if got := messageSortOrder(fields, "no_such_column", false); !reflect.DeepEqual(got, []int{1, 2, 0}) {
		t.Fatalf("unknown key: got perm %v, want the seq-ordered [1 2 0]", got)
	}
	if got := messageSortOrder(nil, "output", true); len(got) != 0 {
		t.Fatalf("empty input: got %v, want empty", got)
	}
}

// TestParseMessagesSortParams pins the query-param clamp: absent or
// unrecognised sort_by resolves to the chronological default INCLUDING the
// direction, so a legacy or garbage caller always gets the historical order.
func TestParseMessagesSortParams(t *testing.T) {
	tests := []struct {
		query    string
		wantBy   string
		wantDesc bool
	}{
		{"", "seq", false},
		{"?sort_by=timestamp", "timestamp", false},
		{"?sort_by=timestamp&sort_dir=asc", "timestamp", false},
		{"?sort_by=timestamp&sort_dir=desc", "timestamp", true},
		{"?sort_by=TIMESTAMP&sort_dir=DESC", "timestamp", true},
		{"?sort_by=+timestamp+&sort_dir=+desc+", "timestamp", true},
		{"?sort_by=cost_usd&sort_dir=sideways", "cost_usd", false},
		{"?sort_by=seq&sort_dir=desc", "seq", true},
		// Unrecognised column → full default, direction included.
		{"?sort_by=drop_table&sort_dir=desc", "seq", false},
		// sort_dir alone is not an explicit sort → historical order.
		{"?sort_dir=desc", "seq", false},
	}
	for _, tc := range tests {
		t.Run(tc.query, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/api/session/s/messages"+tc.query, nil)
			gotBy, gotDesc := parseMessagesSortParams(r)
			if gotBy != tc.wantBy || gotDesc != tc.wantDesc {
				t.Fatalf("got (%q, %v), want (%q, %v)", gotBy, gotDesc, tc.wantBy, tc.wantDesc)
			}
			if want := tc.wantBy == "seq" && !tc.wantDesc; messageSortIsDefault(gotBy, gotDesc) != want {
				t.Fatalf("messageSortIsDefault = %v, want %v", !want, want)
			}
		})
	}
}

// TestMessageContentSortKey pins that the Content sort key reproduces the
// string the Content cell renders (action label + " · " + 60-char-truncated
// target), including the frontend's humanize fallback for unknown types.
func TestMessageContentSortKey(t *testing.T) {
	long := "internal/intelligence/dashboard/dashboard.go:handleSessionMessages:sortBlock"
	tests := []struct {
		actionType string
		target     string
		want       string
	}{
		{"read_file", "main.go", "Read file · main.go"},
		{"run_command", "", "Run command"},
		{"mcp_call", "observer:get_symbols", "MCP call · observer:get_symbols"},
		{"totally_new_type", "x", "Totally New Type · x"},
		{"", "", "Unknown"},
		{"read_file", long, "Read file · " + string([]rune(long)[:59]) + "…"},
	}
	for _, tc := range tests {
		t.Run(tc.actionType+"/"+tc.target, func(t *testing.T) {
			if got := messageContentSortKey(tc.actionType, tc.target); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// HTTP-level tests: the handler wiring.
// ---------------------------------------------------------------------------

type sortMsgResp struct {
	Messages []struct {
		Seq           int    `json:"seq"`
		MessageID     string `json:"message_id"`
		Timestamp     string `json:"timestamp"`
		Role          string `json:"role"`
		Output        int64  `json:"output"`
		ToolCallCount int    `json:"tool_call_count"`
		ElapsedMs     *int64 `json:"elapsed_ms"`
	} `json:"messages"`
	Total  int `json:"total"`
	Offset int `json:"offset"`
	Limit  int `json:"limit"`
}

// newSortFixture builds a session whose message rows differ on every column
// the sort touches: 6 assistant turns with descending output tokens and
// ascending tool-call counts, interleaved with user prompts.
func newSortFixture(t *testing.T, sessionID string) *Server {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.db")
	database, err := openTestDB(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })

	st := store.New(database)
	root := t.TempDir()
	base := time.Date(2026, 4, 28, 6, 50, 0, 0, time.UTC)

	const turns = 6
	var (
		actions []models.ToolEvent
		tokens  []models.TokenEvent
	)
	for i := 0; i < turns; i++ {
		mid := fmt.Sprintf("msg_%d", i)
		ts := base.Add(time.Duration(i) * 10 * time.Second)
		// Each assistant turn carries i+1 tool calls with distinct targets.
		for j := 0; j <= i; j++ {
			actions = append(actions, models.ToolEvent{
				SourceFile: "f", SourceEventID: fmt.Sprintf("tc_%d_%d", i, j),
				SessionID: sessionID, ProjectRoot: root,
				Timestamp: ts.Add(time.Duration(j) * time.Millisecond),
				Tool:      models.ToolClaudeCode, ActionType: models.ActionReadFile,
				Target: fmt.Sprintf("file_%02d.go", turns-i), Success: true,
				MessageID: mid,
			})
		}
		tokens = append(tokens, models.TokenEvent{
			SourceFile: "f", SourceEventID: mid, SessionID: sessionID,
			Timestamp: ts, Tool: models.ToolClaudeCode,
			Model:       fmt.Sprintf("model-%d", turns-i),
			InputTokens: int64(100 * (i + 1)), OutputTokens: int64(100 * (turns - i)),
			CacheReadTokens: int64(10 * (i + 1)), CacheCreationTokens: int64(5 * (turns - i)),
			MessageID: mid, Source: models.TokenSourceJSONL,
			Reliability: models.ReliabilityUnreliable,
		})
	}
	if _, err := st.Ingest(context.Background(), actions, tokens, store.IngestOptions{}); err != nil {
		t.Fatal(err)
	}
	srv, err := New(Options{DB: database, DBPath: path})
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func callSortedMessages(t *testing.T, srv *Server, sessionID, query string) sortMsgResp {
	t.Helper()
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/session/"+sessionID+"/messages"+query, nil)
	srv.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("query %q: status %d body=%s", query, rr.Code, rr.Body.String())
	}
	var out sortMsgResp
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatalf("query %q: decode: %v", query, err)
	}
	return out
}

func seqList(r sortMsgResp) []int {
	out := make([]int, 0, len(r.Messages))
	for _, m := range r.Messages {
		out = append(out, m.Seq)
	}
	return out
}

// TestAPISessionMessages_SortSeqIsChronologicalAndPageIndependent pins that
// `seq` is a whole-timeline ordinal: page 2 continues page 1's numbering, and
// a reordering sort carries each row's ordinal with it.
func TestAPISessionMessages_SortSeqIsChronologicalAndPageIndependent(t *testing.T) {
	srv := newSortFixture(t, "sSeq")
	full := callSortedMessages(t, srv, "sSeq", "")
	if full.Total != 6 {
		t.Fatalf("total = %d, want 6", full.Total)
	}
	if got := seqList(full); !reflect.DeepEqual(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("default seq order = %v, want 1..6", got)
	}
	p2 := callSortedMessages(t, srv, "sSeq", "?limit=2&offset=2")
	if got := seqList(p2); !reflect.DeepEqual(got, []int{3, 4}) {
		t.Fatalf("page 2 seq = %v, want [3 4] (seq must not renumber per page)", got)
	}
	// Under a reversing sort the ordinals travel with their rows.
	rev := callSortedMessages(t, srv, "sSeq", "?sort_by=timestamp&sort_dir=desc")
	if got := seqList(rev); !reflect.DeepEqual(got, []int{6, 5, 4, 3, 2, 1}) {
		t.Fatalf("time-desc seq order = %v, want 6..1", got)
	}
}

// TestAPISessionMessages_SortDefaultUnchanged pins that the sort feature is
// inert unless asked for: no params, an unknown column, and an explicit
// seq/asc all return the identical chronological payload — including the
// derived elapsed_ms values, which must never be corrupted by a reorder.
func TestAPISessionMessages_SortDefaultUnchanged(t *testing.T) {
	srv := newSortFixture(t, "sDef")
	raw := func(query string) string {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/api/session/sDef/messages"+query, nil)
		srv.Handler().ServeHTTP(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("query %q: status %d", query, rr.Code)
		}
		return rr.Body.String()
	}
	want := raw("")
	for _, q := range []string{
		"?sort_by=seq",
		"?sort_by=seq&sort_dir=asc",
		"?sort_by=no_such_column",
		"?sort_by=no_such_column&sort_dir=desc",
		"?sort_dir=desc",
		"?sort_by=",
	} {
		if got := raw(q); got != want {
			t.Errorf("query %q changed the default payload:\n got %s\nwant %s", q, got, want)
		}
	}
}

// TestAPISessionMessages_SortAcrossPages pins the load-bearing behaviour the
// operator asked for: the sort addresses the WHOLE timeline, so time-desc puts
// the newest message at row 1 of page 1 rather than appending it to the last
// page. It also pins that a numeric sort orders by value, not by page.
func TestAPISessionMessages_SortAcrossPages(t *testing.T) {
	srv := newSortFixture(t, "sPage")
	newestFirst := callSortedMessages(t, srv, "sPage", "?sort_by=timestamp&sort_dir=desc&limit=2&offset=0")
	if got := seqList(newestFirst); !reflect.DeepEqual(got, []int{6, 5}) {
		t.Fatalf("page 1 of time-desc = %v, want the newest rows [6 5]", got)
	}
	if newestFirst.Total != 6 {
		t.Fatalf("total = %d, want 6 (paging must not change the count)", newestFirst.Total)
	}
	// Output tokens descend with seq in the fixture, so output-asc is the
	// reverse of chronological and output-desc is chronological.
	if got := seqList(callSortedMessages(t, srv, "sPage", "?sort_by=output&sort_dir=asc")); !reflect.DeepEqual(got, []int{6, 5, 4, 3, 2, 1}) {
		t.Fatalf("output-asc = %v, want 6..1", got)
	}
	if got := seqList(callSortedMessages(t, srv, "sPage", "?sort_by=output&sort_dir=desc")); !reflect.DeepEqual(got, []int{1, 2, 3, 4, 5, 6}) {
		t.Fatalf("output-desc = %v, want 1..6", got)
	}
	// Tool-call count ascends with seq.
	if got := seqList(callSortedMessages(t, srv, "sPage", "?sort_by=tool_call_count&sort_dir=desc")); !reflect.DeepEqual(got, []int{6, 5, 4, 3, 2, 1}) {
		t.Fatalf("tools-desc = %v, want 6..1", got)
	}
	// Content is "Read file · file_NN.go" with NN descending in seq order.
	if got := seqList(callSortedMessages(t, srv, "sPage", "?sort_by=content&sort_dir=asc")); !reflect.DeepEqual(got, []int{6, 5, 4, 3, 2, 1}) {
		t.Fatalf("content-asc = %v, want 6..1", got)
	}
}

// TestAPISessionMessages_SortElapsedNullSinkOverHTTP pins the null-sink end to
// end: the last chronological row has no successor and therefore no
// elapsed_ms, and it stays at the BOTTOM under both directions.
func TestAPISessionMessages_SortElapsedNullSinkOverHTTP(t *testing.T) {
	srv := newSortFixture(t, "sNull")
	for _, dir := range []string{"asc", "desc"} {
		r := callSortedMessages(t, srv, "sNull", "?sort_by=elapsed_ms&sort_dir="+dir)
		last := r.Messages[len(r.Messages)-1]
		if last.ElapsedMs != nil {
			t.Fatalf("dir=%s: last row elapsed_ms = %v, want null (null-sink)", dir, *last.ElapsedMs)
		}
		if last.Seq != 6 {
			t.Fatalf("dir=%s: last row seq = %d, want 6 (the null row)", dir, last.Seq)
		}
		for _, m := range r.Messages[:len(r.Messages)-1] {
			if m.ElapsedMs == nil {
				t.Fatalf("dir=%s: seq %d has null elapsed_ms above a present one", dir, m.Seq)
			}
		}
	}
}

// TestAPISessionMessages_SortWithTail pins that ?tail=N keeps its FROZEN
// meaning under a sort — the last N rows CHRONOLOGICALLY, then reordered for
// display — and that tail+sort is explicitly NOT a 400.
func TestAPISessionMessages_SortWithTail(t *testing.T) {
	srv := newSortFixture(t, "sTailSort")
	r := callSortedMessages(t, srv, "sTailSort", "?tail=3&sort_by=timestamp&sort_dir=desc")
	if got := seqList(r); !reflect.DeepEqual(got, []int{6, 5, 4}) {
		t.Fatalf("tail=3 + time-desc = %v, want the last three reversed [6 5 4]", got)
	}
	if r.Total != 6 || r.Offset != 3 {
		t.Fatalf("tail envelope: total=%d offset=%d, want 6/3", r.Total, r.Offset)
	}
	// The window is chronological even when the sort would have selected a
	// different three rows: output-asc over the WHOLE timeline would start at
	// seq 6, but tail still returns seqs 4,5,6 — reordered.
	r2 := callSortedMessages(t, srv, "sTailSort", "?tail=3&sort_by=output&sort_dir=desc")
	if got := seqList(r2); !reflect.DeepEqual(got, []int{4, 5, 6}) {
		t.Fatalf("tail=3 + output-desc = %v, want [4 5 6]", got)
	}
}

// TestAPISessionMessages_SortWithLocate pins that ?locate= snaps to the page
// containing the message in the EFFECTIVE (post-sort) order — under time-desc
// the chronologically-first message lives on the LAST page, not the first.
func TestAPISessionMessages_SortWithLocate(t *testing.T) {
	srv := newSortFixture(t, "sLoc")
	q := url.Values{"locate": {"msg_0"}, "limit": {"2"}}
	// Chronological: msg_0 is seq 1 → page 1 (offset 0).
	chrono := callSortedMessages(t, srv, "sLoc", "?"+q.Encode())
	if chrono.Offset != 0 || len(chrono.Messages) == 0 || chrono.Messages[0].MessageID != "msg_0" {
		t.Fatalf("chronological locate: offset=%d first=%q, want 0/msg_0", chrono.Offset, chrono.Messages[0].MessageID)
	}
	// Time-desc: msg_0 is now the LAST row (index 5) → offset 4.
	q.Set("sort_by", "timestamp")
	q.Set("sort_dir", "desc")
	rev := callSortedMessages(t, srv, "sLoc", "?"+q.Encode())
	if rev.Offset != 4 {
		t.Fatalf("time-desc locate: offset=%d, want 4 (the page holding msg_0 in the sorted order)", rev.Offset)
	}
	found := false
	for _, m := range rev.Messages {
		if m.MessageID == "msg_0" {
			found = true
		}
	}
	if !found {
		t.Fatalf("time-desc locate: msg_0 not on the returned page %v", seqList(rev))
	}
}

// TestAPISessionMessages_LocateProbeMustCarrySort pins the server half of the
// Processes-panel "jump to the message that spawned this process" contract:
// ?locate= is resolved against the EFFECTIVE (post-sort) row list, so a probe
// that omits the active sort gets an offset addressing a DIFFERENT page than
// the one the table renders — the row is absent and the client's
// scrollIntoView silently no-ops.
//
// The review's proven failing input: sort_by=output&sort_dir=asc active, jump
// to the first message. Under that sort msg_0 is the LAST row, so the
// chronological probe's offset 0 and the correct offset 4 disagree.
func TestAPISessionMessages_LocateProbeMustCarrySort(t *testing.T) {
	srv := newSortFixture(t, "sLocProbe")
	const target = "msg_0"
	onPage := func(r sortMsgResp) bool {
		for _, m := range r.Messages {
			if m.MessageID == target {
				return true
			}
		}
		return false
	}
	// The sort-carrying probe — what the client now sends, including the
	// ?detail= grain — lands on a page that actually holds the target.
	probe := callSortedMessages(t, srv, "sLocProbe",
		"?locate="+target+"&limit=2&detail=turn&sort_by=output&sort_dir=asc")
	if probe.Offset != 4 {
		t.Fatalf("sorted probe: offset=%d, want 4", probe.Offset)
	}
	if !onPage(probe) {
		t.Fatalf("sorted probe: %s not on the returned page %v", target, seqList(probe))
	}
	// Same offset the rendered table reaches by paginating in the active sort:
	// the probe's answer is directly usable as a page number.
	page := callSortedMessages(t, srv, "sLocProbe",
		"?limit=2&offset=4&detail=turn&sort_by=output&sort_dir=asc")
	if !onPage(page) {
		t.Fatalf("probe offset does not address a page holding %s: %v", target, seqList(page))
	}
	// The old, sort-less probe answers 0 — a page that does NOT hold the
	// target under this sort. This is the regression the fix removes.
	stale := callSortedMessages(t, srv, "sLocProbe", "?locate="+target+"&limit=2")
	if stale.Offset != 0 {
		t.Fatalf("chronological probe: offset=%d, want 0", stale.Offset)
	}
	wrong := callSortedMessages(t, srv, "sLocProbe",
		"?limit=2&offset=0&detail=turn&sort_by=output&sort_dir=asc")
	if onPage(wrong) {
		t.Fatalf("fixture no longer distinguishes the two probes: %s is on page 1 of output-asc", target)
	}
}
