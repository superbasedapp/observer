package sessionmsg

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func rlRaw(used int, reset int64) string {
	return fmt.Sprintf(`{"limit_id":"codex","limit_name":null,"primary":{"used_percent":%d,"window_minutes":10080,"resets_at":%d},"secondary":null,"plan_type":"prolite","rate_limit_reached_type":null}`, used, reset)
}

func boolp(b bool) *bool { return &b }

// TestDerive_StatusActionsFold is the table for status.go: a rate_limit
// action is never its own row nor a tool call; it folds onto the message
// it follows with its changed readings marked. One case per rule.
func TestDerive_StatusActionsFold(t *testing.T) {
	turns := []TokenRow{
		{SourceEventID: "tk:f:L3", TurnID: "t1", Timestamp: "2026-09-28T13:22:10Z", Model: "gpt-5.5", Input: 10, Output: 5},
		{SourceEventID: "tk:f:L6", TurnID: "t2", Timestamp: "2026-09-28T13:23:10Z", Model: "gpt-5.5", Input: 10, Output: 5},
		{SourceEventID: "tk:f:L9", TurnID: "t3", Timestamp: "2026-09-28T13:24:10Z", Model: "gpt-5.5", Input: 10, Output: 5},
	}
	rl := func(line int, ts string, raw string, ok bool) ActionRow {
		id := fmt.Sprintf("ratelimit:f:L%d", line)
		return ActionRow{ActionID: id, SourceEventID: id, MessageID: id, ActionType: "rate_limit", Timestamp: ts, Tool: "ok", Success: boolp(ok), StatusRaw: raw}
	}
	type want struct {
		rowKeys    []string
		perRow     []int      // StatusActions per row
		changed    [][]string // Reason per status action, "" = unchanged
		toolCalls  int        // total Actions across rows
		summaries0 string     // first status action's Summary
	}
	cases := []struct {
		name    string
		tokens  []TokenRow
		actions []ActionRow
		want    want
	}{
		{
			name:   "node: one reading per turn, jitter unchanged, tick changed",
			tokens: turns,
			actions: []ActionRow{
				rl(4, "2026-09-28T13:22:11Z", rlRaw(9, 1791047433), true),
				rl(7, "2026-09-28T13:23:11Z", rlRaw(9, 1791047436), true),
				rl(10, "2026-09-28T13:24:11Z", rlRaw(10, 1791047437), true),
			},
			want: want{
				rowKeys: []string{"t1", "t2", "t3"}, perRow: []int{1, 1, 1},
				changed:    [][]string{{"first"}, {""}, {"used_percent"}},
				summaries0: "7d 9% · plan prolite",
			},
		},
		{
			name:   "node: alternating limit families are independent streams, not a change per line",
			tokens: turns,
			actions: []ActionRow{
				rl(4, "2026-09-28T13:22:11Z", rlRaw(9, 1791047433), true),
				rl(5, "2026-09-28T13:22:12Z", strings.Replace(rlRaw(3, 1791047433), `"codex"`, `"codex_bengalfox"`, 1), true),
				rl(7, "2026-09-28T13:23:11Z", rlRaw(9, 1791047433), true),
				rl(8, "2026-09-28T13:23:12Z", strings.Replace(rlRaw(3, 1791047433), `"codex"`, `"codex_bengalfox"`, 1), true),
				rl(10, "2026-09-28T13:24:11Z", rlRaw(9, 1791047433), true),
			},
			want: want{
				rowKeys: []string{"t1", "t2", "t3"}, perRow: []int{2, 2, 1},
				changed:    [][]string{{"first", "first"}, {"", ""}, {""}},
				summaries0: "7d 9% · plan prolite",
			},
		},
		{
			name:   "org: no body, only first and a limit hit are changes",
			tokens: turns,
			actions: []ActionRow{
				rl(4, "2026-09-28T13:22:11Z", "", true),
				rl(7, "2026-09-28T13:23:11Z", "", false),
				rl(10, "2026-09-28T13:24:11Z", "", false),
			},
			want: want{
				rowKeys: []string{"t1", "t2", "t3"}, perRow: []int{1, 1, 1},
				changed: [][]string{{"first"}, {"status"}, {""}},
			},
		},
		{
			name:   "reading before any message lands on the first row",
			tokens: turns[:1],
			actions: []ActionRow{
				rl(1, "2026-09-28T13:22:00Z", rlRaw(9, 1791047433), true),
				rl(4, "2026-09-28T13:22:11Z", rlRaw(9, 1791047433), true),
			},
			want: want{
				rowKeys: []string{"t1"}, perRow: []int{2},
				changed:    [][]string{{"first", ""}},
				summaries0: "7d 9% · plan prolite",
			},
		},
		{
			name:   "reading keyed to a turn still never counts as a tool call",
			tokens: turns[:1],
			actions: []ActionRow{
				{ActionID: "x", SourceEventID: "x", MessageID: "t1", ActionType: "rate_limit", Timestamp: "2026-09-28T13:22:11Z", Success: boolp(true), StatusRaw: rlRaw(9, 1)},
			},
			want: want{rowKeys: []string{"t1"}, perRow: []int{1}, changed: [][]string{{"first"}}, summaries0: "7d 9% · plan prolite"},
		},
		{
			name: "probe-only session keeps one synthesized row per reading",
			actions: []ActionRow{
				rl(1, "2026-09-28T13:22:00Z", rlRaw(9, 1), true),
			},
			want: want{rowKeys: []string{"ratelimit:f:L1"}, perRow: []int{0}, changed: [][]string{{}}, toolCalls: 1},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rows := Derive(DeriveInput{TokenRows: c.tokens, ActionRows: c.actions, Mode: RollupTurn})
			if got := keys(rows); !reflect.DeepEqual(got, c.want.rowKeys) {
				t.Fatalf("row keys %v want %v", got, c.want.rowKeys)
			}
			tc := 0
			for i, r := range rows {
				tc += len(r.Actions)
				if len(r.StatusActions) != c.want.perRow[i] {
					t.Errorf("row %d status actions %d want %d", i, len(r.StatusActions), c.want.perRow[i])
					continue
				}
				for j, sa := range r.StatusActions {
					if sa.Reason != c.want.changed[i][j] || sa.Changed != (c.want.changed[i][j] != "") {
						t.Errorf("row %d status %d: changed=%v reason=%q want %q", i, j, sa.Changed, sa.Reason, c.want.changed[i][j])
					}
				}
				w := r.Status()
				if w.StatusEventCount != len(r.StatusActions) {
					t.Errorf("row %d StatusEventCount=%d", i, w.StatusEventCount)
				}
				nChanged := 0
				for _, reason := range c.want.changed[i] {
					if reason != "" {
						nChanged++
					}
				}
				if len(w.StatusEvents) != nChanged {
					t.Errorf("row %d wire carries %d events, want only the %d changed", i, len(w.StatusEvents), nChanged)
				}
			}
			if tc != c.want.toolCalls {
				t.Errorf("tool calls %d want %d", tc, c.want.toolCalls)
			}
			if c.want.summaries0 != "" {
				var first *StatusAction
				for _, r := range rows {
					if len(r.StatusActions) > 0 {
						first = &r.StatusActions[0]
						break
					}
				}
				if first == nil || first.Summary != c.want.summaries0 {
					t.Errorf("first summary %+v want %q", first, c.want.summaries0)
				}
			}
		})
	}
}

// TestStatusActionTypes pins the kind table's exported view.
func TestStatusActionTypes(t *testing.T) {
	if got := StatusActionTypes(); !reflect.DeepEqual(got, []string{"rate_limit"}) {
		t.Fatalf("StatusActionTypes=%v", got)
	}
	if !IsStatusAction("rate_limit") || IsStatusAction("read_file") {
		t.Fatal("IsStatusAction wrong")
	}
}
