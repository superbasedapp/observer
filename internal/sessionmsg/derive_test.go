package sessionmsg

import (
	"reflect"
	"testing"
)

func keys(rows []*Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Key
	}
	return out
}

func roles(rows []*Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Role
	}
	return out
}

// TestDerive_TwinFold_CodexShape reproduces the codex proxy/JSONL twin: a
// proxy row (id resp_1) and a JSONL row (id tk:file:L1, turn_id trn_1) that
// describe the SAME model call — the proxy's output is GROSS (visible +
// reasoning), the JSONL row already nets reasoning out. Review finding #1:
// before this package existed the org had no twin fold at all and would
// have shown two rows; Derive must show exactly one, keyed by the twin's
// turn_id, with the reasoning split applied.
func TestDerive_TwinFold_CodexShape(t *testing.T) {
	rows := Derive(DeriveInput{
		ProxyRows: []ProxyRow{
			{RequestID: "resp_1", Timestamp: "2026-09-22T10:00:00Z", Model: "gpt-5.5", Input: 100, Output: 150, CacheRead: 0, CacheCreation: 0, CostUSD: 0.02},
		},
		TokenRows: []TokenRow{
			{SourceEventID: "tk:file:L1", TurnID: "trn_1", Timestamp: "2026-09-22T10:00:01Z", Model: "gpt-5.5", Input: 100, Output: 100, Reasoning: 50, CostUSD: 0.02},
		},
		Mode: RollupTurn,
	})
	if len(rows) != 1 {
		t.Fatalf("want 1 merged row, got %d: %v", len(rows), keys(rows))
	}
	r := rows[0]
	if r.Key != "trn_1" {
		t.Errorf("want key adopted from twin's turn_id trn_1, got %q", r.Key)
	}
	if r.Bundle.Output != 100 || r.Bundle.Reasoning != 50 {
		t.Errorf("want reasoning split output=100/reasoning=50, got output=%d reasoning=%d", r.Bundle.Output, r.Bundle.Reasoning)
	}
	if r.Bundle.Input != 100 {
		t.Errorf("want input=100, got %d", r.Bundle.Input)
	}
	// The JSONL twin's own alias identities must resolve to this row too.
	if !containsStr(r.AliasKeys, "resp_1") || !containsStr(r.AliasKeys, "trn_1") {
		t.Errorf("want AliasKeys to include both resp_1 and trn_1, got %v", r.AliasKeys)
	}
}

// TestDerive_TwinFold_DirectIDMatch covers claude-code, where the JSONL
// row's source_event_id literally equals the proxy row's request_id — the
// token row must still be excluded from separate emission (not just
// shape-matched ones).
func TestDerive_TwinFold_DirectIDMatch(t *testing.T) {
	rows := Derive(DeriveInput{
		ProxyRows: []ProxyRow{
			{RequestID: "req_1", Timestamp: "2026-09-22T10:00:00Z", Model: "claude-x", Input: 10, Output: 20, CostUSD: 0.01},
		},
		TokenRows: []TokenRow{
			// Shape does NOT match (different Output) but the id matches
			// directly — must still be excluded, per the two independent
			// exclusion criteria in the original SQL.
			{SourceEventID: "req_1", MessageID: "msg_1", Timestamp: "2026-09-22T10:00:00Z", Model: "claude-x", Input: 999, Output: 999},
		},
		Mode: RollupTurn,
	})
	if len(rows) != 1 {
		t.Fatalf("want 1 row (direct-id fold), got %d: %v", len(rows), keys(rows))
	}
	if rows[0].Bundle.Input != 10 {
		t.Errorf("want the PROXY row's own input (10) preserved, got %d", rows[0].Bundle.Input)
	}
}

// TestDerive_GroupKeyPrecedence_MessageIDOverSourceEventID is finding #2:
// the group key must prefer message_id over source_event_id even with no
// turn_id present (OpenCode/Kilo/Zcode shape) — two token rows sharing one
// message_id but carrying DIFFERENT source_event_ids must merge into one
// row.
func TestDerive_GroupKeyPrecedence_MessageIDOverSourceEventID(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{SourceEventID: "ev1", MessageID: "msg_shared", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Input: 10, Output: 5},
			{SourceEventID: "ev2", MessageID: "msg_shared", Timestamp: "2026-09-22T10:00:01Z", Model: "m", Input: 0, Output: 3},
		},
		Mode: RollupTurn,
	})
	if len(rows) != 1 {
		t.Fatalf("want 1 merged row keyed by shared message_id, got %d: %v", len(rows), keys(rows))
	}
	if rows[0].Key != "msg_shared" {
		t.Errorf("want key msg_shared, got %q", rows[0].Key)
	}
	if rows[0].Bundle.Input != 10 || rows[0].Bundle.Output != 8 {
		t.Errorf("want summed input=10 output=8, got input=%d output=%d", rows[0].Bundle.Input, rows[0].Bundle.Output)
	}
}

// TestDerive_UserRowKeyedLikeEveryOtherAction is finding #3: a user_prompt
// action must be keyed by COALESCE(message_id, source_event_id) — the SAME
// rule as every other action — and must be APPENDED into the row's Actions,
// not merely used to seed metadata and dropped.
func TestDerive_UserRowKeyedLikeEveryOtherAction(t *testing.T) {
	rows := Derive(DeriveInput{
		ActionRows: []ActionRow{
			{MessageID: "user:gen1", SourceEventID: "irrelevant", ActionType: "user_prompt", Timestamp: "2026-09-22T10:00:00Z", EffortLevel: "high"},
		},
	})
	if len(rows) != 1 {
		t.Fatalf("want 1 synthesized user row, got %d", len(rows))
	}
	r := rows[0]
	if r.Key != "user:gen1" {
		t.Errorf("want key from message_id (user:gen1), got %q — must not fall back to source_event_id when message_id is present", r.Key)
	}
	if r.Role != "user" {
		t.Errorf("want role user, got %q", r.Role)
	}
	if len(r.Actions) != 1 {
		t.Fatalf("want the user_prompt action appended to the row, got %d actions", len(r.Actions))
	}
	if r.EffortLevel != "high" {
		t.Errorf("want effort_level propagated from the action, got %q", r.EffortLevel)
	}
	if r.AccountKey != "user:user:gen1" {
		t.Errorf("want AccountKey role:key = user:user:gen1, got %q", r.AccountKey)
	}
}

// TestDerive_CursorUserAssistantPeerModel covers Cursor's user:<gen> /
// assistant:<gen> key-prefix convention: a synthesized user row with no
// model of its own inherits its assistant peer's model.
func TestDerive_CursorUserAssistantPeerModel(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{MessageID: "assistant:gen1", Timestamp: "2026-09-22T10:00:01Z", Model: "gpt-5.5", Input: 5, Output: 5},
		},
		ActionRows: []ActionRow{
			{MessageID: "user:gen1", ActionType: "user_prompt", Timestamp: "2026-09-22T10:00:00Z"},
		},
		DefaultModel: "session-default",
	})
	var userRow *Row
	for _, r := range rows {
		if r.Role == "user" {
			userRow = r
		}
	}
	if userRow == nil {
		t.Fatalf("want a user row, got %v", roles(rows))
	}
	if userRow.Model != "gpt-5.5" {
		t.Errorf("want user row to inherit assistant:gen1 peer's model, got %q", userRow.Model)
	}
}

// TestDerive_ShadowPairing_OneToOne is finding #7: two LEGITIMATE Copilot
// turns sharing the same output count must NOT both collapse to one row —
// pairing is one-to-one, so with two full rows and two shadow rows sharing
// output=152, both pairs survive as two independent messages.
func TestDerive_ShadowPairing_OneToOne(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{SourceEventID: "full1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Model: "gpt-x", Input: 10, Output: 152},
			{SourceEventID: "shadow1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Model: "gpt-x", Input: 0, Output: 152},
			{SourceEventID: "full2", MessageID: "m2", Timestamp: "2026-09-22T10:05:00Z", Model: "gpt-x", Input: 8, Output: 152},
			{SourceEventID: "shadow2", MessageID: "m2", Timestamp: "2026-09-22T10:05:00Z", Model: "gpt-x", Input: 0, Output: 152},
		},
		ShadowCapable: true,
		Mode:          RollupTurn,
	})
	if len(rows) != 2 {
		t.Fatalf("want 2 legitimate turns to survive (one shadow paired off each), got %d: %v", len(rows), keys(rows))
	}
	for _, r := range rows {
		if r.Bundle.Output != 152 {
			t.Errorf("row %s: want output 152 (not doubled), got %d", r.Key, r.Bundle.Output)
		}
	}
}

// TestDerive_ShadowPairing_ExtraShadowSurvivesAsOwnRow: a shadow row with NO
// available full-row partner (every full row in its output bucket already
// claimed) must remain a real, visible row — never silently dropped by a
// set-membership test.
func TestDerive_ShadowPairing_ExtraShadowSurvivesAsOwnRow(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{SourceEventID: "full1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Model: "gpt-x", Input: 10, Output: 152},
			{SourceEventID: "shadow1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Model: "gpt-x", Input: 0, Output: 152},
			// A second shadow with the SAME output and no full-row partner —
			// a genuine extra turn (e.g. a retried completion), not a dup.
			{SourceEventID: "shadow2", MessageID: "m2", Timestamp: "2026-09-22T10:06:00Z", Model: "gpt-x", Input: 0, Output: 152},
		},
		ShadowCapable: true,
		Mode:          RollupTurn,
	})
	if len(rows) != 2 {
		t.Fatalf("want the unpaired shadow to survive as its own row, got %d: %v", len(rows), keys(rows))
	}
}

// TestDerive_ShadowPairing_NotAppliedWhenIncapable: the capability flag
// gates the whole mechanism — when false (any non-shadow-capable tool), no
// row is ever excluded, so an adapter that happens to emit two token rows
// with equal output for unrelated reasons is untouched.
func TestDerive_ShadowPairing_NotAppliedWhenIncapable(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{SourceEventID: "a", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Model: "x", Input: 10, Output: 50},
			{SourceEventID: "b", MessageID: "m2", Timestamp: "2026-09-22T10:00:01Z", Model: "x", Input: 0, Output: 50},
		},
		ShadowCapable: false,
	})
	if len(rows) != 2 {
		t.Fatalf("want no shadow suppression when incapable, got %d rows", len(rows))
	}
}

// TestDerive_OrphanActionSynthesis_GooseShape: a session-level token row
// (no message_id, a synthetic session-wide key) joins none of the
// session's individual tool-call actions; every action must still surface
// as its own bare row rather than being silently dropped.
func TestDerive_OrphanActionSynthesis_GooseShape(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{SourceEventID: "tokens:sess1", Timestamp: "2026-09-22T10:10:00Z", Model: "m", Input: 100, Output: 50},
		},
		ActionRows: []ActionRow{
			{SourceEventID: "act1", ActionType: "run_command", Timestamp: "2026-09-22T10:00:00Z"},
			{SourceEventID: "act2", ActionType: "read_file", Timestamp: "2026-09-22T10:01:00Z"},
		},
	})
	if len(rows) != 3 {
		t.Fatalf("want 1 session-level token row + 2 synthesized action rows = 3, got %d: %v", len(rows), keys(rows))
	}
}

// TestDerive_DeterministicOrder_IndependentOfInputOrder feeds the same rows
// in several different input orders and checks Derive always returns the
// identical final key/role sequence — finding #6, the parity requirement
// between an SQLite scan order and a PostgreSQL one that need not agree.
func TestDerive_DeterministicOrder_IndependentOfInputOrder(t *testing.T) {
	build := func(tokenOrder []int) []*Row {
		all := []TokenRow{
			{SourceEventID: "e1", MessageID: "m1", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Output: 1},
			{SourceEventID: "e2", MessageID: "m2", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Output: 1}, // same timestamp as e1
			{SourceEventID: "e3", MessageID: "m3", Timestamp: "2026-09-22T10:00:01Z", Model: "m", Output: 1},
		}
		shuffled := make([]TokenRow, len(tokenOrder))
		for i, idx := range tokenOrder {
			shuffled[i] = all[idx]
		}
		actions := []ActionRow{
			{SourceEventID: "u1", MessageID: "m1", ActionType: "user_prompt", Timestamp: "2026-09-22T10:00:00Z"},
		}
		return Derive(DeriveInput{TokenRows: shuffled, ActionRows: actions, Mode: RollupTurn})
	}
	base := keys(build([]int{0, 1, 2}))
	for _, perm := range [][]int{{1, 0, 2}, {2, 1, 0}, {0, 2, 1}} {
		got := keys(build(perm))
		if !reflect.DeepEqual(got, base) {
			t.Errorf("input order %v produced a different final order: got %v, want %v", perm, got, base)
		}
	}
}

// TestDerive_InferenceMode_TurnBucketFallback exercises ?detail=inference:
// an action carrying the TURN id (codex-shape) with no matching
// per-inference bucket must land on the inference bucket whose timestamp
// window contains it, not be dropped or wrongly synthesized as its own row.
func TestDerive_InferenceMode_TurnBucketFallback(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{SourceEventID: "tk1", TurnID: "trn_1", Timestamp: "2026-09-22T10:00:00Z", Model: "m", Output: 1},
			{SourceEventID: "tk2", TurnID: "trn_1", Timestamp: "2026-09-22T10:00:05Z", Model: "m", Output: 1},
		},
		ActionRows: []ActionRow{
			// Action carries the TURN id, not either inference id — should
			// resolve to the SECOND bucket (its timestamp is after tk1's
			// bound but the row key "trn_1" matches neither tk1 nor tk2).
			{MessageID: "trn_1", ActionType: "tool_call", Timestamp: "2026-09-22T10:00:06Z"},
		},
		Mode: RollupInference,
	})
	if len(rows) != 2 {
		t.Fatalf("want 2 inference-grain rows, got %d: %v", len(rows), keys(rows))
	}
	total := 0
	for _, r := range rows {
		total += len(r.Actions)
	}
	if total != 1 {
		t.Fatalf("want the action attached to exactly one inference bucket, got %d total", total)
	}
	if len(rows[1].Actions) != 1 {
		t.Errorf("want the action on the SECOND (later) inference bucket (key %q), got %d actions there and %d on the first",
			rows[1].Key, len(rows[1].Actions), len(rows[0].Actions))
	}
}

// TestPairShadowRows_S4Rules is the table-driven oracle for S4 (2026-09-22
// review round 3): id match wins regardless of distance, adjacency pairs
// only within shadowPairMaxDelta and only when neither side carries a
// comparable stable id, an out-of-bound pair (even a plausible-looking
// "shadow precedes full" order) is rejected, and a row carrying any
// non-zero billable field besides output is never classified as a shadow
// in the first place.
func TestPairShadowRows_S4Rules(t *testing.T) {
	cases := []struct {
		name   string
		tokens []TokenRow
		want   []bool // per-index excluded
	}{
		{
			name: "id match pairs regardless of distance",
			tokens: []TokenRow{
				{SourceEventID: "full", MessageID: "m1", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "shadow", MessageID: "m1", Timestamp: "2026-09-22T17:00:00Z", Output: 50},
			},
			want: []bool{false, true},
		},
		{
			name: "turn_id match pairs when message_id absent on both sides",
			tokens: []TokenRow{
				{SourceEventID: "full", TurnID: "t1", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "shadow", TurnID: "t1", Timestamp: "2026-09-22T09:05:00Z", Output: 50},
			},
			want: []bool{false, true},
		},
		{
			name: "id mismatch never falls through to adjacency even when close",
			tokens: []TokenRow{
				{SourceEventID: "full", MessageID: "other", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "shadow", MessageID: "mine", Timestamp: "2026-09-22T09:00:01Z", Output: 50},
			},
			want: []bool{false, false},
		},
		{
			name: "adjacency within bound pairs when neither side carries an id",
			tokens: []TokenRow{
				{SourceEventID: "full", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "shadow", Timestamp: "2026-09-22T09:00:20Z", Output: 50},
			},
			want: []bool{false, true},
		},
		{
			name: "shadow before full within bound still pairs (symmetric)",
			tokens: []TokenRow{
				{SourceEventID: "shadow", Timestamp: "2026-09-22T09:00:00Z", Output: 50},
				{SourceEventID: "full", Timestamp: "2026-09-22T09:00:20Z", Output: 50, Input: 10},
			},
			want: []bool{true, false},
		},
		{
			name: "out of bound not paired",
			tokens: []TokenRow{
				{SourceEventID: "full", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "shadow", Timestamp: "2026-09-22T09:05:00Z", Output: 50}, // 5 min > 30s bound
			},
			want: []bool{false, false},
		},
		{
			name: "non-zero reasoning not paired (never classified as a shadow)",
			tokens: []TokenRow{
				{SourceEventID: "full", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "reasoning-bearing", Timestamp: "2026-09-22T09:00:01Z", Output: 50, Reasoning: 5},
			},
			want: []bool{false, false},
		},
		{
			name: "non-zero cache_creation_1h not paired",
			tokens: []TokenRow{
				{SourceEventID: "full", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "cache1h-bearing", Timestamp: "2026-09-22T09:00:01Z", Output: 50, CacheCreation1h: 5},
			},
			want: []bool{false, false},
		},
		{
			name: "non-zero web_search_requests not paired",
			tokens: []TokenRow{
				{SourceEventID: "full", Timestamp: "2026-09-22T09:00:00Z", Output: 50, Input: 10},
				{SourceEventID: "websearch-bearing", Timestamp: "2026-09-22T09:00:01Z", Output: 50, WebSearchRequests: 2},
			},
			want: []bool{false, false},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PairShadowRows(c.tokens, true)
			if !reflect.DeepEqual(got, c.want) {
				t.Errorf("PairShadowRows() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDerive_KeylessRowSurvives is review round 5 finding #7: a proxy or
// token row carrying NONE of its real identity fields (request_id /
// message_id / source_event_id / turn_id — a legacy pre-fallback capture)
// used to be silently dropped by Derive (the empty-key "continue" branch);
// it must now surface as its own row via a synthesized key, exactly like
// TestAPISessionDetail_TotalsSurviveIDlessLegacyRows' dashboard fixture,
// so Detail, Messages and the org's SessionMessageMetrics — all three
// direct callers of this function — see the identical row rather than
// only the caller that used to patch a local id in before calling Derive.
func TestDerive_KeylessRowSurvives(t *testing.T) {
	t.Run("token row", func(t *testing.T) {
		rows := Derive(DeriveInput{
			TokenRows: []TokenRow{
				{Timestamp: "2026-09-22T10:00:00Z", Model: "claude-sonnet-4-6", Input: 1000},
			},
			Mode: RollupTurn,
		})
		if len(rows) != 1 {
			t.Fatalf("want 1 row (keyless token row must survive), got %d: %v", len(rows), keys(rows))
		}
		if !rows[0].Keyless {
			t.Errorf("want Keyless=true on a row synthesized from an id-less token row")
		}
		if rows[0].Key == "" {
			t.Errorf("want a non-empty synthesized key, got empty")
		}
		if rows[0].Bundle.Input != 1000 {
			t.Errorf("want input=1000 preserved, got %d", rows[0].Bundle.Input)
		}
	})

	t.Run("proxy row", func(t *testing.T) {
		rows := Derive(DeriveInput{
			ProxyRows: []ProxyRow{
				{Timestamp: "2026-09-22T10:00:00Z", Model: "claude-sonnet-4-6", Input: 500, Output: 200},
			},
			Mode: RollupTurn,
		})
		if len(rows) != 1 {
			t.Fatalf("want 1 row (keyless proxy row must survive), got %d: %v", len(rows), keys(rows))
		}
		if !rows[0].Keyless {
			t.Errorf("want Keyless=true on a row synthesized from an id-less proxy row")
		}
		if !rows[0].IsProxy {
			t.Errorf("want IsProxy=true (Source proxy) preserved on a keyless proxy row")
		}
		if rows[0].Bundle.Input != 500 || rows[0].Bundle.Output != 200 {
			t.Errorf("want input=500/output=200 preserved, got input=%d output=%d", rows[0].Bundle.Input, rows[0].Bundle.Output)
		}
	})
}

// TestDerive_KeylessRowsNeverFoldTogether covers two DISTINCT keyless
// token rows with no shape/id relationship — each must land on its own
// row (never merged just because both lack an id), and non-keyless rows
// present in the same session must be unaffected (no accidental key
// collision with the synthesized "keyless:…" namespace).
func TestDerive_KeylessRowsNeverFoldTogether(t *testing.T) {
	rows := Derive(DeriveInput{
		TokenRows: []TokenRow{
			{Timestamp: "2026-09-22T10:00:00Z", Model: "m", Input: 10, Output: 1},
			{Timestamp: "2026-09-22T10:00:01Z", Model: "m", Input: 20, Output: 2},
			{SourceEventID: "real-id", Timestamp: "2026-09-22T10:00:02Z", Model: "m", Input: 30, Output: 3},
		},
		Mode: RollupTurn,
	})
	if len(rows) != 3 {
		t.Fatalf("want 3 distinct rows (two keyless never folded together, one real-id row unaffected), got %d: %v", len(rows), keys(rows))
	}
	keylessCount, realCount := 0, 0
	seen := map[string]bool{}
	for _, r := range rows {
		if seen[r.Key] {
			t.Fatalf("duplicate key %q across rows — a fold happened where none should", r.Key)
		}
		seen[r.Key] = true
		if r.Keyless {
			keylessCount++
		} else {
			realCount++
		}
	}
	if keylessCount != 2 {
		t.Errorf("want 2 Keyless rows, got %d", keylessCount)
	}
	if realCount != 1 {
		t.Errorf("want 1 non-Keyless row (the real-id one), got %d", realCount)
	}
}

// TestDerive_KeylessRowTwinsViaShapeMatch confirms a keyless PROXY row can
// still fold with a keyless TOKEN row when the existing shape-matching
// twin rule (assignTwins, keyed on model/input/output/cache — never on
// Key) says they're the same captured turn: the "unless the existing
// shape rules would" carve-out in keylessKey's doc comment.
func TestDerive_KeylessRowTwinsViaShapeMatch(t *testing.T) {
	rows := Derive(DeriveInput{
		ProxyRows: []ProxyRow{
			{Timestamp: "2026-09-22T10:00:00Z", Model: "claude-sonnet-4-6", Input: 100, Output: 150, CostUSD: 0.02},
		},
		TokenRows: []TokenRow{
			// Shape-matches the proxy row above (gross output 150 = 100
			// visible + 50 reasoning) but carries no id of its own either.
			{Timestamp: "2026-09-22T10:00:01Z", Model: "claude-sonnet-4-6", Input: 100, Output: 100, Reasoning: 50},
		},
		Mode: RollupTurn,
	})
	if len(rows) != 1 {
		t.Fatalf("want 1 merged row (keyless proxy+token twin fold via shape match), got %d: %v", len(rows), keys(rows))
	}
	if rows[0].Bundle.Output != 100 || rows[0].Bundle.Reasoning != 50 {
		t.Errorf("want the twin's reasoning split applied (output=100/reasoning=50), got output=%d reasoning=%d", rows[0].Bundle.Output, rows[0].Bundle.Reasoning)
	}
}

// TestDerive_KeylessRows_EqualTimestampOrderIndependent is review round 6
// finding F3: two id-less token rows sharing one timestamp used to resolve
// their synthesized key from their ORDINAL POSITION in whatever order
// Derive happened to receive them. A caller's SQL ORDER BY can't
// disambiguate that tie — both readers' secondary sort key (request_id /
// source_event_id) is itself empty for a genuinely keyless row, so SQLite
// and PostgreSQL give no portable guarantee about which physical row scans
// first among equal-timestamp keyless rows. Feeding Derive the identical
// two rows in either arrival order must therefore yield the identical
// (input, key) pairing now that the key is derived from the rows' own
// content (fingerprint) instead of their position.
func TestDerive_KeylessRows_EqualTimestampOrderIndependent(t *testing.T) {
	a := TokenRow{Timestamp: "2026-09-23T10:00:00Z", Model: "m", Input: 10, Output: 1}
	b := TokenRow{Timestamp: "2026-09-23T10:00:00Z", Model: "m", Input: 20, Output: 2}

	forward := Derive(DeriveInput{TokenRows: []TokenRow{a, b}, Mode: RollupTurn})
	reverse := Derive(DeriveInput{TokenRows: []TokenRow{b, a}, Mode: RollupTurn})

	if len(forward) != 2 || len(reverse) != 2 {
		t.Fatalf("want 2 rows each way, got forward=%d reverse=%d", len(forward), len(reverse))
	}

	keyForInput := func(rows []*Row, input int64) string {
		t.Helper()
		for _, r := range rows {
			if r.Bundle.Input == input {
				return r.Key
			}
		}
		t.Fatalf("no row with input=%d in %v", input, keys(rows))
		return ""
	}

	fwdKeyA, fwdKeyB := keyForInput(forward, 10), keyForInput(forward, 20)
	revKeyA, revKeyB := keyForInput(reverse, 10), keyForInput(reverse, 20)

	if fwdKeyA != revKeyA {
		t.Errorf("input=10 row's key depends on arrival order: forward=%q reverse=%q", fwdKeyA, revKeyA)
	}
	if fwdKeyB != revKeyB {
		t.Errorf("input=20 row's key depends on arrival order: forward=%q reverse=%q", fwdKeyB, revKeyB)
	}
	if fwdKeyA == fwdKeyB {
		t.Errorf("two distinct-content keyless rows must not share a key, got %q for both", fwdKeyA)
	}
	for _, r := range forward {
		if !r.Keyless {
			t.Errorf("want Keyless=true on both synthesized rows, row key=%q", r.Key)
		}
	}
}

// TestDerive_KeylessProxyRows_EqualTimestampOrderIndependent is the proxy-
// row twin of TestDerive_KeylessRows_EqualTimestampOrderIndependent —
// foldProxyRows/resolveKeylessProxyKeys share the same content-fingerprint
// mechanism, so the same order-independence must hold there too.
func TestDerive_KeylessProxyRows_EqualTimestampOrderIndependent(t *testing.T) {
	a := ProxyRow{Timestamp: "2026-09-23T10:00:00Z", Model: "m", Input: 10, Output: 1}
	b := ProxyRow{Timestamp: "2026-09-23T10:00:00Z", Model: "m", Input: 20, Output: 2}

	forward := Derive(DeriveInput{ProxyRows: []ProxyRow{a, b}, Mode: RollupTurn})
	reverse := Derive(DeriveInput{ProxyRows: []ProxyRow{b, a}, Mode: RollupTurn})

	if len(forward) != 2 || len(reverse) != 2 {
		t.Fatalf("want 2 rows each way, got forward=%d reverse=%d", len(forward), len(reverse))
	}

	keyForInput := func(rows []*Row, input int64) string {
		t.Helper()
		for _, r := range rows {
			if r.Bundle.Input == input {
				return r.Key
			}
		}
		t.Fatalf("no row with input=%d in %v", input, keys(rows))
		return ""
	}

	if got, want := keyForInput(forward, 10), keyForInput(reverse, 10); got != want {
		t.Errorf("input=10 row's key depends on arrival order: forward=%q reverse=%q", got, want)
	}
	if got, want := keyForInput(forward, 20), keyForInput(reverse, 20); got != want {
		t.Errorf("input=20 row's key depends on arrival order: forward=%q reverse=%q", got, want)
	}
	if keyForInput(forward, 10) == keyForInput(forward, 20) {
		t.Errorf("two distinct-content keyless proxy rows must not share a key")
	}
}

// TestDerive_KeylessRows_DuplicateContentOrderIndependent covers the
// residual tie canonicalizeKeyless must still break: two BYTE-IDENTICAL
// keyless token rows (same timestamp, same fingerprint) resolve to two
// DISTINCT keys (consecutive dup ordinals) rather than colliding/merging,
// and — because the two source rows are content-identical — the aggregate
// result (two rows, each carrying the shared bundle) is the same
// regardless of which physical instance a caller's scan happened to hand
// Derive first (there is nothing to tell them apart by, so it doesn't
// matter which gets ordinal 0 vs 1).
func TestDerive_KeylessRows_DuplicateContentOrderIndependent(t *testing.T) {
	row := TokenRow{Timestamp: "2026-09-23T11:00:00Z", Model: "m", Input: 7, Output: 3}

	rows := Derive(DeriveInput{TokenRows: []TokenRow{row, row}, Mode: RollupTurn})
	if len(rows) != 2 {
		t.Fatalf("want 2 distinct rows for two byte-identical keyless inputs, got %d: %v", len(rows), keys(rows))
	}
	if rows[0].Key == rows[1].Key {
		t.Errorf("want distinct dup-ordinal keys for byte-identical rows, got %q twice", rows[0].Key)
	}
	for _, r := range rows {
		if r.Bundle.Input != 7 || r.Bundle.Output != 3 {
			t.Errorf("want each row's bundle to match the shared source row, got input=%d output=%d", r.Bundle.Input, r.Bundle.Output)
		}
		if !r.Keyless {
			t.Errorf("want Keyless=true on both duplicate rows")
		}
	}
}

// TestDerive_KeylessFingerprint_ExcludesFastAndCost is round 7 finding F3:
// Fast and CostUSD are not wire-stable (see fingerprintProxyRow's doc
// comment for the field-by-field wire evidence) and must not participate
// in a keyless row's synthesized identity. Two otherwise byte-identical
// keyless token rows that disagree ONLY on Fast/CostUSD must now collapse
// into the SAME fingerprint group — exactly like
// TestDerive_KeylessRows_DuplicateContentOrderIndependent's byte-identical
// case — rather than each hashing to its own distinct fingerprint, which
// is what let the node (real Fast/Cost) and the org (Fast always false,
// Cost possibly repriced) resolve DIFFERENT synthetic keys for what is,
// on the wire, the identical row.
//
// Round 8 finding F4 (VERIFIED against this exact test): the original
// version of this test compared only the resolved KEY SET between arrival
// orders and declared "which physical row lands on which ordinal is
// immaterial" — but it is NOT immaterial for the node itself, which holds
// Fast/CostUSD and folds them into row.Bundle.Fast / row.RecordedCostUSD.
// Reversing scan order used to swap which bundle (fast=true,cost=0 vs
// fast=false,cost=0.05) ended up under the ":0" ordinal vs the ":1"
// ordinal, even though the KEY SET itself looked identical either way —
// exactly the counterexample the finding gave. This rewrite asserts the
// actual key -> bundle mapping is identical (not just the key set) across
// both arrival orders.
func TestDerive_KeylessFingerprint_ExcludesFastAndCost(t *testing.T) {
	a := TokenRow{Timestamp: "2026-09-23T12:00:00Z", Model: "m", Input: 7, Output: 3, Fast: true, CostUSD: 0}
	b := TokenRow{Timestamp: "2026-09-23T12:00:00Z", Model: "m", Input: 7, Output: 3, Fast: false, CostUSD: 0.05}

	forward := Derive(DeriveInput{TokenRows: []TokenRow{a, b}, Mode: RollupTurn})
	reverse := Derive(DeriveInput{TokenRows: []TokenRow{b, a}, Mode: RollupTurn})
	if len(forward) != 2 || len(reverse) != 2 {
		t.Fatalf("want 2 rows each way, got forward=%d reverse=%d", len(forward), len(reverse))
	}
	if forward[0].Key == forward[1].Key {
		t.Fatalf("want distinct dup-ordinal keys even though both rows share one fingerprint, got %q twice", forward[0].Key)
	}

	// The KEY SET must be identical regardless of arrival order — the
	// actual node/org divergence risk.
	keySet := func(rows []*Row) map[string]bool {
		out := map[string]bool{}
		for _, r := range rows {
			out[r.Key] = true
		}
		return out
	}
	if !reflect.DeepEqual(keySet(forward), keySet(reverse)) {
		t.Errorf("key set depends on arrival order: forward=%v reverse=%v", keySet(forward), keySet(reverse))
	}

	// F4: the key -> bundle MAPPING (not just the key set) must also be
	// identical regardless of arrival order — each key must resolve to
	// the SAME physical row's Fast/CostUSD content both ways.
	byKey := func(rows []*Row) map[string]*Row {
		out := make(map[string]*Row, len(rows))
		for _, r := range rows {
			out[r.Key] = r
		}
		return out
	}
	fwdByKey, revByKey := byKey(forward), byKey(reverse)
	for key, fr := range fwdByKey {
		rr, ok := revByKey[key]
		if !ok {
			t.Fatalf("key %q present forward but not reverse: forward=%v reverse=%v", key, keys(forward), keys(reverse))
		}
		if fr.Bundle.Fast != rr.Bundle.Fast || fr.RecordedCostUSD != rr.RecordedCostUSD {
			t.Errorf("key %q bundle depends on arrival order: forward={fast:%v cost:%v} reverse={fast:%v cost:%v}",
				key, fr.Bundle.Fast, fr.RecordedCostUSD, rr.Bundle.Fast, rr.RecordedCostUSD)
		}
	}

	for _, r := range forward {
		if !r.Keyless {
			t.Errorf("want Keyless=true, row key=%q", r.Key)
		}
	}
}

// TestDerive_TwinFold_EqualDistanceTieBreaksOnFingerprint is round 7
// finding F4: a proxy row with TWO equal-timestamp (so equidistant),
// equally shape-matching token candidates that disagree on the
// output/reasoning SPLIT (both sum to the proxy's gross output, so both
// pass shapeMatches) must resolve to the SAME twin regardless of which
// order the caller happened to hand the two candidates to Derive in —
// assignTwins' old "first encountered wins a tie" rule made the pick
// depend on arrival order, which is exactly what a caller's non-portable
// SQL scan order (node vs org) could flip.
func TestDerive_TwinFold_EqualDistanceTieBreaksOnFingerprint(t *testing.T) {
	proxy := ProxyRow{Timestamp: "2026-09-23T13:00:00Z", Model: "m", Input: 100, Output: 150}
	// Both candidates: Input=100 (net), Output+Reasoning=150 (gross),
	// same timestamp as the proxy row (delta=0 for both) — genuinely
	// equidistant, genuinely different content (the split).
	candA := TokenRow{Timestamp: "2026-09-23T13:00:00Z", Model: "m", Input: 100, Output: 100, Reasoning: 50}
	candB := TokenRow{Timestamp: "2026-09-23T13:00:00Z", Model: "m", Input: 100, Output: 90, Reasoning: 60}

	// Both candidates shape-match the proxy row, so only ONE is claimed as
	// the twin (merging into the proxy's row); the other survives as its
	// own, separate keyless row — hence 2 rows total, not 1. Pull out the
	// proxy-merged row (IsProxy=true) specifically.
	build := func(tokens []TokenRow) *Row {
		rows := Derive(DeriveInput{ProxyRows: []ProxyRow{proxy}, TokenRows: tokens, Mode: RollupTurn})
		if len(rows) != 2 {
			t.Fatalf("want 2 rows (twin-merged proxy row + surviving unpicked candidate), got %d: %v", len(rows), keys(rows))
		}
		for _, r := range rows {
			if r.IsProxy {
				return r
			}
		}
		t.Fatalf("no proxy row found among %v", keys(rows))
		return nil
	}

	forward := build([]TokenRow{candA, candB})
	reverse := build([]TokenRow{candB, candA})

	if forward.Bundle.Output != reverse.Bundle.Output || forward.Bundle.Reasoning != reverse.Bundle.Reasoning {
		t.Errorf("twin pick depends on arrival order: forward={output:%d reasoning:%d} reverse={output:%d reasoning:%d}",
			forward.Bundle.Output, forward.Bundle.Reasoning, reverse.Bundle.Output, reverse.Bundle.Reasoning)
	}
	// Pin the deterministic winner explicitly (smaller fingerprintTokenRow)
	// so this test would catch a tie-break direction regression too, not
	// just an order-independence one.
	wantOutput, wantReasoning := candA.Output, candA.Reasoning
	if fingerprintTokenRow(candB) < fingerprintTokenRow(candA) {
		wantOutput, wantReasoning = candB.Output, candB.Reasoning
	}
	if forward.Bundle.Output != wantOutput || forward.Bundle.Reasoning != wantReasoning {
		t.Errorf("want deterministic winner output=%d reasoning=%d (smaller fingerprint), got output=%d reasoning=%d",
			wantOutput, wantReasoning, forward.Bundle.Output, forward.Bundle.Reasoning)
	}
}

// TestDerive_TwinFold_EqualFingerprintTieBreaksOnFastCost is round 8
// finding F4 (the literal counterexample the finding gave): two candidate
// token rows equidistant from the proxy row's timestamp AND sharing an
// IDENTICAL wire fingerprint (same model/input/output+reasoning-sum/cache)
// — genuinely distinct physical rows that disagree ONLY on Fast/CostUSD,
// exactly the "fast=true,cost=0 vs fast=false,cost=.05" pair the finding
// cited. Before this fix, assignTwins' tie-break compared
// fingerprintTokenRow alone; since that ties too, `best` kept whichever
// candidate the loop reached first — i.e. reversing the caller's scan
// order silently swapped which candidate's Fast state the merged proxy
// row inherited. lessTokenCandidate's local (Fast, CostUSD) tier must now
// make that pick a pure function of the row set.
func TestDerive_TwinFold_EqualFingerprintTieBreaksOnFastCost(t *testing.T) {
	proxy := ProxyRow{Timestamp: "2026-09-23T13:30:00Z", Model: "m", Input: 100, Output: 150}
	// Both candidates: Input=100 (net), Output+Reasoning=150 (gross), same
	// timestamp as the proxy row (delta=0 for both), same output/reasoning
	// SPLIT (75/75) — so fingerprintTokenRow(candA) == fingerprintTokenRow(candB)
	// exactly (Fast/CostUSD are excluded from that hash by round 7 F3).
	// They differ ONLY in Fast/CostUSD, the literal round 8 F4 counterexample.
	candFastFree := TokenRow{Timestamp: "2026-09-23T13:30:00Z", Model: "m", Input: 100, Output: 75, Reasoning: 75, Fast: true, CostUSD: 0}
	candSlowPaid := TokenRow{Timestamp: "2026-09-23T13:30:00Z", Model: "m", Input: 100, Output: 75, Reasoning: 75, Fast: false, CostUSD: 0.05}

	if fingerprintTokenRow(candFastFree) != fingerprintTokenRow(candSlowPaid) {
		t.Fatalf("test setup bug: candidates must share one wire fingerprint, got %q vs %q",
			fingerprintTokenRow(candFastFree), fingerprintTokenRow(candSlowPaid))
	}

	// Pull out the twin-merged proxy row (IsProxy=true) specifically —
	// the other candidate survives as its own separate keyless row.
	build := func(tokens []TokenRow) *Row {
		rows := Derive(DeriveInput{ProxyRows: []ProxyRow{proxy}, TokenRows: tokens, Mode: RollupTurn})
		if len(rows) != 2 {
			t.Fatalf("want 2 rows (twin-merged proxy row + surviving unpicked candidate), got %d: %v", len(rows), keys(rows))
		}
		for _, r := range rows {
			if r.IsProxy {
				return r
			}
		}
		t.Fatalf("no proxy row found among %v", keys(rows))
		return nil
	}

	forward := build([]TokenRow{candFastFree, candSlowPaid})
	reverse := build([]TokenRow{candSlowPaid, candFastFree})

	if forward.Bundle.Fast != reverse.Bundle.Fast {
		t.Errorf("twin pick's inherited fast state depends on arrival order: forward=%v reverse=%v", forward.Bundle.Fast, reverse.Bundle.Fast)
	}

	// Pin the deterministic winner explicitly (smaller localTiebreak over
	// (Fast, CostUSD) — the only remaining signal once the wire fingerprint
	// already ties) so this test would catch a tie-break direction
	// regression, not just an order-independence one.
	wantFast := candFastFree.Fast
	if localTiebreak(candSlowPaid.Fast, candSlowPaid.CostUSD) < localTiebreak(candFastFree.Fast, candFastFree.CostUSD) {
		wantFast = candSlowPaid.Fast
	}
	if forward.Bundle.Fast != wantFast {
		t.Errorf("want deterministic winner fast=%v (smaller local tiebreak), got fast=%v", wantFast, forward.Bundle.Fast)
	}
}

// TestPickShadowPartner_EqualDistanceTieBreaksOnFingerprint is F4's
// shadow-pairing twin, exercising pickShadowPartner directly (white-box,
// same package) so the actual PICK — not just whether pairing happened at
// all — can be asserted: a shadow row equidistant from two id-less
// full-usage candidates that differ in content (distinguishable via
// fingerprintTokenRow, here via CacheRead) must pick the SAME partner
// regardless of the order `fulls` is handed in, which is exactly the
// order the canonical presort (orderedTokenIndex) now controls end to end.
func TestPickShadowPartner_EqualDistanceTieBreaksOnFingerprint(t *testing.T) {
	shadow := TokenRow{SourceEventID: "shadow", Timestamp: "2026-09-23T14:00:00Z", Output: 50}
	// Both candidates are id-less full-usage rows, equidistant from the
	// shadow (10s before / 10s after), differing in CacheRead so their
	// fingerprints differ.
	fullA := TokenRow{SourceEventID: "full-a", Timestamp: "2026-09-23T13:59:50Z", Output: 50, Input: 10, CacheRead: 1}
	fullB := TokenRow{SourceEventID: "full-b", Timestamp: "2026-09-23T14:00:10Z", Output: 50, Input: 10, CacheRead: 2}

	tokens := []TokenRow{shadow, fullA, fullB} // index 0=shadow, 1=fullA, 2=fullB
	pickAB := pickShadowPartner(tokens, 0, []int{1, 2}, map[int]bool{})
	pickBA := pickShadowPartner(tokens, 0, []int{2, 1}, map[int]bool{})

	if pickAB == -1 || pickBA == -1 {
		t.Fatalf("want a partner picked both ways, got pickAB=%d pickBA=%d", pickAB, pickBA)
	}
	gotAB, gotBA := tokens[pickAB].SourceEventID, tokens[pickBA].SourceEventID
	if gotAB != gotBA {
		t.Errorf("shadow partner pick depends on candidate order: fulls=[1,2] picked %q, fulls=[2,1] picked %q", gotAB, gotBA)
	}
	// The deterministic winner is whichever candidate has the smaller
	// fingerprintTokenRow — pin that explicitly so this test would catch a
	// tie-break direction regression, not just an order-independence one.
	want := fullA.SourceEventID
	if fingerprintTokenRow(fullB) < fingerprintTokenRow(fullA) {
		want = fullB.SourceEventID
	}
	if gotAB != want {
		t.Errorf("want deterministic winner %q (smaller fingerprint), got %q", want, gotAB)
	}
}

func containsStr(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}
