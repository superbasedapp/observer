package store

import (
	"context"
	"strings"
	"testing"
	"time"
)

// Bundle BUD-N store tests: the per-subject slice of the guard's one spend
// read. What is being pinned is not "a map comes back" but that the subject
// totals obey the SAME window bounds and the SAME per-session
// MAX(proxy, watcher) de-duplication as the node-wide totals they sit beside —
// a per-tool cap that contradicted the daily cap would be unexplainable to the
// developer it stopped.

func TestGuardBudgetSpendPriced_PerSubjectTotals(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "sess")
	guardBudgetTestSession(t, s, "other")
	day, week, month := guardBudgetTestWindows()
	inDay := day.Add(2 * time.Hour)
	inMonthNotDay := month.Add(2 * time.Hour) // inside the month, before the day
	beforeMonth := month.Add(-48 * time.Hour)

	// The natively captured substrate names a TOOL; the proxy substrate never
	// does (api_turns has no tool column at all) but does name the model.
	insertGuardBudgetUsage(t, db, "sess", "claude-sonnet", "u1", inDay, 100, 50, 2)
	insertGuardBudgetUsage(t, db, "sess", "claude-sonnet", "u2", inMonthNotDay, 10, 5, 1)
	insertGuardBudgetUsage(t, db, "other", "claude-sonnet", "u3", inDay, 10, 5, 4)
	insertGuardBudgetUsage(t, db, "sess", "claude-sonnet", "u4", beforeMonth, 999, 999, 99)
	insertGuardBudgetAPI(t, db, "sess", "claude-sonnet", inDay, 20, 10, 0.5)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false })
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}

	tool := spend.ByTool["claude-code"]
	// DAILY, tool: session "sess" contributes MAX(proxy 0.50, watcher 2.00) = 2,
	// but the proxy row names no tool, so the tool bucket sees the watcher side
	// only. Session "other" adds its own 4.
	assertGuardBudgetNear(t, "ByTool[claude-code].DailyUSD", tool.DailyUSD, 6)
	if tool.DailyTokens != 150+15 {
		t.Errorf("ByTool[claude-code].DailyTokens = %d, want %d", tool.DailyTokens, 165)
	}
	// MONTHLY picks up the extra in-month row; the pre-month one is outside
	// every window and must not appear anywhere.
	assertGuardBudgetNear(t, "ByTool[claude-code].MonthlyUSD", tool.MonthlyUSD, 7)
	// SESSION is scoped to the REQUESTED session and, exactly like the
	// node-wide session total, is NOT time-bounded: a session budget spans the
	// session's lifetime, so the row from before the month boundary counts
	// here and nowhere else (2 + 1 + 99).
	assertGuardBudgetNear(t, "ByTool[claude-code].SessionUSD", tool.SessionUSD, 102)

	model := spend.ByModel["claude-sonnet"]
	// The model bucket sees BOTH substrates, so the requested session's day
	// resolves to MAX(proxy 0.50, watcher 2.00) = 2, plus "other"'s 4.
	assertGuardBudgetNear(t, "ByModel[claude-sonnet].DailyUSD", model.DailyUSD, 6)
	// The same session-lifetime rule in tokens, folded MAX against the proxy
	// substrate's 30: 150 + 15 + 1998.
	if got := spend.ByModel["claude-sonnet"].SessionTokens; got != 2163 {
		t.Errorf("ByModel session tokens = %d, want 2163", got)
	}
	// And the node-wide session total agrees with the subject slice.
	assertGuardBudgetNear(t, "SessionUSD", spend.SessionUSD, 102)
	// The node-wide totals must agree with the subject slice about the same
	// rows: same query, same windows, same fold.
	assertGuardBudgetNear(t, "DailyUSD", spend.DailyUSD, 6)

	if spend.SessionTool != "claude-code" {
		t.Errorf("SessionTool = %q, want claude-code", spend.SessionTool)
	}
	if spend.SessionModel != "claude-sonnet" {
		t.Errorf("SessionModel = %q, want claude-sonnet", spend.SessionModel)
	}
}

// TestGuardBudgetSpendPriced_SubjectKeysAreNormalized pins the one rule both
// ends of a subject cap are compared under: the organization typed the cap's
// id, an adapter captured the row's, and they must meet.
func TestGuardBudgetSpendPriced_SubjectKeysAreNormalized(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "sess")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, db, "sess", "Claude-Sonnet-4-5", "u1", day.Add(time.Hour), 10, 10, 1)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false })
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if _, ok := spend.ByModel["claude-sonnet-4-5"]; !ok {
		t.Fatalf("ByModel keys = %v, want the lowercased id", keysOf(spend.ByModel))
	}
	if spend.SessionModel != "claude-sonnet-4-5" {
		t.Errorf("SessionModel = %q, want the lowercased id", spend.SessionModel)
	}
}

// TestGuardBudgetSpendPriced_AmbiguousSessionResolvesNoSubject pins the honesty
// rule behind SessionTool/SessionModel: they exist so the proxy admission lane
// (a session id and nothing else) can scope a subject cap, and a session whose
// rows disagree resolves to NEITHER rather than to a coin flip.
func TestGuardBudgetSpendPriced_AmbiguousSessionResolvesNoSubject(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "sess")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetUsage(t, db, "sess", "model-a", "u1", day.Add(time.Hour), 10, 10, 1)
	insertGuardBudgetUsage(t, db, "sess", "model-b", "u2", day.Add(2*time.Hour), 10, 10, 1)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false })
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if spend.SessionModel != "" {
		t.Errorf("SessionModel = %q, want empty for a two-model session", spend.SessionModel)
	}
	// Each model still has its OWN bucket: ambiguity blocks the session-level
	// shortcut, not the per-subject accounting.
	if len(spend.ByModel) != 2 {
		t.Errorf("ByModel = %v, want both models", keysOf(spend.ByModel))
	}
}

// TestGuardBudgetSpendPriced_NoSubjectsWithoutIdentifiers pins that nothing is
// attributed on faith: a proxy row names no tool and must not land in any
// tool bucket.
func TestGuardBudgetSpendPriced_NoSubjectsWithoutIdentifiers(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "sess")
	day, week, month := guardBudgetTestWindows()
	insertGuardBudgetAPI(t, db, "sess", "claude-sonnet", day.Add(time.Hour), 20, 10, 3)

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false })
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if len(spend.ByTool) != 0 {
		t.Errorf("ByTool = %v, want empty — a proxy turn names no tool", keysOf(spend.ByTool))
	}
	if spend.SessionTool != "" {
		t.Errorf("SessionTool = %q, want empty", spend.SessionTool)
	}
	assertGuardBudgetNear(t, "ByModel[claude-sonnet].DailyUSD", spend.ByModel["claude-sonnet"].DailyUSD, 3)
}

func keysOf(m map[string]GuardBudgetSubjectWindows) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestGuardBudgetSpendPriced_SubjectResolverFoldsModelAliases is the P1-3 alias
// pair on the ACCOUNTING side: two spellings of one model must land in ONE
// ByModel bucket, because the org's cap was composed onto that same resolved
// identity. Without it a dated model name and its family are two subjects and
// the cap sees half the spend.
func TestGuardBudgetSpendPriced_SubjectResolverFoldsModelAliases(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "sess")
	day, week, month := guardBudgetTestWindows()
	inDay := day.Add(2 * time.Hour)

	insertGuardBudgetUsage(t, db, "sess", "claude-sonnet-5", "u1", inDay, 100, 50, 2)
	insertGuardBudgetUsage(t, db, "sess", "claude-sonnet-5-20260501", "u2", inDay, 100, 50, 3)

	pricer := func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false }

	// WITHOUT a resolver: two buckets, and a cap on either sees half the spend.
	plain, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month, pricer)
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if len(plain.ByModel) != 2 {
		t.Fatalf("ByModel = %+v, want the two unresolved spellings", plain.ByModel)
	}
	if plain.SessionModel != "" {
		t.Errorf("SessionModel = %q, want empty (two spellings read as ambiguous)", plain.SessionModel)
	}

	// WITH the price table's ladder (stood in for here): one subject.
	resolve := func(kind, id string) string {
		if kind == "model" && strings.HasPrefix(id, "claude-sonnet-5") {
			return "claude-sonnet-5"
		}
		return id
	}
	folded, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month, pricer,
		GuardBudgetReadOptions{ResolveSubject: resolve})
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	if len(folded.ByModel) != 1 {
		t.Fatalf("ByModel = %+v, want one folded subject", folded.ByModel)
	}
	assertGuardBudgetNear(t, "ByModel[claude-sonnet-5].DailyUSD", folded.ByModel["claude-sonnet-5"].DailyUSD, 5)
	if folded.SessionModel != "claude-sonnet-5" {
		t.Errorf("SessionModel = %q, want claude-sonnet-5", folded.SessionModel)
	}
	// A TOOL has no alias ladder and must be untouched by the same resolver.
	if _, ok := folded.ByTool["claude-code"]; !ok {
		t.Errorf("ByTool = %+v, want the captured tool id unchanged", folded.ByTool)
	}
}

// TestGuardBudgetSpendPriced_MalformedTimestampBucketsLikeTheTokenCTE is P2-7:
// the per-subject buckets key on the SAME derived ordering value the node-wide
// token CTE derives in SQL, so one malformed row cannot be inside the daily
// token total and outside the daily per-tool total over the same corpus.
func TestGuardBudgetSpendPriced_MalformedTimestampBucketsLikeTheTokenCTE(t *testing.T) {
	s, db := newTestStore(t)
	guardBudgetTestSession(t, s, "sess")
	day, week, month := guardBudgetTestWindows()

	// A timestamp Go's RFC3339Nano parser rejects (no zone) sitting EXACTLY on
	// the day boundary — the shape where the two keys disagreed. Compared raw,
	// "2026-09-10T00:00:00" is a strict prefix of the canonical boundary stamp
	// and therefore sorts BELOW it (outside the day); padded the way the SQL
	// pads it, it equals the boundary and is inside, which is where the token
	// CTE has always put it.
	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO token_usage(
			session_id, timestamp, tool, model, input_tokens, output_tokens,
			estimated_cost_usd, source, reliability, source_event_id)
		VALUES ('sess', '2026-09-10T00:00:00', 'claude-code', 'm', 100, 50, 2, 'jsonl', 'accurate', 'bad')`,
	); err != nil {
		t.Fatalf("insert malformed row: %v", err)
	}

	spend, err := s.GuardBudgetSpendPriced(context.Background(), "sess", day, week, month,
		func(string, time.Time, PushTokenSplit) (float64, string, bool) { return 0, "miss", false })
	if err != nil {
		t.Fatalf("GuardBudgetSpendPriced: %v", err)
	}
	tok, err := s.GuardBudgetTokens(context.Background(), "sess", day, week, month)
	if err != nil {
		t.Fatalf("GuardBudgetTokens: %v", err)
	}
	// The assertion that matters is AGREEMENT, not a particular bucket: both
	// reads decide the same row belongs to the same windows.
	inSubjectDay := spend.ByTool["claude-code"].DailyTokens > 0
	inNodeWideDay := tok.DailyTokens > 0
	if inSubjectDay != inNodeWideDay {
		t.Errorf("malformed row bucketed differently: per-subject daily=%v, node-wide daily=%v",
			inSubjectDay, inNodeWideDay)
	}
	if spend.ByTool["claude-code"].DailyTokens != tok.DailyTokens {
		t.Errorf("per-subject daily tokens %d != node-wide daily tokens %d",
			spend.ByTool["claude-code"].DailyTokens, tok.DailyTokens)
	}
	if !inNodeWideDay {
		t.Fatalf("the boundary row fell outside the token CTE's day window; the case no longer exercises the divergence")
	}
	// And the node-wide DOLLAR read keys the same row the same way, so the
	// three reads in this function cannot disagree about one row.
	assertGuardBudgetNear(t, "DailyUSD", spend.DailyUSD, 2)
}

// TestGuardBudgetOrderedAt mirrors the SQL expression's own table.
func TestGuardBudgetOrderedAt(t *testing.T) {
	cases := []struct{ in, want string }{
		{"2026-09-10T02:00:00Z", "2026-09-10T02:00:00.000000000Z"},
		{"2026-09-10T02:00:00.1Z", "2026-09-10T02:00:00.100000000Z"},
		{"2026-09-10T02:00:00.123456789Z", "2026-09-10T02:00:00.123456789Z"},
		{"2026-09-10T02:00:00", "2026-09-10T02:00:00.000000000Z"},
		{"", ".000000000Z"},
	}
	for _, tc := range cases {
		if got := guardBudgetOrderedAt(tc.in); got != tc.want {
			t.Errorf("guardBudgetOrderedAt(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
