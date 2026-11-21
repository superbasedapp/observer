package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
)

func TestPlanAccountsRoundTrip(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	a := PlanAccountRow{
		ID: "acc-1", Provider: planlimits.ProviderOpenRouter, Source: planlimits.SourceOpenRouter,
		Label: "Personal", Params: map[string]string{"x": "y"}, SecretKeys: []string{"key"}, Enabled: true,
	}
	if err := st.InsertPlanAccount(ctx, a); err != nil {
		t.Fatal(err)
	}
	got, err := st.PlanAccount(ctx, "acc-1")
	if err != nil || got.Label != "Personal" || got.Params["x"] != "y" || len(got.SecretKeys) != 1 || !got.Enabled {
		t.Fatalf("round trip %+v %v", got, err)
	}
	now := time.Unix(1_760_000_000, 0).UTC()
	st2 := planlimits.RunState{Status: planlimits.StatusAuthNeeded, Failures: 2, Stopped: true, NextDue: now}
	if err := st.UpdatePlanAccountState(ctx, "acc-1", st2, now); err != nil {
		t.Fatal(err)
	}
	got, _ = st.PlanAccount(ctx, "acc-1")
	if got.State.Status != planlimits.StatusAuthNeeded || !got.State.Stopped || !got.LastRunAt.Equal(now) {
		t.Fatalf("state %+v", got.State)
	}
	got.Label = "Work"
	if err := st.UpdatePlanAccount(ctx, got); err != nil {
		t.Fatal(err)
	}
	got, _ = st.PlanAccount(ctx, "acc-1")
	if got.Label != "Work" || got.State.Stopped {
		t.Fatalf("an edit must clear a stopped poll: %+v", got)
	}

	snap := planlimits.Snapshot{
		Provider: planlimits.ProviderOpenRouter, Source: planlimits.SourceOpenRouter,
		Kind: planlimits.KindOfficialAPI, Rung: planlimits.RungOfficial, Status: planlimits.StatusOK, ObservedAt: now,
		Balances: []planlimits.Balance{{Kind: "prepaid", Unit: planlimits.UnitUSDMicros, Amount: 5}},
	}
	for i := 0; i < 3; i++ {
		snap.ObservedAt = now.Add(time.Duration(i) * time.Minute)
		if err := st.InsertPlanSnapshot(ctx, "acc-1", "", snap); err != nil {
			t.Fatal(err)
		}
	}
	latest, err := st.LatestPlanSnapshots(ctx)
	if err != nil || !latest["acc-1"].ObservedAt.Equal(now.Add(2*time.Minute)) {
		t.Fatalf("latest %+v %v", latest, err)
	}
	hist, _ := st.PlanSnapshotHistory(ctx, "acc-1", now, 10)
	if len(hist) != 3 || !hist[0].ObservedAt.Equal(now) {
		t.Fatalf("history %d", len(hist))
	}
	if err := st.InsertPlanRun(ctx, PlanRunRow{AccountID: "acc-1", StartedAt: now, EndedAt: now, Outcome: "ok", Detail: string(make([]byte, 500))}); err != nil {
		t.Fatal(err)
	}
	runs, _ := st.RecentPlanRuns(ctx, "acc-1", 5)
	if len(runs) != 1 || len(runs[0].Detail) != maxPlanRunDetail {
		t.Fatalf("runs %+v", runs)
	}
	// Prune keeps the newest snapshot of the account.
	if _, err := st.PrunePlanHistory(ctx, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if hist, _ := st.PlanSnapshotHistory(ctx, "acc-1", time.Unix(0, 0), 10); len(hist) != 1 {
		t.Fatalf("prune kept %d", len(hist))
	}

	if err := st.SetPlanOptIn(ctx, planlimits.ProviderCursor, true); err != nil {
		t.Fatal(err)
	}
	_ = st.SetPlanOptIn(ctx, planlimits.ProviderCursor, true) // idempotent
	if o, _ := st.PlanOptIns(ctx); !o[planlimits.ProviderCursor] {
		t.Fatal("opt-in")
	}
	_ = st.SetPlanOptIn(ctx, planlimits.ProviderCursor, false)
	if o, _ := st.PlanOptIns(ctx); o[planlimits.ProviderCursor] {
		t.Fatal("opt-out")
	}

	if err := st.DeletePlanAccount(ctx, "acc-1"); err != nil {
		t.Fatal(err)
	}
	if _, err := st.PlanAccount(ctx, "acc-1"); !errors.Is(err, ErrPlanAccountNotFound) {
		t.Fatalf("deleted: %v", err)
	}
	if l, _ := st.LatestPlanSnapshots(ctx); len(l) != 0 {
		t.Fatal("snapshots must go with the account")
	}
	if err := st.DeletePlanAccount(ctx, "acc-1"); !errors.Is(err, ErrPlanAccountNotFound) {
		t.Fatalf("double delete: %v", err)
	}
}

func TestLoadPlanPassiveSignals(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	now := time.Unix(1_760_000_000, 0).UTC()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/p', ?)`, timestamp(now))
	exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s-claude', 1, 'claude-code', ?)`, timestamp(now))
	exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s-codex', 1, 'codex', ?)`, timestamp(now))
	exec(`INSERT INTO tool_account_observations (session_id, tool, binding_kind, binding_id, role, account_key, email, source, scope, stage, observed_at)
		VALUES ('s-claude', 'claude-code', 'session', 's-claude', 'primary', 'k1', 'me@example.test', 'hook', 'session', 'final', ?)`, timestamp(now))
	// Two proxy rows for one session: only the newest is read.
	for i, u := range []float64{0.2, 0.3} {
		exec(`INSERT INTO limit_snapshots (scope_hash, provider, session_id, observed_at, window_5h_util, window_5h_reset)
			VALUES ('default', 'anthropic', 's-claude', ?, ?, ?)`, now.Add(time.Duration(i)*time.Minute).Unix(), u, now.Add(3*time.Hour).Unix())
	}
	// A row without windows and an old row are not read.
	exec(`INSERT INTO limit_snapshots (scope_hash, provider, observed_at, req_limit) VALUES ('default', 'anthropic', ?, 5)`, now.Unix())
	exec(`INSERT INTO limit_snapshots (scope_hash, provider, observed_at, window_5h_util) VALUES ('default', 'anthropic', ?, 0.9)`, now.Add(-30*24*time.Hour).Unix())
	exec(`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, raw_tool_input) VALUES ('s-codex', 1, ?, 'rate_limit', 'codex', ?)`,
		timestamp(now), `{"primary":{"used_percent":40,"window_minutes":10080,"resets_at":1760400000},"plan_type":"plus"}`)
	sl := planlimits.Snapshot{
		Provider: planlimits.ProviderClaude, Source: planlimits.SourceClaudeStatusLine, Kind: planlimits.KindStatusLine,
		Rung: planlimits.RungOfficial, Status: planlimits.StatusOK, ObservedAt: now,
		Windows: []planlimits.Window{{Key: "5h", Unit: planlimits.UnitPercent, UsedFrac: planlimits.F(0.35)}},
	}
	if err := st.InsertPlanSnapshot(ctx, "", "s-claude", sl); err != nil {
		t.Fatal(err)
	}

	sig, err := st.LoadPlanPassiveSignals(ctx, now.Add(-8*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(sig.Limits) != 1 || *sig.Limits[0].Window5hUtil != 0.3 || sig.Limits[0].Tool != "claude-code" {
		t.Fatalf("limits %+v", sig.Limits)
	}
	if len(sig.Logs) != 1 || sig.Logs[0].Tool != "codex" {
		t.Fatalf("logs %+v", sig.Logs)
	}
	if len(sig.StatusLine) != 1 || sig.StatusLine[0].SessionID != "s-claude" {
		t.Fatalf("status line %+v", sig.StatusLine)
	}
	if len(sig.Accounts) != 1 || sig.Accounts[0].AccountKey != "k1" {
		t.Fatalf("accounts %+v", sig.Accounts)
	}
	bound := planlimits.BindPassive(sig.Limits, sig.Logs, sig.StatusLine, sig.Accounts)
	scopes := map[string]string{}
	for _, b := range bound {
		scopes[b.Source] = b.Scope
	}
	if scopes[planlimits.SourceClaudeProxy] != "acct:k1" || scopes[planlimits.SourceClaudeStatusLine] != "acct:k1" ||
		scopes[planlimits.SourceCodexLogs] != planlimits.DefaultScope {
		t.Fatalf("scopes %+v", scopes)
	}
	// The read never writes: limit_snapshots keeps its rows unchanged.
	var n int
	_ = st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM limit_snapshots WHERE scope_hash = 'default'`).Scan(&n)
	if n != 4 {
		t.Fatalf("limit_snapshots changed: %d rows", n)
	}
}

func TestPlanUsageDaily(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	t0 := time.Unix(1_760_000_000, 0).UTC()
	acct := PlanAccountRow{ID: "acc-cx", Provider: planlimits.ProviderChatGPT, Source: planlimits.SourceCodexAppServer, Enabled: true}
	if err := st.InsertPlanAccount(ctx, acct); err != nil {
		t.Fatal(err)
	}
	if days, last, err := st.PlanUsageDaily(ctx, "acc-cx", "2026-01-01", "2026-12-31"); err != nil || len(days) != 0 || !last.IsZero() {
		t.Fatalf("empty: %+v %v %v", days, last, err)
	}
	first := []planlimits.UsageDay{{Day: "2026-10-01", Tokens: 10}, {Day: "2026-10-02", Tokens: 20}}
	if err := st.UpsertPlanUsageDaily(ctx, "acc-cx", planlimits.ProviderChatGPT, first, t0); err != nil {
		t.Fatal(err)
	}
	// A later reading updates a day and omits another: the omitted day stays.
	later := []planlimits.UsageDay{{Day: "2026-10-02", Tokens: 25}, {Day: "2026-10-03", Tokens: 30}}
	if err := st.UpsertPlanUsageDaily(ctx, "acc-cx", planlimits.ProviderChatGPT, later, t0.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	days, last, err := st.PlanUsageDaily(ctx, "acc-cx", "2026-10-01", "2026-10-31")
	want := []planlimits.UsageDay{{Day: "2026-10-01", Tokens: 10}, {Day: "2026-10-02", Tokens: 25}, {Day: "2026-10-03", Tokens: 30}}
	if err != nil || len(days) != 3 || days[0] != want[0] || days[1] != want[1] || days[2] != want[2] {
		t.Fatalf("days %+v %v", days, err)
	}
	if !last.Equal(t0.Add(time.Hour)) {
		t.Fatalf("last fetched %v", last)
	}
	if days, _, _ := st.PlanUsageDaily(ctx, "acc-cx", "2026-10-02", "2026-10-02"); len(days) != 1 {
		t.Fatalf("window %+v", days)
	}
	// Removing the account removes its rows.
	if err := st.DeletePlanAccount(ctx, "acc-cx"); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM plan_usage_daily`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("rows left after remove: %d %v", n, err)
	}
	if err := st.UpsertPlanUsageDaily(ctx, "", planlimits.ProviderChatGPT, first, t0); err != nil {
		t.Fatal(err)
	}
}

func TestCapturedToolTokensByDay(t *testing.T) {
	st := newPredictTestStore(t)
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := st.db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	day := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	exec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/p', ?)`, timestamp(day))
	for _, s := range [][2]string{{"cx-1", "codex"}, {"cx-2", "codex"}, {"cc-1", "claude-code"}} {
		exec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES (?, 1, ?, ?)`, s[0], s[1], timestamp(day))
	}
	usage := func(sid, tool, ts string, in, cache, out, reasoning int64) {
		t.Helper()
		exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, cache_read_tokens, output_tokens, reasoning_tokens, source, reliability)
			VALUES (?, ?, ?, 'gpt-x', ?, ?, ?, ?, 'jsonl', 'accurate')`, sid, ts, tool, in, cache, out, reasoning)
	}
	usage("cx-1", "codex", "2026-10-08T01:00:00Z", 100, 1000, 10, 5) // 1115
	usage("cx-1", "codex", "2026-10-08T23:59:59Z", 1, 2, 3, 4)       // 10
	// A non-UTC offset lands on its UTC day: 2026-10-09 02:00 UTC.
	usage("cx-2", "codex", "2026-10-08T21:00:00-05:00", 7, 0, 0, 0)
	// Another tool and a day outside the window are not counted.
	usage("cc-1", "claude-code", "2026-10-08T05:00:00Z", 999, 0, 0, 0)
	usage("cx-2", "codex", "2026-10-05T05:00:00Z", 999, 0, 0, 0)
	// A proxy-only codex turn counts: input + cache read + output.
	exec(`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cache_read_tokens, cost_usd)
		VALUES ('cx-2', '2026-10-09T03:00:00Z', 'openai', 'gpt-x', 20, 30, 50, 0)`) // 100
	// A turn both the proxy and the transcript saw counts once (the stored
	// sessionmsg verdicts): 40 + 10.
	exec(`INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cache_read_tokens, cost_usd)
		VALUES ('cx-1', '2026-10-09T04:00:00Z', 'openai', 'gpt-x', 40, 10, 0, 0)`)
	exec(`INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, cache_read_tokens, output_tokens, source, reliability, source_event_id)
		VALUES ('cx-1', '2026-10-09T04:00:02Z', 'codex', 'gpt-x', 40, 0, 10, 'jsonl', 'accurate', 'tk-twin')`)

	got, err := st.CapturedToolTokensByDay(ctx, []string{"codex"}, "2026-10-07", "2026-10-09")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]int64{"2026-10-08": 1125, "2026-10-09": 157}
	if len(got) != len(want) || got["2026-10-08"] != want["2026-10-08"] || got["2026-10-09"] != want["2026-10-09"] {
		t.Fatalf("got %v, want %v", got, want)
	}
	if got, _ := st.CapturedToolTokensByDay(ctx, nil, "2026-10-07", "2026-10-09"); len(got) != 0 {
		t.Fatalf("no tools: %v", got)
	}
	if _, err := st.CapturedToolTokensByDay(ctx, []string{"codex"}, "bad", "2026-10-09"); err == nil {
		t.Fatal("a malformed window must error")
	}
}
