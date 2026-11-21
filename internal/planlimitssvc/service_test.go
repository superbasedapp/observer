package planlimitssvc

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// fakeNet records every call and answers from a table. A test that expects
// zero egress fails on the first call.
type fakeNet struct {
	mu       sync.Mutex
	calls    []string
	answer   map[string]planlimits.Response // by request key
	forbid   bool
	t        *testing.T
	converse func(planlimits.PlanInput) (planlimits.Snapshot, error)
}

func (f *fakeNet) Do(_ context.Context, src planlimits.SourceDef, reqs []planlimits.Request) map[string]planlimits.Response {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]planlimits.Response{}
	for _, r := range reqs {
		if f.forbid {
			f.t.Errorf("unexpected egress: %s %s", src.ID, r.URL)
		}
		f.calls = append(f.calls, src.ID+" "+r.URL)
		out[r.Key] = f.answer[r.Key]
	}
	return out
}

func (f *fakeNet) Converse(_ context.Context, src planlimits.SourceDef, _ planlimits.Driver, in planlimits.PlanInput) (planlimits.Snapshot, error) {
	f.mu.Lock()
	if f.forbid {
		f.t.Errorf("unexpected process: %s", src.ID)
	}
	f.calls = append(f.calls, src.ID)
	f.mu.Unlock()
	return f.converse(in)
}

type fakeLocal struct{ files map[string][]byte }

func (f fakeLocal) Read(_ context.Context, specs []planlimits.LocalSpec) (map[string][]byte, error) {
	out := map[string][]byte{}
	for _, s := range specs {
		b, ok := f.files[s.Key]
		if !ok {
			return nil, planlimits.ErrUnavailable
		}
		out[s.Key] = b
	}
	return out, nil
}

func newTestService(t *testing.T, net *fakeNet, local LocalReader, now time.Time) (*Service, *store.Store, *keystore.MemStore) {
	t.Helper()
	s, st, keys, _ := newTestServiceDB(t, net, local, now)
	return s, st, keys
}

// newTestServiceDB is newTestService that also returns the database, for a
// test that seeds capture rows the service only reads.
func newTestServiceDB(t *testing.T, net *fakeNet, local LocalReader, now time.Time) (*Service, *store.Store, *keystore.MemStore, *sql.DB) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: t.TempDir() + "/p.db"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	keys := &keystore.MemStore{}
	net.t = t
	return New(Options{Store: st, Keys: keys, Net: net, Local: local, Now: func() time.Time { return now }}), st, keys, database
}

var t0 = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func TestNoAccountsMeansNoEgress(t *testing.T) {
	net := &fakeNet{forbid: true}
	s, _, _ := newTestService(t, net, fakeLocal{}, t0)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { s.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if res := s.RefreshAll(context.Background()); len(res) != 0 || len(net.calls) != 0 {
		t.Fatalf("no account must mean no call: %v %v", res, net.calls)
	}
	v, err := s.Status(context.Background())
	if err != nil || len(v.Cards) != 0 {
		t.Fatalf("view %+v %v", v, err)
	}
}

func TestAddRefreshRemoveKeepsSecretsInKeychain(t *testing.T) {
	net := &fakeNet{answer: map[string]planlimits.Response{
		"main": {Status: 200, Body: []byte(`{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"3.12","granted_balance":"0.12","topped_up_balance":"3.00"}]}`)},
	}}
	s, st, keys := newTestService(t, net, fakeLocal{}, t0)
	ctx := context.Background()
	if _, err := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderDeepSeek, Source: planlimits.SourceDeepSeek}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a missing key must be refused: %v", err)
	}
	if _, err := s.AddAccount(ctx, AddRequest{
		Provider: planlimits.ProviderDeepSeek, Source: planlimits.SourceOpenRouter,
		Secrets: map[string]string{"key": "K"},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a source of another provider must be refused: %v", err)
	}
	a, err := s.AddAccount(ctx, AddRequest{
		Provider: planlimits.ProviderDeepSeek, Source: planlimits.SourceDeepSeek,
		Label: "Mine", Secrets: map[string]string{"key": "sk-SECRET-VALUE"},
	})
	if err != nil {
		t.Fatal(err)
	}
	row, _ := st.PlanAccount(ctx, a.ID)
	if strings.Contains(strings.Join(row.SecretKeys, ",")+row.Label, "SECRET") || len(row.SecretKeys) != 1 {
		t.Fatalf("the database holds secret names only: %+v", row)
	}
	if v, err := keys.Get(secretName(a.ID, "key")); err != nil || v != "sk-SECRET-VALUE" {
		t.Fatalf("keychain %q %v", v, err)
	}
	res, err := s.Refresh(ctx, a.ID)
	if err != nil || res.Outcome != planlimits.StatusOK || res.Snapshot == nil {
		t.Fatalf("refresh %+v %v", res, err)
	}
	v, _ := s.Status(ctx)
	if len(v.Cards) != 1 || len(v.Cards[0].Balances) != 3 || v.Cards[0].Health != planlimits.HealthFresh {
		t.Fatalf("view %+v", v.Cards)
	}
	if err := s.RemoveAccount(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Get(secretName(a.ID, "key")); !errors.Is(err, keystore.ErrNotFound) {
		t.Fatalf("remove must delete the keychain item: %v", err)
	}
}

func TestAuthFailureStopsAndClearsTransientKeeps(t *testing.T) {
	net := &fakeNet{answer: map[string]planlimits.Response{"main": {
		Status: 200,
		Body:   []byte(`{"is_available":true,"balance_infos":[{"currency":"USD","total_balance":"1","granted_balance":"0","topped_up_balance":"1"}]}`),
	}}}
	s, st, _ := newTestService(t, net, fakeLocal{}, t0)
	ctx := context.Background()
	a, _ := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderDeepSeek, Source: planlimits.SourceDeepSeek, Secrets: map[string]string{"key": "K"}})
	if _, err := s.Refresh(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	net.answer["main"] = planlimits.Response{Status: 503}
	res, _ := s.Refresh(ctx, a.ID)
	if res.Outcome != planlimits.StatusThrottled {
		t.Fatalf("503: %+v", res)
	}
	v, _ := s.Status(ctx)
	if len(v.Cards[0].Balances) != 3 {
		t.Fatal("a transient failure keeps the last good reading")
	}
	net.answer["main"] = planlimits.Response{Status: 401}
	res, _ = s.Refresh(ctx, a.ID)
	row, _ := st.PlanAccount(ctx, a.ID)
	if res.Outcome != planlimits.StatusAuthNeeded || !row.State.Stopped {
		t.Fatalf("401: %+v %+v", res, row.State)
	}
	v, _ = s.Status(ctx)
	if len(v.Cards[0].Balances) != 0 || v.Cards[0].Health != planlimits.StatusAuthNeeded {
		t.Fatalf("an auth failure clears the numbers: %+v", v.Cards[0])
	}
	calls := len(net.calls)
	s.tick(ctx, false)
	if len(net.calls) != calls {
		t.Fatal("a stopped account is not polled until the user acts")
	}
}

func TestExperimentalNeedsOptInAndLadder(t *testing.T) {
	creds := `{"claudeAiOauth":{"accessToken":"FAKE","expiresAt":1893456000000,"scopes":["user:profile"]}}`
	net := &fakeNet{answer: map[string]planlimits.Response{"usage": {
		Status: 200,
		Body:   []byte(`{"five_hour":{"utilization":20,"resets_at":"2026-10-13T15:00:00Z"}}`),
	}}}
	s, st, _ := newTestService(t, net, fakeLocal{files: map[string][]byte{"creds": []byte(creds)}}, t0)
	ctx := context.Background()
	if _, err := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderClaude, Source: planlimits.SourceClaudeOAuth}); !errors.Is(err, ErrNeedsOptIn) {
		t.Fatalf("experimental without opt-in: %v", err)
	}
	if err := s.SetOptIn(ctx, planlimits.ProviderDeepSeek, true); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a provider without an experimental source: %v", err)
	}
	if err := s.SetOptIn(ctx, planlimits.ProviderClaude, true); err != nil {
		t.Fatal(err)
	}
	a, err := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderClaude, Source: planlimits.SourceClaudeOAuth})
	if err != nil {
		t.Fatal(err)
	}
	// A fresh status line reading (rung 1) covers Claude: the scheduled
	// poll skips the experimental source without any call.
	fwd := planlimits.StatusLineForward{
		SessionID: "s1", ObservedAt: t0.Add(-time.Minute).Unix(),
		RateLimits: &planlimits.StatusLineLimits{},
	}
	_ = fwd
	sl := planlimits.Snapshot{
		Provider: planlimits.ProviderClaude, Source: planlimits.SourceClaudeStatusLine, Kind: planlimits.KindStatusLine,
		Rung: planlimits.RungOfficial, Status: planlimits.StatusOK, ObservedAt: t0.Add(-time.Minute),
		Windows: []planlimits.Window{{Key: "5h", Unit: planlimits.UnitPercent, UsedFrac: planlimits.F(0.1)}},
	}
	if err := st.InsertPlanSnapshot(ctx, "", "s1", sl); err != nil {
		t.Fatal(err)
	}
	s.tick(ctx, false)
	if len(net.calls) != 0 {
		t.Fatalf("rung 1 is fresh, rung 2 must not run: %v", net.calls)
	}
	// A user refresh runs it anyway (the opt-in is on).
	res, err := s.Refresh(ctx, a.ID)
	if err != nil || res.Outcome != planlimits.StatusOK || len(net.calls) != 1 {
		t.Fatalf("forced refresh %+v %v %v", res, err, net.calls)
	}
	// Opting out stops it even when forced.
	_ = s.SetOptIn(ctx, planlimits.ProviderClaude, false)
	res, _ = s.Refresh(ctx, a.ID)
	if res.Outcome != planlimits.StatusNotOptedIn || len(net.calls) != 1 {
		t.Fatalf("opted out %+v %v", res, net.calls)
	}
}

func TestSuspiciousResetIsHeldUntilConfirmed(t *testing.T) {
	body := func(pct int) planlimits.Response {
		return planlimits.Response{Status: 200, Body: []byte(`{"plan_type":"pro","rate_limit":{"secondary_window":{"used_percent":` +
			itoa(pct) + `,"limit_window_seconds":604800,"reset_at":1792000000}}}`)}
	}
	auth := `{"tokens":{"access_token":"` + jwt(`{"exp":1893456000}`) + `"}}`
	net := &fakeNet{answer: map[string]planlimits.Response{"usage": body(80)}}
	s, st, _ := newTestService(t, net, fakeLocal{files: map[string][]byte{"auth": []byte(auth)}}, t0)
	ctx := context.Background()
	_ = s.SetOptIn(ctx, planlimits.ProviderChatGPT, true)
	a, err := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderChatGPT, Source: planlimits.SourceChatGPTWham})
	if err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Refresh(ctx, a.ID); r.Outcome != planlimits.StatusOK || r.Held {
		t.Fatalf("first %+v", r)
	}
	net.answer["usage"] = body(5)
	if r, _ := s.Refresh(ctx, a.ID); !r.Held {
		t.Fatalf("a sharp drop before the stated reset must be held: %+v", r)
	}
	latest, _ := st.LatestPlanSnapshots(ctx)
	if w, _ := planlimits.FindWindow(latest[a.ID], "weekly"); *w.UsedFrac != 0.8 {
		t.Fatalf("the held reading must not replace the last good one: %v", *w.UsedFrac)
	}
	if r, _ := s.Refresh(ctx, a.ID); r.Held {
		t.Fatalf("a second agreeing reading confirms it: %+v", r)
	}
	latest, _ = st.LatestPlanSnapshots(ctx)
	if w, _ := planlimits.FindWindow(latest[a.ID], "weekly"); *w.UsedFrac != 0.05 {
		t.Fatalf("confirmed %v", *w.UsedFrac)
	}
}

func TestManualEntryUsesObservedSpend(t *testing.T) {
	net := &fakeNet{forbid: true}
	s, _, _ := newTestService(t, net, fakeLocal{}, t0)
	ctx := context.Background()
	a, err := s.AddAccount(ctx, AddRequest{
		Provider: planlimits.ProviderCursor, Source: planlimits.SourceManual,
		Params: map[string]string{"plan": "Pro", "unit": "usd", "allowance": "20", "renews_day": "1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddAccount(ctx, AddRequest{
		Provider: planlimits.ProviderCursor, Source: planlimits.SourceManual,
		Params: map[string]string{"unit": "usd", "allowance": "x"},
	}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a non-number allowance: %v", err)
	}
	res, err := s.Refresh(ctx, a.ID)
	if err != nil || res.Outcome != planlimits.StatusOK {
		t.Fatalf("manual %+v %v", res, err)
	}
	w := res.Snapshot.Windows[0]
	if w.Used == nil || *w.Used != 0 || res.Snapshot.Confidence != planlimits.ConfEstimated {
		t.Fatalf("observed spend (none recorded) %+v", w)
	}
}

func TestStatusLineIngestDedups(t *testing.T) {
	s, st, _ := newTestService(t, &fakeNet{forbid: true}, fakeLocal{}, t0)
	ctx := context.Background()
	p := 40.0
	r := int64(1760400000)
	f := planlimits.StatusLineForward{
		SessionID: "s1", ObservedAt: t0.Unix(),
		RateLimits: &planlimits.StatusLineLimits{FiveHour: &planlimits.StatusLineWindow{UsedPercentage: &p, ResetsAt: &r}},
	}
	for i := 0; i < 3; i++ {
		if err := s.IngestStatusLine(ctx, f); err != nil {
			t.Fatal(err)
		}
	}
	sig, _ := st.LoadPlanPassiveSignals(ctx, t0.Add(-time.Hour))
	if len(sig.StatusLine) != 1 {
		t.Fatalf("status line rows %d", len(sig.StatusLine))
	}
	if err := s.IngestStatusLine(ctx, planlimits.StatusLineForward{SessionID: "s1"}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an empty reading: %v", err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func jwt(claims string) string {
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc([]byte(claims)) + ".sig"
}

// TestDailyUsageReconciliation covers the app-server account's daily usage:
// nothing before a reading, the reading's totals stored beside the snapshot,
// reconciled against this node's captured codex rows, and gone with the
// account.
func TestDailyUsageReconciliation(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	usage := &planlimits.UsageReport{Days: []planlimits.UsageDay{{Day: "2026-10-08", Tokens: 1000}, {Day: "2026-10-09", Tokens: 500}}}
	net := &fakeNet{converse: func(in planlimits.PlanInput) (planlimits.Snapshot, error) {
		snap, err := planlimits.MapAppServer(planlimits.AppServerRateLimits{RateLimits: &planlimits.AppServerBucket{
			LimitID: "codex", Primary: &planlimits.AppServerWindow{UsedPercent: 10},
		}}, "plus", in.Now)
		snap.Usage = usage
		return snap, err
	}}
	s, st, _, database := newTestServiceDB(t, net, fakeLocal{}, now)
	ctx := context.Background()
	a, err := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderChatGPT, Source: planlimits.SourceCodexAppServer})
	if err != nil {
		t.Fatal(err)
	}
	if !a.DailyUsage {
		t.Fatal("the app-server account must declare daily usage")
	}
	v, err := s.Usage(ctx, a.ID, 0)
	if err != nil || !v.Available || v.Reconciliation != nil || v.FetchedAt != nil || v.Days != DefaultUsageDays {
		t.Fatalf("before a reading: %+v %v", v, err)
	}
	if res, err := s.Refresh(ctx, a.ID); err != nil || res.Outcome != planlimits.StatusOK {
		t.Fatalf("refresh %+v %v", res, err)
	}
	// Captured on this node: a codex session on the 8th.
	pid, err := st.UpsertProject(ctx, "/tmp/usage-proj", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('cx', ?, 'codex', ?)`, pid, now.Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ExecContext(ctx, `INSERT INTO token_usage (session_id, timestamp, tool, model, input_tokens, cache_read_tokens, output_tokens, source, reliability)
		VALUES ('cx', '2026-10-08T10:00:00Z', 'codex', 'gpt-x', 100, 800, 40, 'jsonl', 'accurate')`); err != nil {
		t.Fatal(err)
	}
	v, err = s.Usage(ctx, a.ID, 7)
	if err != nil || v.Reconciliation == nil || v.FetchedAt == nil {
		t.Fatalf("after a reading: %+v %v", v, err)
	}
	r := v.Reconciliation
	if r.From != "2026-10-03" || r.To != "2026-10-09" || len(r.Days) != 2 {
		t.Fatalf("window %+v", r)
	}
	if d := r.Days[1]; d.Day != "2026-10-08" || d.VendorTokens != 1000 || d.CapturedTokens != 940 || d.UncapturedTokens != 60 {
		t.Fatalf("day %+v", d)
	}
	if r.Totals.UncapturedTokens != 560 || strings.Join(v.Tools, ",") != "codex" {
		t.Fatalf("totals %+v tools %v", r.Totals, v.Tools)
	}
	// The snapshot body never carries the usage.
	hist, _, _ := s.History(ctx, a.ID, 1)
	if len(hist) != 1 || hist[0].Usage != nil {
		t.Fatalf("history %+v", hist)
	}
	if err := s.RemoveAccount(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if days, last, _ := st.PlanUsageDaily(ctx, a.ID, "2026-01-01", "2026-12-31"); len(days) != 0 || !last.IsZero() {
		t.Fatalf("rows left after remove: %+v", days)
	}
	// A source without the capability reports Available=false.
	b, err := s.AddAccount(ctx, AddRequest{Provider: planlimits.ProviderDeepSeek, Source: planlimits.SourceDeepSeek, Secrets: map[string]string{"key": "k"}})
	if err != nil {
		t.Fatal(err)
	}
	if v, err := s.Usage(ctx, b.ID, 30); err != nil || v.Available || v.Reconciliation != nil {
		t.Fatalf("no capability: %+v %v", v, err)
	}
	if _, err := s.Usage(ctx, "missing", 30); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unknown account: %v", err)
	}
}
