package repricesvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/reprice"
	"github.com/marmutapp/superbased-observer/internal/store"
)

var fixedNow = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

func TestParseBound(t *testing.T) {
	cases := []struct {
		in      string
		want    time.Time
		wantErr bool
	}{
		{"", time.Time{}, false},
		{"2026-09-01", time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC), false},
		{"2026-09-01T10:30:00+02:00", time.Date(2026, 9, 1, 8, 30, 0, 0, time.UTC), false},
		{"7d", fixedNow.AddDate(0, 0, -7), false},
		{"0d", fixedNow, false},
		{"-3d", time.Time{}, true},
		{"yesterday", time.Time{}, true},
		{"2026-13-01", time.Time{}, true},
	}
	for _, tc := range cases {
		got, err := ParseBound(tc.in, fixedNow)
		if tc.wantErr {
			if !errors.Is(err, ErrBadFilter) {
				t.Errorf("%q: err %v, want ErrBadFilter", tc.in, err)
			}
			continue
		}
		if err != nil || !got.Equal(tc.want) {
			t.Errorf("%q: got %v %v, want %v", tc.in, got, err, tc.want)
		}
	}
}

func TestDigestCanonicalString(t *testing.T) {
	info := PricingInfo{Source: "org", Version: 12, Description: "ignored by the digest"}
	canon := "reprice-digest-v1\nsince=2026-09-01T00:00:00Z\nuntil=\nmodel=m\npricing_source=org\npricing_version=12\nrule_version=1\nchanged=3\nfilled=1\nold_usd=1.500000000\nnew_usd=3.400000000"
	sum := sha256.Sum256([]byte(canon))
	want := hex.EncodeToString(sum[:])
	if got := Digest("2026-09-01T00:00:00Z", "", "m", info, 1, 3, 1, 1.5, 3.4); got != want {
		t.Fatalf("digest %s, want %s", got, want)
	}
	// Rounding to 9 decimals absorbs summation-order noise; the description
	// is display only.
	info.Description = "other"
	if got := Digest("2026-09-01T00:00:00Z", "", "m", info, 1, 3, 1, 1.5+1e-13, 3.4); got != want {
		t.Fatal("sub-1e-9 noise or the description changed the digest")
	}
	for name, d := range map[string]string{
		"version": Digest("2026-09-01T00:00:00Z", "", "m", PricingInfo{Source: "org", Version: 13}, 1, 3, 1, 1.5, 3.4),
		"source":  Digest("2026-09-01T00:00:00Z", "", "m", PricingInfo{Source: "feed", Version: 12}, 1, 3, 1, 1.5, 3.4),
		"changed": Digest("2026-09-01T00:00:00Z", "", "m", PricingInfo{Source: "org", Version: 12}, 1, 4, 1, 1.5, 3.4),
		"new_usd": Digest("2026-09-01T00:00:00Z", "", "m", PricingInfo{Source: "org", Version: 12}, 1, 3, 1, 1.5, 3.5),
		"window":  Digest("2026-09-02T00:00:00Z", "", "m", PricingInfo{Source: "org", Version: 12}, 1, 3, 1, 1.5, 3.4),
	} {
		if d == want {
			t.Errorf("changing %s did not change the digest", name)
		}
	}
}

type svcFixture struct {
	st   *store.Store
	svc  *Service
	rate *float64
}

func newSvcFixture(t *testing.T) svcFixture {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: filepath.Join(t.TempDir(), "svc.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { database.Close() })
	st := store.New(database)
	pid, err := st.UpsertProject(ctx, "/tmp/reprice-svc", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('s1', ?, 'claude-code', '2026-09-01T00:00:00Z')`,
	} {
		if _, err := database.ExecContext(ctx, q, pid); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		ts   string
		cost any
	}{{"2026-09-02T10:00:00Z", 1.0}, {"2026-09-03T10:00:00Z", nil}} {
		if _, err := database.ExecContext(ctx, `INSERT INTO api_turns (session_id, timestamp, provider, model, input_tokens, output_tokens, cost_usd, source)
			VALUES ('s1', ?, 'anthropic', 'm', 1000, 0, ?, 'proxy')`, row.ts, row.cost); err != nil {
			t.Fatal(err)
		}
	}
	rate := 0.002
	f := svcFixture{st: st, rate: &rate}
	price := func(model string, _ time.Time, tk reprice.Tokens) reprice.Quote {
		if model != "m" {
			return reprice.Quote{}
		}
		return reprice.Quote{USD: float64(tk.Input) * *f.rate, OK: true, Source: "seed"}
	}
	f.svc = New(st, price, func(context.Context) PricingInfo {
		return PricingInfo{Source: PricingSourceSeed, Description: "the built-in rate table"}
	}, func() time.Time { return fixedNow })
	return f
}

func TestServicePlanApplyRevert(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	plan, err := f.svc.Plan(ctx, Filter{Since: "2026-09-01"})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Summary.Changed != 2 || plan.Summary.Filled != 1 || plan.Since != "2026-09-01T00:00:00Z" || plan.Until != "" {
		t.Fatalf("plan %+v", plan)
	}
	if plan.Org.Enrolled || !strings.Contains(plan.Org.Note, "not enrolled") {
		t.Fatalf("org note %+v", plan.Org)
	}
	// The wire view carries non-null maps and slices.
	b, _ := json.Marshal(plan.View())
	for _, key := range []string{`"digest":"` + plan.Digest + `"`, `"skipped":{}`, `"rule_version":1`, `"resend_queued":0`} {
		if !strings.Contains(string(b), key) {
			t.Fatalf("plan view %s lacks %s", b, key)
		}
	}

	// An empty digest never applies.
	if _, err := f.svc.Apply(ctx, Request{Filter: Filter{Since: "2026-09-01"}, Actor: "t"}); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("empty digest: %v", err)
	}
	// Prices moved since the dry run: refused with the fresh plan.
	*f.rate = 0.003
	_, err = f.svc.Apply(ctx, Request{Filter: Filter{Since: "2026-09-01"}, Actor: "t", Digest: plan.Digest})
	var pc *PlanChangedError
	if !errors.As(err, &pc) || pc.Plan.Digest == plan.Digest || pc.Plan.Summary.NewUSD != 6.0 {
		t.Fatalf("stale digest: %v %+v", err, pc)
	}
	runs, _ := f.svc.Runs(ctx, 10)
	if len(runs) != 0 {
		t.Fatalf("a refused apply wrote a run: %+v", runs)
	}
	// Applying the fresh plan's digest works.
	run, err := f.svc.Apply(ctx, Request{Filter: Filter{Since: "2026-09-01"}, Actor: "t", Digest: pc.Plan.Digest})
	if err != nil {
		t.Fatal(err)
	}
	if run.Changed != 2 || run.Since != "2026-09-01T00:00:00Z" || run.PricingSource != "seed" || run.RuleVersion != reprice.RuleVersion {
		t.Fatalf("run %+v", run)
	}
	rv, err := f.svc.Revert(ctx, run.ID, "t")
	if err != nil || rv.RevertsRun != run.ID {
		t.Fatalf("revert %+v %v", rv, err)
	}
	if _, err := f.svc.Revert(ctx, run.ID, "t"); !IsRefusal(err) {
		t.Fatalf("second revert not a refusal: %v", err)
	}
	if _, err := f.svc.Revert(ctx, rv.ID, "t"); !IsRefusal(err) {
		t.Fatalf("revert of a revert not a refusal: %v", err)
	}
	views := ViewRuns(mustRuns(t, f.svc))
	if len(views) != 2 || views[0].Kind != "revert" || views[1].Status != "reverted" || views[1].RevertedByRun != views[0].ID {
		t.Fatalf("run views %+v", views)
	}
}

func mustRuns(t *testing.T, s *Service) []store.RepriceRun {
	t.Helper()
	r, err := s.Runs(context.Background(), 20)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestServiceBadFilter(t *testing.T) {
	f := newSvcFixture(t)
	for _, flt := range []Filter{{Since: "soon"}, {Since: "2026-09-02", Until: "2026-09-01"}} {
		if _, err := f.svc.Plan(context.Background(), flt); !errors.Is(err, ErrBadFilter) {
			t.Errorf("%+v: %v", flt, err)
		}
	}
}

func TestOrgNote(t *testing.T) {
	cases := []struct {
		name string
		in   store.RepriceOrgParity
		want string
	}{
		{"not enrolled", store.RepriceOrgParity{}, "not enrolled"},
		{"nothing changes", store.RepriceOrgParity{Enrolled: true, Tracked: true}, "sees nothing new"},
		{"untracked", store.RepriceOrgParity{Enrolled: true, BelowFloor: 3}, "not set up"},
		{"queued only", store.RepriceOrgParity{Enrolled: true, Tracked: true, Queued: 4}, "4 changed proxy turn(s) are re-sent"},
		{
			"below floor",
			store.RepriceOrgParity{Enrolled: true, Tracked: true, Queued: 1, BelowFloor: 2, OldestBelowFloor: "2026-09-27T12:00:00Z"},
			"observer org resync --since 72h --confirm",
		},
	}
	for _, tc := range cases {
		n := orgNote(tc.in, fixedNow)
		if !strings.Contains(n.Note, tc.want) {
			t.Errorf("%s: note %q lacks %q", tc.name, n.Note, tc.want)
		}
		if strings.ContainsRune(n.Note, '—') {
			t.Errorf("%s: em-dash in user-facing copy", tc.name)
		}
	}
}

// TestBareDateUntilCoversItsDay pins the one window reading shared with the
// org's re-price: a bare-date until names its whole UTC day, an RFC3339 until
// is exclusive, and since == until as dates is a one-day window.
func TestBareDateUntilCoversItsDay(t *testing.T) {
	cases := []struct {
		name, since, until string
		wantUntil          string
		wantErr            bool
	}{
		{"date until covers the day", "2026-09-01", "2026-09-01", "2026-09-02T00:00:00Z", false},
		{"instant until is exclusive", "2026-09-01", "2026-09-01T12:00:00Z", "2026-09-01T12:00:00Z", false},
		{"open until", "2026-09-01", "", "", false},
		{"until before since", "2026-09-02", "2026-09-01", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := Filter{Since: tc.since, Until: tc.until}.resolve(fixedNow)
			if tc.wantErr {
				if !errors.Is(err, ErrBadFilter) {
					t.Fatalf("err %v, want ErrBadFilter", err)
				}
				return
			}
			if err != nil || r.until != tc.wantUntil {
				t.Fatalf("until %q err %v, want %q", r.until, err, tc.wantUntil)
			}
		})
	}
}

// TestApplyRefusedUnderPricingPin pins review finding 5: the org's pin on the
// pricing Settings section refuses an APPLY in the service itself, so the CLI
// and the dashboard (both callers of Apply) are refused alike; a dry run and a
// revert are not.
func TestApplyRefusedUnderPricingPin(t *testing.T) {
	cases := []struct {
		name       string
		eff        govern.Effective
		wantRefuse bool
	}{
		{"ungoverned", govern.Effective{}, false},
		{"governed, pricing editable", govern.Effective{Active: true, ReadOnlySettings: []string{"terminal"}}, false},
		{"governed, pricing read-only", govern.Effective{Active: true, OrgName: "Acme", ReadOnlySettings: []string{SettingsSection}}, true},
		{"governed, pricing hidden", govern.Effective{Active: true, HiddenSettings: []string{SettingsSection}}, true},
		{"inactive posture listing pricing", govern.Effective{Active: false, ReadOnlySettings: []string{SettingsSection}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newSvcFixture(t)
			ctx := context.Background()
			f.svc.WithGovernance(func(context.Context) govern.Effective { return tc.eff })
			plan, err := f.svc.Plan(ctx, Filter{})
			if err != nil {
				t.Fatalf("a dry run is never refused: %v", err)
			}
			run, err := f.svc.Apply(ctx, Request{Actor: "t", Digest: plan.Digest})
			if tc.wantRefuse {
				var gr *GovernanceRefusedError
				if !errors.As(err, &gr) || !errors.Is(err, ErrGovernanceRefused) || !IsRefusal(err) || gr.Section != SettingsSection {
					t.Fatalf("apply under the pin = %+v, %v; want *GovernanceRefusedError", run, err)
				}
				if runs := mustRuns(t, f.svc); len(runs) != 0 {
					t.Fatalf("a refused apply wrote a run: %+v", runs)
				}
				return
			}
			if err != nil || run.Changed != 2 {
				t.Fatalf("apply = %+v, %v", run, err)
			}
		})
	}
	// A revert is never refused by the pin.
	f := newSvcFixture(t)
	ctx := context.Background()
	plan, _ := f.svc.Plan(ctx, Filter{})
	run, err := f.svc.Apply(ctx, Request{Actor: "t", Digest: plan.Digest})
	if err != nil {
		t.Fatal(err)
	}
	f.svc.WithGovernance(func(context.Context) govern.Effective {
		return govern.Effective{Active: true, ReadOnlySettings: []string{SettingsSection}}
	})
	if _, err := f.svc.Revert(ctx, run.ID, "t"); err != nil {
		t.Fatalf("revert under the pin: %v", err)
	}
}

// TestRelativeWindowAppliesWithResolvedBounds pins review finding 9: a
// relative "Nd" dry run carries its resolved absolute bounds, and applying
// with those bounds matches the dry run's digest after the clock has moved on
// (a re-read "Nd" would name a different instant).
func TestRelativeWindowAppliesWithResolvedBounds(t *testing.T) {
	f := newSvcFixture(t)
	ctx := context.Background()
	clock := time.Date(2026, 9, 5, 10, 0, 0, 123456789, time.UTC) // sub-second on purpose
	f.svc.now = func() time.Time { return clock }
	plan, err := f.svc.Plan(ctx, Filter{Since: "3d"})
	if err != nil {
		t.Fatal(err)
	}
	want := clock.AddDate(0, 0, -3)
	got, err := time.Parse(time.RFC3339Nano, plan.Since)
	if err != nil || !got.Equal(want) {
		t.Fatalf("plan.Since %q, want the exact resolved instant %s", plan.Since, want.Format(time.RFC3339Nano))
	}
	if b, _ := json.Marshal(plan.View()); !strings.Contains(string(b), `"since":"`+plan.Since+`"`) {
		t.Fatalf("the plan view does not carry the resolved since: %s", b)
	}
	clock = clock.Add(90 * time.Second)
	// The raw relative window no longer matches: its instant moved.
	if _, err := f.svc.Apply(ctx, Request{Filter: Filter{Since: "3d"}, Actor: "t", Digest: plan.Digest}); !errors.Is(err, ErrPlanChanged) {
		t.Fatalf("raw relative window: %v, want plan_changed", err)
	}
	run, err := f.svc.Apply(ctx, Request{Filter: Filter{Since: plan.Since, Until: plan.Until, Model: plan.Model}, Actor: "t", Digest: plan.Digest})
	if err != nil || run.Since != plan.Since {
		t.Fatalf("apply with the resolved bounds = %+v, %v", run, err)
	}
}
