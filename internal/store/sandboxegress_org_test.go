package store

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestSelectSandboxEgressRefusalDays: one case per shape the aggregate sums.
// Recorded refusals count per (day, tier, rule); dropped and evicted refusals
// land on rule "" under the run's tier on the day their count last grew; the
// uncertain count is left out; a tier or rule outside its vocabulary lands as
// ""; refusals older than the window are not sent. No row carries a host,
// port, key, project root or run id.
func TestSelectSandboxEgressRefusalDays(t *testing.T) {
	ctx := context.Background()
	today := time.Now().UTC().Truncate(24 * time.Hour).Add(12 * time.Hour)
	day := func(d int) string { return today.AddDate(0, 0, -d).Format("2006-01-02") }
	type refusal struct {
		run, host, tier, rule string
		ago                   int
	}
	type drop struct {
		run                         string
		dropped, uncertain, evicted int
		ago                         int
	}
	for _, c := range []struct {
		name     string
		runs     map[string]string // run id -> stored egress tier
		refusals []refusal
		drops    []drop
		want     []orgcontract.SandboxEgressRefusalDayRow
	}{
		{name: "empty", want: []orgcontract.SandboxEgressRefusalDayRow{}},
		{
			name: "multi-day, per tier and rule",
			refusals: []refusal{
				{"r1", "a.example", "proxy_only", "allow-list-miss", 0},
				{"r1", "b.example", "proxy_only", "allow-list-miss", 0},
				{"r1", "c.example", "proxy_only", "port-not-allowed", 0},
				{"r2", "10.0.0.1", "internet", "private-range", 2},
			},
			want: []orgcontract.SandboxEgressRefusalDayRow{
				{Day: day(2), Tier: "internet", Rule: "private-range", Refusals: 1},
				{Day: day(0), Tier: "proxy_only", Rule: "allow-list-miss", Refusals: 2},
				{Day: day(0), Tier: "proxy_only", Rule: "port-not-allowed", Refusals: 1},
			},
		},
		{
			name: "closed vocabularies coerce, and coerced buckets sum",
			refusals: []refusal{
				{"r1", "a.example", "SECRET-tier", "SECRET-rule", 1},
				{"r1", "b.example", "", "also-not-a-rule", 1},
			},
			want: []orgcontract.SandboxEgressRefusalDayRow{{Day: day(1), Tier: "", Rule: "", Refusals: 2}},
		},
		{
			name:     "drops and evictions land on rule \"\" under the run's tier, uncertain left out",
			runs:     map[string]string{"r1": "proxy_only"},
			refusals: []refusal{{"r1", "a.example", "proxy_only", "", 0}},
			drops:    []drop{{"r1", 3, 7, 2, 0}, {"r-gone", 1, 0, 0, 0}, {"r-uncertain-only", 0, 5, 0, 0}},
			want: []orgcontract.SandboxEgressRefusalDayRow{
				{Day: day(0), Tier: "", Rule: "", Dropped: 1},
				{Day: day(0), Tier: "proxy_only", Rule: "", Refusals: 1, Dropped: 5},
			},
		},
		{
			name:     "outside the window is not sent",
			refusals: []refusal{{"r1", "a.example", "none", "tier-none", sandboxEgressOrgWindowDays + 2}},
			want:     []orgcontract.SandboxEgressRefusalDayRow{},
		},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			for id, tier := range c.runs {
				if err := s.InsertTerminalRun(ctx, TerminalRun{
					RunID: id, Tool: "claude-code", Kind: "fresh", LaunchedAt: today,
					Isolation: TerminalRunIsolation{Class: "process", Stack: []string{"bwrap"}, EgressTier: tier},
				}); err != nil {
					t.Fatal(err)
				}
			}
			for _, r := range c.refusals {
				// The rule column is written directly so an out-of-vocabulary
				// value (which the receiver never writes) can be seeded.
				at := today.AddDate(0, 0, -r.ago).Format(sandboxEgressTimeLayout)
				if _, err := s.db.ExecContext(ctx, `INSERT INTO sandbox_egress_refusals
					(run_id, project_root, backend, tier, host, port, rule, rule_key, minute_bucket, refused_at)
					VALUES (?, '/home/dev/SECRET-project', 'bwrap', ?, ?, 8443, ?, 'terminal.sandbox.SECRET_key', ?, ?)`,
					r.run, r.tier, r.host, r.rule, time.Now().UnixNano(), at); err != nil {
					t.Fatal(err)
				}
			}
			for _, d := range c.drops {
				at := today.AddDate(0, 0, -d.ago).Format(sandboxEgressTimeLayout)
				if _, err := s.db.ExecContext(ctx, `INSERT INTO sandbox_egress_refusal_drops
					(run_id, dropped, uncertain, evicted, updated_at) VALUES (?, ?, ?, ?, ?)`,
					d.run, d.dropped, d.uncertain, d.evicted, at); err != nil {
					t.Fatal(err)
				}
			}
			got, err := s.SelectSandboxEgressRefusalDays(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != len(c.want) {
				t.Fatalf("got %+v\nwant %+v", got, c.want)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Errorf("row %d: got %+v want %+v", i, got[i], c.want[i])
				}
			}
			b, _ := json.Marshal(got)
			for _, leak := range []string{"example", "10.0.0.1", "8443", "SECRET", "bwrap", "r1", "r2"} {
				if strings.Contains(string(b), leak) {
					t.Fatalf("refusal counts carry %q: %s", leak, b)
				}
			}
		})
	}
}

// TestSandboxEgressCountsManagedOnly: the counts compose ONLY on a managed
// node (ShareOptions.Managed). An individual node ships none in any share
// posture, including full content; a managed node ships them in the
// metadata-only posture; and a node with no refusals sends nothing, so the
// key stays absent (an old server never sees it).
func TestSandboxEgressCountsManagedOnly(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	empty, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org", "dev@example.test", ShareOptions{Managed: true}, ScopeOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if empty.SandboxEgressRefusals != nil {
		t.Fatalf("no refusals composed %+v", empty.SandboxEgressRefusals)
	}
	if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{
		RunID: "run-1", Host: "blocked.example", Port: 443, Rule: "allow-list-miss", Tier: "proxy_only", Key: "terminal.sandbox.allowed_hosts",
	}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		share ShareOptions
		want  int
	}{
		{"individual, metadata only", ShareOptions{}, 0},
		{"individual, every tier on", ShareOptions{FullContent: true, AdminManaged: true, EnterpriseGranted: true, TerminalDetail: true}, 0},
		{"managed, metadata only", ShareOptions{Managed: true}, 1},
	} {
		// A fresh gate per case, so an earlier compose cannot leave the
		// family clean.
		s.snap = newSnapGate()
		b, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@example.test", c.share, ScopeOptions{})
		if err != nil {
			t.Fatal(err)
		}
		if len(b.SandboxEgressRefusals) != c.want {
			t.Fatalf("%s: %d rows %+v, want %d", c.name, len(b.SandboxEgressRefusals), b.SandboxEgressRefusals, c.want)
		}
		if c.want == 0 {
			continue
		}
		r := b.SandboxEgressRefusals[0]
		if r.OrgID != "org-1" || r.UserEmail != "dev@example.test" || r.Tier != "proxy_only" || r.Rule != "allow-list-miss" || r.Refusals != 1 {
			t.Fatalf("%s: row %+v", c.name, r)
		}
		if !b.hasAggregates() {
			t.Fatalf("%s: a batch carrying only refusal counts must push", c.name)
		}
	}
}

// TestSandboxEgressCountsCountAgainstTheBudget: the rows are charged to the
// envelope's snapshot budget like every other family: a budget too small for
// every day bucket ships a leading page and charges exactly what it kept.
func TestSandboxEgressCountsCountAgainstTheBudget(t *testing.T) {
	ctx := context.Background()
	s, _ := newTestStore(t)
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{
			RunID: "run-1", Host: "h.example", Port: 443, Rule: "ssrf-floor", Tier: "internet", At: now.AddDate(0, 0, -i),
		}); err != nil {
			t.Fatal(err)
		}
	}
	all, err := s.SelectSandboxEgressRefusalDays(ctx)
	if err != nil || len(all) != 6 {
		t.Fatalf("rows %d %v, want 6", len(all), err)
	}
	for i := range all {
		all[i].OrgID, all[i].UserEmail = "org-1", "dev@example.test"
	}
	one := jsonSize(all[0])
	limit := 3*one + one/2
	b := &envelopeBudget{max: limit + pushEnvelopeBudgetReserve, snapshotLimit: limit}
	got, err := s.composeSandboxEgressCounts(ctx, b, "org-1", "dev@example.test")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("kept %d rows under a three-row budget", len(got))
	}
	var charged int64
	for _, r := range got {
		charged += jsonSize(r)
	}
	if b.est != charged {
		t.Fatalf("budget charged %d, the kept rows are %d bytes", b.est, charged)
	}
}
