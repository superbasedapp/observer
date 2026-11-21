package store

import (
	"context"
	"testing"
	"time"
)

// TestSandboxEgressRefusalInsertAndDedupe pins the one writer: a refusal is
// written once per (run, host, minute); the next minute, another host or
// another run is a new row; a row missing run id, host or rule is refused.
func TestSandboxEgressRefusalInsertAndDedupe(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 30, 12, 0, 10, 0, time.UTC)
	cases := []struct {
		name string
		r    SandboxEgressRefusal
		want bool
	}{
		{"first", SandboxEgressRefusal{RunID: "run-a", Host: "evil.example", Port: 443, Rule: "allow-list-miss", Key: "terminal.sandbox.egress_allow_hosts", At: t0}, true},
		{"same host same minute", SandboxEgressRefusal{RunID: "run-a", Host: "evil.example", Port: 8443, Rule: "port-not-allowed", At: t0.Add(40 * time.Second)}, false},
		{"same host next minute", SandboxEgressRefusal{RunID: "run-a", Host: "evil.example", Port: 443, Rule: "allow-list-miss", At: t0.Add(time.Minute)}, true},
		{"another host", SandboxEgressRefusal{RunID: "run-a", Host: "10.0.0.5", Port: 443, Rule: "private-range", At: t0}, true},
		{"another run", SandboxEgressRefusal{RunID: "run-b", Host: "evil.example", Port: 443, Rule: "allow-list-miss", At: t0}, true},
	}
	for _, tc := range cases {
		got, err := s.InsertSandboxEgressRefusal(ctx, tc.r)
		if err != nil || got != tc.want {
			t.Fatalf("%s: inserted %v err %v, want %v", tc.name, got, err, tc.want)
		}
	}
	for _, bad := range []SandboxEgressRefusal{
		{Host: "h", Rule: "ssrf-floor"},
		{RunID: "r", Rule: "ssrf-floor"},
		{RunID: "r", Host: "h"},
	} {
		if _, err := s.InsertSandboxEgressRefusal(ctx, bad); err == nil {
			t.Fatalf("incomplete row %+v accepted", bad)
		}
	}
	all, err := s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{})
	if err != nil || len(all) != 4 {
		t.Fatalf("rows %d err %v", len(all), err)
	}
}

// TestSandboxEgressRefusalStampsFromTerminalRun: an insert without backend
// and tier takes them from the run's stored terminal_run row; one that
// names them keeps its own.
func TestSandboxEgressRefusalStampsFromTerminalRun(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO terminal_run (run_id, tool, kind, launched_at, stack, egress_tier) VALUES ('tr-1', 'claude-code', 'fresh', '2026-10-30T12:00:00Z', 'bwrap', 'internet')`); err != nil {
		t.Fatal(err)
	}
	at := time.Date(2026, 10, 30, 12, 1, 0, 0, time.UTC)
	if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: "tr-1", Host: "a.example", Rule: "allow-list-miss", At: at}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: "tr-1", Host: "b.example", Rule: "allow-list-miss", Backend: "oci-runc", Tier: "proxy_only", At: at}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: "no-row", Host: "c.example", Rule: "allow-list-miss", At: at}); err != nil {
		t.Fatal(err)
	}
	got := map[string]SandboxEgressRefusal{}
	rows, err := s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		got[r.Host] = r
	}
	if r := got["a.example"]; r.Backend != "bwrap" || r.Tier != "internet" {
		t.Errorf("stamped %+v", r)
	}
	if r := got["b.example"]; r.Backend != "oci-runc" || r.Tier != "proxy_only" {
		t.Errorf("own values %+v", r)
	}
	if r := got["c.example"]; r.Backend != "" || r.Tier != "" {
		t.Errorf("no row %+v", r)
	}
}

// TestSandboxEgressRefusalLists: by run and by project, newest first, with
// the page bound and the before cursor.
func TestSandboxEgressRefusalLists(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	ins := func(run, project, host string, at time.Time) {
		t.Helper()
		if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: run, ProjectRoot: project, Host: host, Rule: "ssrf-floor", At: at}); err != nil {
			t.Fatal(err)
		}
	}
	ins("r1", "/p/one", "a.example", t0)
	ins("r1", "/p/one", "b.example", t0.Add(time.Minute))
	ins("r2", "/p/one", "c.example", t0.Add(2*time.Minute))
	ins("r3", "/p/two", "d.example", t0.Add(3*time.Minute))
	hosts := func(rs []SandboxEgressRefusal) string {
		out := ""
		for _, r := range rs {
			out += r.Host[:1]
		}
		return out
	}
	byRun, err := s.ListSandboxEgressRefusalsByRun(ctx, "r1", 0, 0)
	if err != nil || hosts(byRun) != "ba" {
		t.Fatalf("by run %q %v", hosts(byRun), err)
	}
	if !byRun[0].At.Equal(t0.Add(time.Minute)) {
		t.Fatalf("time %v", byRun[0].At)
	}
	byProject, err := s.ListSandboxEgressRefusalsByProject(ctx, "/p/one", 0, 0)
	if err != nil || hosts(byProject) != "cba" {
		t.Fatalf("by project %q %v", hosts(byProject), err)
	}
	page, err := s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{Limit: 2})
	if err != nil || hosts(page) != "dc" {
		t.Fatalf("page %q %v", hosts(page), err)
	}
	next, err := s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{Limit: 2, Before: page[1].ID})
	if err != nil || hosts(next) != "ba" {
		t.Fatalf("next page %q %v", hosts(next), err)
	}
	none, err := s.ListSandboxEgressRefusalsByRun(ctx, "nope", 0, 0)
	if err != nil || none == nil || len(none) != 0 {
		t.Fatalf("empty list %v %v", none, err)
	}
}

// TestSandboxEgressRefusalPrune deletes only rows older than the cutoff.
func TestSandboxEgressRefusalPrune(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for i, age := range []time.Duration{40 * 24 * time.Hour, 31 * 24 * time.Hour, 29 * 24 * time.Hour, time.Hour} {
		if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: "r", Host: string(rune('a'+i)) + ".example", Rule: "ssrf-floor", At: now.Add(-age)}); err != nil {
			t.Fatal(err)
		}
	}
	n, err := s.PruneSandboxEgressRefusals(ctx, now.Add(-SandboxEgressRefusalRetention))
	if err != nil || n != 2 {
		t.Fatalf("pruned %d err %v", n, err)
	}
	left, _ := s.ListSandboxEgressRefusals(ctx, SandboxEgressRefusalQuery{})
	if len(left) != 2 {
		t.Fatalf("left %d", len(left))
	}
}

// TestSandboxEgressRefusalDrops (lane OC, audit findings O3-W2 and OC-A1):
// the one writer adds to a run's dropped and uncertain counts, the read
// answers only the runs asked that have one, an empty run, a negative
// count or no positive count is refused, and the retention delete prunes
// counts not added to since the cutoff.
func TestSandboxEgressRefusalDrops(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, add := range []struct {
		run    string
		n, unc int
		at     time.Time
	}{{"run-a", 3, 0, t0}, {"run-a", 4, 2, t0.Add(time.Minute)}, {"run-b", 1, 0, t0}, {"run-u", 0, 5, t0}} {
		if err := s.AddSandboxEgressRefusalDrops(ctx, add.run, add.n, add.unc, add.at); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []struct {
		run    string
		n, unc int
	}{{"", 1, 0}, {"run-c", 0, 0}, {"run-c", -2, 3}, {"run-c", 2, -1}} {
		if err := s.AddSandboxEgressRefusalDrops(ctx, bad.run, bad.n, bad.unc, t0); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	got, err := s.SandboxEgressRefusalDrops(ctx, []string{"run-a", "run-b", "run-u", "run-a", "run-none", ""})
	want := map[string]SandboxEgressRefusalDrop{"run-a": {Dropped: 7, Uncertain: 2}, "run-b": {Dropped: 1}, "run-u": {Uncertain: 5}}
	if err != nil || len(got) != len(want) {
		t.Fatalf("drops %v err %v", got, err)
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s: %+v, want %+v", k, got[k], w)
		}
	}
	if empty, err := s.SandboxEgressRefusalDrops(ctx, nil); err != nil || len(empty) != 0 {
		t.Fatalf("no ids: %v %v", empty, err)
	}
	if _, err := s.PruneSandboxEgressRefusals(ctx, t0.Add(30*time.Second)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.SandboxEgressRefusalDrops(ctx, []string{"run-a", "run-b", "run-u"}); len(got) != 1 || got["run-a"] != (SandboxEgressRefusalDrop{Dropped: 7, Uncertain: 2}) {
		t.Fatalf("after the prune: %v", got)
	}
}

// TestSandboxEgressRefusalLinkLoss (F-012, audit finding N4-A4; migration
// 233): lost refusals add to dropped and link_lost, closed requests to
// egress_closed only, on top of the run's other counts; bad input is
// refused.
func TestSandboxEgressRefusalLinkLoss(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	if err := s.AddSandboxEgressRefusalDrops(ctx, "run-a", 2, 1, t0); err != nil {
		t.Fatal(err)
	}
	for _, add := range []struct {
		run          string
		lost, closed int
	}{{"run-a", 3, 0}, {"run-a", 1, 4}, {"run-c", 0, 9}} {
		if err := s.AddSandboxEgressRefusalLinkLoss(ctx, add.run, add.lost, add.closed, t0); err != nil {
			t.Fatal(err)
		}
	}
	for _, bad := range []struct {
		run          string
		lost, closed int
	}{{"", 1, 0}, {"run-x", 0, 0}, {"run-x", -1, 2}, {"run-x", 1, -1}} {
		if err := s.AddSandboxEgressRefusalLinkLoss(ctx, bad.run, bad.lost, bad.closed, t0); err == nil {
			t.Fatalf("%+v accepted", bad)
		}
	}
	got, err := s.SandboxEgressRefusalDrops(ctx, []string{"run-a", "run-c"})
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]SandboxEgressRefusalDrop{
		"run-a": {Dropped: 6, Uncertain: 1, LinkLost: 4, EgressClosed: 4},
		"run-c": {EgressClosed: 9},
	}
	for k, w := range want {
		if got[k] != w {
			t.Fatalf("%s: %+v, want %+v", k, got[k], w)
		}
	}
}

// TestSandboxEgressRefusalPerRunBound (F-009, audit finding N1-A4): past
// the per-run total bound the run's oldest rows go as each new one is
// written, the removals are counted, and another run is untouched.
func TestSandboxEgressRefusalPerRunBound(t *testing.T) {
	old := sandboxEgressRefusalMaxPerRun
	sandboxEgressRefusalMaxPerRun = 3
	t.Cleanup(func() { sandboxEgressRefusalMaxPerRun = old })
	s, _ := newTestStore(t)
	ctx := context.Background()
	t0 := time.Date(2026, 11, 2, 12, 0, 0, 0, time.UTC)
	for i, host := range []string{"a", "b", "c", "d", "e"} {
		if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: "run-x", Host: host, Rule: "ssrf-floor", At: t0.Add(time.Duration(i) * time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := s.InsertSandboxEgressRefusal(ctx, SandboxEgressRefusal{RunID: "run-y", Host: "z", Rule: "ssrf-floor", At: t0}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.ListSandboxEgressRefusalsByRun(ctx, "run-x", 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hosts string
	for _, r := range rows {
		hosts += r.Host
	}
	if hosts != "edc" {
		t.Fatalf("kept %q, want the newest three", hosts)
	}
	got, err := s.SandboxEgressRefusalDrops(ctx, []string{"run-x", "run-y"})
	if err != nil {
		t.Fatal(err)
	}
	if got["run-x"] != (SandboxEgressRefusalDrop{Evicted: 2}) {
		t.Fatalf("run-x counts %+v", got["run-x"])
	}
	if _, ok := got["run-y"]; ok {
		t.Fatalf("an untouched run has counts: %+v", got["run-y"])
	}
}
