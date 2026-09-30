package projectroi

import (
	"testing"
	"time"
)

// healthyProxyInput builds a ProxyInput where every proxy should be
// Available: one prompt, one AI-edited file that reaches one commit,
// one session, one done task, and token usage with a cache-read split.
func healthyProxyInput() ProxyInput {
	prompts := []Prompt{{ActionID: 1, SessionID: "s1", At: t0}}
	edits := []Edit{
		{ActionID: 11, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "a", AddedCode: 10, ModifiedCode: 5},
	}
	commits := []Commit{
		{ID: 1, SHA: "c1", CommittedAt: t0.Add(time.Hour), Reachable: true, Files: []CommitFile{{PathHash: "a"}}},
	}
	turns := []Turn{
		{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 50, Input: 100, CacheRead: 25},
	}
	sessions := []Session{{ID: "s1", Tool: "claude-code", StartedAt: t0, EndedAt: t0.Add(time.Hour), CostUSD: 50}}
	tasks := []Task{{SessionID: "s1", Key: "T1", Status: taskStatusDone, CostUSD: 50}}

	l := Link(prompts, edits, commits, Options{})
	spend := AttributeSpend(l, turns, prompts)

	return ProxyInput{
		WindowDays:     30,
		Turns:          turns,
		Sessions:       sessions,
		Linkage:        l,
		Spend:          spend,
		Tasks:          tasks,
		AIAdded:        10,
		AIModified:     5,
		HumanCapture:   "none",
		CommitCapture:  commitCaptureOK,
		Commits:        commits,
		TasksAvailable: true,
	}
}

func proxiesByKey(t *testing.T, in ProxyInput) map[string]Proxy {
	t.Helper()
	byKey := make(map[string]Proxy)
	for _, p := range Proxies(in) {
		if _, dup := byKey[p.Key]; dup {
			t.Fatalf("duplicate proxy key %q", p.Key)
		}
		byKey[p.Key] = p
	}
	wantKeys := []string{
		"usd_per_reached_ai_line", "ai_files_reached_share", "sessions_no_commit_usd",
		"usd_per_commit", "usd_per_task_done", "prompts_per_commit", "turns_per_commit", "cache_read_share",
	}
	if len(byKey) != len(wantKeys) {
		t.Fatalf("got %d proxies, want %d", len(byKey), len(wantKeys))
	}
	for _, k := range wantKeys {
		if _, ok := byKey[k]; !ok {
			t.Errorf("missing proxy key %q", k)
		}
	}
	return byKey
}

// TestProxies_Order pins Proxies' fixed, deterministic key order.
func TestProxies_Order(t *testing.T) {
	got := Proxies(healthyProxyInput())
	want := []string{
		"usd_per_reached_ai_line", "ai_files_reached_share", "sessions_no_commit_usd",
		"usd_per_commit", "usd_per_task_done", "prompts_per_commit", "turns_per_commit", "cache_read_share",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d", len(got), len(want))
	}
	for i, k := range want {
		if got[i].Key != k {
			t.Errorf("position %d key = %q, want %q", i, got[i].Key, k)
		}
	}
}

// TestProxies_Healthy checks every proxy's exact Key/Label/Unit/value
// when every input the metric needs is present, and pins R10's two
// verbatim-required strings.
func TestProxies_Healthy(t *testing.T) {
	byKey := proxiesByKey(t, healthyProxyInput())

	line := byKey["usd_per_reached_ai_line"]
	if !line.Available {
		t.Fatalf("usd_per_reached_ai_line not available: %s", line.Caveat)
	}
	if line.Label != "Spend per AI code line that reached a commit" {
		t.Errorf("label = %q", line.Label)
	}
	if line.Caveat != "file-level reach, not verified line survival" {
		t.Errorf("caveat = %q", line.Caveat)
	}
	// spend attributed to the one commit (50) / reached lines (10+5=15).
	if !almostEqual(line.Value, 50.0/15.0) {
		t.Errorf("value = %v, want %v", line.Value, 50.0/15.0)
	}

	share := byKey["ai_files_reached_share"]
	if !share.Available {
		t.Fatalf("ai_files_reached_share not available: %s", share.Caveat)
	}
	if share.Label != "AI-touched files that reached a commit" {
		t.Errorf("label = %q", share.Label)
	}
	if !almostEqual(share.Value, 1.0) {
		t.Errorf("value = %v, want 1.0", share.Value)
	}

	noCommit := byKey["sessions_no_commit_usd"]
	if !noCommit.Available {
		t.Fatalf("sessions_no_commit_usd not available: %s", noCommit.Caveat)
	}
	if noCommit.Label != "Spend in sessions with no linked commit (yet)" {
		t.Errorf("label = %q", noCommit.Label)
	}
	if !almostEqual(noCommit.Value, 0) {
		t.Errorf("value = %v, want 0 (the one session's file reached a commit)", noCommit.Value)
	}

	if v := byKey["usd_per_commit"]; !v.Available || !almostEqual(v.Value, 50.0) {
		t.Errorf("usd_per_commit = %+v, want available 50.0", v)
	}
	if v := byKey["usd_per_task_done"]; !v.Available || !almostEqual(v.Value, 50.0) {
		t.Errorf("usd_per_task_done = %+v, want available 50.0", v)
	}
	if v := byKey["prompts_per_commit"]; !v.Available || !almostEqual(v.Value, 1.0) {
		t.Errorf("prompts_per_commit = %+v, want available 1.0", v)
	}
	if v := byKey["turns_per_commit"]; !v.Available || !almostEqual(v.Value, 1.0) {
		t.Errorf("turns_per_commit = %+v, want available 1.0", v)
	}
	if v := byKey["cache_read_share"]; !v.Available || !almostEqual(v.Value, 0.2) {
		t.Errorf("cache_read_share = %+v, want available 0.2", v)
	}
}

// TestProxies_CommitCaptureUnavailable checks that every commit-shaped
// proxy reports Available=false naming the capture state, while
// commit-independent proxies (task cost, cache-read share) are
// unaffected.
func TestProxies_CommitCaptureUnavailable(t *testing.T) {
	in := healthyProxyInput()
	in.CommitCapture = "no_git"
	byKey := proxiesByKey(t, in)

	gated := []string{
		"usd_per_reached_ai_line", "ai_files_reached_share", "sessions_no_commit_usd",
		"usd_per_commit", "prompts_per_commit", "turns_per_commit",
	}
	for _, k := range gated {
		p := byKey[k]
		if p.Available {
			t.Errorf("%s: available = true, want false when commit capture is %q", k, in.CommitCapture)
		}
		if p.Caveat != "commit capture unavailable" {
			t.Errorf("%s: caveat = %q, want %q", k, p.Caveat, "commit capture unavailable")
		}
		if p.Value != 0 {
			t.Errorf("%s: value = %v, want 0 when unavailable", k, p.Value)
		}
	}

	if v := byKey["usd_per_task_done"]; !v.Available {
		t.Errorf("usd_per_task_done should be unaffected by commit capture: %+v", v)
	}
	if v := byKey["cache_read_share"]; !v.Available {
		t.Errorf("cache_read_share should be unaffected by commit capture: %+v", v)
	}
}

// TestProxies_NoCommitsCapturedYet checks the distinct "no commits"
// reason (capture IS running, there just aren't any yet) versus
// "commit capture unavailable".
func TestProxies_NoCommitsCapturedYet(t *testing.T) {
	prompts := []Prompt{{ActionID: 1, SessionID: "s1", At: t0}}
	edits := []Edit{{ActionID: 11, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "a"}}
	turns := []Turn{{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 10}}
	l := Link(prompts, edits, nil, Options{})
	spend := AttributeSpend(l, turns, prompts)

	in := ProxyInput{
		Turns: turns, Linkage: l, Spend: spend,
		CommitCapture: commitCaptureOK, Commits: nil,
	}
	byKey := proxiesByKey(t, in)

	for _, k := range []string{"usd_per_reached_ai_line", "usd_per_commit", "prompts_per_commit", "turns_per_commit"} {
		p := byKey[k]
		if p.Available {
			t.Errorf("%s: available = true, want false with zero commits", k)
		}
		if p.Caveat != "no commits" {
			t.Errorf("%s: caveat = %q, want %q", k, p.Caveat, "no commits")
		}
	}

	// ai_files_reached_share IS computable with zero commits: it is a
	// valid, honest zero (nothing has reached anything yet), not an
	// unavailable metric.
	share := byKey["ai_files_reached_share"]
	if !share.Available {
		t.Fatalf("ai_files_reached_share should be available (a real zero): %s", share.Caveat)
	}
	if share.Value != 0 {
		t.Errorf("ai_files_reached_share = %v, want 0", share.Value)
	}
}

// TestProxies_ZeroSpend checks the "zero spend" unavailable reason for
// dollar-shaped proxies.
func TestProxies_ZeroSpend(t *testing.T) {
	in := healthyProxyInput()
	zeroTurns := []Turn{{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 0, Input: 100, CacheRead: 25}}
	in.Turns = zeroTurns
	l := Link([]Prompt{{ActionID: 1, SessionID: "s1", At: t0}},
		[]Edit{{ActionID: 11, SessionID: "s1", At: t0.Add(time.Minute), PathHash: "a"}},
		in.Commits, Options{})
	in.Linkage = l
	in.Spend = AttributeSpend(l, zeroTurns, []Prompt{{ActionID: 1, SessionID: "s1", At: t0}})

	byKey := proxiesByKey(t, in)

	if v := byKey["usd_per_commit"]; v.Available || v.Caveat != "no spend in this window" {
		t.Errorf("usd_per_commit = %+v, want unavailable %q", v, "no spend in this window")
	}
	if v := byKey["usd_per_task_done"]; v.Available || v.Caveat != "no spend in this window" {
		t.Errorf("usd_per_task_done = %+v, want unavailable %q", v, "no spend in this window")
	}
	// cache_read_share does not depend on spend at all.
	if v := byKey["cache_read_share"]; !v.Available {
		t.Errorf("cache_read_share should be unaffected by zero spend: %+v", v)
	}
}

// TestProxies_NoDoneTasks checks usd_per_task_done's own gate,
// independent of commit capture.
func TestProxies_NoDoneTasks(t *testing.T) {
	in := healthyProxyInput()
	in.Tasks = []Task{{SessionID: "s1", Key: "T1", Status: "in_progress", CostUSD: 50}}
	byKey := proxiesByKey(t, in)
	if v := byKey["usd_per_task_done"]; v.Available {
		t.Errorf("usd_per_task_done = %+v, want unavailable with no done tasks", v)
	}
}

// TestProxies_TasksUnavailable pins 2026-09-22 rework finding #11:
// usd_per_task_done must report itself Unavailable ("task rollup
// unavailable") when TasksAvailable is false, even when in.Tasks still
// carries "done" rows (the raw task_items fallback a failed rollup
// leaves behind) — a fabricated-looking figure must never render next
// to a KPI that already says "unavailable".
func TestProxies_TasksUnavailable(t *testing.T) {
	in := healthyProxyInput()
	in.TasksAvailable = false
	byKey := proxiesByKey(t, in)
	v := byKey["usd_per_task_done"]
	if v.Available {
		t.Errorf("usd_per_task_done = %+v, want unavailable when TasksAvailable is false", v)
	}
	if v.Caveat != "task rollup unavailable" {
		t.Errorf("usd_per_task_done caveat = %q, want %q", v.Caveat, "task rollup unavailable")
	}
	if v.Value != 0 {
		t.Errorf("usd_per_task_done value = %v, want 0 when unavailable", v.Value)
	}
}

// TestProxies_NoTokenUsage checks cache_read_share's own gate.
func TestProxies_NoTokenUsage(t *testing.T) {
	in := healthyProxyInput()
	in.Turns = []Turn{{SessionID: "s1", At: t0.Add(2 * time.Minute), CostUSD: 50}}
	byKey := proxiesByKey(t, in)
	if v := byKey["cache_read_share"]; v.Available {
		t.Errorf("cache_read_share = %+v, want unavailable with zero input+cache_read", v)
	}
}

// TestProxies_HumanCaptureNeverGates checks that HumanCapture, in
// either value, never changes any of the eight shipped proxies —
// H uman-capture gating is reserved for a not-yet-built human_share
// proxy this version does not emit.
func TestProxies_HumanCaptureNeverGates(t *testing.T) {
	none := healthyProxyInput()
	none.HumanCapture = "none"
	vscode := healthyProxyInput()
	vscode.HumanCapture = "vscode"

	byNone := proxiesByKey(t, none)
	byVSCode := proxiesByKey(t, vscode)
	for k, p := range byNone {
		q := byVSCode[k]
		if p.Available != q.Available || p.Value != q.Value {
			t.Errorf("%s differs by HumanCapture: %+v vs %+v", k, p, q)
		}
	}
}

// TestProxies_SessionsNoCommitUSD checks the bucket actually excludes a
// session whose prompt reached a commit and includes one that did not.
func TestProxies_SessionsNoCommitUSD(t *testing.T) {
	prompts := []Prompt{
		{ActionID: 1, SessionID: "committed-session", At: t0},
		{ActionID: 2, SessionID: "wip-session", At: t0},
	}
	edits := []Edit{
		{ActionID: 11, SessionID: "committed-session", At: t0.Add(time.Minute), PathHash: "a"},
		{ActionID: 21, SessionID: "wip-session", At: t0.Add(time.Minute), PathHash: "b"},
	}
	commits := []Commit{
		{ID: 1, SHA: "c1", CommittedAt: t0.Add(time.Hour), Reachable: true, Files: []CommitFile{{PathHash: "a"}}},
	}
	sessions := []Session{
		{ID: "committed-session", CostUSD: 10},
		{ID: "wip-session", CostUSD: 25},
	}
	l := Link(prompts, edits, commits, Options{})
	in := ProxyInput{
		Sessions: sessions, Linkage: l, CommitCapture: commitCaptureOK, Commits: commits,
	}
	byKey := proxiesByKey(t, in)
	v := byKey["sessions_no_commit_usd"]
	if !v.Available {
		t.Fatalf("not available: %s", v.Caveat)
	}
	if !almostEqual(v.Value, 25.0) {
		t.Errorf("value = %v, want 25.0 (wip-session only)", v.Value)
	}
}
