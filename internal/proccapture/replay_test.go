package proccapture

import (
	"fmt"
	"math/rand/v2"
	"testing"
	"time"
)

// genTree builds one random session tree: a seed root, tool-call shells, build
// fan-out, console hosts, an occasional service with a polling subtree,
// failures, findings and side effects, plus unattributed held and not-held
// runs.
func genTree(r *rand.Rand, session string, n int) []RunFacts {
	exes := []string{"go", "compile.exe", "vet.exe", "conhost.exe", "git", "docker-buildx.exe", "node", "Docker Desktop.exe", "docker.exe", "git-credential-manager.exe"}
	root := RunFacts{ProcessKey: session + "-root", SessionID: session, AttributionSource: "env_token", ExeBasename: "claude.exe", Time: t0}
	out := []RunFacts{root}
	keys := []string{root.ProcessKey}
	for i := range n {
		parent := keys[r.IntN(len(keys))]
		exe := exes[r.IntN(len(exes))]
		f := RunFacts{
			ProcessKey:        fmt.Sprintf("%s-%d", session, i),
			ParentKey:         parent,
			ExeBasename:       exe,
			Argv:              exe + " " + []string{"stats --no-stream", "build ./...", "docker-cli-plugin-metadata", "status", fmt.Sprint(r.IntN(9))}[r.IntN(5)],
			SessionID:         session,
			AttributionSource: []string{"env_token", "inherited"}[r.IntN(2)],
			Time:              t0.Add(time.Duration(i+1) * time.Duration(r.IntN(4000)+1) * time.Millisecond),
			Ended:             r.IntN(10) != 0,
			AliveFor:          time.Duration(r.IntN(40)) * time.Second,
			Failed:            r.IntN(25) == 0,
			FindingsFired:     map[bool]int{true: 1}[r.IntN(60) == 0],
			SideEffects:       r.IntN(80) == 0,
			DurationMs:        int64(r.IntN(5000)),
			CPUMs:             int64(r.IntN(900)),
		}
		switch r.IntN(30) {
		case 0:
			f.SessionID, f.AttributionSource, f.HeldForCorrelation = "", "none", true
		case 1:
			f.SessionID, f.AttributionSource = "", "none"
		}
		out = append(out, f)
		keys = append(keys, f.ProcessKey)
	}
	return out
}

// TestReplayCountInvariant is the plan §5 property: kept + folded + rolled_up +
// service_kept + service_rolled_up + dropped == observed, per session and in
// total, over generated trees under several configs; and R1/R2 always win.
func TestReplayCountInvariant(t *testing.T) {
	configs := map[string]Config{"default": DefaultConfig()}
	tight := DefaultConfig()
	tight.PerToolCall, tight.PerSession, tight.PerMinute, tight.ExemplarsPerService = 3, 40, 5, 2
	configs["tight"] = tight
	noTrack := DefaultConfig()
	noTrack.TrackServices = false
	noTrack.FoldEnabled = false
	configs["no-track-no-fold"] = noTrack
	off := DefaultConfig()
	off.Enabled = false
	configs["disabled"] = off

	for seed := range uint64(25) {
		r := rand.New(rand.NewPCG(seed, 99))
		var history []RunFacts
		for s := range 3 {
			history = append(history, genTree(r, fmt.Sprintf("s%d-%d", seed, s), 150+r.IntN(300))...)
		}
		for name, cfg := range configs {
			res := Replay(history, cfg)
			var observed int64
			for sess, st := range res.Stats {
				if st.Observed != st.Accounted() {
					t.Fatalf("seed %d %s session %q: observed %d != accounted %d (%+v)", seed, name, sess, st.Observed, st.Accounted(), st)
				}
				if st.Kept < 0 || st.ServiceKept < 0 {
					t.Fatalf("seed %d %s session %q: negative counter %+v", seed, name, sess, st)
				}
				observed += st.Observed
			}
			if observed != int64(len(history)) {
				t.Fatalf("seed %d %s: observed %d, history %d", seed, name, observed, len(history))
			}
			// Rollup counts equal the rolled-up counters.
			rolled := map[string]int64{}
			for _, ru := range res.Rollups {
				rolled[ru.Key.SessionID] += ru.Count
			}
			for sess, st := range res.Stats {
				if want := st.Folded + st.RolledUp + st.ServiceRolledUp; rolled[sess] != want {
					t.Fatalf("seed %d %s session %q: rollup count %d, counters %d", seed, name, sess, rolled[sess], want)
				}
			}
			for _, o := range res.Outcomes {
				f := o.Facts
				if (f.FindingsFired > 0 || f.SideEffects || f.Failed) && !o.Decision.Action.Persists() {
					t.Fatalf("seed %d %s: a finding/side effect/failure was not kept: %+v -> %+v", seed, name, f, o.Decision)
				}
				if f.ToolCallRoot && !o.Decision.Action.Persists() {
					t.Fatalf("seed %d %s: a tool-call root was not kept", seed, name)
				}
			}
		}
	}
}

// TestReplayMeasuredShape replays a miniature of the measured session (plan
// §1): a Docker Desktop restarted from a tool call polling `docker.exe stats`
// with a console host each, long after the agent moved on, beside a real
// build. The poll is tracked (root + exemplars), then rolled up, then dropped
// after the tail; every tool-call root and failure stays.
func TestReplayMeasuredShape(t *testing.T) {
	var h []RunFacts
	add := func(f RunFacts) { h = append(h, f) }
	add(RunFacts{ProcessKey: "root", SessionID: "s", AttributionSource: "env_token", ExeBasename: "claude.exe", Time: t0})
	add(RunFacts{ProcessKey: "sh1", ParentKey: "root", SessionID: "s", AttributionSource: "env_token", ExeBasename: "bash.exe", Argv: "bash -c go test ./...", Time: t0.Add(time.Second), Ended: true, AliveFor: 40 * time.Second})
	for i := range 400 {
		add(RunFacts{
			ProcessKey: fmt.Sprint("c", i), ParentKey: "sh1", SessionID: "s", AttributionSource: "env_token", ExeBasename: "compile.exe",
			Argv: fmt.Sprint("compile.exe -p pkg", i%40), Time: t0.Add(2*time.Second + time.Duration(i)*50*time.Millisecond), Ended: true, AliveFor: time.Second, Failed: i == 7,
		})
	}
	add(RunFacts{ProcessKey: "sh2", ParentKey: "root", SessionID: "s", AttributionSource: "env_token", ExeBasename: "powershell.exe", Argv: "Start-Process Docker Desktop", Time: t0.Add(time.Minute), Ended: true, AliveFor: time.Second})
	add(RunFacts{ProcessKey: "dd", ParentKey: "sh2", SessionID: "s", AttributionSource: "env_token", ExeBasename: "Docker Desktop.exe", Time: t0.Add(61 * time.Second)})
	for i := range 3000 {
		ts := t0.Add(62*time.Second + time.Duration(i)*3*time.Second)
		add(RunFacts{
			ProcessKey: fmt.Sprint("ds", i), ParentKey: "dd", SessionID: "s", AttributionSource: "env_token", ExeBasename: "docker.exe",
			Argv: "docker.exe stats --all --no-trunc --no-stream", Time: ts, Ended: true, AliveFor: 2 * time.Second,
		})
		add(RunFacts{
			ProcessKey: fmt.Sprint("ch", i), ParentKey: fmt.Sprint("ds", i), SessionID: "s", AttributionSource: "env_token", ExeBasename: "conhost.exe",
			Time: ts.Add(10 * time.Millisecond), Ended: true, AliveFor: 2 * time.Second,
		})
	}
	res := Replay(h, DefaultConfig())
	st := res.Stats["s"]
	if st.Observed != int64(len(h)) || st.Observed != st.Accounted() {
		t.Fatalf("stats %+v for %d runs", st, len(h))
	}
	kept := 0
	for _, o := range res.Outcomes {
		if o.Decision.Action.Persists() {
			kept++
		}
		if (o.Facts.Failed || o.Facts.ToolCallRoot || o.Facts.SeedRoot) && !o.Decision.Action.Persists() {
			t.Fatalf("lost a run that matters: %+v", o.Facts)
		}
	}
	// root + 2 shells + 200 compile exemplars (+1 failure) + service root + 20
	// service exemplars.
	if kept > 230 || kept < 220 {
		t.Fatalf("kept %d rows of %d", kept, len(h))
	}
	if st.Dropped == 0 {
		t.Fatal("the poll after the session tail was not dropped")
	}
	if st.ServiceRolledUp == 0 || st.RolledUp == 0 {
		t.Fatalf("expected service and budget rollups: %+v", st)
	}
	// The poll groups per minute bucket, not per run.
	if len(res.Rollups) > 200 {
		t.Fatalf("%d rollup rows for %d rolled-up runs", len(res.Rollups), st.RolledUp+st.ServiceRolledUp+st.Folded)
	}
}

// TestReplayDetachHeuristic: a dev server started by a tool call keeps
// spawning long after the call ended and becomes a service root.
func TestReplayDetachHeuristic(t *testing.T) {
	h := []RunFacts{
		{ProcessKey: "root", SessionID: "s", AttributionSource: "bridge", ExeBasename: "claude", Time: t0},
		{ProcessKey: "sh", ParentKey: "root", SessionID: "s", AttributionSource: "inherited", ExeBasename: "bash", Time: t0.Add(time.Second), Ended: true, AliveFor: 2 * time.Second},
		{ProcessKey: "npm", ParentKey: "sh", SessionID: "s", AttributionSource: "inherited", ExeBasename: "node", Argv: "node dev-server", Time: t0.Add(2 * time.Second), AliveFor: time.Hour},
		{ProcessKey: "early", ParentKey: "npm", SessionID: "s", AttributionSource: "inherited", ExeBasename: "esbuild", Time: t0.Add(5 * time.Second), Ended: true},
		{ProcessKey: "late", ParentKey: "npm", SessionID: "s", AttributionSource: "inherited", ExeBasename: "esbuild", Time: t0.Add(20 * time.Minute), Ended: true},
	}
	res := Replay(h, DefaultConfig())
	byKey := map[string]Outcome{}
	for _, o := range res.Outcomes {
		byKey[o.Facts.ProcessKey] = o
	}
	if o := byKey["npm"]; !o.Detached || o.Decision.Class != ClassServiceRoot {
		t.Fatalf("npm not detached: %+v", o)
	}
	if o := byKey["early"]; o.Facts.ServiceRootKey != "" {
		t.Fatalf("a row recorded before the detach moved into the service: %+v", o.Facts)
	}
	if o := byKey["late"]; o.Facts.ServiceRootKey != "npm" || o.Decision.Class != ClassService {
		t.Fatalf("late child not the service's: %+v %+v", o.Facts, o.Decision)
	}
	if st := res.Stats["s"]; st.Observed != st.Accounted() || st.ServiceKept < 2 {
		t.Fatalf("stats %+v", st)
	}
}

// TestAccumulatorMergesGroups pins the rollup accumulator's arithmetic.
func TestAccumulatorMergesGroups(t *testing.T) {
	acc := NewAccumulator()
	k := GroupKey{SessionID: "s", Kind: GroupBudget, ExeBasename: "x"}
	acc.AddRollup(k, RunFacts{ProcessKey: "a", Argv: "x 1", Time: t0.Add(time.Second), DurationMs: 10, CPUMs: 3, PeakRSSBytes: 100})
	acc.AddRollup(k, RunFacts{ProcessKey: "b", Argv: "x 2", Time: t0, DurationMs: 30, CPUMs: 4, PeakRSSBytes: 50, Failed: true})
	d := acc.Delta()
	if len(d.Rollups) != 1 {
		t.Fatalf("%d groups", len(d.Rollups))
	}
	r := d.Rollups[0]
	if r.Count != 2 || r.FailedCount != 1 || r.DurationSumMs != 40 || r.DurationMaxMs != 30 || r.CPUSumMs != 7 ||
		r.PeakRSSBytes != 100 || !r.FirstSeen.Equal(t0) || !r.LastSeen.Equal(t0.Add(time.Second)) ||
		r.ExampleProcessKey != "a" || r.ExampleArgvPreview != "x 1" {
		t.Fatalf("rollup %+v", r)
	}
	other := r
	r.Merge(other)
	if r.Count != 4 || r.DurationMaxMs != 30 {
		t.Fatalf("merge %+v", r)
	}
}

// TestReplayParentsBeforeChildrenOnTiedStartTimes: stored start times are
// coarse, so a parent and its child often tie, and the tie break (the
// process key) can put the child first. Replay must still see the parent
// first: otherwise every such child looks like an AI tool's root (R3) and
// is kept, which is what made compaction keep ~90% of a legacy session.
func TestReplayParentsBeforeChildrenOnTiedStartTimes(t *testing.T) {
	var h []RunFacts
	// Keys sort children ("a…") before their parents ("z…"); every run
	// starts in the same second.
	h = append(h, RunFacts{ProcessKey: "zroot", SessionID: "s", AttributionSource: "env_token", ExeBasename: "claude.exe", Time: t0})
	h = append(h, RunFacts{ProcessKey: "zsh", ParentKey: "zroot", SessionID: "s", AttributionSource: "env_token", ExeBasename: "bash.exe", Time: t0, Ended: true, AliveFor: time.Second})
	for i := range 600 {
		h = append(h, RunFacts{
			ProcessKey: fmt.Sprintf("a%03d", i), ParentKey: "zsh", SessionID: "s", AttributionSource: "env_token",
			ExeBasename: "git", Argv: "git status", Time: t0, Ended: true, AliveFor: time.Second,
		})
	}
	res := Replay(h, DefaultConfig())
	seeds, kept := 0, 0
	for _, o := range res.Outcomes {
		if o.Facts.SeedRoot {
			seeds++
		}
		if o.Decision.Action.Persists() {
			kept++
		}
	}
	if seeds != 1 {
		t.Fatalf("%d runs taken for an AI tool's root, want 1", seeds)
	}
	// root + the tool call's shell + 200 exemplars under the per-tool-call budget.
	if kept > 205 {
		t.Fatalf("kept %d of %d runs, want about 202", kept, len(h))
	}
	if st := res.Stats["s"]; st.Observed != st.Accounted() {
		t.Fatalf("count invariant: %+v", st)
	}
}

func TestParentsFirstKeepsTimeOrderOtherwise(t *testing.T) {
	in := []RunFacts{
		{ProcessKey: "b", ParentKey: "c"},
		{ProcessKey: "x"},
		{ProcessKey: "c", ParentKey: "d"},
		{ProcessKey: "d"},
		{ProcessKey: "y", ParentKey: "y"},
		{ProcessKey: "p", ParentKey: "q"},
		{ProcessKey: "q", ParentKey: "p"},
	}
	var got []string
	for _, r := range parentsFirst(in) {
		got = append(got, r.ProcessKey)
	}
	want := []string{"d", "c", "b", "x", "y", "q", "p"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
