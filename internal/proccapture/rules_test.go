package proccapture

import (
	"testing"
	"time"
)

var t0 = time.Date(2026, 11, 4, 10, 0, 0, 0, time.UTC)

// base is an attributed, plain run: no row of the table above R8 fires for it.
func base() RunFacts {
	return RunFacts{
		ProcessKey: "k-run", ParentKey: "k-parent", AnchorKey: "k-parent",
		ExeBasename: "go", Argv: "go build ./...", SessionID: "s1",
		AttributionSource: "inherited", Time: t0, ToolCallKey: "k-tc",
	}
}

// TestDecisionTableRows is one case per row of the decision table (CLAUDE.md
// rule 5), plus the disabled path. Each case is the smallest change to base()
// that makes exactly that row the first match.
func TestDecisionTableRows(t *testing.T) {
	cfg := DefaultConfig()
	full := BudgetState{ToolCall: cfg.PerToolCall, Session: cfg.PerSession, Minute: cfg.PerMinute}
	cases := []struct {
		name   string
		cfg    func(*Config)
		facts  func(*RunFacts)
		budget BudgetState
		rule   string
		action Action
		kind   GroupKind
		ctr    Counter
	}{
		{name: "R1 finding beats a full budget", facts: func(f *RunFacts) { f.FindingsFired = 1 }, budget: full, rule: "R1", action: ActionKeep, ctr: CounterKept},
		{name: "R1 side effect beats the fold table", facts: func(f *RunFacts) { f.SideEffects = true; f.ExeBasename = "conhost.exe" }, rule: "R1", action: ActionKeep, ctr: CounterKept},
		{name: "R2 failure", facts: func(f *RunFacts) { f.Failed = true; f.Ended = true }, budget: full, rule: "R2", action: ActionKeep, ctr: CounterKept},
		{name: "R3 action link", facts: func(f *RunFacts) { f.ActionID = 7 }, budget: full, rule: "R3", action: ActionKeep, ctr: CounterKept},
		{name: "R3 seed root", facts: func(f *RunFacts) { f.SeedRoot = true }, budget: full, rule: "R3", action: ActionKeep, ctr: CounterKept},
		{name: "R3 tool-call root", facts: func(f *RunFacts) { f.ToolCallRoot = true }, budget: full, rule: "R3", action: ActionKeep, ctr: CounterKept},
		{name: "R4 service table", facts: func(f *RunFacts) { f.ExeBasename = "Docker Desktop.exe"; f.ServiceRootKey = f.ProcessKey }, rule: "R4", action: ActionDetach, ctr: CounterServiceKept},
		{name: "R4 detach heuristic", facts: func(f *RunFacts) { f.DetachHeuristic = true }, rule: "R4", action: ActionDetach, ctr: CounterServiceKept},
		{name: "R5 service exemplar", facts: func(f *RunFacts) { f.ServiceRootKey = "k-svc" }, budget: full, rule: "R5", action: ActionKeep, ctr: CounterServiceKept},
		{name: "R5 service cap full rolls up", facts: func(f *RunFacts) { f.ServiceRootKey = "k-svc" }, budget: BudgetState{Service: 20}, rule: "R5", action: ActionRollup, kind: GroupService, ctr: CounterServiceRolledUp},
		{name: "R5 fold-table run under a service rolls up", facts: func(f *RunFacts) { f.ServiceRootKey = "k-svc"; f.ExeBasename = "conhost.exe" }, rule: "R5", action: ActionRollup, kind: GroupService, ctr: CounterServiceRolledUp},
		{name: "R5 after the session tail drops", facts: func(f *RunFacts) {
			f.ServiceRootKey = "k-svc"
			f.SessionLastActivity = t0.Add(-31 * time.Minute)
		}, rule: "R5", action: ActionDrop, ctr: CounterDropped},
		{name: "R5 untracked services drop", cfg: func(c *Config) { c.TrackServices = false }, facts: func(f *RunFacts) { f.ServiceRootKey = "k-svc" }, rule: "R5", action: ActionDrop, ctr: CounterDropped},
		{name: "R6 conhost folds", facts: func(f *RunFacts) { f.ExeBasename = "conhost.exe" }, rule: "R6", action: ActionFold, kind: GroupFold, ctr: CounterFolded},
		{name: "R7 long-lived", facts: func(f *RunFacts) { f.AliveFor = 31 * time.Second }, budget: full, rule: "R7", action: ActionKeep, ctr: CounterKept},
		{name: "R8 budget room", rule: "R8", action: ActionKeep, ctr: CounterKept},
		{name: "R9 tool-call budget full", budget: BudgetState{ToolCall: 200}, rule: "R9", action: ActionRollup, kind: GroupBudget, ctr: CounterRolledUp},
		{name: "R9 session budget full", budget: BudgetState{Session: 5000}, rule: "R9", action: ActionRollup, kind: GroupBudget, ctr: CounterRolledUp},
		{name: "R9 per-minute burst guard", budget: BudgetState{Minute: 300}, rule: "R9", action: ActionRollup, kind: GroupBudget, ctr: CounterRolledUp},
		{name: "R10 unattributed, not held", facts: func(f *RunFacts) { f.SessionID = "" }, rule: "R10", action: ActionDrop, ctr: CounterDropped},
		{name: "R11 unattributed, held for correlation", facts: func(f *RunFacts) { f.SessionID = ""; f.HeldForCorrelation = true }, rule: "R11", action: ActionKeep, ctr: CounterKept},
		{name: "disabled keeps everything", cfg: func(c *Config) { c.Enabled = false }, facts: func(f *RunFacts) { f.ExeBasename = "conhost.exe" }, rule: "disabled", action: ActionKeep, ctr: CounterKept},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := DefaultConfig()
			if tc.cfg != nil {
				tc.cfg(&c)
			}
			f := base()
			if tc.facts != nil {
				tc.facts(&f)
			}
			d := NewPolicy(c).Classify(f, tc.budget)
			if d.Rule != tc.rule || d.Action != tc.action || d.Counter != tc.ctr {
				t.Fatalf("got rule %s action %s counter %s, want %s %s %s", d.Rule, d.Action, d.Counter, tc.rule, tc.action, tc.ctr)
			}
			if d.Group.Kind != tc.kind {
				t.Fatalf("group kind %q, want %q", d.Group.Kind, tc.kind)
			}
			// A rollup group is keyed by its parent; a fold group is not (a
			// minute of console hosts is one row) and carries the parent as
			// the fold anchor instead.
			if tc.action == ActionRollup && d.Group.ParentProcessKey == "" {
				t.Fatalf("a rollup group needs a parent key: %+v", d.Group)
			}
			if tc.action == ActionFold && (d.Group.ParentProcessKey != "" || d.FoldAnchor == "") {
				t.Fatalf("a fold has no group parent and a fold anchor: group %+v anchor %q", d.Group, d.FoldAnchor)
			}
		})
	}
}

// TestBudgetsUncappedAtZero pins "<= 0 is uncapped" for every budget.
func TestBudgetsUncappedAtZero(t *testing.T) {
	c := DefaultConfig()
	c.PerToolCall, c.PerSession, c.PerMinute = 0, 0, 0
	d := NewPolicy(c).Classify(base(), BudgetState{ToolCall: 1e6, Session: 1e6, Minute: 1e6})
	if d.Rule != "R8" {
		t.Fatalf("rule %s, want R8", d.Rule)
	}
}

// TestBudgetSlotsTakenOnlyByBudgetRules pins that R1-R3 never take a budget
// slot and R5 takes only the service slot.
func TestBudgetSlotsTakenOnlyByBudgetRules(t *testing.T) {
	p := NewPolicy(DefaultConfig())
	l := NewLedger()
	f := base()
	f.Failed = true
	l.Record(f, p.Classify(f, l.State(f)))
	if s := l.State(f); s.Session != 0 || s.ToolCall != 0 || s.Minute != 0 {
		t.Fatalf("R2 took a slot: %+v", s)
	}
	g := base()
	l.Record(g, p.Classify(g, l.State(g)))
	if s := l.State(g); s.Session != 1 || s.ToolCall != 1 || s.Minute != 1 {
		t.Fatalf("R8 did not take a slot: %+v", s)
	}
	h := base()
	h.ServiceRootKey = "k-svc"
	l.Record(h, p.Classify(h, l.State(h)))
	if s := l.State(h); s.Service != 1 || s.Session != 1 {
		t.Fatalf("R5 slots wrong: %+v", s)
	}
}

// TestDerive pins the tree-derived facts: seed root, tool-call root, tool-call
// key inheritance, the service boundary, and anchors.
func TestDerive(t *testing.T) {
	p := NewPolicy(DefaultConfig())
	// The AI tool's root: env-token identity, untracked parent.
	root := RunFacts{ProcessKey: "root", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "claude.exe"}
	p.Derive(&root, nil)
	if !root.SeedRoot || root.ToolCallRoot {
		t.Fatalf("root: %+v", root)
	}
	rootLin := LineageOf(root, Decision{Action: ActionKeep})
	// A tool call's shell: carries the token too, but its parent is the session.
	shell := RunFacts{ProcessKey: "sh", ParentKey: "root", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "bash.exe"}
	p.Derive(&shell, &rootLin)
	if shell.SeedRoot || !shell.ToolCallRoot || shell.ToolCallKey != "sh" || shell.AnchorKey != "root" {
		t.Fatalf("shell: %+v", shell)
	}
	// A Windows host the cross-OS pass matched is the tool's root too, so its
	// env-token shells are tool-call roots exactly as under a bridge hit.
	host := RunFacts{ProcessKey: "win", SessionID: "s1", AttributionSource: "cross_os_correlation", ExeBasename: "claude.exe"}
	p.Derive(&host, nil)
	if !host.SeedRoot || host.ToolCallRoot {
		t.Fatalf("cross-OS host: %+v", host)
	}
	hostLin := LineageOf(host, Decision{Action: ActionKeep})
	winShell := RunFacts{ProcessKey: "wsh", ParentKey: "win", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "bash.exe"}
	p.Derive(&winShell, &hostLin)
	if winShell.SeedRoot || !winShell.ToolCallRoot {
		t.Fatalf("cross-OS host's shell: %+v", winShell)
	}
	shellLin := LineageOf(shell, Decision{Action: ActionKeep})
	child := RunFacts{ProcessKey: "go", ParentKey: "sh", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "go.exe"}
	p.Derive(&child, &shellLin)
	if child.ToolCallRoot || child.ToolCallKey != "sh" || child.AnchorKey != "sh" {
		t.Fatalf("child: %+v", child)
	}
	// A rolled-up child anchors its own children to ITS anchor.
	childLin := LineageOf(child, Decision{Action: ActionRollup})
	grand := RunFacts{ProcessKey: "compile", ParentKey: "go", SessionID: "s1", AttributionSource: "inherited"}
	p.Derive(&grand, &childLin)
	if grand.AnchorKey != "sh" {
		t.Fatalf("grand anchor %q, want sh", grand.AnchorKey)
	}
	// A service started from the tool call: the env token does not make it
	// (or its children) a seed root, and the service propagates.
	svc := RunFacts{ProcessKey: "dd", ParentKey: "sh", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "Docker Desktop.exe"}
	p.Derive(&svc, &shellLin)
	if svc.ServiceRootKey != "dd" || svc.SeedRoot || svc.ToolCallRoot || svc.ToolCallKey != "sh" {
		t.Fatalf("service root: %+v", svc)
	}
	svcLin := LineageOf(svc, Decision{Action: ActionDetach})
	poll := RunFacts{ProcessKey: "stats", ParentKey: "dd", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "docker.exe"}
	p.Derive(&poll, &svcLin)
	if poll.ServiceRootKey != "dd" || poll.SeedRoot || poll.ToolCallRoot {
		t.Fatalf("service child: %+v", poll)
	}
	// An orphaned service (parent untracked) is still a service, not a seed root.
	orphan := RunFacts{ProcessKey: "dd2", SessionID: "s1", AttributionSource: "env_token", ExeBasename: "Docker Desktop.exe"}
	p.Derive(&orphan, nil)
	if orphan.SeedRoot || orphan.ServiceRootKey != "dd2" {
		t.Fatalf("orphan service: %+v", orphan)
	}
}

// TestShouldDetach pins the detach heuristic.
func TestShouldDetach(t *testing.T) {
	p := NewPolicy(DefaultConfig())
	parent := Lineage{ProcessKey: "npm", SessionID: "s1", ToolCallKey: "sh"}
	ended := t0
	cases := []struct {
		name    string
		parent  Lineage
		ended   time.Time
		spawnAt time.Time
		want    bool
	}{
		{"outlived by more than the grace", parent, ended, ended.Add(11 * time.Minute), true},
		{"inside the grace", parent, ended, ended.Add(9 * time.Minute), false},
		{"tool call still running", parent, time.Time{}, ended.Add(time.Hour), false},
		{"already a service", Lineage{ProcessKey: "npm", SessionID: "s1", ToolCallKey: "sh", ServiceRootKey: "x"}, ended, ended.Add(time.Hour), false},
		{"the tool-call root itself", Lineage{ProcessKey: "sh", SessionID: "s1", ToolCallKey: "sh"}, ended, ended.Add(time.Hour), false},
		{"unattributed", Lineage{ProcessKey: "npm", ToolCallKey: "sh"}, ended, ended.Add(time.Hour), false},
	}
	for _, tc := range cases {
		if got := p.ShouldDetach(tc.parent, tc.ended, tc.spawnAt); got != tc.want {
			t.Errorf("%s: got %v want %v", tc.name, got, tc.want)
		}
	}
}
