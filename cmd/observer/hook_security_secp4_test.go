//go:build !sbo_omit_security

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
)

// TestSecurityFunctionLineCommitAnswersUnknown (lane SEC-P4 decision 1,
// SECP-18): a line that defines a function reads its commit unplaced
// under a clean posture, POSIX and PowerShell, so S-794 asks; before, a
// POSIX body's commit was placed where it is written, and a header glued
// to it (`f(){ git commit`) hid the commit from the gate.
func TestSecurityFunctionLineCommitAnswersUnknown(t *testing.T) {
	n := newGate5Repos(t)
	for _, tc := range []struct {
		line    string
		dialect policy.Dialect
	}{
		{"f(){ git commit -m wip; }; cd " + shPath(n.other) + " && f", policy.DialectPosix},
		{"f () { git commit -m wip; }; cd " + shPath(n.other) + " && f", policy.DialectPosix},
		{"function f { git commit -m wip; }; cd " + shPath(n.other) + "; f", policy.DialectPosix},
		{"function f { git commit -m wip }; Set-Location " + n.other + "; f", policy.DialectPowerShell},
		{"filter g { git commit -m wip }; g", policy.DialectPowerShell},
	} {
		n.writePostureFor(t, n.root, nil)
		pe := shellCommit(tc.line, n.root, "")
		pe.Dialect = tc.dialect
		if v := n.evaluate(t, pe); v.RuleID != "S-794" || v.Decision != policy.DecisionAsk {
			t.Fatalf("%q: verdict %+v (security %+v), want S-794 ask", tc.line, v, pe.Security)
		}
	}
}

// mcpEvent is an MCP call from the session's project carrying args.
func mcpEvent(tool, cwd, args string) *policy.Event {
	return &policy.Event{Kind: policy.KindMCPCall, ActionType: models.ActionMCPCall, Target: tool, Cwd: cwd, Raw: []byte(args)}
}

// TestSecurityMCPRepoPathPlacement (lane SEC-P4 decision 2): the reference
// git server's commit is placed at its repo_path. Another repository with
// no posture asks (S-794); an absent repo_path asks; the event's own
// repository under a clean posture proceeds (the golden row).
func TestSecurityMCPRepoPathPlacement(t *testing.T) {
	n := newGate5Repos(t)
	tool := "mcp__git__git_commit"

	n.writePostureFor(t, n.root, nil)
	pe := mcpEvent(tool, n.root, `{"repo_path":"`+n.other+`","message":"m"}`)
	if v := n.evaluate(t, pe); v.RuleID != "S-794" {
		t.Fatalf("other repository: verdict %+v (security %+v), want S-794", v, pe.Security)
	}

	n.writePostureFor(t, n.root, nil)
	pe = mcpEvent(tool, n.root, `{"message":"m"}`)
	if v := n.evaluate(t, pe); v.RuleID != "S-794" {
		t.Fatalf("no repo_path: verdict %+v (security %+v), want S-794", v, pe.Security)
	}

	n.writePostureFor(t, n.root, nil)
	pe = mcpEvent(tool, n.root, `{"repo_path":`+jsonString(n.root)+`,"message":"m"}`)
	if v := n.evaluate(t, pe); v.RuleID == "S-794" || v.RuleID == "S-793" || v.RuleID == "S-791" {
		t.Fatalf("own repository: verdict %+v (security %+v), want it to proceed", v, pe.Security)
	}
	if pe.Security == nil || pe.Security.Posture != policy.SecurityPostureClean {
		t.Fatalf("own repository: security %+v, want clean", pe.Security)
	}
}

// TestSecurityMCPContentCarriesSecret (lane SEC-P4 decision 2): a GitHub
// content tool carrying a secret gates as blocking (S-791) under a clean
// posture; unreadable arguments ask (S-794); clean contents and the
// merge row keep today's placement and proceed.
func TestSecurityMCPContentCarriesSecret(t *testing.T) {
	n := newGate5Repos(t)
	secret := `k = \"` + fakeSecretAWSKeyID + `\"\n`

	n.writePostureFor(t, n.root, nil)
	pe := mcpEvent("mcp__github__push_files", n.root, `{"owner":"o","repo":"r","files":[{"path":"cfg.py","content":"`+secret+`"}]}`)
	if v := n.evaluate(t, pe); v.RuleID != "S-791" {
		t.Fatalf("secret in push_files: verdict %+v (security %+v), want S-791", v, pe.Security)
	}

	n.writePostureFor(t, n.root, nil)
	pe = mcpEvent("mcp__github__create_or_update_file", n.root, `{"content":`)
	if v := n.evaluate(t, pe); v.RuleID != "S-794" {
		t.Fatalf("unreadable arguments: verdict %+v (security %+v), want S-794", v, pe.Security)
	}

	for _, tc := range []struct{ tool, args string }{
		{"mcp__github__create_or_update_file", `{"path":"a.txt","content":"hello"}`},
		{"mcp__github__merge_pull_request", `{"owner":"o","repo":"r","pull_number":1}`},
	} {
		n.writePostureFor(t, n.root, nil)
		pe = mcpEvent(tc.tool, n.root, tc.args)
		if v := n.evaluate(t, pe); v.RuleID == "S-791" || v.RuleID == "S-793" || v.RuleID == "S-794" {
			t.Fatalf("%s: verdict %+v (security %+v), want it to proceed", tc.tool, v, pe.Security)
		}
	}
}

// TestSecurityRaisesEveryWrittenRepo (lane SEC-P4 decision 3): a shell line
// that changes into another repository and writes there, and a file tool
// writing there, raise that repository's dirty counter; a line that only
// reads there raises nothing (audit F6); a network place is never touched,
// and a line inside the project raises no other counter.
func TestSecurityRaisesEveryWrittenRepo(t *testing.T) {
	n := newGate5Repos(t)
	counter := func(root string) uint64 {
		v, _ := secposture.ReadDirty(n.layout, secposture.ProjectRootHash(root))
		return v
	}
	if err := os.MkdirAll(filepath.Join(n.root, "pkg"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		pe    *policy.Event
		raise bool
	}{
		{"cd then write", shellCommit("cd "+shPath(n.other)+" && echo x > f", n.root, ""), true},
		{"powershell set-location", &policy.Event{Kind: policy.KindShellExec, ActionType: models.ActionRunCommand, Target: "Set-Location " + n.other + "; Set-Content f x", Cwd: n.root, Dialect: policy.DialectPowerShell}, true},
		{"file tool outside the root", &policy.Event{Kind: policy.KindFileAccess, ActionType: models.ActionWriteFile, Target: filepath.Join(n.other, "f.txt"), Cwd: n.root, ProjectRoot: n.root, Edits: []policy.ProposedEdit{{Kind: policy.EditWhole, New: "x\n"}}}, true},
		{"inside the project", shellCommit("cd pkg && echo x > f", n.root, ""), false},
		{"network place", shellCommit("cd //host/share && echo x > f; cd "+shPath(n.other), n.root, ""), false},
		// Audit SEC-P4 F6: only a directory a later unit may write into.
		{"cd then a listing only", shellCommit("cd "+shPath(n.other)+" && ls", n.root, ""), false},
		{"cd then reads only", shellCommit("cd "+shPath(n.other)+" && cat f | grep x && pwd", n.root, ""), false},
		{"cd then a read redirected", shellCommit("cd "+shPath(n.other)+" && ls > out", n.root, ""), true},
		{"cd then read, then write", shellCommit("cd "+shPath(n.other)+" && ls && touch f", n.root, ""), true},
		{"cd then tee", shellCommit("cd "+shPath(n.other)+" && cat f | tee g", n.root, ""), true},
		{"cd elsewhere, back, then write", shellCommit("cd "+shPath(n.other)+" && ls; cd "+shPath(n.root)+" && touch f", n.root, ""), false},
		{"powershell set-location, listing only", &policy.Event{Kind: policy.KindShellExec, ActionType: models.ActionRunCommand, Target: "Set-Location " + n.other + "; Get-ChildItem", Cwd: n.root, Dialect: policy.DialectPowerShell}, false},
	} {
		n.writePostureFor(t, n.root, nil)
		n.writePostureFor(t, n.other, nil)
		before := counter(n.other)
		n.evaluate(t, tc.pe)
		if got := counter(n.other) > before; got != tc.raise {
			t.Fatalf("%s: other repository raised = %v, want %v", tc.name, got, tc.raise)
		}
	}
}

// TestWholeSecondHeadWriteIsStale (lane SEC-P4 decision 6): on a file
// system that keeps whole seconds, a branch switch in the second the
// default was resolved (or the posture signed) drops the default, on the
// daemon's table and on the hook alike; a whole-second write the second
// before keeps it.
func TestWholeSecondHeadWriteIsStale(t *testing.T) {
	at := time.Date(2026, 10, 23, 10, 0, 5, 300_000_000, time.UTC)
	for _, tc := range []struct {
		name string
		head time.Time
		keep bool
	}{
		{"whole-second write in the resolution's second", at.Truncate(time.Second), false},
		{"whole-second write the second before", at.Truncate(time.Second).Add(-time.Second), true},
		{"sub-second write just before", at.Add(-time.Millisecond), true},
	} {
		oldHook, oldTable := hookHeadWrite, pushDefaultHeadWrite
		hookHeadWrite = func(string) (time.Time, bool) { return tc.head, true }
		pushDefaultHeadWrite = func(string) (time.Time, bool) { return tc.head, true }
		reading := secposture.Reading{File: &secposture.File{IssuedAt: at}}
		got := hookDropStalePushDefault(policy.Security{DefaultPushRemote: "origin"}, reading, "/r").DefaultPushRemote
		table := &pushDefaultTable{m: map[string]pushDefaultEntry{"h": {remote: "origin", root: "/r", at: at}}}
		fromTable := table.get("h")
		hookHeadWrite, pushDefaultHeadWrite = oldHook, oldTable
		if (got == "origin") != tc.keep || (fromTable == "origin") != tc.keep {
			t.Errorf("%s: hook %q, table %q, want kept=%v", tc.name, got, fromTable, tc.keep)
		}
	}
	// The future-write clamp of a whole-second write counts it resolved
	// from the next second, so the entry is not stale on every look.
	now := time.Now()
	future := now.Add(time.Hour).Truncate(time.Second)
	if c := clampFutureHeadWrite(future, now, now); !git.HeadWriteBefore(future, c) {
		t.Fatalf("clamp %v of a whole-second future write %v still reads stale", c, future)
	}
}

// TestSecurityMergeElsewhereKeepsStricterFloor (lane SEC-P4 decision 9): a
// commit from an unfloored session into a floored repository takes the
// floor's cells (S-794 deny where the individual column asks); the merge
// never drops a floor the event's own project has.
func TestSecurityMergeElsewhereKeepsStricterFloor(t *testing.T) {
	n := newGate5Repos(t)
	line := "cd " + shPath(n.other) + " && git commit -m wip"
	n.writePostureFor(t, n.root, nil)
	n.writePostureFor(t, n.other, func(f *secposture.File) { f.CommitGateFloor = policy.CommitGateFloorQuickScan })
	pe := shellCommit(line, n.root, "")
	v := n.evaluate(t, pe)
	if pe.Security.CommitGateFloor != policy.CommitGateFloorQuickScan || v.Decision != policy.DecisionDeny || v.RuleID != "S-793" {
		t.Fatalf("floored other repository: verdict %+v (security %+v), want the floor's S-793 deny", v, pe.Security)
	}
	n.writePostureFor(t, n.root, func(f *secposture.File) { f.CommitGateFloor = policy.CommitGateFloorQuickScan })
	n.writePostureFor(t, n.other, nil)
	pe = shellCommit(line, n.root, "")
	if v := n.evaluate(t, pe); pe.Security.CommitGateFloor != policy.CommitGateFloorQuickScan || v.Decision != policy.DecisionDeny {
		t.Fatalf("floored own project, unfloored other: verdict %+v (security %+v), want deny", v, pe.Security)
	}
	// The own repository golden: a clean floored project's commit proceeds.
	n.writePostureFor(t, n.root, func(f *secposture.File) { f.CommitGateFloor = policy.CommitGateFloorQuickScan })
	pe = shellCommit("git commit -m wip", n.root, "")
	if v := n.evaluate(t, pe); v.RuleID != "" {
		t.Fatalf("clean floored project: verdict %+v, want it to proceed", v)
	}
}
