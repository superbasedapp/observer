//go:build !sbo_omit_security

package store

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestSecBoxCommitsScanned: only a commit-scope run whose target is a box
// commit marks the commit as scanned, for its own project; any other
// target (none, a baseline) is never read as one.
func TestSecBoxCommitsScanned(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	for _, r := range []SecScanRun{
		{ProjectRootHash: "h", Driver: "native", Scope: policy.FindingScopeCommit, Target: map[string]any{"box": true, "commit": "aaaaaaa", "ref": "refs/observer/sandbox/R"}, Outcome: "clean", StartedAt: now},
		{ProjectRootHash: "h", Driver: "native", Scope: policy.FindingScopeCommit, Target: map[string]any{"box": true, "commit": "bbbbbbb"}, Outcome: "unknown", StartedAt: now},
		{ProjectRootHash: "h", Driver: "native", Scope: policy.FindingScopeCommit, Outcome: "clean", StartedAt: now},
		{ProjectRootHash: "h", Driver: "baseline:native", Scope: policy.FindingScopeCommit, Target: SecBaselineScan{Ref: "ccccccc"}, Outcome: "clean", StartedAt: now},
		{ProjectRootHash: "other", Driver: "native", Scope: policy.FindingScopeCommit, Target: map[string]any{"box": true, "commit": "ddddddd"}, Outcome: "clean", StartedAt: now},
	} {
		if err := s.InsertSecScanRun(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.SecBoxCommitsScanned(ctx, "h", []string{"aaaaaaa", "bbbbbbb", "ccccccc", "ddddddd", "eeeeeee"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !got["aaaaaaa"] || !got["bbbbbbb"] {
		t.Fatalf("scanned = %v", got)
	}
}

// TestSecFindingRunIDStored: a finding's lineage run id is written on
// insert (agent migration 192).
func TestSecFindingRunIDStored(t *testing.T) {
	s, db := newTestStore(t)
	f := secFinding("h", "k")
	f.Lineage.RunID = "RUN1"
	if _, _, err := s.UpsertSecFinding(context.Background(), f, time.Now()); err != nil {
		t.Fatal(err)
	}
	var run string
	if err := db.QueryRow(`SELECT run_id FROM sec_findings WHERE local_key = 'k'`).Scan(&run); err != nil || run != "RUN1" {
		t.Fatalf("run_id = %q %v", run, err)
	}
}

// TestSecBoxFindingStaysOffTheTree (lane sec-box audit finding 1): box work
// writes its commit row but no file sighting, so it holds the push and not
// the developer's own commits; an existing host finding of the same
// identity keeps its path, lines and status (an open one is not moved, a
// closed one is not reopened), and only gains the commit row.
func TestSecBoxFindingStaysOffTheTree(t *testing.T) {
	s, db := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	sha := strings.Repeat("a", 40)
	box := func(key string) secfinding.Finding {
		f := secFinding("h", key)
		f.Scope = policy.FindingScopeCommit
		f.Commit.SHA = sha
		f.Location.RelPath, f.Location.StartLine, f.Location.EndLine = "box.py", 9, 9
		f.Lineage.RunID = "RUNBOX"
		return f
	}
	count := func(q string, args ...any) int {
		t.Helper()
		var n int
		if err := db.QueryRow(q, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	sightings := func(id string) int {
		return count(`SELECT COUNT(*) FROM sec_finding_sightings WHERE finding_id = ?`, id)
	}
	commits := func(id string) int {
		return count(`SELECT COUNT(*) FROM sec_finding_commits WHERE finding_id = ?`, id)
	}

	// A box-only finding: its commit row, no sighting; history only.
	boxID, _, err := s.UpsertSecFinding(ctx, box("k1"), now)
	if err != nil {
		t.Fatal(err)
	}
	if sightings(boxID) != 0 || commits(boxID) != 1 {
		t.Fatalf("box finding: %d sightings, %d commits; want 0 and 1", sightings(boxID), commits(boxID))
	}
	sev := []secfinding.Severity{policy.FindingSeverityHigh, policy.FindingSeverityCritical}
	held, err := s.SecBlockingKeys(ctx, SecBlockingQuery{ProjectRootHash: "h", Severities: sev, HistoryOnly: true}, 10)
	if err != nil || len(held) != 1 || held[0] != "k1" {
		t.Fatalf("history-only keys %v %v, want [k1]", held, err)
	}

	// An open host finding, then box work of the same identity.
	hostID, _, err := s.UpsertSecFinding(ctx, secFinding("h", "k2"), now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSecFinding(ctx, box("k2"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	var rel, scope, run, status string
	var line int
	if err := db.QueryRow(`SELECT rel_path, start_line, scope, run_id, status FROM sec_findings WHERE id = ?`, hostID).Scan(&rel, &line, &scope, &run, &status); err != nil {
		t.Fatal(err)
	}
	if rel != "a.go" || line != 3 || scope == string(policy.FindingScopeCommit) || run != "" || status != string(policy.FindingStatusOpen) {
		t.Fatalf("open host finding rewritten: rel=%s line=%d scope=%s run=%q status=%s", rel, line, scope, run, status)
	}
	if sightings(hostID) != 1 || count(`SELECT COUNT(*) FROM sec_finding_sightings WHERE finding_id = ? AND rel_path = 'box.py'`, hostID) != 0 || commits(hostID) != 1 {
		t.Fatalf("open host finding: %d sightings (box.py must not be one), %d commits", sightings(hostID), commits(hostID))
	}

	// A closed host finding stays closed with its path.
	closedID, _, err := s.UpsertSecFinding(ctx, secFinding("h", "k3"), now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SetSecFindingStatus(ctx, closedID, policy.FindingStatusNotReproduced, "", now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.UpsertSecFinding(ctx, box("k3"), now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT rel_path, status FROM sec_findings WHERE id = ?`, closedID).Scan(&rel, &status); err != nil {
		t.Fatal(err)
	}
	if rel != "a.go" || status != string(policy.FindingStatusNotReproduced) {
		t.Fatalf("closed host finding: rel=%s status=%s, want a.go and not_reproduced", rel, status)
	}
	if n := count(`SELECT COUNT(*) FROM sec_finding_events WHERE finding_id = ? AND kind = ?`, closedID, SecEventReopened); n != 0 {
		t.Fatalf("box work reopened a closed host finding (%d events)", n)
	}
}
