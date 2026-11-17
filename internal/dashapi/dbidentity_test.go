package dashapi

import (
	"path/filepath"
	"testing"
)

// TestDaemonHandoffTable pins every row of the handoff decision (L-125):
// listen-record evidence present/absent x the daemon's answer.
func TestDaemonHandoffTable(t *testing.T) {
	cases := []struct {
		name     string
		match    DBMatch
		evidence bool
		want     bool
	}{
		{"no daemon, record absent", DBNoDaemon, false, false},
		{"no daemon, record present", DBNoDaemon, true, false},
		{"same database, record absent", DBSame, false, true},
		{"same database, record present", DBSame, true, true},
		{"other database, record absent", DBOther, false, false},
		{"other database, record present", DBOther, true, false},
		{"unknown (older daemon), record present", DBUnknown, true, true},
		{"unknown (older daemon), record absent: the default-port case", DBUnknown, false, false},
		{"unrecognised answer", DBMatch(99), true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, reason := DaemonHandoff(tc.match, tc.evidence)
			if got != tc.want {
				t.Fatalf("DaemonHandoff(%v, %v) = %v (%s), want %v", tc.match, tc.evidence, got, reason, tc.want)
			}
			if reason == "" {
				t.Fatal("every decision carries a reason")
			}
		})
	}
}

// TestDaemonHandoffRulesCoverEveryCombination fails when a row is added or
// dropped without covering each match x evidence pair exactly once.
func TestDaemonHandoffRulesCoverEveryCombination(t *testing.T) {
	seen := map[[2]int]int{}
	for _, r := range daemonHandoffRules {
		ev := 0
		if r.recordEvidence {
			ev = 1
		}
		seen[[2]int{int(r.match), ev}]++
	}
	for _, m := range []DBMatch{DBNoDaemon, DBUnknown, DBSame, DBOther} {
		for ev := 0; ev < 2; ev++ {
			if n := seen[[2]int{int(m), ev}]; n != 1 {
				t.Errorf("match %d evidence %d has %d rows, want 1", m, ev, n)
			}
		}
	}
}

func TestClassifyDBIdentity(t *testing.T) {
	cases := []struct {
		name, want, served string
		out                DBMatch
	}{
		{"no identity named", "aaaa", "", DBUnknown},
		{"same", "aaaa", "aaaa", DBSame},
		{"other", "aaaa", "bbbb", DBOther},
		{"CLI without a database names none", "", "bbbb", DBOther},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyDBIdentity(tc.want, tc.served); got != tc.out {
				t.Fatalf("ClassifyDBIdentity(%q, %q) = %v, want %v", tc.want, tc.served, got, tc.out)
			}
		})
	}
}

func TestDBIdentity(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a", "observer.db")
	b := filepath.Join(dir, "b", "observer.db")
	if DBIdentity("") != "" || DBIdentity("   ") != "" {
		t.Fatal("an empty path has no identity")
	}
	if DBIdentity(a) == "" || len(DBIdentity(a)) != 32 {
		t.Fatalf("identity %q, want 32 hex chars", DBIdentity(a))
	}
	if DBIdentity(a) == DBIdentity(b) {
		t.Fatal("two databases share an identity")
	}
	same := filepath.Join(dir, "a", ".", "x", "..", "observer.db")
	if DBIdentity(a) != DBIdentity(same) {
		t.Fatalf("an equivalent spelling of the same path changed the identity: %q vs %q", a, same)
	}
}
