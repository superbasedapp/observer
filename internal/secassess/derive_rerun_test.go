package secassess

import (
	"fmt"
	"testing"
)

// rerunThreat is a threat with one missing mitigation at path:line, found by
// its needle (so the needle, not the line, is the identity anchor).
func rerunThreat(id, cwe, path string, line int, needle string) Threat {
	t := thr(id, "Title "+id, "tampering", elAPI, 4, 4)
	t.CWE = []string{cwe}
	t.Missing = []Missing{{Text: "x", Refs: []Ref{{Path: path, Line: line, Needle: needle, State: RefFound, MatchLine: line}}}}
	return t
}

func deriveOf(ts ...Threat) Derivation {
	return DeriveSARIF(Result{TM: &ThreatModelDoc{Threats: ts}}, DeriveOptions{Tag: "tm", RunID: "0123456789abcdef", Dedup: true})
}

func prints(d Derivation) map[string]bool {
	m := map[string]bool{}
	for _, r := range d.Results {
		m[r.RuleID+"|"+r.Fingerprint] = true
	}
	return m
}

func sharedCount(a, b Derivation) int {
	pa, pb, n := prints(a), prints(b), 0
	for k := range pa {
		if pb[k] {
			n++
		}
	}
	return n
}

// TestDeriveRerunIdentity (depth plan W3.5, D26): with dedup on the identity of a
// derived finding is its rule id and content fingerprint, so a re-run updates
// what it shares with the run before and adds only what is new.
func TestDeriveRerunIdentity(t *testing.T) {
	five := func(run string) []Threat {
		var ts []Threat
		for i, f := range []string{"a.go", "b.go", "c.go", "d.go", "e.go"} {
			ts = append(ts, rerunThreat(fmt.Sprintf("%s-%d", run, i), fmt.Sprintf("CWE-%d", 20+i), f, 10+i, "needleName"+f[:1]))
		}
		return ts
	}
	first := deriveOf(five("A")...)
	if first.Kept != 5 {
		t.Fatalf("first run kept %d", first.Kept)
	}

	t.Run("the same findings under other agent ids are the same findings", func(t *testing.T) {
		if got := sharedCount(first, deriveOf(five("B")...)); got != 5 {
			t.Errorf("shared %d of 5", got)
		}
	})
	t.Run("three of five the same", func(t *testing.T) {
		second := five("B")[:3]
		second = append(second,
			rerunThreat("B-9", "CWE-79", "f.go", 5, "needleNameF"),
			rerunThreat("B-10", "CWE-89", "g.go", 7, "needleNameG"))
		d := deriveOf(second...)
		if d.Kept != 5 || sharedCount(first, d) != 3 {
			t.Errorf("kept %d, shared %d; want 5 and 3", d.Kept, sharedCount(first, d))
		}
	})
	t.Run("line drift with a needle keeps the identity", func(t *testing.T) {
		moved := five("B")
		moved[0].Missing[0].Refs[0].Line, moved[0].Missing[0].Refs[0].MatchLine = 80, 80
		if got := sharedCount(first, deriveOf(moved...)); got != 5 {
			t.Errorf("shared %d of 5 after a line moved", got)
		}
	})
	t.Run("no needle: the line is the identity", func(t *testing.T) {
		// A reference whose needle was not given reads as a place only (exists):
		// its identity is the cited line, so the same line is the same finding and
		// a line that moved is a new one (D26). The needle is what keeps an
		// identity across a line drift, as the row before shows.
		noNeedle := func(run string, moveFirst int) []Threat {
			ts := five(run)
			for i := range ts {
				r := &ts[i].Missing[0].Refs[0]
				r.Needle, r.State, r.MatchLine = "", RefExists, 0
			}
			if moveFirst > 0 {
				ts[0].Missing[0].Refs[0].Line = moveFirst
			}
			return ts
		}
		base := deriveOf(noNeedle("A", 0)...)
		if base.Kept != 5 {
			t.Fatalf("a place-only reference is still a finding: kept %d", base.Kept)
		}
		if got := sharedCount(base, deriveOf(noNeedle("B", 0)...)); got != 5 {
			t.Errorf("the same lines under other ids: shared %d of 5", got)
		}
		if got := sharedCount(base, deriveOf(noNeedle("B", 80)...)); got != 4 {
			t.Errorf("one line moved without a needle: shared %d of 5, want 4", got)
		}
		// The same drift with a needle keeps the identity (the contrast).
		if got := sharedCount(first, deriveOf(func() []Threat {
			ts := five("B")
			ts[0].Missing[0].Refs[0].Line, ts[0].Missing[0].Refs[0].MatchLine = 80, 80
			return ts
		}()...)); got != 5 {
			t.Errorf("with a needle the identity holds across the drift: shared %d of 5", got)
		}
	})
	t.Run("a renamed file is a new finding", func(t *testing.T) {
		renamed := five("B")
		renamed[0].Missing[0].Refs[0].Path = "renamed/a.go"
		d := deriveOf(renamed...)
		if got := sharedCount(first, d); got != 4 {
			t.Errorf("shared %d of 5 after a rename, want 4", got)
		}
	})
	t.Run("a changed rating or wording is still the same finding", func(t *testing.T) {
		changed := five("B")
		changed[1].Rating = Rating{Likelihood: 5, Impact: 5}
		changed[1].Band, changed[1].Score = BandOf(changed[1].Rating), changed[1].Rating.Score()
		changed[1].Title = "Entirely new wording"
		if got := sharedCount(first, deriveOf(changed...)); got != 5 {
			t.Errorf("shared %d of 5", got)
		}
	})
	t.Run("another weakness class at the same place is a new finding", func(t *testing.T) {
		other := five("B")
		other[2].CWE = []string{"CWE-999"}
		if got := sharedCount(first, deriveOf(other...)); got != 4 {
			t.Errorf("shared %d of 5, want 4", got)
		}
	})
	t.Run("the previous copy missing leaves the diff all added", func(t *testing.T) {
		d := DiffModels(nil, &ThreatModelDoc{Threats: five("B")})
		if len(d.Added) != 5 || len(d.Removed) != 0 || len(d.Changed) != 0 {
			t.Errorf("diff = %+v", d)
		}
	})
	t.Run("run-scoped identity keeps the run apart", func(t *testing.T) {
		a := DeriveSARIF(Result{TM: &ThreatModelDoc{Threats: five("A")}}, DeriveOptions{Tag: "tm", RunID: "0123456789abcdef"})
		b := DeriveSARIF(Result{TM: &ThreatModelDoc{Threats: five("A")}}, DeriveOptions{Tag: "tm", RunID: "ffffffffffffffff"})
		if sharedCount(a, b) != 0 {
			t.Error("two runs share an identity with dedup off")
		}
	})
}
