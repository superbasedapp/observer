package secrulepack

import "testing"

// TestExcludeTestsIsPerRule: the floor pack drops a test-path result only
// for a rule that sets exclude_tests.
func TestExcludeTestsIsPerRule(t *testing.T) {
	p, err := Floor()
	if err != nil {
		t.Fatal(err)
	}
	var on, off string
	for _, r := range p.Manifest.Rules {
		if r.ExcludeTests && on == "" {
			on = r.ID
		}
		if !r.ExcludeTests && off == "" {
			off = r.ID
		}
	}
	if on == "" || off == "" {
		t.Fatalf("want rules with and without exclude_tests (on %q, off %q)", on, off)
	}
	if !p.TestExcluded(on, "tests/a.py") || p.TestExcluded(on, "app/a.py") {
		t.Errorf("%s: exclusion wrong", on)
	}
	if p.TestExcluded(off, "tests/a.py") || p.TestExcluded("no.such-rule", "tests/a.py") {
		t.Errorf("%s: excluded without the flag", off)
	}
}
