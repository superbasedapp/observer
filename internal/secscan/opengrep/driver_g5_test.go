package opengrep

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// TestExcludeTestResults: an exclude_tests rule's result in a test path is
// dropped (counted in a note, not a skip, so the run stays closable); the
// same rule outside tests, and a rule without the flag in tests, are kept;
// a run left with nothing is clean only when the self-test passed.
func TestExcludeTestResults(t *testing.T) {
	t.Parallel()
	pack, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	f := func(rule, path string) secfinding.Finding {
		return secfinding.Finding{Rule: secfinding.Rule{ID: rule}, Location: secfinding.Location{RelPath: path}}
	}
	if r, _ := pack.Rule("python.tls-verify-off"); !r.ExcludeTests {
		t.Fatal("python.tls-verify-off should exclude tests")
	}
	if r, _ := pack.Rule("python.shell-interpolation"); r.ExcludeTests {
		t.Fatal("python.shell-interpolation should not exclude tests")
	}
	in := []secfinding.Finding{
		f("python.tls-verify-off", "tests/test_client.py"),
		f("python.tls-verify-off", "app/client.py"),
		f("python.shell-interpolation", "tests/test_run.py"),
	}
	got, cov := excludeTestResults(pack, in, secscan.Coverage{Outcome: secscan.OutcomeFindings}, true)
	if len(got) != 2 || got[0].Location.RelPath != "app/client.py" || got[1].Rule.ID != "python.shell-interpolation" {
		t.Fatalf("kept %+v", got)
	}
	if len(cov.Skipped) != 0 || len(cov.Notes) != 1 || !strings.HasPrefix(cov.Notes[0], TestExcludedPrefix+": 1 ") {
		t.Fatalf("coverage %+v", cov)
	}
	if !closable(true, cov) {
		t.Fatal("an exclusion made the run unclosable")
	}
	only := []secfinding.Finding{f("go.tls-verify-off", "pkg/client_test.go")}
	if got, cov := excludeTestResults(pack, only, secscan.Coverage{Outcome: secscan.OutcomeFindings}, true); len(got) != 0 || cov.Outcome != secscan.OutcomeClean {
		t.Fatalf("all excluded, self-test passed: %+v %+v", got, cov)
	}
	only = []secfinding.Finding{f("go.tls-verify-off", "pkg/client_test.go")}
	if _, cov := excludeTestResults(pack, only, secscan.Coverage{Outcome: secscan.OutcomeFindings}, false); cov.Outcome != secscan.OutcomeUnknown {
		t.Fatalf("all excluded, no self-test: %+v", cov)
	}
}
