package secverify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secciwf"
)

// dangerousWorkflow is the acceptance case (security plan section 5.6,
// lane SEC-C2 milestone 3): a pull_request_target workflow that checks
// out the pull request's head and runs it with a secret.
var dangerousWorkflow = []string{
	"on: pull_request_target",
	"permissions: {contents: read}",
	"jobs:",
	"  build:",
	"    runs-on: ubuntu-latest",
	"    steps:",
	"      - uses: actions/checkout@v4",
	"        with:",
	"          ref: ${{ github.event.pull_request.head.sha }}",
	"      - run: make test",
	"        env:",
	"          TOKEN: ${{ secrets.DEPLOY_TOKEN }}",
}

// TestDangerousWorkflowFailsVerify: the new dangerous workflow fails the
// check with an S-771 deny; a safe one passes.
func TestDangerousWorkflowFailsVerify(t *testing.T) {
	rep := run(t, DefaultPolicy(), nil, change{"A", ".github/workflows/pr.yml", dangerousWorkflow})
	if rep.Verdict != VerdictFail {
		t.Fatalf("verdict %s (%s), findings %+v", rep.Verdict, rep.Reason, rep.Findings)
	}
	found := false
	for _, f := range rep.Findings {
		if f.Detector == "ci_workflow" && f.RuleID == "ci/s-771" && f.Action == ActionDeny && f.Path == ".github/workflows/pr.yml" {
			found = true
		}
		if strings.Contains(f.Message, "DEPLOY_TOKEN") {
			t.Fatalf("a finding carries repository text: %+v", f)
		}
	}
	if !found {
		t.Fatalf("no S-771 deny: %+v", rep.Findings)
	}
	safe := []string{"on: push", "permissions: {contents: read}", "jobs:", "  t:", "    runs-on: ubuntu-latest", "    steps:", "      - run: make test"}
	if rep := run(t, DefaultPolicy(), nil, change{"A", ".github/workflows/ci.yml", safe}); rep.Verdict != VerdictPass {
		t.Fatalf("safe workflow = %s (%s) %+v", rep.Verdict, rep.Reason, rep.Findings)
	}
}

// TestCIWorkflowReadsTheHeadFile: a modified workflow is checked whole
// through ReadHead; without a reader, over the cap, unparsable or on a
// read error it is skipped and the required check is unknown, never pass.
func TestCIWorkflowReadsTheHeadFile(t *testing.T) {
	whole := []byte(strings.Join(dangerousWorkflow, "\n") + "\n")
	n, p := build(change{"M", ".github/workflows/pr.yml", []string{"          ref: ${{ github.event.pull_request.head.sha }}"}})
	cases := []struct {
		name string
		read func(string) ([]byte, bool, error)
		want Verdict
	}{
		{"head read", func(string) ([]byte, bool, error) { return whole, false, nil }, VerdictFail},
		{"no reader", nil, VerdictUnknown},
		{"over cap", func(string) ([]byte, bool, error) { return nil, true, nil }, VerdictUnknown},
		{"read error", func(string) ([]byte, bool, error) { return nil, false, errors.New("gone") }, VerdictUnknown},
		{"not yaml", func(string) ([]byte, bool, error) { return []byte("a: [1, 2\n  b: {\n"), false, nil }, VerdictUnknown},
	}
	for _, tc := range cases {
		rep := Verify(context.Background(), Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p, ReadHead: tc.read}, nil)
		if rep.Verdict != tc.want {
			t.Errorf("%s: verdict %s (%s)", tc.name, rep.Verdict, rep.Reason)
		}
	}
	if secciwf.MaxWorkflowBytes <= 0 {
		t.Fatal("no cap")
	}
}

// TestTestTamperingFlagsOnly: a new skip marker and removed assertions are
// flagged, never a deny, and read the removed lines of the diff.
func TestTestTamperingFlagsOnly(t *testing.T) {
	n := []byte("M\x00pkg/a_test.go\x00")
	p := []byte("diff --git a/pkg/a_test.go b/pkg/a_test.go\n--- a/pkg/a_test.go\n+++ b/pkg/a_test.go\n" +
		"@@ -10,2 +10,1 @@\n-\tif got != 1 {\n-\t\tt.Fatalf(\"got %d\", got)\n+\tt.Skip(\"later\")\n")
	rep := Verify(context.Background(), Request{Policy: DefaultPolicy(), NameStatus: n, Patch: p}, nil)
	if rep.Verdict != VerdictPass {
		t.Fatalf("verdict %s (%s)", rep.Verdict, rep.Reason)
	}
	rules := map[string]bool{}
	for _, f := range rep.Findings {
		if f.Detector == "test_tampering" {
			if f.Action != ActionFlag {
				t.Fatalf("a test-tampering finding is not flag only: %+v", f)
			}
			rules[f.RuleID] = true
		}
	}
	if !rules["code/s-767"] || !rules["code/s-768"] {
		t.Fatalf("rules = %v, want code/s-767 and code/s-768", rules)
	}
}
