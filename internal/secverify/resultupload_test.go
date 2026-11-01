package secverify

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestRenderWorkflowResultUpload: the result and register jobs are
// appended after every other job, which renders byte-identical with the
// upload off and on; the result job reads only the verdict job's artifact,
// the register job reads nothing and posts pending; each holds only the CI
// credential and `id-token: write` (no other job does), checks nothing out
// and cannot fail the run.
func TestRenderWorkflowResultUpload(t *testing.T) {
	p := ExampleOrgWorkflowParams(testVendorKey)
	off, err := RenderWorkflow(p)
	if err != nil {
		t.Fatal(err)
	}
	p.ResultUpload = true
	on, err := RenderWorkflow(p)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(on, strings.TrimSuffix(off, "\n")) {
		t.Fatal("the upload changed a job before it")
	}
	tail := strings.TrimPrefix(on, strings.TrimSuffix(off, "\n"))
	if !strings.HasPrefix(tail, "\n\n  result:\n") {
		t.Fatalf("the result job is not a separate trailing job:\n%s", tail)
	}
	job, register, ok := strings.Cut(tail, "\n  register:\n")
	if !ok {
		t.Fatalf("no register job after the result job:\n%s", tail)
	}
	for _, want := range []string{"needs: verify", "continue-on-error: true", "permissions:\n      id-token: write\n    steps:", "name: observer-security-sarif", "--upload observer-security.sarif", "--org-url \"$VERIFY_ORG_URL\""} {
		if !strings.Contains(job, want) {
			t.Errorf("result job lacks %q", want)
		}
	}
	for _, want := range []string{"continue-on-error: true", "permissions:\n      id-token: write\n    steps:", "--upload-pending", "--org-url \"$VERIFY_ORG_URL\""} {
		if !strings.Contains(register, want) {
			t.Errorf("register job lacks %q", want)
		}
	}
	if strings.Contains(register, "needs:") || strings.Contains(register, "--upload ") {
		t.Error("the register job must start with the run and read no SARIF")
	}
	for name, j := range map[string]string{"result": job, "register": register} {
		if strings.Count(j, "secrets.") != 1 || !strings.Contains(j, "secrets.OBSERVER_CI_CREDENTIAL") {
			t.Errorf("the %s job must hold the CI credential and no other secret", name)
		}
		if strings.Contains(j, "actions/checkout") || strings.Contains(j, "upload-artifact") {
			t.Errorf("the %s job must not check out the change or write an artifact", name)
		}
	}
	if strings.Contains(off, "id-token: write") || strings.Count(on, "      id-token: write\n") != 2 {
		t.Error("id-token: write belongs to the result and register jobs only")
	}
	// The upload without org mode is refused, and off it renders nothing.
	q := ExampleWorkflowParams(testVendorKey)
	q.ResultUpload = true
	if _, err := RenderWorkflow(q); err == nil {
		t.Error("a result upload without org mode rendered")
	}
}

func testSARIF(t *testing.T, rep Report) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := WriteSARIF(&b, rep, "/repo", "v1.2.3"); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestResultFromSARIF maps the verdict job's SARIF, and every SARIF it
// cannot trust to unknown.
func TestResultFromSARIF(t *testing.T) {
	head, base := strings.Repeat("a", 40), strings.Repeat("b", 40)
	in := ResultUploadInput{Repository: "acme/app", Base: base, Head: head, Attempt: 2, RunURL: "https://github.com/acme/app/actions/runs/9/attempts/2"}
	rep := Report{Verdict: VerdictFail, Rule: "secret.added", Base: base, Head: head}
	rep.Policy.Source, rep.Policy.Mode = "protected_file", "enforce"
	cases := []struct {
		name, verdict, rule string
		sarif               []byte
	}{
		{"fail", "fail", "secret.added", testSARIF(t, rep)},
		{"pass", "pass", "", testSARIF(t, Report{Verdict: VerdictPass, Base: base, Head: head})},
		{"missing", "unknown", UploadRuleSARIFMissing, nil},
		{"not json", "unknown", UploadRuleSARIFInvalid, []byte("{")},
		{"another tool", "unknown", UploadRuleSARIFInvalid, []byte(`{"runs":[{"tool":{"driver":{"name":"other"}},"properties":{"superbased/verdict":"pass","superbased/head":"` + head + `"}}]}`)},
		{"another commit", "unknown", UploadRuleHeadMismatch, testSARIF(t, Report{Verdict: VerdictPass, Base: base, Head: strings.Repeat("c", 40)})},
		{"bad verdict", "unknown", UploadRuleSARIFInvalid, []byte(`{"runs":[{"tool":{"driver":{"name":"` + ToolName + `"}},"properties":{"superbased/verdict":"success","superbased/head":"` + head + `"}}]}`)},
		{"bad rule word", "unknown", UploadRuleSARIFInvalid, []byte(`{"runs":[{"tool":{"driver":{"name":"` + ToolName + `"}},"properties":{"superbased/verdict":"pass","superbased/verdict_rule":"a b","superbased/head":"` + head + `"}}]}`)},
	}
	for _, c := range cases {
		u, err := ResultFromSARIF(c.sarif, in)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if u.Verdict != c.verdict || u.VerdictRule != c.rule || u.HeadSHA != head || u.Attempt != 2 {
			t.Errorf("%s: %+v", c.name, u)
		}
		if _, ok := orgcontract.NormalizeCIResult(u); !ok {
			t.Errorf("%s: the body is not a valid upload", c.name)
		}
		if b, _ := json.Marshal(u); len(b) > orgcontract.MaxCIResultBytes {
			t.Errorf("%s: over the cap", c.name)
		}
	}
	if _, err := ResultFromSARIF(nil, ResultUploadInput{Repository: "acme/app", Head: "xyz", Attempt: 1, RunURL: in.RunURL}); err == nil {
		t.Error("a bad head was accepted")
	}
	if _, err := ResultFromSARIF(nil, ResultUploadInput{Repository: "acme/app", Head: head, Attempt: 1, RunURL: "https://evil.example/x"}); err == nil {
		t.Error("a foreign run URL was accepted")
	}
}

// TestResultCarriesTheRunsVersions (lane LEFT2-SEC item R-019): a run under
// the org's signed CI policy writes that policy's version and the build's
// pack version into its SARIF, and the upload carries both; a run under
// another policy carries no policy version, and a development build no
// pack version.
func TestResultCarriesTheRunsVersions(t *testing.T) {
	head := strings.Repeat("a", 40)
	in := ResultUploadInput{Repository: "acme/app", Head: head, Attempt: 1, RunURL: "https://github.com/acme/app/actions/runs/9"}
	rep := Report{Verdict: VerdictPass, Head: head}
	rep.Policy.Source, rep.Policy.Mode, rep.Policy.OrgVersion = SourceOrg, ModeEnforce, 7
	u, err := ResultFromSARIF(testSARIF(t, rep), in)
	if err != nil {
		t.Fatal(err)
	}
	if u.PolicyVersion != "7" || u.PackVersion != "1.2.3" || u.PolicySource != orgcontract.CIPolicySourceOrg {
		t.Fatalf("versions %q %q %q", u.PolicyVersion, u.PackVersion, u.PolicySource)
	}
	rep.Policy.Source = "protected_file"
	if u, _ = ResultFromSARIF(testSARIF(t, rep), in); u.PolicyVersion != "" {
		t.Errorf("a non-org policy reported version %q", u.PolicyVersion)
	}
	var b bytes.Buffer
	if err := WriteSARIF(&b, rep, "/repo", ""); err != nil {
		t.Fatal(err)
	}
	if u, _ = ResultFromSARIF(b.Bytes(), in); u.PackVersion != "" {
		t.Errorf("a development build reported pack %q", u.PackVersion)
	}
}
