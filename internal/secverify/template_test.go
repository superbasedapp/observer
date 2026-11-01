package secverify

import (
	"strings"
	"testing"
)

const testVendorKey = "npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="

func TestRenderWorkflow(t *testing.T) {
	p := ExampleWorkflowParams(testVendorKey)
	p.Version = "v1.40.0"
	p.ArchiveSHA256 = strings.Repeat("ab", 32)
	out, err := RenderWorkflow(p)
	if err != nil {
		t.Fatal(err)
	}
	musts := []string{
		"pull_request:\n",
		"merge_group:\n",
		"permissions: {}",
		"contents: read",
		"security-events: write",
		"persist-credentials: false",
		"observer-v1.40.0-linux-x64.tar.gz",
		"sha256sum --check --strict",
		"openssl pkeyutl -verify",
		"MCowBQYDK2VwAyEA$VERIFY_VENDOR_KEY",
		"VERIFY_VENDOR_KEY: " + testVendorKey,
		`--policy "policy/observer-security-ci.toml"`,
		"repository: your-org/observer-security-policy",
		"continue-on-error: true",
		"ADVISORY ONLY",
	}
	for _, m := range musts {
		if !strings.Contains(out, m) {
			t.Errorf("template lacks %q", m)
		}
	}
	// Security plan 7.9 and the S-771 to S-779 rules it must itself pass.
	for _, banned := range []string{"pull_request_target", "secrets.", "@v", "write-all", "latest"} {
		if strings.Contains(out, "uses: actions/checkout"+banned) || (banned != "@v" && strings.Contains(out, banned)) {
			t.Errorf("template contains %q", banned)
		}
	}
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "uses: ") {
			ref := strings.Fields(trimmed)[1]
			at := strings.LastIndex(ref, "@")
			if at < 0 || len(ref[at+1:]) != 40 {
				t.Errorf("action not pinned by commit SHA: %s", trimmed)
			}
		}
		// No `${{ github.event... }}` interpolated into a run: script.
		if strings.HasPrefix(trimmed, "run:") || (strings.HasPrefix(line, "          ") && !strings.Contains(line, ":")) {
			if strings.Contains(line, "${{") {
				t.Errorf("expression inside a script: %s", line)
			}
		}
	}
}

func TestRenderWorkflowRefusesInjection(t *testing.T) {
	base := ExampleWorkflowParams(testVendorKey)
	mut := []func(*WorkflowParams){
		func(p *WorkflowParams) { p.Version = "latest" },
		func(p *WorkflowParams) { p.Version = "v1.0.0\nrun: curl evil" },
		func(p *WorkflowParams) { p.ArchiveSHA256 = "ABC" },
		func(p *WorkflowParams) { p.VendorKey = "not-base64!" },
		func(p *WorkflowParams) { p.VendorKey = "AAAA" },
		func(p *WorkflowParams) { p.PolicyRepository = "org/repo\n  evil: 1" },
		func(p *WorkflowParams) { p.PolicyRef = "main" },
		func(p *WorkflowParams) { p.PolicyPath = "../escape.toml" },
		func(p *WorkflowParams) { p.PolicyPath = "a\"b" },
		func(p *WorkflowParams) { p.ReleaseBaseURL = "http://insecure.example" },
		func(p *WorkflowParams) { p.ReleaseBaseURL = "https://x.example/$(id)" },
	}
	for i, m := range mut {
		p := base
		m(&p)
		if _, err := RenderWorkflow(p); err == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
	if _, err := RenderWorkflow(base); err != nil {
		t.Errorf("example params refused: %v", err)
	}
}

// TestRenderWorkflowOrgMode: the org mode adds the commits and fetch jobs;
// the CI credential appears in the fetch job only, which checks out
// nothing; the verdict job pins the org key, reads the org documents, holds
// no secret and runs even when the fetch failed (unknown, never skipped).
func TestRenderWorkflowOrgMode(t *testing.T) {
	out, err := RenderWorkflow(ExampleOrgWorkflowParams(testVendorKey))
	if err != nil {
		t.Fatal(err)
	}
	jobs := map[string]string{}
	var cur string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   ") && strings.HasSuffix(line, ":") {
			cur = strings.TrimSuffix(strings.TrimSpace(line), ":")
		}
		if cur != "" {
			jobs[cur] += line + "\n"
		}
	}
	for _, j := range []string{"commits", "fetch", "verify", "upload"} {
		if jobs[j] == "" {
			t.Fatalf("job %s missing:\n%s", j, out)
		}
	}
	if strings.Count(out, "secrets.") != 1 || !strings.Contains(jobs["fetch"], "secrets.OBSERVER_CI_CREDENTIAL") {
		t.Errorf("the credential must appear exactly once, in the fetch job")
	}
	if strings.Contains(jobs["fetch"], "actions/checkout") {
		t.Errorf("the fetch job must not check out the pull request")
	}
	for _, m := range []string{"needs: fetch", "if: always()", "--org-policy", "--org-lookup", "VERIFY_ORG_KEY: " + ExampleOrgWorkflowParams(testVendorKey).OrgKey, "VERIFY_ORG_ID: your-org-id"} {
		if !strings.Contains(jobs["verify"], m) {
			t.Errorf("verify job lacks %q", m)
		}
	}
	if strings.Contains(jobs["verify"], "--policy \"policy/") {
		t.Errorf("org mode must not read a policy file")
	}
	if !strings.Contains(jobs["commits"], "security verify commits") || !strings.Contains(jobs["fetch"], "security verify fetch") {
		t.Errorf("commits or fetch command missing")
	}
	// Partial org values are refused.
	p := ExampleWorkflowParams(testVendorKey)
	p.OrgURL = "https://org.example.com"
	if _, err := RenderWorkflow(p); err == nil {
		t.Errorf("org URL without id and key accepted")
	}
	for _, mut := range []func(*WorkflowParams){
		func(p *WorkflowParams) { p.OrgURL = "http://org.example.com" },
		func(p *WorkflowParams) { p.OrgURL = "https://org.example.com/" },
		func(p *WorkflowParams) { p.OrgID = "org\nevil: 1" },
		func(p *WorkflowParams) { p.OrgKey = "AAAA" },
	} {
		q := ExampleOrgWorkflowParams(testVendorKey)
		mut(&q)
		if _, err := RenderWorkflow(q); err == nil {
			t.Errorf("org mutation accepted: %+v", q)
		}
	}
}
