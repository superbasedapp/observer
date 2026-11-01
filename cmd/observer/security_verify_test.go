//go:build !sbo_omit_security && !sbo_omit_org_update

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/secverify"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
	"github.com/marmutapp/superbased-observer/internal/update"
)

// verifyRepo is a throwaway git repository with a base commit.
type verifyRepo struct {
	t    *testing.T
	dir  string
	base string
}

func newVerifyRepo(t *testing.T) *verifyRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	r := &verifyRepo{t: t, dir: t.TempDir()}
	r.git("init", "-q")
	r.git("symbolic-ref", "HEAD", "refs/heads/main")
	r.git("config", "user.email", "t@example.invalid")
	r.git("config", "user.name", "t")
	r.git("config", "commit.gpgsign", "false")
	r.write("README.md", "hello\n")
	r.base = r.commit("base")
	return r
}

func (r *verifyRepo) git(args ...string) string {
	r.t.Helper()
	cmd := exec.Command("git", append([]string{"-C", r.dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+r.dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		r.t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func (r *verifyRepo) write(rel, body string) {
	r.t.Helper()
	p := filepath.Join(r.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		r.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		r.t.Fatal(err)
	}
}

func (r *verifyRepo) commit(msg string) string {
	r.git("add", "-A")
	r.git("commit", "-q", "--allow-empty", "-m", msg)
	return r.git("rev-parse", "HEAD")
}

func runVerifyForTest(t *testing.T, o securityVerifyOpts) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	err := runSecurityVerify(context.Background(), &out, &errb, o)
	code := 0
	var ec exitErr
	switch {
	case errors.As(err, &ec):
		code = int(ec)
	case err != nil:
		t.Fatalf("unexpected error: %v", err)
	}
	return code, out.String(), errb.String()
}

var verifyFakeKey = "AKIA" + "Q3EGRQ7XB2LPHJ5N"

func TestSecurityVerifyAcceptance(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  int
	}{
		{"clean change", map[string]string{"src/app.go": "package app\n"}, secverify.ExitPass},
		{"adds a secret", map[string]string{"config/prod.py": "KEY = '" + verifyFakeKey + "'\n"}, secverify.ExitFail},
		{"plants an agent config", map[string]string{".mcp.json": `{"mcpServers":{"x":{"command":"sh"}}}` + "\n"}, secverify.ExitFail},
		{"plants a hook config", map[string]string{".claude/settings.json": `{"hooks":{"PreToolUse":[]}}` + "\n"}, secverify.ExitFail},
		// SEC-C2 milestone 3: the dangerous-workflow acceptance case (a
		// pull_request_target workflow that runs the PR head with a secret).
		{"adds a dangerous workflow", map[string]string{".github/workflows/pr.yml": "on: pull_request_target\npermissions: {contents: read}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make test\n"}, secverify.ExitFail},
		{"adds a safe workflow", map[string]string{".github/workflows/ci.yml": "on: push\npermissions: {contents: read}\njobs:\n  t:\n    runs-on: ubuntu-latest\n    steps:\n      - run: make test\n"}, secverify.ExitPass},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newVerifyRepo(t)
			for p, b := range c.files {
				r.write(p, b)
			}
			head := r.commit("change")
			sarif := filepath.Join(t.TempDir(), "out.sarif")
			code, out, errOut := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, sarif: sarif})
			if code != c.want {
				t.Fatalf("exit %d, want %d\nstdout:\n%s\nstderr:\n%s", code, c.want, out, errOut)
			}
			raw, err := os.ReadFile(sarif)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(raw), verifyFakeKey) || strings.Contains(string(raw), r.dir) {
				t.Error("SARIF holds the secret value or the absolute repository path")
			}
			var doc map[string]any
			if err := json.Unmarshal(raw, &doc); err != nil {
				t.Fatalf("SARIF is not JSON: %v", err)
			}
		})
	}
}

// TestSecurityVerifyIsHermetic: the PR head adds a permissive policy file,
// a project config and the run carries OBSERVER_* and git redirection
// variables; none of it changes the verdict (security plan 11.1 F1, X12).
func TestSecurityVerifyIsHermetic(t *testing.T) {
	r := newVerifyRepo(t)
	permissive := "version = 1\nmode = \"observe\"\n[detectors]\nsecrets = \"flag\"\nagent_config = \"flag\"\n"
	r.write("observer-security-ci.toml", permissive)
	r.write(".observer/config.toml", "[security]\nenabled = false\n")
	r.write("config/prod.py", "KEY = '"+verifyFakeKey+"'\n")
	head := r.commit("evil")

	decoy := t.TempDir()
	t.Setenv("OBSERVER_CONFIG", filepath.Join(r.dir, ".observer/config.toml"))
	t.Setenv("OBSERVER_SECURITY_MODE", "observe")
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
	t.Setenv("GIT_EXTERNAL_DIFF", "/bin/true")

	code, out, errOut := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head})
	if code != secverify.ExitFail {
		t.Fatalf("exit %d, want fail\n%s\n%s", code, out, errOut)
	}
	if !strings.Contains(errOut, "hermetic mode ignored GIT_DIR") {
		t.Errorf("stderr does not name the ignored git variables: %s", errOut)
	}
	if !strings.Contains(out, "policy builtin_defaults") {
		t.Errorf("summary policy source:\n%s", out)
	}
	// The same permissive file named with --policy from inside the
	// repository under test is refused, not used.
	code, _, errOut = runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head, policyFile: filepath.Join(r.dir, "observer-security-ci.toml")})
	if code != secverify.ExitUnknown || !strings.Contains(errOut, "inside the repository under test") {
		t.Errorf("in-repo policy: exit %d, %s", code, errOut)
	}
}

func TestSecurityVerifyPolicySources(t *testing.T) {
	r := newVerifyRepo(t)
	r.write("ci/policy.toml", "version = 1\n[detectors]\nsecrets = \"flag\"\n")
	base := r.commit("policy at base")
	// The head makes the policy strict again and adds a secret; only the
	// base copy counts.
	r.write("ci/policy.toml", "version = 1\n")
	r.write("a.py", "k = '"+verifyFakeKey+"'\n")
	head := r.commit("head")

	code, out, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: base, head: head, baseFile: "ci/policy.toml"})
	if code != secverify.ExitPass || !strings.Contains(out, "ADVISORY") || !strings.Contains(out, "base_commit_advisory") {
		t.Errorf("base policy: exit %d\n%s", code, out)
	}

	protected := filepath.Join(t.TempDir(), "policy.toml")
	if err := os.WriteFile(protected, []byte("version = 1\nmode = \"enforce\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, _ = runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: base, head: head, policyFile: protected})
	if code != secverify.ExitFail || !strings.Contains(out, "protected_file") {
		t.Errorf("protected policy: exit %d\n%s", code, out)
	}

	if err := os.WriteFile(protected, []byte("version = 1\nallow = true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: base, head: head, policyFile: protected}); code != secverify.ExitUnknown {
		t.Errorf("bad policy: exit %d, want unknown", code)
	}
}

func TestSecurityVerifyFailsClosed(t *testing.T) {
	r := newVerifyRepo(t)
	head := r.commit("empty")
	cases := []struct {
		name string
		o    securityVerifyOpts
	}{
		{"ref instead of sha", securityVerifyOpts{repo: r.dir, base: "main", head: head}},
		{"option injection", securityVerifyOpts{repo: r.dir, base: "--output=/tmp/x", head: head}},
		{"unknown commit", securityVerifyOpts{repo: r.dir, base: strings.Repeat("a", 40), head: head}},
		{"not a repository", securityVerifyOpts{repo: t.TempDir(), base: r.base, head: head}},
		{"both policy flags", securityVerifyOpts{repo: r.dir, base: r.base, head: head, policyFile: "/x", baseFile: "y"}},
		{"base policy path escapes", securityVerifyOpts{repo: r.dir, base: r.base, head: head, baseFile: "../x"}},
		{"missing base policy", securityVerifyOpts{repo: r.dir, base: r.base, head: head, baseFile: "nope.toml"}},
		{"sarif path unwritable", securityVerifyOpts{repo: r.dir, base: r.base, head: head, sarif: filepath.Join(t.TempDir(), "no", "such", "dir", "x.sarif")}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if code, out, errOut := runVerifyForTest(t, c.o); code != secverify.ExitUnknown {
				t.Errorf("exit %d, want %d\n%s\n%s", code, secverify.ExitUnknown, out, errOut)
			}
		})
	}
	// An empty change passes.
	if code, out, _ := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head}); code != secverify.ExitPass {
		t.Errorf("empty change: exit %d\n%s", code, out)
	}
}

// TestSecurityVerifyIgnoresRepositoryDiffConfig: the repository's own git
// config cannot reshape the diff the parser reads (an external diff
// driver, no prefixes, a textconv filter on the secret's file).
func TestSecurityVerifyIgnoresRepositoryDiffConfig(t *testing.T) {
	r := newVerifyRepo(t)
	r.git("config", "diff.noprefix", "true")
	r.git("config", "diff.external", "/bin/true")
	r.git("config", "diff.hide.textconv", "true")
	r.write(".gitattributes", "*.py diff=hide\n")
	r.write("a b.py", "k = '"+verifyFakeKey+"'\n")
	head := r.commit("hidden")
	if code, out, errOut := runVerifyForTest(t, securityVerifyOpts{repo: r.dir, base: r.base, head: head}); code != secverify.ExitFail {
		t.Fatalf("exit %d\n%s\n%s", code, out, errOut)
	}
}

func TestSecurityVerifyCommandWiring(t *testing.T) {
	root := newRootCmd()
	cmd, _, err := root.Find([]string{"security", "verify", "template"})
	if err != nil || cmd.Name() != "template" {
		t.Fatalf("security verify template not registered: %v", err)
	}
	for _, sub := range []string{"commits", "fetch"} {
		if c, _, err := root.Find([]string{"security", "verify", sub}); err != nil || c.Name() != sub {
			t.Errorf("security verify %s not registered: %v", sub, err)
		}
	}
	for _, flag := range []string{"repo", "base", "head", "policy", "policy-from-base", "sarif", "org-policy", "org-lookup", "org-key", "org-id", "min-policy-version"} {
		v, _, _ := root.Find([]string{"security", "verify"})
		if v.Flags().Lookup(flag) == nil {
			t.Errorf("verify lacks --%s", flag)
		}
	}
}

// TestSecurityVerifyTemplateMatchesDocsExample is the drift gate for the
// documented example workflow: it must be exactly what the generator
// renders from the example parameters.
func TestSecurityVerifyTemplateMatchesDocsExample(t *testing.T) {
	publictree.Skip(t, "docs/examples/security-verify")
	want, err := secverify.RenderWorkflow(secverify.ExampleWorkflowParams(update.VendorPublicKeyV1))
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "security-verify", "observer-security-verify.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := yaml.Unmarshal(got, &parsed); err != nil || parsed["jobs"] == nil {
		t.Errorf("the example workflow is not valid YAML: %v", err)
	}
	pol, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "security-verify", "observer-security-ci.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := secverify.ParsePolicy(pol, secverify.SourceProtected); err != nil {
		t.Errorf("the example policy does not parse: %v", err)
	}
	if string(got) != want {
		t.Errorf("docs/examples/security-verify/observer-security-verify.yml drifted from the generator; regenerate it with:\n  go run ./cmd/observer security verify template > docs/examples/security-verify/observer-security-verify.yml")
	}

	wantOrg, err := secverify.RenderWorkflow(secverify.ExampleOrgWorkflowParams(update.VendorPublicKeyV1))
	if err != nil {
		t.Fatal(err)
	}
	gotOrg, err := os.ReadFile(filepath.Join("..", "..", "docs", "examples", "security-verify", "observer-security-verify-org.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(gotOrg, &parsed); err != nil || parsed["jobs"] == nil {
		t.Errorf("the org example workflow is not valid YAML: %v", err)
	}
	if string(gotOrg) != wantOrg {
		t.Errorf("docs/examples/security-verify/observer-security-verify-org.yml drifted from the generator; regenerate it with:\n  go run ./cmd/observer security verify template --org-url https://observer-org.example.com --org-id your-org-id --org-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= > docs/examples/security-verify/observer-security-verify-org.yml")
	}

	cmd := newSecurityVerifyTemplateCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"--version", "v1.40.0", "--sha256", strings.Repeat("ab", 32), "--policy-repo", "acme/sec-policy", "--policy-ref", strings.Repeat("c", 40)})
	if err := cmd.Execute(); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "observer-v1.40.0-linux-x64.tar.gz") || !strings.Contains(out.String(), "repository: acme/sec-policy") {
		t.Errorf("template output:\n%s", out.String())
	}
	cmd = newSecurityVerifyTemplateCmd()
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	cmd.SetArgs([]string{"--policy-ref", "main"})
	if err := cmd.Execute(); err == nil {
		t.Error("a branch name as --policy-ref was accepted")
	}
}

// TestSecurityVerifyNotGated (lane sec-a2, SEC-F1 audit): the verb gate
// never wraps `observer security verify`, so the hermetic claim holds. A
// fresh HOME with the full build runs it to its verdict and leaves the
// home untouched, and a runner config that switches the module off cannot
// refuse it, while the module's other
// verbs stay gated.
func TestSecurityVerifyNotGated(t *testing.T) {
	r := newVerifyRepo(t)
	r.write("main.go", "package main\n")
	head := r.commit("clean change")
	run := func(args ...string) (int, string) {
		t.Helper()
		root := newRootCmd()
		var out, errb bytes.Buffer
		root.SetOut(&out)
		root.SetErr(&errb)
		root.SetArgs(args)
		err := root.Execute()
		var ec exitErr
		switch {
		case errors.As(err, &ec):
			return int(ec), out.String() + errb.String()
		case err != nil:
			t.Fatalf("%v: %v\n%s%s", args, err, out.String(), errb.String())
		}
		return 0, out.String() + errb.String()
	}
	verify := []string{"security", "verify", "--repo", r.dir, "--base", r.base, "--head", head}

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(r.dir)
	if code, out := run(verify...); code != secverify.ExitPass {
		t.Fatalf("fresh HOME: exit %d, want %d\n%s", code, secverify.ExitPass, out)
	}
	if entries, _ := os.ReadDir(home); len(entries) != 0 {
		t.Fatalf("verify wrote under a fresh HOME: %v", entries)
	}

	// The remove list is derived from the catalog: the module root and
	// every child under it that this build compiles, so a new security
	// child cannot leave the module active and break the gate check.
	var secIDs []string
	for _, id := range components.Compiled(components.BinaryNode) {
		if id == "security" || strings.HasPrefix(id, "security.") {
			secIDs = append(secIDs, strconv.Quote(id))
		}
	}
	if len(secIDs) < 2 || secIDs[0] != strconv.Quote("security") {
		t.Fatalf("catalog security set looks wrong: %v", secIDs)
	}
	off := []byte("[components]\nremove = [" + strings.Join(secIDs, ", ") + "]\n")
	if err := os.MkdirAll(filepath.Join(home, ".observer"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".observer", "config.toml"), off, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := run(verify...); code != secverify.ExitPass {
		t.Fatalf("module off in config: exit %d, want %d\n%s", code, secverify.ExitPass, out)
	}
	if code, out := run("security", "status"); code != 3 {
		t.Fatalf("security status with the module off: exit %d, want 3\n%s", code, out)
	}
}
