package invariant

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// publish_workflow_test.go pins .github/workflows/publish.yml, the public
// repository's trusted publishing (OIDC) workflow for npm and PyPI, the two
// scripts it runs (scripts/publish-verify.sh, scripts/publish-npm.sh) and
// the packaging facts they depend on. It ships on the public tree, where the
// workflow runs.
//
// npm and PyPI check a trusted publish against the workflow's FILE NAME, the
// environment, the repository and the job's OIDC token; nothing about it can
// be tried before a real release. So the shape the registries require is
// pinned here (id-token: write only on the two publishing jobs, each in its
// environment, on a GitHub-hosted runner, no token, the minimum Node and
// npm), and the step scripts are EXECUTED against stub `gh` and `npm`
// programs: the asset check, download, signature and checksum verification,
// publish order, idempotent re-runs, the stable dist-tag, the SDK rules and
// the PyPI staging.

// publishWorkflowPath is the public publish workflow. Its file name is part
// of every package's trusted publisher on npmjs.com and pypi.org.
const publishWorkflowPath = ".github/workflows/publish.yml"

// publishDoc is the parsed public publish workflow.
type publishDoc struct {
	On          map[string]yaml.Node   `yaml:"on"`
	Permissions map[string]string      `yaml:"permissions"`
	Env         map[string]string      `yaml:"env"`
	Jobs        map[string]workflowJob `yaml:"jobs"`
	RunsOn      map[string]string      `yaml:"-"`
}

// publishJobRunsOn is the runs-on of each job, read separately because
// workflowJob does not model it.
type publishJobRunsOn struct {
	Jobs map[string]struct {
		RunsOn string `yaml:"runs-on"`
	} `yaml:"jobs"`
}

// loadPublishWorkflow parses the public publish workflow.
func loadPublishWorkflow(t *testing.T) (publishDoc, string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), filepath.FromSlash(publishWorkflowPath)))
	if err != nil {
		t.Fatalf("read %s: %v", publishWorkflowPath, err)
	}
	var doc publishDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("%s is not valid YAML: %v", publishWorkflowPath, err)
	}
	var ro publishJobRunsOn
	if err := yaml.Unmarshal(raw, &ro); err != nil {
		t.Fatalf("%s: %v", publishWorkflowPath, err)
	}
	doc.RunsOn = map[string]string{}
	for name, j := range ro.Jobs {
		doc.RunsOn[name] = j.RunsOn
	}
	return doc, string(raw)
}

// publishStep returns the step with the given id; step ids are unique across
// the workflow's jobs.
func publishStep(t *testing.T, doc publishDoc, id string) workflowStep {
	t.Helper()
	var found []workflowStep
	for _, job := range doc.Jobs {
		for _, s := range job.Steps {
			if s.ID == id {
				found = append(found, s)
			}
		}
	}
	if len(found) != 1 {
		t.Fatalf("%s: want exactly one step with id %q, found %d", publishWorkflowPath, id, len(found))
	}
	return found[0]
}

// publishStepIndex is the position of the step with the given id in job, or -1.
func publishStepIndex(job workflowJob, id string) int {
	for i, s := range job.Steps {
		if s.ID == id {
			return i
		}
	}
	return -1
}

// semverAtLeast reports whether the exact x.y.z version v is at least min.
func semverAtLeast(t *testing.T, v, min string) bool {
	t.Helper()
	parse := func(s string) [3]int {
		var out [3]int
		parts := strings.Split(s, ".")
		if len(parts) != 3 {
			t.Fatalf("%q is not an exact x.y.z version", s)
		}
		for i, p := range parts {
			n, err := strconv.Atoi(p)
			if err != nil {
				t.Fatalf("%q is not an exact x.y.z version", s)
			}
			out[i] = n
		}
		return out
	}
	a, b := parse(v), parse(min)
	for i := range a {
		if a[i] != b[i] {
			return a[i] > b[i]
		}
	}
	return true
}

// codeLines returns the lines of src with any # comment removed.
func codeLines(src string) []string {
	var out []string
	for _, line := range strings.Split(src, "\n") {
		if j := strings.Index(line, "#"); j >= 0 {
			line = line[:j]
		}
		out = append(out, line)
	}
	return out
}

// TestPublishWorkflowIsATrustedPublisher pins what npm's and PyPI's trusted
// publishing require of the workflow, and what keeps it token-free.
func TestPublishWorkflowIsATrustedPublisher(t *testing.T) {
	doc, raw := loadPublishWorkflow(t)

	// Triggers: a published release (pre-releases fire `published` too) and
	// a manual re-run naming the release.
	rel, ok := doc.On["release"]
	if !ok {
		t.Fatal("publish.yml is not triggered by `release`")
	}
	var relCfg struct {
		Types []string `yaml:"types"`
	}
	if err := rel.Decode(&relCfg); err != nil || len(relCfg.Types) != 1 || relCfg.Types[0] != "published" {
		t.Errorf("publish.yml must trigger on release types [published] only, got %v (%v)", relCfg.Types, err)
	}
	disp, ok := doc.On["workflow_dispatch"]
	if !ok {
		t.Fatal("publish.yml has no workflow_dispatch trigger for a manual re-run")
	}
	var dispCfg struct {
		Inputs map[string]struct {
			Required bool `yaml:"required"`
		} `yaml:"inputs"`
	}
	if err := disp.Decode(&dispCfg); err != nil || !dispCfg.Inputs["tag"].Required {
		t.Errorf("workflow_dispatch must take a required `tag` input (%v)", err)
	}
	for name := range doc.On {
		if name != "release" && name != "workflow_dispatch" {
			t.Errorf("publish.yml has an extra trigger %q", name)
		}
	}

	// Jobs and permissions: nothing at the top; plan reads only; the two
	// publishing jobs hold id-token: write, each in its own environment (the
	// trusted publishers name it), on a GitHub-hosted runner (npm refuses
	// self-hosted runners), after plan, and only on the public repository.
	if len(doc.Permissions) != 0 {
		t.Errorf("top-level permissions must be {}, got %v", doc.Permissions)
	}
	var names []string
	for n := range doc.Jobs {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.Join(names, ",") != "npm,plan,pypi,pypi_sdk" {
		t.Fatalf("publish.yml jobs are %v, want exactly plan, npm, pypi and pypi_sdk", names)
	}
	plan := doc.Jobs["plan"]
	if len(plan.Permissions) != 1 || plan.Permissions["contents"] != "read" {
		t.Errorf("the plan job's permissions are %v, want exactly contents: read", plan.Permissions)
	}
	if plan.If != "github.repository == 'superbasedapp/observer'" {
		t.Errorf("the plan job is gated %q, want it to run only on superbasedapp/observer", plan.If)
	}
	for job, env := range map[string]string{"npm": "npm", "pypi": "pypi", "pypi_sdk": "pypi"} {
		j := doc.Jobs[job]
		want := map[string]string{"contents": "read", "id-token": "write"}
		if len(j.Permissions) != len(want) {
			t.Errorf("the %s job's permissions are %v, want exactly %v", job, j.Permissions, want)
		}
		for k, v := range want {
			if j.Permissions[k] != v {
				t.Errorf("the %s job's permission %s is %q, want %q", job, k, j.Permissions[k], v)
			}
		}
		var e struct {
			Name string `yaml:"name"`
		}
		if err := j.Environment.Decode(&e); err != nil || e.Name != env {
			t.Errorf("the %s job's environment is %q (%v), want %q: the trusted publishers name it", job, e.Name, err, env)
		}
		if !contains(needsOf(j), "plan") {
			t.Errorf("the %s job does not need plan", job)
		}
	}
	for job := range doc.Jobs {
		if got := doc.RunsOn[job]; got != "ubuntu-latest" {
			t.Errorf("the %s job runs on %q; trusted publishing needs a GitHub-hosted runner (ubuntu-latest)", job, got)
		}
	}

	// No token of any kind: no secret, no NODE_AUTH_TOKEN, no password for
	// the PyPI action, and the retired tokens not even named outside a
	// comment.
	for i, code := range codeLines(raw) {
		for _, banned := range []string{"secrets.", "NODE_AUTH_TOKEN", "NPM_TOKEN", "PYPI_TOKEN", "_authToken", "password:"} {
			if strings.Contains(code, banned) {
				t.Errorf("publish.yml:%d uses %q; trusted publishing needs no token: %s", i+1, banned, strings.TrimSpace(code))
			}
		}
	}

	// Node and npm: exact pins at or above npm's minimums (publish over
	// OIDC: Node 22.14.0, npm 11.5.1; dist-tag over OIDC: npm 11.21.0).
	node, npm := doc.Env["NODE_VERSION"], doc.Env["NPM_VERSION"]
	if !semverAtLeast(t, node, "22.14.0") {
		t.Errorf("NODE_VERSION %s is below npm trusted publishing's minimum 22.14.0", node)
	}
	if !semverAtLeast(t, npm, "11.21.0") {
		t.Errorf("NPM_VERSION %s is below 11.21.0, the first npm that runs `npm dist-tag` over OIDC (publish needs 11.5.1)", npm)
	}

	// Every action pinned to a commit; the checkouts keep no credential.
	shaPin := regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$`)
	var setupNode, installNpm bool
	for name, job := range doc.Jobs {
		for _, s := range job.Steps {
			if s.Uses != "" && !shaPin.MatchString(s.Uses) {
				t.Errorf("%s step %q uses %q: an action in this workflow must be pinned to a commit sha", name, s.Name, s.Uses)
			}
			if strings.HasPrefix(s.Uses, "actions/checkout@") && s.With["persist-credentials"] != false {
				t.Errorf("%s: the checkout must set persist-credentials: false", name)
			}
			if strings.HasPrefix(s.Uses, "actions/setup-node@") {
				setupNode = name == "npm"
				if s.With["node-version"] != "${{ env.NODE_VERSION }}" {
					t.Errorf("setup-node's node-version is %v, want ${{ env.NODE_VERSION }}", s.With["node-version"])
				}
			}
			if strings.Contains(s.Run, `npm install -g "npm@${NPM_VERSION}"`) {
				installNpm = name == "npm"
			}
		}
	}
	if !setupNode || !installNpm {
		t.Errorf("the npm job needs setup-node with the pinned Node (%v) and the pinned npm install (%v)", setupNode, installNpm)
	}

	// The npm job: fetch, verify, publish the observer packages, move
	// stable (final releases), then the SDKs (final releases), in that
	// order; a failure prints the hand-publish fallback.
	nj := doc.Jobs["npm"]
	order := []string{"fetch", "verify", "npm", "stable", "sdk", "fallback"}
	for i := 1; i < len(order); i++ {
		a, b := publishStepIndex(nj, order[i-1]), publishStepIndex(nj, order[i])
		if a < 0 || b < 0 || a >= b {
			t.Errorf("npm job steps out of order: %s at %d, %s at %d (want %v)", order[i-1], a, order[i], b, order)
		}
	}
	if v := publishStepIndex(nj, "verify"); v > 0 {
		for _, s := range nj.Steps[:v] {
			if strings.Contains(s.Run, "npm publish") || strings.Contains(s.Run, "publish-npm.sh") {
				t.Errorf("step %q publishes before the verify step", s.Name)
			}
		}
	}
	if !strings.Contains(publishStep(t, doc, "verify").Run, `bash "${GITHUB_WORKSPACE}/scripts/publish-verify.sh" . "${files[@]}"`) {
		t.Error("the npm verify step does not run scripts/publish-verify.sh over every planned tarball")
	}
	npmStep := publishStep(t, doc, "npm")
	if !strings.Contains(npmStep.Run, `scripts/publish-npm.sh" "${RUNNER_TEMP}/npm-release" observer "${DIST_TAG}"`) ||
		npmStep.Env["DIST_TAG"] != "${{ needs.plan.outputs.dist_tag }}" {
		t.Errorf("the npm step must publish the observer packages under the plan's dist-tag: run %q env %v", npmStep.Run, npmStep.Env)
	}
	if st := publishStep(t, doc, "stable"); !strings.Contains(st.If, "needs.plan.outputs.channel == 'stable'") ||
		!strings.Contains(st.Run, "npm dist-tag add") {
		t.Errorf("the stable step must add the stable dist-tag on the stable channel only (if %q)", st.If)
	}
	sdk := publishStep(t, doc, "sdk")
	if !strings.Contains(sdk.Run, `scripts/publish-npm.sh" "${RUNNER_TEMP}/npm-release" sdk latest`) ||
		!strings.Contains(sdk.If, "needs.plan.outputs.sdk == 'true'") || !strings.Contains(sdk.If, "steps.verify.outcome == 'success'") {
		t.Errorf("the sdk step must publish the SDK packages under latest, only when plan marks them and verify passed (if %q)", sdk.If)
	}
	if fb := publishStep(t, doc, "fallback"); fb.If != "failure()" || !strings.Contains(fb.Run, "--otp") {
		t.Error("the npm job has no failure() step printing the manual `npm publish --otp` fallback")
	}

	// PyPI: one job per project, each fetch, verify, exactly one upload with
	// the PyPI action (trusted publishing, attestations, skip-existing; the
	// action does not support a second run in one job), then the fallback.
	for job, c := range map[string]struct {
		ids []string
		dir string
	}{
		"pypi":     {[]string{"pypi_fetch", "pypi_verify", "pypi_upload", "pypi_fallback"}, "publish-dist/observer/"},
		"pypi_sdk": {[]string{"pypi_sdk_fetch", "pypi_sdk_verify", "pypi_sdk_upload", "pypi_sdk_fallback"}, "publish-dist/sdk/"},
	} {
		j := doc.Jobs[job]
		for i := 1; i < len(c.ids); i++ {
			a, b := publishStepIndex(j, c.ids[i-1]), publishStepIndex(j, c.ids[i])
			if a < 0 || b < 0 || a >= b {
				t.Errorf("%s job steps out of order: %s at %d, %s at %d (want %v)", job, c.ids[i-1], a, c.ids[i], b, c.ids)
			}
		}
		var uploads []string
		for _, st := range j.Steps {
			if strings.Contains(st.Uses, "gh-action-pypi-publish") {
				uploads = append(uploads, st.ID)
			}
		}
		if len(uploads) != 1 || uploads[0] != c.ids[2] {
			t.Errorf("the %s job runs the PyPI upload action in steps %v, want exactly once (%s)", job, uploads, c.ids[2])
		}
		if !strings.Contains(publishStep(t, doc, c.ids[1]).Run, `scripts/publish-verify.sh" . "${files[@]}"`) {
			t.Errorf("the %s verify step does not run scripts/publish-verify.sh", job)
		}
		s := publishStep(t, doc, c.ids[2])
		if !strings.HasPrefix(s.Uses, "pypa/gh-action-pypi-publish@") {
			t.Errorf("%s uses %q, want pypa/gh-action-pypi-publish", c.ids[2], s.Uses)
		}
		if s.With["packages-dir"] != c.dir || s.With["skip-existing"] != true || s.With["attestations"] != true {
			t.Errorf("%s: with %v, want packages-dir %s, skip-existing and attestations true", c.ids[2], s.With, c.dir)
		}
		if _, ok := s.With["password"]; ok {
			t.Errorf("%s passes a password; trusted publishing needs none", c.ids[2])
		}
		if s.If != "" {
			t.Errorf("%s is conditional (%q); the job's own if decides whether it runs", c.ids[2], s.If)
		}
		if fb := publishStep(t, doc, c.ids[3]); fb.If != "failure()" || !strings.Contains(fb.Run, "twine upload") {
			t.Errorf("the %s job has no failure() step printing the manual twine fallback", job)
		}
	}
	if got := doc.Jobs["pypi"].If; got != "needs.plan.outputs.pypi == 'true'" {
		t.Errorf("the pypi job runs on %q, want only when plan found the wheels", got)
	}
	// The SDK last, after the observer wheels, but not held back by their
	// failure; only when plan marks it (a final release).
	sj := doc.Jobs["pypi_sdk"]
	if !contains(needsOf(sj), "pypi") {
		t.Error("the pypi_sdk job does not need pypi: the SDK publishes after the observer wheels")
	}
	if sj.If != "${{ !cancelled() && needs.plan.outputs.sdk == 'true' }}" {
		t.Errorf("the pypi_sdk job runs on %q, want ${{ !cancelled() && needs.plan.outputs.sdk == 'true' }}", sj.If)
	}

	// The publish itself (scripts/publish-npm.sh): one `npm publish`, with
	// public access, the dist-tag and provenance.
	src, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", "publish-npm.sh"))
	if err != nil {
		t.Fatal(err)
	}
	lines := regexp.MustCompile(`(?m)^\s*npm publish [^\n]*`).FindAllString(string(src), -1)
	if len(lines) != 1 {
		t.Fatalf("scripts/publish-npm.sh should run exactly one `npm publish` command line, found %d", len(lines))
	}
	for _, flag := range []string{`--access public`, `--tag "${dist_tag}"`, `--provenance`} {
		if !strings.Contains(lines[0], flag) {
			t.Errorf("`%s` lacks %s", strings.TrimSpace(lines[0]), flag)
		}
	}
}

// TestNoWorkflowUsesTheRetiredRegistryTokens pins the retirement of the CI
// registry tokens: no workflow reads any of them (a comment may still name
// them).
func TestNoWorkflowUsesTheRetiredRegistryTokens(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(repoRoot(t), ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows found (%v)", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for i, code := range codeLines(string(raw)) {
			for _, tok := range []string{"NPM_TOKEN_OBSERVER", "PYPI_TOKEN_OBSERVER", "NPM_TOKEN_SDK", "PYPI_TOKEN_SDK"} {
				if strings.Contains(code, tok) {
					t.Errorf("%s:%d still uses the retired %s: %s", filepath.Base(f), i+1, tok, strings.TrimSpace(code))
				}
			}
		}
	}
}

// TestNpmPackageBinTargetsAreShipped pins the packaging fact behind the
// broken superbased 3.42.1 (published without bin/superbased.js, which the
// repository's bin/ ignore rule hid): every `bin` target an npm package
// declares exists and is not git-ignored, so a clean checkout packs it.
func TestNpmPackageBinTargetsAreShipped(t *testing.T) {
	root := repoRoot(t)
	manifests, err := filepath.Glob(filepath.Join(root, "npm", "*", "package.json"))
	if err != nil || len(manifests) < 7 {
		t.Fatalf("want the seven npm packages under npm/, found %d (%v)", len(manifests), err)
	}
	git, gitErr := exec.LookPath("git")
	for _, m := range manifests {
		raw, err := os.ReadFile(m)
		if err != nil {
			t.Fatal(err)
		}
		var pkg struct {
			Name string            `json:"name"`
			Bin  map[string]string `json:"bin"`
		}
		if err := json.Unmarshal(raw, &pkg); err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		dir := filepath.Dir(m)
		for cmd, target := range pkg.Bin {
			p := filepath.Join(dir, filepath.FromSlash(strings.TrimPrefix(target, "./")))
			if _, err := os.Stat(p); err != nil {
				t.Errorf("%s: bin %q -> %s does not exist", pkg.Name, cmd, target)
				continue
			}
			if gitErr != nil {
				continue
			}
			rel, _ := filepath.Rel(root, p)
			c := exec.Command(git, "-C", root, "check-ignore", "-q", "--", filepath.ToSlash(rel))
			err := c.Run()
			var exitErr *exec.ExitError
			switch {
			case err == nil:
				t.Errorf("%s: bin target %s is git-ignored, so a clean checkout packs the package without it", pkg.Name, filepath.ToSlash(rel))
			case errors.As(err, &exitErr) && exitErr.ExitCode() == 1:
				// Not ignored.
			default:
				t.Logf("git check-ignore %s: %v (not a git checkout?)", rel, err)
			}
		}
	}
}

// npmPubHaveTools skips t unless the step scripts can run here.
func npmPubHaveTools(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the step scripts and the gh/npm stubs are bash; run on Linux or WSL")
	}
	for _, tool := range []string{"bash", "node", "tar", "sha256sum", "awk", "sort", "diff", "base64"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s is not available", tool)
		}
	}
}

// npmPubRun runs one step script with bash in dir, with env added to the
// test's environment, and returns the combined output, the GITHUB_OUTPUT
// key/values and the error.
func npmPubRun(t *testing.T, script, dir string, env map[string]string) (string, map[string]string, error) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "github_output")
	if err := os.WriteFile(out, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", script)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GITHUB_OUTPUT="+out)
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	combined, err := cmd.CombinedOutput()
	raw, rerr := os.ReadFile(filepath.Clean(out))
	if rerr != nil {
		t.Fatal(rerr)
	}
	got := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			got[k] = v
		}
	}
	return string(combined), got, err
}

// TestPublishResolveStep runs the resolve step: the dist-tag follows the
// tag shape exactly as the release's channel job decides it, the short name
// rides at major + 2, and a tag that is not an observer release is skipped
// cleanly rather than guessed at.
func TestPublishResolveStep(t *testing.T) {
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash is not available")
	}
	doc, _ := loadPublishWorkflow(t)
	step := publishStep(t, doc, "resolve")
	if step.Env["EVENT_TAG"] != "${{ github.event.release.tag_name }}" || step.Env["INPUT_TAG"] != "${{ inputs.tag }}" {
		t.Errorf("resolve reads the tag from %q / %q, want the release event and the dispatch input", step.Env["EVENT_TAG"], step.Env["INPUT_TAG"])
	}
	cases := []struct {
		event, input string
		fail         bool
		want         map[string]string
	}{
		{event: "v1.43.0", want: map[string]string{"publish": "true", "tag": "v1.43.0", "version": "1.43.0", "short_version": "3.43.0", "channel": "stable", "dist_tag": "latest"}},
		{event: "v1.43.0-rc.1", want: map[string]string{"publish": "true", "version": "1.43.0-rc.1", "short_version": "3.43.0-rc.1", "channel": "edge", "dist_tag": "edge"}},
		{input: "v2.0.1-beta.2", want: map[string]string{"publish": "true", "tag": "v2.0.1-beta.2", "short_version": "4.0.1-beta.2", "channel": "edge", "dist_tag": "edge"}},
		{input: "v1.42.1", want: map[string]string{"publish": "true", "short_version": "3.42.1", "dist_tag": "latest"}},
		{event: "sdk-v1.0.0", want: map[string]string{"publish": "false"}},
		{event: "sdk/go/v0.1.0", want: map[string]string{"publish": "false"}},
		{event: "", want: map[string]string{"publish": "false"}},
		{event: "v1.43", fail: true},
		{event: "v01.2.3", fail: true},
		{event: "v1.2.3.4", fail: true},
		{input: "v1.2.3;echo", fail: true},
	}
	for _, tc := range cases {
		name := tc.event + tc.input
		if name == "" {
			name = "empty"
		}
		t.Run(strings.ReplaceAll(name, "/", "_"), func(t *testing.T) {
			out, got, err := npmPubRun(t, step.Run, t.TempDir(), map[string]string{"EVENT_TAG": tc.event, "INPUT_TAG": tc.input})
			if tc.fail {
				if err == nil {
					t.Fatalf("resolve accepted %q:\n%s", name, out)
				}
				if got["publish"] == "true" {
					t.Errorf("resolve failed but still emitted publish=true")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolve failed on %q: %v\n%s", name, err, out)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s=%q, want %q", k, got[k], v)
				}
			}
		})
	}
}

// npmPubPackage is one npm package of a fake release.
type npmPubPackage struct {
	name, version, file string
}

// npmPubPackages is the observer plan for version v, in publish order.
func npmPubPackages(v, short string) []npmPubPackage {
	var out []npmPubPackage
	for _, t := range []string{"linux-x64", "linux-arm64", "darwin-x64", "darwin-arm64", "win32-x64"} {
		out = append(out, npmPubPackage{"@superbased/observer-" + t, v, "superbased-observer-" + t + "-" + v + ".tgz"})
	}
	out = append(out,
		npmPubPackage{"@superbased/observer", v, "superbased-observer-" + v + ".tgz"},
		npmPubPackage{"superbased", short, "superbased-" + short + ".tgz"},
	)
	return out
}

// pubSdkVersion is the SDK version line of the fake releases.
const pubSdkVersion = "0.1.0"

// npmPubSdkPackages is the SDK's npm plan, in publish order.
func npmPubSdkPackages(v string) []npmPubPackage {
	return []npmPubPackage{
		{"@superbased/sdk", v, "superbased-sdk-" + v + ".tgz"},
		{"@superbased/feedback-widget", v, "superbased-feedback-widget-" + v + ".tgz"},
	}
}

// pubWheelPlatforms are the platform tags of the superbased-observer wheels.
var pubWheelPlatforms = []string{"manylinux2014_x86_64", "manylinux2014_aarch64", "macosx_13_0_x86_64", "macosx_13_0_arm64", "win_amd64"}

// pubPyVersion is the PEP 440 spelling the wheel build gives version v.
func pubPyVersion(v string) string {
	core, pre, ok := strings.Cut(v, "-")
	if !ok {
		return v
	}
	return core + strings.NewReplacer("rc.", "rc", "beta.", "b", "alpha.", "a").Replace(pre)
}

// npmPubTarball builds an npm tarball holding only package/package.json.
func npmPubTarball(t *testing.T, name, version, repo string) []byte {
	t.Helper()
	pj, err := json.Marshal(map[string]any{
		"name": name, "version": version,
		"repository": map[string]string{"type": "git", "url": repo},
	})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "package/package.json", Mode: 0o644, Size: int64(len(pj))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(pj); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// npmPubStubGh serves a fake release from $STUB_RELEASE_DIR/assets. Every
// call is logged to $STUB_LOG.
const npmPubStubGh = `#!/usr/bin/env bash
set -euo pipefail
R="${STUB_RELEASE_DIR}"
echo "gh $*" >> "${STUB_LOG}"
args=("$@")
case "$1 $2" in
  "release view")
    field=""
    for ((i=0; i<${#args[@]}; i++)); do
      [ "${args[$i]}" = --json ] && field="${args[$((i+1))]}"
    done
    case "${field}" in
      isDraft) cat "${R}/draft" 2>/dev/null || echo false ;;
      assets) ls -1 "${R}/assets" ;;
      *) echo "stub gh: unexpected --json ${field}" >&2; exit 2 ;;
    esac
    ;;
  "release download")
    dir="."
    pats=()
    for ((i=0; i<${#args[@]}; i++)); do
      case "${args[$i]}" in
        --dir) dir="${args[$((i+1))]}" ;;
        --pattern) pats+=("${args[$((i+1))]}") ;;
      esac
    done
    shopt -s nullglob
    for p in "${pats[@]}"; do
      for f in "${R}"/assets/${p}; do cp "${f}" "${dir}/"; done
    done
    ;;
  *) echo "stub gh: unexpected $*" >&2; exit 2 ;;
esac
`

// npmPubStubNpm is a registry in $STUB_NPM_STATE: pub/<name>@<version>
// holds a published version's integrity, tags/<name>.<tag> a dist-tag.
// Names have / replaced by __. Every mutation is logged to $STUB_LOG.
const npmPubStubNpm = `#!/usr/bin/env bash
set -euo pipefail
S="${STUB_NPM_STATE}"
mkdir -p "${S}/pub" "${S}/tags"
key() { printf '%s' "$1" | sed 's#/#__#g'; }
case "$1" in
  view)
    spec="$2"; field="$3"
    case "${field}" in
      dist.integrity)
        f="${S}/pub/$(key "${spec}")"
        if [ -f "${f}" ]; then cat "${f}"; echo; else echo "npm error code E404" >&2; exit 1; fi
        ;;
      dist-tags.*)
        f="${S}/tags/$(key "${spec}").${field#dist-tags.}"
        [ -f "${f}" ] && { cat "${f}"; echo; }
        exit 0
        ;;
      *) echo "stub npm: unexpected view ${field}" >&2; exit 2 ;;
    esac
    ;;
  publish)
    file="$2"; shift 2
    tag=""
    flags="$*"
    while [ $# -gt 0 ]; do [ "$1" = --tag ] && tag="$2"; shift; done
    pj=$(tar -xzOf "${file}" package/package.json)
    name=$(printf '%s' "${pj}" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).name))')
    version=$(printf '%s' "${pj}" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s).version))')
    if [ -n "${STUB_NPM_REFUSE:-}" ] && [ "${STUB_NPM_REFUSE}" = "${name}" ]; then
      echo "npm error code E404 Not Found - PUT https://registry.npmjs.org/${name}" >&2
      exit 1
    fi
    node -e 'process.stdout.write("sha512-"+require("crypto").createHash("sha512").update(require("fs").readFileSync(process.argv[1])).digest("base64"))' "${file}" > "${S}/pub/$(key "${name}@${version}")"
    printf '%s' "${version}" > "${S}/tags/$(key "${name}").${tag}"
    echo "publish ${name}@${version} ${flags}" >> "${STUB_LOG}"
    ;;
  dist-tag)
    [ "$2" = add ] || { echo "stub npm: unexpected dist-tag $2" >&2; exit 2; }
    spec="$3"; tag="$4"
    name="${spec%@*}"; version="${spec##*@}"
    printf '%s' "${version}" > "${S}/tags/$(key "${name}").${tag}"
    echo "dist-tag ${name}@${version} ${tag}" >> "${STUB_LOG}"
    ;;
  *) echo "stub npm: unexpected $*" >&2; exit 2 ;;
esac
`

// pubFixture is one fake release, a workspace holding the two publish
// scripts and the installer with the vendor key, and stub gh and npm.
type pubFixture struct {
	t                                                    *testing.T
	doc                                                  publishDoc
	release, assets, state, runner, bin, logf, workspace string
	pkgs, sdkPkgs                                        []npmPubPackage
	wheels, sdkPy                                        []string
	tag, version, short, distTag, channel                string
	sums                                                 map[string][]byte
}

// newPubFixture builds a release for tag carrying everything a v1.43.0+
// release carries: the seven observer tarballs, the five wheels, the SDK's
// four files, an archive, SHA256SUMS listing them all and SHA256SUMS.sig by
// a fresh vendor key, which the workspace's scripts/install.sh carries.
func newPubFixture(t *testing.T, tag string) *pubFixture {
	t.Helper()
	npmPubHaveTools(t)
	doc, _ := loadPublishWorkflow(t)
	base := t.TempDir()
	f := &pubFixture{
		t: t, doc: doc,
		release:   filepath.Join(base, "release"),
		state:     filepath.Join(base, "registry"),
		runner:    filepath.Join(base, "runner"),
		bin:       filepath.Join(base, "bin"),
		logf:      filepath.Join(base, "calls.log"),
		workspace: filepath.Join(base, "workspace"),
		tag:       tag,
		sums:      map[string][]byte{},
	}
	f.assets = filepath.Join(f.release, "assets")
	for _, d := range []string{f.assets, f.state, f.runner, f.bin, filepath.Join(f.workspace, "scripts")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{"gh": npmPubStubGh, "npm": npmPubStubNpm} {
		if err := os.WriteFile(filepath.Join(f.bin, name), []byte(body), 0o755); err != nil { //nolint:gosec // a test stub must be executable
			t.Fatal(err)
		}
	}
	for _, s := range []string{"publish-verify.sh", "publish-npm.sh"} {
		b, err := os.ReadFile(filepath.Join(repoRoot(t), "scripts", s))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(f.workspace, "scripts", s), b, 0o755); err != nil { //nolint:gosec // a script under test
			t.Fatal(err)
		}
	}
	// The resolve step decides the versions; the fixture uses its answer.
	out, got, err := npmPubRun(t, publishStep(t, doc, "resolve").Run, base, map[string]string{"EVENT_TAG": tag})
	if err != nil || got["publish"] != "true" {
		t.Fatalf("resolve %s: %v %v\n%s", tag, err, got, out)
	}
	f.version, f.short, f.distTag, f.channel = got["version"], got["short_version"], got["dist_tag"], got["channel"]
	const repo = "git+https://github.com/superbasedapp/observer.git"
	f.pkgs = npmPubPackages(f.version, f.short)
	f.sdkPkgs = npmPubSdkPackages(pubSdkVersion)
	for _, p := range append(append([]npmPubPackage{}, f.pkgs...), f.sdkPkgs...) {
		f.put(p.file, npmPubTarball(t, p.name, p.version, repo))
	}
	pyv := pubPyVersion(f.version)
	for _, plat := range pubWheelPlatforms {
		w := "superbased_observer-" + pyv + "-py3-none-" + plat + ".whl"
		f.wheels = append(f.wheels, w)
		f.put(w, []byte("wheel "+plat))
	}
	f.sdkPy = []string{"superbased_sdk-" + pubSdkVersion + "-py3-none-any.whl", "superbased_sdk-" + pubSdkVersion + ".tar.gz"}
	for _, p := range f.sdkPy {
		f.put(p, []byte("sdk "+p))
	}
	f.put("observer-"+tag+"-linux-x64.tar.gz", []byte("archive"))
	f.resum()
	return f
}

// put places one asset on the fake release, listed in SHA256SUMS at the next
// resum.
func (f *pubFixture) put(name string, b []byte) {
	f.t.Helper()
	f.sums[name] = b
	f.write(name, b)
}

// write places one asset on the fake release without listing it.
func (f *pubFixture) write(name string, b []byte) {
	f.t.Helper()
	if err := os.WriteFile(filepath.Join(f.assets, name), b, 0o644); err != nil { //nolint:gosec // test fixture
		f.t.Fatal(err)
	}
}

// drop removes assets from the fake release (and from SHA256SUMS at the
// next resum).
func (f *pubFixture) drop(names ...string) {
	f.t.Helper()
	for _, n := range names {
		delete(f.sums, n)
		if err := os.Remove(filepath.Join(f.assets, n)); err != nil {
			f.t.Fatal(err)
		}
	}
}

// resum rewrites SHA256SUMS over every put asset and signs it.
func (f *pubFixture) resum() {
	f.t.Helper()
	var names []string
	for n := range f.sums {
		names = append(names, n)
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		h := sha256.Sum256(f.sums[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(h[:]), n)
	}
	f.write("SHA256SUMS", []byte(b.String()))
	f.sign(nil)
}

// sign signs SHA256SUMS with a fresh key and publishes the key in the
// workspace's scripts/install.sh; with a non-nil other key the signature is
// made with it instead, so it does not verify.
func (f *pubFixture) sign(other ed25519.PrivateKey) {
	f.t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.t.Fatal(err)
	}
	signer := priv
	if other != nil {
		signer = other
	}
	sums, err := os.ReadFile(filepath.Join(f.assets, "SHA256SUMS"))
	if err != nil {
		f.t.Fatal(err)
	}
	f.write("SHA256SUMS.sig", ed25519.Sign(signer, sums))
	inst := "#!/bin/sh\nVENDOR_KEYS=\"" + base64.StdEncoding.EncodeToString(pub) + "\"\n"
	if err := os.WriteFile(filepath.Join(f.workspace, "scripts", "install.sh"), []byte(inst), 0o644); err != nil { //nolint:gosec // test fixture
		f.t.Fatal(err)
	}
}

// env is the environment the workflow wires for a step: the plan's outputs
// as a complete final (or pre-) release decides them.
func (f *pubFixture) env(extra map[string]string) map[string]string {
	sdk := "false"
	if f.channel == "stable" {
		sdk = "true"
	}
	env := map[string]string{
		"PATH":                f.bin + string(os.PathListSeparator) + os.Getenv("PATH"),
		"RUNNER_TEMP":         f.runner,
		"GITHUB_WORKSPACE":    f.workspace,
		"GITHUB_REPOSITORY":   "superbasedapp/observer",
		"GITHUB_STEP_SUMMARY": filepath.Join(f.runner, "summary.md"),
		"STUB_RELEASE_DIR":    f.release,
		"STUB_NPM_STATE":      f.state,
		"STUB_LOG":            f.logf,
		"STUB_NPM_REFUSE":     "",
		"TAG":                 f.tag,
		"VERSION":             f.version,
		"SHORT_VERSION":       f.short,
		"DIST_TAG":            f.distTag,
		"CHANNEL":             f.channel,
		"NPM":                 "true",
		"PYPI":                "true",
		"SDK":                 sdk,
		"SDK_VERSION":         pubSdkVersion,
		"INSTALL_SH":          "",
		"PUBLISH_VERIFIER":    "",
	}
	for k, v := range extra {
		env[k] = v
	}
	return env
}

// run runs the step with the given id the way the workflow wires its env.
func (f *pubFixture) run(id string, extra map[string]string) (string, map[string]string, error) {
	f.t.Helper()
	return npmPubRun(f.t, publishStep(f.t, f.doc, id).Run, f.runner, f.env(extra))
}

// mustRun runs a step and fails the test if it fails.
func (f *pubFixture) mustRun(id string, extra map[string]string) map[string]string {
	f.t.Helper()
	out, got, err := f.run(id, extra)
	if err != nil {
		f.t.Fatalf("step %s failed: %v\n%s", id, err, out)
	}
	return got
}

// calls returns the logged stub calls that start with prefix.
func (f *pubFixture) calls(prefix string) []string {
	f.t.Helper()
	raw, err := os.ReadFile(f.logf)
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	var out []string
	for _, l := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(l, prefix) {
			out = append(out, l)
		}
	}
	return out
}

// setRegistry records an existing version or dist-tag in the fake registry.
func (f *pubFixture) setRegistry(rel, value string) {
	f.t.Helper()
	p := filepath.Join(f.state, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		f.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(value), 0o644); err != nil { //nolint:gosec // test fixture
		f.t.Fatal(err)
	}
}

// summary is the job summary the steps wrote so far.
func (f *pubFixture) summary() string {
	f.t.Helper()
	raw, err := os.ReadFile(filepath.Join(f.runner, "summary.md"))
	if err != nil && !os.IsNotExist(err) {
		f.t.Fatal(err)
	}
	return string(raw)
}

// listDir is the sorted file names in dir.
func listDir(t *testing.T, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// TestPublishPlanStep runs the plan job's asset check against fake
// releases: a complete final release publishes everything, a pre-release
// leaves the SDK out, every incomplete or unexpected set fails the run
// before any registry is touched, and a release from before trusted
// publishing is skipped.
func TestPublishPlanStep(t *testing.T) {
	t.Run("a complete final release plans npm, PyPI and the SDK", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		got := f.mustRun("assets", nil)
		want := map[string]string{"npm": "true", "pypi": "true", "sdk": "true", "sdk_version": pubSdkVersion}
		for k, v := range want {
			if got[k] != v {
				t.Errorf("%s=%q, want %q", k, got[k], v)
			}
		}
		if n := len(f.calls("gh release download")); n != 0 {
			t.Errorf("plan downloaded %d times; it reads names only", n)
		}
	})

	t.Run("a pre-release plans npm and PyPI but no SDK", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0-rc.1")
		out, got, err := f.run("assets", nil)
		if err != nil {
			t.Fatalf("assets: %v\n%s", err, out)
		}
		if got["npm"] != "true" || got["pypi"] != "true" || got["sdk"] != "false" || got["sdk_version"] != "" {
			t.Errorf("rc plan: %v", got)
		}
		if !strings.Contains(out, "published only from a final release") {
			t.Errorf("the SDK's absence from a pre-release is not explained:\n%s", out)
		}
	})

	t.Run("a release from before trusted publishing is skipped", func(t *testing.T) {
		f := newPubFixture(t, "v1.42.1")
		for _, p := range append(append([]npmPubPackage{}, f.pkgs...), f.sdkPkgs...) {
			f.drop(p.file)
		}
		f.drop(append(append([]string{}, f.wheels...), f.sdkPy...)...)
		out, got, err := f.run("assets", nil)
		if err != nil || got["npm"] != "false" || got["pypi"] != "false" || got["sdk"] != "false" || !strings.Contains(out, "::warning::") {
			t.Fatalf("an old release: %v %v\n%s", err, got, out)
		}
	})

	fails := []struct {
		name, want string
		mutate     func(f *pubFixture)
	}{
		{"a missing observer tarball", "seven expected npm tarballs", func(f *pubFixture) { f.drop(f.pkgs[2].file) }},
		{"an unexpected tarball", "seven expected npm tarballs", func(f *pubFixture) { f.put("superbased-observer-freebsd-x64-1.43.0.tgz", []byte("x")) }},
		{"a missing wheel", "want 1", func(f *pubFixture) { f.drop(f.wheels[3]) }},
		{"a wheel at another version", "does not match", func(f *pubFixture) {
			f.drop(f.wheels[0])
			f.put("superbased_observer-1.42.0-py3-none-manylinux2014_x86_64.whl", []byte("old"))
		}},
		{"a foreign wheel", "neither", func(f *pubFixture) { f.put("requests-2.0.0-py3-none-any.whl", []byte("x")) }},
		{"an incomplete SDK", "SDK's four files", func(f *pubFixture) { f.drop(f.sdkPy[1]) }},
		{"SDK files at two versions", "SDK's four files", func(f *pubFixture) {
			f.drop(f.sdkPy[0])
			f.put("superbased_sdk-0.2.0-py3-none-any.whl", []byte("x"))
		}},
		{"an SDK tarball at a pre-release version", "x.y.z", func(f *pubFixture) {
			f.drop(f.sdkPkgs[0].file)
			f.put("superbased-sdk-0.1.0-rc.1.tgz", []byte("x"))
		}},
		{"no SHA256SUMS", "no SHA256SUMS", func(f *pubFixture) {
			if err := os.Remove(filepath.Join(f.assets, "SHA256SUMS")); err != nil {
				f.t.Fatal(err)
			}
		}},
		{"a draft", "still a draft", func(f *pubFixture) {
			if err := os.WriteFile(filepath.Join(f.release, "draft"), []byte("true\n"), 0o644); err != nil { //nolint:gosec // test fixture
				f.t.Fatal(err)
			}
		}},
	}
	for _, tc := range fails {
		t.Run(tc.name+" fails", func(t *testing.T) {
			f := newPubFixture(t, "v1.43.0")
			tc.mutate(f)
			out, got, err := f.run("assets", nil)
			if err == nil {
				t.Fatalf("passed: %v\n%s", got, out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("the refusal does not say %q:\n%s", tc.want, out)
			}
			if got["npm"] == "true" || got["pypi"] == "true" || got["sdk"] == "true" {
				t.Errorf("a refused plan still emitted outputs: %v", got)
			}
		})
	}

	t.Run("an rc's wheels must carry its pre-release", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0-rc.1")
		f.drop(f.wheels...)
		for _, plat := range pubWheelPlatforms {
			f.put("superbased_observer-1.43.0-py3-none-"+plat+".whl", []byte(plat))
		}
		if out, _, err := f.run("assets", nil); err == nil || !strings.Contains(out, "does not match") {
			t.Fatalf("final-version wheels on an rc passed: %v\n%s", err, out)
		}
	})
}

// TestPublishNpmJobEndToEnd runs the npm job's steps against stub gh and
// npm: the seven observer packages go out in dependency order under the
// channel's dist-tag with provenance, then stable, then the two SDK packages
// under latest; a re-run publishes nothing, and every refusal stops the run
// before the packages that depend on it.
func TestPublishNpmJobEndToEnd(t *testing.T) {
	t.Run("final release: seven in order, stable, then the SDKs; a re-run is a no-op", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		f.mustRun("verify", nil)
		f.mustRun("npm", nil)
		f.mustRun("stable", nil)
		f.mustRun("sdk", nil)
		pubs := f.calls("publish ")
		if len(pubs) != 9 {
			t.Fatalf("want 9 publishes, got %d:\n%s", len(pubs), strings.Join(pubs, "\n"))
		}
		for i, p := range append(append([]npmPubPackage{}, f.pkgs...), f.sdkPkgs...) {
			want := "publish " + p.name + "@" + p.version + " --access public --tag latest --provenance"
			if pubs[i] != want {
				t.Errorf("publish #%d is %q, want %q", i+1, pubs[i], want)
			}
		}
		tags := f.calls("dist-tag ")
		if len(tags) != 7 {
			t.Fatalf("want 7 stable dist-tags (the observer packages only), got:\n%s", strings.Join(tags, "\n"))
		}
		if tags[6] != "dist-tag superbased@3.43.0 stable" {
			t.Errorf("the short name's stable tag is %q", tags[6])
		}
		// Re-run: same bytes on the registry, nothing republished or retagged.
		f.mustRun("npm", nil)
		f.mustRun("stable", nil)
		f.mustRun("sdk", nil)
		if n := len(f.calls("publish ")); n != 9 {
			t.Errorf("a re-run published again (%d publishes)", n)
		}
		if n := len(f.calls("dist-tag ")); n != 7 {
			t.Errorf("a re-run moved stable again (%d dist-tag calls)", n)
		}
	})

	t.Run("pre-release: edge only, and no SDK in the plan", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0-rc.1")
		f.mustRun("fetch", nil)
		plan, err := os.ReadFile(filepath.Join(f.runner, "npm-release", "plan.tsv"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(plan), "\tsdk\n") || strings.Count(string(plan), "\n") != 7 {
			t.Errorf("an rc plan must hold the seven observer packages only:\n%s", plan)
		}
		f.mustRun("verify", nil)
		f.mustRun("npm", nil)
		pubs := f.calls("publish ")
		if len(pubs) != 7 {
			t.Fatalf("want 7 publishes, got %v", pubs)
		}
		for _, p := range pubs {
			if !strings.Contains(p, "--tag edge") {
				t.Errorf("an rc published as %q", p)
			}
		}
		if pubs[6] != "publish superbased@3.43.0-rc.1 --access public --tag edge --provenance" {
			t.Errorf("short-name publish is %q", pubs[6])
		}
	})

	t.Run("the fetch downloads only the planned tarballs", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		want := []string{"SHA256SUMS", "SHA256SUMS.sig", "plan.tsv"}
		for _, p := range append(append([]npmPubPackage{}, f.pkgs...), f.sdkPkgs...) {
			want = append(want, p.file)
		}
		sort.Strings(want)
		if got := listDir(t, filepath.Join(f.runner, "npm-release")); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("fetched %v, want %v", got, want)
		}
	})

	t.Run("a tampered tarball fails verification", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.write(f.pkgs[5].file, npmPubTarball(t, f.pkgs[5].name, f.pkgs[5].version, "git+https://github.com/superbasedapp/observer.git#x"))
		f.mustRun("fetch", nil)
		if out, _, err := f.run("verify", nil); err == nil || !strings.Contains(out, "checksum MISMATCH") {
			t.Fatalf("a tampered tarball passed: %v\n%s", err, out)
		}
	})

	t.Run("a signature by another key fails verification", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		_, other, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		f.sign(other)
		f.mustRun("fetch", nil)
		if out, _, err := f.run("verify", nil); err == nil || !strings.Contains(out, "does not verify") {
			t.Fatalf("a foreign signature passed: %v\n%s", err, out)
		}
	})

	t.Run("an unsigned release is verified by checksum with a warning", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		if err := os.Remove(filepath.Join(f.assets, "SHA256SUMS.sig")); err != nil {
			t.Fatal(err)
		}
		f.mustRun("fetch", nil)
		out, _, err := f.run("verify", nil)
		if err != nil || !strings.Contains(out, "::warning::") {
			t.Fatalf("an unsigned release: %v\n%s", err, out)
		}
	})

	t.Run("a package naming another repository fails verification", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		p := f.sdkPkgs[1]
		f.put(p.file, npmPubTarball(t, p.name, p.version, "git+https://github.com/someone/fork.git"))
		f.resum()
		f.mustRun("fetch", nil)
		if out, _, err := f.run("verify", nil); err == nil || !strings.Contains(out, "repository.url") {
			t.Fatalf("a foreign repository.url passed: %v\n%s", err, out)
		}
	})

	t.Run("different observer bytes already on npm stop the run before anything is published", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		f.mustRun("verify", nil)
		f.setRegistry("pub/@superbased__observer-linux-x64@1.43.0", "sha512-somethingelse")
		if out, _, err := f.run("npm", nil); err == nil || !strings.Contains(out, "DIFFERENT bytes") {
			t.Fatalf("a conflicting version was not refused: %v\n%s", err, out)
		}
		if n := len(f.calls("publish ")); n != 0 {
			t.Errorf("%d packages were published after the conflict", n)
		}
	})

	t.Run("different SDK bytes already on npm are skipped with a warning", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		f.mustRun("verify", nil)
		f.setRegistry("pub/@superbased__sdk@"+pubSdkVersion, "sha512-somethingelse")
		out, _, err := f.run("sdk", nil)
		if err != nil || !strings.Contains(out, "::warning::") || !strings.Contains(out, "raise the SDK version") {
			t.Fatalf("an SDK version with other bytes: %v\n%s", err, out)
		}
		pubs := f.calls("publish ")
		if len(pubs) != 1 || !strings.HasPrefix(pubs[0], "publish @superbased/feedback-widget@") {
			t.Errorf("want only the widget published, got %v", pubs)
		}
		if !strings.Contains(f.summary(), "NOT published") {
			t.Errorf("the summary does not say the SDK was not published:\n%s", f.summary())
		}
	})

	t.Run("the SDK moves latest off the placeholder", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		f.mustRun("verify", nil)
		f.setRegistry("pub/@superbased__sdk@0.0.1-placeholder.0", "sha512-placeholder")
		f.setRegistry("tags/@superbased__sdk.latest", "0.0.1-placeholder.0")
		f.setRegistry("tags/@superbased__sdk.placeholder", "0.0.1-placeholder.0")
		f.mustRun("sdk", nil)
		if pubs := f.calls("publish @superbased/sdk@"); len(pubs) != 1 || !strings.Contains(pubs[0], "--tag latest") {
			t.Errorf("the SDK did not publish under latest over the placeholder: %v", pubs)
		}
	})

	t.Run("a refused publish stops before the packages that depend on it", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		f.mustRun("verify", nil)
		if out, _, err := f.run("npm", map[string]string{"STUB_NPM_REFUSE": "@superbased/observer-darwin-x64"}); err == nil {
			t.Fatalf("a refused publish passed:\n%s", out)
		}
		if n := len(f.calls("publish ")); n != 2 {
			t.Errorf("want the two packages before the refusal published, got %d", n)
		}
	})

	t.Run("the failure fallback lists the hand publish in dependency order", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fallback", nil)
		var pubs, want []string
		for _, l := range strings.Split(f.summary(), "\n") {
			if strings.HasPrefix(l, "npm publish ") {
				pubs = append(pubs, l)
			}
		}
		for _, p := range append(append([]npmPubPackage{}, f.pkgs...), f.sdkPkgs...) {
			want = append(want, "npm publish "+p.file+" --access public --tag latest --otp <code>")
		}
		if strings.Join(pubs, "\n") != strings.Join(want, "\n") {
			t.Errorf("the fallback lists:\n%s\nwant:\n%s", strings.Join(pubs, "\n"), strings.Join(want, "\n"))
		}
		if !strings.Contains(f.summary(), "npm dist-tag add superbased@3.43.0 stable --otp <code>") {
			t.Errorf("the fallback does not move stable on the short name:\n%s", f.summary())
		}
	})

	t.Run("an older final release never moves latest or stable back", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("fetch", nil)
		f.mustRun("verify", nil)
		f.setRegistry("tags/@superbased__observer-linux-x64.latest", "1.44.0")
		if out, _, err := f.run("npm", nil); err == nil || !strings.Contains(out, "would move it back") {
			t.Fatalf("publishing under latest below the current latest was not refused: %v\n%s", err, out)
		}
		g := newPubFixture(t, "v1.43.0")
		g.mustRun("fetch", nil)
		g.mustRun("verify", nil)
		g.mustRun("npm", nil)
		g.setRegistry("tags/superbased.stable", "3.44.0")
		g.mustRun("stable", nil)
		for _, c := range g.calls("dist-tag ") {
			if strings.HasPrefix(c, "dist-tag superbased@") {
				t.Errorf("stable moved back: %s", c)
			}
		}
	})
}

// TestPublishPypiJobSteps runs the fetch, verify and fallback steps of the
// two PyPI jobs: each project's files land in their own upload directory
// (the action uploads a whole directory) and nothing else does, and a
// tampered file stops the job before the upload.
func TestPublishPypiJobSteps(t *testing.T) {
	for _, tag := range []string{"v1.43.0", "v1.43.0-rc.1"} {
		t.Run("the wheels of "+tag+", verified", func(t *testing.T) {
			f := newPubFixture(t, tag)
			f.mustRun("pypi_fetch", nil)
			dist := filepath.Join(f.workspace, "publish-dist")
			want := append([]string{}, f.wheels...)
			sort.Strings(want)
			if got := listDir(t, filepath.Join(dist, "observer")); strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("observer upload dir holds %v, want %v", got, want)
			}
			if _, err := os.Stat(filepath.Join(dist, "sdk")); !os.IsNotExist(err) {
				t.Errorf("the pypi job staged an sdk directory (%v)", err)
			}
			f.mustRun("pypi_verify", nil)
		})
	}

	t.Run("the SDK's sdist and wheel, verified", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("pypi_sdk_fetch", nil)
		dist := filepath.Join(f.workspace, "publish-dist")
		want := append([]string{}, f.sdkPy...)
		sort.Strings(want)
		if got := listDir(t, filepath.Join(dist, "sdk")); strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("sdk upload dir holds %v, want %v", got, want)
		}
		if _, err := os.Stat(filepath.Join(dist, "observer")); !os.IsNotExist(err) {
			t.Errorf("the pypi_sdk job staged an observer directory (%v)", err)
		}
		f.mustRun("pypi_sdk_verify", nil)
	})

	t.Run("a tampered wheel fails verification", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.write(f.wheels[1], []byte("not the wheel"))
		f.mustRun("pypi_fetch", nil)
		if out, _, err := f.run("pypi_verify", nil); err == nil || !strings.Contains(out, "checksum MISMATCH") {
			t.Fatalf("a tampered wheel passed: %v\n%s", err, out)
		}
	})

	t.Run("a tampered SDK sdist fails verification", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.write(f.sdkPy[1], []byte("not the sdist"))
		f.mustRun("pypi_sdk_fetch", nil)
		if out, _, err := f.run("pypi_sdk_verify", nil); err == nil || !strings.Contains(out, "checksum MISMATCH") {
			t.Fatalf("a tampered sdist passed: %v\n%s", err, out)
		}
	})

	// The stub gh refuses a pattern that matches nothing (its cp fails);
	// either that or the step's own count check stops the job.
	t.Run("a missing SDK file fails the fetch", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.drop(f.sdkPy[0])
		f.resum()
		if out, _, err := f.run("pypi_sdk_fetch", nil); err == nil {
			t.Fatalf("one SDK file passed the fetch:\n%s", out)
		}
	})

	t.Run("each fallback names twine for its own project", func(t *testing.T) {
		f := newPubFixture(t, "v1.43.0")
		f.mustRun("pypi_fallback", nil)
		s := f.summary()
		for _, want := range []string{"twine upload --skip-existing superbased_observer-*.whl", "gh workflow run publish.yml"} {
			if !strings.Contains(s, want) {
				t.Errorf("the superbased-observer fallback lacks %q:\n%s", want, s)
			}
		}
		if strings.Contains(s, "superbased_sdk") {
			t.Errorf("the superbased-observer fallback names the SDK:\n%s", s)
		}
		g := newPubFixture(t, "v1.43.0")
		g.mustRun("pypi_sdk_fallback", nil)
		s = g.summary()
		for _, want := range []string{"twine upload --skip-existing superbased_sdk-0.1.0-py3-none-any.whl superbased_sdk-0.1.0.tar.gz", "gh workflow run publish.yml"} {
			if !strings.Contains(s, want) {
				t.Errorf("the superbased-sdk fallback lacks %q:\n%s", want, s)
			}
		}
		if strings.Contains(s, "superbased_observer") {
			t.Errorf("the superbased-sdk fallback names the observer wheels:\n%s", s)
		}
	})
}

// TestPublishVerifyVerifiers runs scripts/publish-verify.sh with each
// Ed25519 verifier it can pick: each accepts the vendor signature, refuses
// one by another key, and refuses a file SHA256SUMS does not list.
func TestPublishVerifyVerifiers(t *testing.T) {
	npmPubHaveTools(t)
	script := filepath.Join(repoRoot(t), "scripts", "publish-verify.sh")
	for _, v := range []string{"openssl", "node"} {
		t.Run(v, func(t *testing.T) {
			if _, err := exec.LookPath(v); err != nil {
				t.Skipf("%s is not available", v)
			}
			dir := t.TempDir()
			body := []byte("the package")
			if err := os.WriteFile(filepath.Join(dir, "pkg.tgz"), body, 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			h := sha256.Sum256(body)
			sums := []byte(hex.EncodeToString(h[:]) + "  pkg.tgz\n")
			if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"), sums, 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			pub, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			_, other, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			inst := filepath.Join(dir, "install.sh")
			if err := os.WriteFile(inst, []byte("VENDOR_KEYS=\""+base64.StdEncoding.EncodeToString(pub)+"\"\n"), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			run := func(signer ed25519.PrivateKey, files ...string) (string, error) {
				if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS.sig"), ed25519.Sign(signer, sums), 0o644); err != nil { //nolint:gosec // test fixture
					t.Fatal(err)
				}
				cmd := exec.Command("bash", append([]string{script, dir}, files...)...)
				cmd.Env = append(os.Environ(), "INSTALL_SH="+inst, "PUBLISH_VERIFIER="+v)
				out, err := cmd.CombinedOutput()
				return string(out), err
			}
			out, err := run(priv, "pkg.tgz")
			if err != nil && strings.Contains(out, "no working Ed25519 verifier") {
				// openssl before 3.0 has no `pkeyutl -rawin`; the script then
				// falls through to node, which the other subtest covers.
				t.Skipf("%s here cannot verify Ed25519 (it failed the RFC 8032 vector)", v)
			}
			if err != nil || !strings.Contains(out, "vendor signature ok ("+v+")") {
				t.Fatalf("a good signature: %v\n%s", err, out)
			}
			if out, err := run(other, "pkg.tgz"); err == nil || !strings.Contains(out, "does not verify") {
				t.Fatalf("a foreign signature passed: %v\n%s", err, out)
			}
			if err := os.WriteFile(filepath.Join(dir, "extra.whl"), []byte("x"), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			if out, err := run(priv, "pkg.tgz", "extra.whl"); err == nil || !strings.Contains(out, "not listed in SHA256SUMS") {
				t.Fatalf("an unlisted file passed: %v\n%s", err, out)
			}
		})
	}
}

// TestNpmPackCheck runs scripts/npm-pack-check.mjs, the release's check of
// the seven packed tarballs, on a good set and on the 3.42.1 shape (the
// short name packed without its bin script).
func TestNpmPackCheck(t *testing.T) {
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is not available")
	}
	root := repoRoot(t)
	script := filepath.Join(root, "scripts", "npm-pack-check.mjs")
	build := func(t *testing.T, dropBin bool) (string, error) {
		t.Helper()
		dir := t.TempDir()
		npmDir := filepath.Join(dir, "npm")
		tarballs := filepath.Join(dir, "npm-tarballs")
		packJSON := filepath.Join(dir, "runner")
		for _, d := range []string{tarballs, packJSON} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range npmPubPackages("1.43.0", "3.43.0") {
			dirName := strings.TrimPrefix(p.name, "@superbased/")
			bins := map[string]string{}
			var files []map[string]any
			switch {
			case p.name == "superbased":
				bins = map[string]string{"superbased": "bin/superbased.js", "observer": "bin/superbased.js"}
				if !dropBin {
					files = append(files, map[string]any{"path": "bin/superbased.js"})
				}
			case p.name == "@superbased/observer":
				bins = map[string]string{"observer": "bin/observer.js"}
				files = append(files, map[string]any{"path": "bin/observer.js"})
			case strings.HasSuffix(p.name, "win32-x64"):
				files = append(files, map[string]any{"path": "bin/observer.exe"})
			default:
				files = append(files, map[string]any{"path": "bin/observer"})
			}
			files = append(files, map[string]any{"path": "package.json"})
			if err := os.MkdirAll(filepath.Join(npmDir, dirName), 0o755); err != nil {
				t.Fatal(err)
			}
			manifest, _ := json.Marshal(map[string]any{"name": p.name, "version": p.version, "bin": bins})
			if err := os.WriteFile(filepath.Join(npmDir, dirName, "package.json"), manifest, 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			pack, _ := json.Marshal([]map[string]any{{"name": p.name, "version": p.version, "filename": p.file, "files": files, "entryCount": len(files), "integrity": "sha512-x"}})
			if err := os.WriteFile(filepath.Join(packJSON, "pack-"+dirName+".json"), pack, 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(tarballs, p.file), []byte("tgz"), 0o644); err != nil { //nolint:gosec // test fixture
				t.Fatal(err)
			}
		}
		cmd := exec.Command("node", script)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "VERSION=1.43.0", "SHORT_VERSION=3.43.0", "RUNNER_TEMP="+packJSON)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}
	if out, err := build(t, false); err != nil {
		t.Fatalf("a good set failed: %v\n%s", err, out)
	}
	out, err := build(t, true)
	if err == nil || !strings.Contains(out, "lacks bin/superbased.js") {
		t.Fatalf("superbased packed without bin/superbased.js passed: %v\n%s", err, out)
	}
}
