package actionlint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

// fixture is a workflow with actionlint findings: an undefined context in
// an expression and a job needing a job that does not exist. Its run step
// is shell, the input shellcheck would read if it ran.
const fixture = `on: push
jobs:
  build:
    runs-on: ubuntu-latest
    needs: [does-not-exist]
    steps:
      - run: echo ${{ nope.value }} $UNQUOTED
`

// TestWorkflowFixtureFindings: the fixture's findings are flag-only CI
// configuration findings with templated messages and actionlint rule ids.
func TestWorkflowFixtureFindings(t *testing.T) {
	res := Run(Input{ProjectRootHash: "h", Scope: policy.FindingScopeManual, Files: []File{{Rel: ".github/workflows/ci.yml", Content: []byte(fixture)}}})
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) < 2 {
		t.Fatalf("got %+v", res)
	}
	kinds := map[string]bool{}
	for _, f := range res.Findings {
		kinds[f.Rule.ID] = true
		if f.Category != policy.FindingCIConfig || f.Severity != policy.FindingSeverityLow || f.Confidence != policy.FindingConfidenceMedium || f.Baseline != policy.FindingBaselineUnknown {
			t.Errorf("not flag-only ci_config: %+v", f)
		}
		if f.Rule.Pack != RulePack || f.Location.RelPath != ".github/workflows/ci.yml" || f.Location.StartLine == 0 {
			t.Errorf("identity: %+v", f)
		}
		if strings.Contains(f.Message, "nope") || !strings.HasPrefix(f.Message, "Reported by actionlint rule ") {
			t.Errorf("engine text in message: %q", f.Message)
		}
	}
	for _, want := range []string{"actionlint/expression", "actionlint/job-needs"} {
		if !kinds[want] {
			t.Errorf("missing %s in %v", want, kinds)
		}
	}
}

// TestNoProcessStarted puts an executable shellcheck and pyflakes first on
// PATH that write a marker when run; linting a workflow with shell and
// Python steps must never start them.
func TestNoProcessStarted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fake executables are shell scripts")
	}
	dir := t.TempDir()
	marker := filepath.Join(dir, "ran")
	for _, name := range []string{"shellcheck", "pyflakes"} {
		script := "#!/bin/sh\necho " + name + " >> '" + marker + "'\n"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o700); err != nil { //nolint:gosec // G306: a test executable
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	wf := fixture + "      - shell: python\n        run: import os\n"
	_ = Run(Input{ProjectRootHash: "h", Files: []File{{Rel: ".github/workflows/ci.yml", Content: []byte(wf)}}})
	if _, err := os.Stat(marker); err == nil {
		b, _ := os.ReadFile(marker)
		t.Fatalf("an external linter ran: %s", b)
	}
}

// TestNoRepositoryConfigRead: a repository-local .github/actionlint.yaml
// that would ignore every error is not read (the lint path never exists).
func TestNoRepositoryConfigRead(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".github", "actionlint.yaml"), []byte("paths:\n  .github/workflows/**/*.yml:\n    ignore: ['.*']\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(dir)
	res := Run(Input{ProjectRootHash: "h", Files: []File{{Rel: ".github/workflows/ci.yml", Content: []byte(fixture)}}})
	if len(res.Findings) == 0 {
		t.Fatal("the repository config silenced the run")
	}
}

// TestCleanNeedsSelfTestAndWholeRun: a clean workflow is clean; a skipped
// file makes the run unknown; no workflow at all is not scanned.
func TestCleanNeedsSelfTestAndWholeRun(t *testing.T) {
	clean := "on: push\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo hi\n"
	if !SelfTest() {
		t.Fatal("self-test failed")
	}
	res := Run(Input{ProjectRootHash: "h", Files: []File{{Rel: ".github/workflows/ok.yaml", Content: []byte(clean)}}})
	if res.Coverage.Outcome != secscan.OutcomeClean || res.Coverage.FilesScanned != 1 {
		t.Errorf("clean: %+v", res.Coverage)
	}
	res = Run(Input{ProjectRootHash: "h", Files: []File{{Rel: ".github/workflows/ok.yaml", Content: []byte(clean)}}, Skipped: []secscan.Skip{{Path: ".github/workflows/big.yml", Reason: "too_large"}}})
	if res.Coverage.Outcome != secscan.OutcomeUnknown {
		t.Errorf("skipped: %+v", res.Coverage)
	}
	if res := Run(Input{ProjectRootHash: "h"}); res.Coverage.Outcome != secscan.OutcomeNotScanned {
		t.Errorf("none: %+v", res.Coverage)
	}
}

// TestBrokenYAML: a file that is not YAML yields a syntax-check finding
// with its line, never a crash.
func TestBrokenYAML(t *testing.T) {
	res := Run(Input{ProjectRootHash: "h", Files: []File{{Rel: ".github/workflows/x.yml", Content: []byte("on: push\njobs:\n  a: [\n")}}})
	if len(res.Findings) == 0 || res.Findings[0].Rule.ID != "actionlint/syntax-check" {
		t.Fatalf("got %+v", res)
	}
}

func TestIsWorkflowPath(t *testing.T) {
	t.Parallel()
	for p, want := range map[string]bool{
		".github/workflows/ci.yml": true, ".github/workflows/ci.YAML": true, ".github/workflows/.yml": false,
		".github/workflows/sub/ci.yml": false, ".github/ci.yml": false, "ci.yml": false, ".github/workflows/ci.json": false,
	} {
		if got := IsWorkflowPath(p); got != want {
			t.Errorf("%s: %v", p, got)
		}
	}
}

// thirdPartyDir is the in-module copy of actionlint (audit finding 1: no
// replace directive, no nested go.mod).
const thirdPartyDir = "../../thirdparty/actionlint"

// patchedFiles are the only files of the copy that differ from the release.
var patchedFiles = []string{"action_metadata.go", "parse.go"}

// TestThirdPartyManifest: the copy is exactly the release UPSTREAM names
// (audit finding 8). The version is PinnedVersion; every file in the
// directory has a "file" line; an unpatched file hashes to the upstream
// sha256; only patchedFiles are patched, each hashing to its recorded patched
// sha256 and carrying its diff; there is no nested go.mod; and the module's
// go.mod has no replace directive.
func TestThirdPartyManifest(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(thirdPartyDir, "UPSTREAM"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	head, diff, ok := strings.Cut(text, "# The patch, as `diff -u upstream patched`:")
	if !ok {
		t.Fatal("UPSTREAM has no patch section")
	}
	type entry struct{ upstream, state, patched string }
	files := map[string]entry{}
	var version, module string
	for _, line := range strings.Split(head, "\n") {
		f := strings.Fields(line)
		switch {
		case len(f) == 2 && f[0] == "version":
			version = f[1]
		case len(f) == 2 && f[0] == "module":
			module = f[1]
		case len(f) >= 4 && f[0] == "file":
			e := entry{upstream: f[2], state: f[3]}
			if len(f) == 5 {
				e.patched = f[4]
			}
			files[f[1]] = e
		}
	}
	if module != "github.com/rhysd/actionlint" || version != PinnedVersion {
		t.Fatalf("UPSTREAM names %s %s, pinned %s", module, version, PinnedVersion)
	}
	ents, err := os.ReadDir(thirdPartyDir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	var patched []string
	for _, de := range ents {
		name := de.Name()
		if name == "UPSTREAM" {
			continue
		}
		if name == "go.mod" || de.IsDir() {
			t.Errorf("%s: the copy must be one plain package of this module", name)
			continue
		}
		e, ok := files[name]
		if !ok {
			t.Errorf("%s: not in UPSTREAM", name)
			continue
		}
		seen++
		b, err := os.ReadFile(filepath.Join(thirdPartyDir, name))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(b)
		got := hex.EncodeToString(sum[:])
		switch e.state {
		case "same":
			if got != e.upstream {
				t.Errorf("%s: sha256 %s, upstream %s (unrecorded change)", name, got, e.upstream)
			}
		case "patched":
			patched = append(patched, name)
			if got != e.patched || e.patched == e.upstream {
				t.Errorf("%s: sha256 %s, recorded patch %s", name, got, e.patched)
			}
			if !strings.Contains(diff, "+++ patched/"+name) {
				t.Errorf("%s: no diff in UPSTREAM", name)
			}
		default:
			t.Errorf("%s: state %q", name, e.state)
		}
	}
	if seen != len(files) {
		t.Errorf("UPSTREAM lists %d files, the directory holds %d", len(files), seen)
	}
	sort.Strings(patched)
	if strings.Join(patched, ",") != strings.Join(patchedFiles, ",") {
		t.Errorf("patched files %v, want %v", patched, patchedFiles)
	}
	gomod, err := os.ReadFile("../../../go.mod")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(gomod), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "replace") || strings.Contains(line, "rhysd/actionlint") {
			t.Errorf("go.mod: %q (audit finding 1: no replace, no external actionlint)", line)
		}
	}
}

// TestLintPathNamesNoDirectory: every rel, including Windows absolute and
// device paths, is linted as actionlint's stdin sentinel, which names no
// directory on any OS (audit finding 7).
func TestLintPathNamesNoDirectory(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{
		".github/workflows/ci.yml",
		`.github\workflows\ci.yml`,
		`C:\__observer_actionlint_virtual__\.github\workflows\ci.yml`,
		`\\?\C:\__observer__\.github\workflows\ci.yml`,
		`\\server\share\.github\workflows\ci.yml`,
		"/__observer_actionlint_virtual__/.github/workflows/ci.yml",
		"",
	} {
		got := lintPath(rel)
		if got != "<stdin>" || filepath.IsAbs(got) || filepath.VolumeName(got) != "" || strings.ContainsAny(got, `/\`) {
			t.Errorf("%q: linted as %q", rel, got)
		}
	}
}

// TestNoPlantedRootRead: a working directory that looks like a planted
// project root (a .git, a .github/actionlint.yaml that ignores every error,
// the workflow itself, and on unix a file named like the stdin sentinel) is
// never read: the findings still come back.
func TestNoPlantedRootRead(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{".git", filepath.Join(".github", "workflows")} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	ignore := []byte("paths:\n  '**/*':\n    ignore: ['.*']\n  .github/workflows/**/*.yml:\n    ignore: ['.*']\n")
	for name, body := range map[string][]byte{
		filepath.Join(".github", "actionlint.yaml"):     ignore,
		filepath.Join(".github", "actionlint.yml"):      ignore,
		filepath.Join(".github", "workflows", "ci.yml"): []byte(fixture),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if runtime.GOOS != "windows" {
		if err := os.WriteFile(filepath.Join(dir, "<stdin>"), []byte(fixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Chdir(dir)
	res := Run(Input{ProjectRootHash: "h", Files: []File{{Rel: ".github/workflows/ci.yml", Content: []byte(fixture)}}})
	if len(res.Findings) < 2 {
		t.Fatalf("a planted root's config silenced the run: %+v", res.Coverage)
	}
}

func TestDriverRowRegisters(t *testing.T) {
	t.Parallel()
	d := Driver{RootHash: func(string) string { return "h" }, Read: func(context.Context, string) ([]File, []secscan.Skip, error) {
		return []File{{Rel: ".github/workflows/ci.yml", Content: []byte(fixture)}}, nil, nil
	}}
	if _, err := secscan.NewRegistry(d); err != nil {
		t.Fatal(err)
	}
	res, err := d.Scan(context.Background(), secscan.Target{ProjectRoot: "/p"})
	if err != nil || len(res.Findings) == 0 {
		t.Fatalf("%+v %v", res, err)
	}
}
