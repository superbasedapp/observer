//go:build linux && !sbo_omit_security && !sbo_omit_security_scan_opengrep

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	extrunhost "github.com/marmutapp/superbased-observer/internal/extrun/host"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secengine"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secrulepack"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/opengrep"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/toolresolve"
)

// security_opengrep_live_test.go drives the Opengrep driver through the
// real host runner and a real git, with a POSIX shell stand-in for
// Opengrep (the SEC-G1 merge fixes for audit findings 2, 3 and 6). The
// stand-in prints `opengrep --version`, writes the JSON copy and prints
// SARIF with the canary result; when it is handed --baseline-commit it
// checks the base out with git worktree add, as Opengrep does (JSP-8).

// fakeOpengrep writes the stand-in as dir/opengrep and returns its path and
// its call log. findings are (rule, path) results; scanned are the project
// paths the JSON copy lists; baseWT is where a --baseline-commit run checks
// the base out.
func fakeOpengrep(t *testing.T, dir string, findings [][2]string, scanned []string, baseWT string) (string, string) {
	t.Helper()
	log := filepath.Join(dir, "calls.log")
	var sc, res strings.Builder
	for _, s := range scanned {
		fmt.Fprintf(&sc, "%q,", s)
	}
	for i, f := range findings {
		fmt.Fprintf(&res, `{"ruleId":%q,"fingerprints":{"matchBasedId/v1":"fp%d"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%q},"region":{"startLine":2,"endLine":2}}}]},`, f[0], i, f[1])
	}
	script := "#!/bin/sh\n" +
		"printf '%s\\n' \"$PWD $*\" >> '" + log + "'\n" +
		"for a in \"$@\"; do if [ \"$a\" = \"--version\" ]; then echo 1.30.1; exit 0; fi; done\n" +
		"out=''; base=''; prev=''; last=''\n" +
		"for a in \"$@\"; do\n" +
		"  case \"$a\" in --json-output=*) out=\"${a#--json-output=}\";; esac\n" +
		"  if [ \"$prev\" = \"--baseline-commit\" ]; then base=\"$a\"; fi\n" +
		"  prev=\"$a\"; last=\"$a\"\n" +
		"done\n" +
		"if [ -n \"$base\" ]; then git worktree add --detach '" + baseWT + "' \"$base\" >/dev/null 2>&1; fi\n" +
		"printf '%s' '{\"paths\":{\"scanned\":[" + sc.String() + "\"'\"$last\"'\"]},\"errors\":[]}' > \"$out\"\n" +
		"printf '%s' '{\"version\":\"2.1.0\",\"runs\":[{\"tool\":{\"driver\":{\"name\":\"Opengrep OSS\",\"rules\":[" +
		"{\"id\":\"python.sql-string-concat\",\"defaultConfiguration\":{\"level\":\"error\"}}," +
		"{\"id\":\"observer-code.canary\",\"defaultConfiguration\":{\"level\":\"note\"}}]}},\"results\":[" + res.String() +
		"{\"ruleId\":\"observer-code.canary\",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"'\"$last\"'\"},\"region\":{\"startLine\":5,\"endLine\":5}}}]}]}]}'\n"
	bin := filepath.Join(dir, "opengrep")
	if err := os.WriteFile(bin, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

// liveDriver is the driver over the real host runner, resolving Opengrep to
// bin and git to the host's git, on an individual node (the stand-in's
// digest is not pinned, so its runs are labelled unverified).
func liveDriver(t *testing.T, bin string) *opengrep.Driver {
	t.Helper()
	gitPath, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not installed")
	}
	if real, err := filepath.EvalSymlinks(gitPath); err == nil {
		gitPath = real
	}
	r := extrunhost.NewRunner(extrunhost.Options{})
	r.Resolve = func(s integration.BinaryResolveSpec) toolresolve.Resolution {
		switch {
		case slices.Contains(s.Names.Unix, "opengrep"):
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: bin}
		case slices.Contains(s.Names.Unix, "git"):
			return toolresolve.Resolution{Verdict: toolresolve.VerdictOK, Bin: gitPath}
		}
		return toolresolve.Resolution{Verdict: toolresolve.VerdictNotFound}
	}
	pack, err := secrulepack.Floor()
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	packDir, err := materializePack(root, pack)
	if err != nil {
		t.Fatal(err)
	}
	cache := filepath.Join(root, "engine")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	return opengrep.New(opengrep.Env{
		Runner: r, Pack: pack, PackDir: packDir, CacheDir: cache, OutDir: t.TempDir(),
		State: codeStateStore{path: filepath.Join(t.TempDir(), codeStateFile)}, ListTree: listEngineTree,
		ReadFile: readCappedFile, GOOS: "linux", GOARCH: "amd64",
	})
}

func readLog(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func evalDir(t *testing.T, p string) string {
	t.Helper()
	if err := os.MkdirAll(p, 0o700); err != nil {
		t.Fatal(err)
	}
	r, err := filepath.EvalSymlinks(p)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// TestOpengrepLinkedWorktreeLive (audit finding 2): a scan from a linked
// worktree reads the worktree's files, lands its findings on the main
// project and closes nothing of main's; a clean complete run of main itself
// still closes a gone finding.
func TestOpengrepLinkedWorktreeLive(t *testing.T) {
	ctx := context.Background()
	main := evalDir(t, filepath.Join(t.TempDir(), "main"))
	gitInitMain(t, main)
	if err := os.WriteFile(filepath.Join(main, "a.py"), []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitRun(t, main, "add", "a.py")
	gitRun(t, main, "commit", "-q", "-m", "first")
	wtParent := evalDir(t, t.TempDir())
	wt := filepath.Join(wtParent, "wt")
	gitRun(t, main, "worktree", "add", "-q", wt)
	if err := os.WriteFile(filepath.Join(wt, "b.py"), []byte("q = 'select ' + x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	st, _ := openTestStore(t)
	if _, err := st.UpsertProject(ctx, main, ""); err != nil {
		t.Fatal(err)
	}
	root, checkout, err := knownProjectRoot(ctx, st, wt)
	if err != nil || root != main || checkout != wt {
		t.Fatalf("roots %q %q %v", root, checkout, err)
	}
	hash := secposture.ProjectRootHash(main)
	seed := secfinding.Normalize(secfinding.Finding{
		LocalKey: "main-a", Rule: secfinding.Rule{ID: "python.sql-string-concat", Pack: secrulepack.PackID}, Engine: secfinding.Engine{Driver: opengrep.DriverID},
		Category: policy.FindingCodeVuln, Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceMedium,
		Project: secfinding.Project{RootHash: hash}, Scope: policy.FindingScopeManual, Location: secfinding.Location{RelPath: "a.py", StartLine: 1},
	})
	if _, _, err := st.UpsertSecFinding(ctx, seed, time.Now()); err != nil {
		t.Fatal(err)
	}
	status := func() map[string]secfinding.Status {
		list, err := st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: hash, Limit: 100})
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]secfinding.Status{}
		for _, f := range list {
			out[f.Location.RelPath] = f.Status
		}
		return out
	}

	bin, log := fakeOpengrep(t, t.TempDir(), [][2]string{{"python.sql-string-concat", "b.py"}}, []string{"a.py", "b.py"}, "")
	tgt := secscan.Target{ProjectRoot: root, CheckoutRoot: checkout, Scope: policy.FindingScopeManual}
	res, scanned, err := liveDriver(t, bin).ScanFiles(ctx, tgt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || len(res.Findings) != 1 || len(scanned.Files) != 0 {
		t.Fatalf("worktree run: %+v, %d findings, closable %v", res.Coverage, len(res.Findings), scanned.Files)
	}
	for _, line := range strings.Split(strings.TrimSpace(readLog(t, log)), "\n") {
		if !strings.HasPrefix(line, wt+" ") {
			t.Errorf("the stand-in ran in %q, want the worktree %s", line, wt)
		}
	}
	if _, err := recordCodeScan(ctx, st, tgt, res, scanned, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if s := status(); s["b.py"] != policy.FindingStatusOpen || s["a.py"] != policy.FindingStatusOpen {
		t.Fatalf("after the worktree run: %v (b.py lands on the main project, a.py of main stays open)", s)
	}

	// A clean complete run of main itself closes main's gone finding.
	bin2, _ := fakeOpengrep(t, t.TempDir(), nil, []string{"a.py"}, "")
	main2 := secscan.Target{ProjectRoot: main, Scope: policy.FindingScopeManual}
	res, scanned, err = liveDriver(t, bin2).ScanFiles(ctx, main2)
	if err != nil || res.Coverage.Outcome != secscan.OutcomeClean || !slices.Equal(scanned.Files, []string{"a.py"}) {
		t.Fatalf("main run: %+v closable %v %v", res.Coverage, scanned.Files, err)
	}
	if _, err := recordCodeScan(ctx, st, main2, res, scanned, time.Now(), nil); err != nil {
		t.Fatal(err)
	}
	if s := status(); s["a.py"] == policy.FindingStatusOpen || s["b.py"] != policy.FindingStatusOpen {
		t.Fatalf("after the clean main run: %v (a.py closed, b.py was not read)", s)
	}
}

// TestOpengrepDiffRefusedOnFilterDriverLive (audit finding 3): in a
// repository whose own config sets a filter driver that writes a marker
// file, a diff run is refused before anything checks the base out (no
// marker, the stand-in never starts); a full run, which never checks
// anything out, runs and leaves no marker. Without the filter, the same
// diff run gets past the check.
func TestOpengrepDiffRefusedOnFilterDriverLive(t *testing.T) {
	ctx := context.Background()
	repo := evalDir(t, filepath.Join(t.TempDir(), "r"))
	gitInitMain(t, repo)
	for name, body := range map[string]string{"a.txt": "hello\n", ".gitattributes": "*.txt filter=mark\n"} {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitRun(t, repo, "add", "a.txt", ".gitattributes")
	gitRun(t, repo, "commit", "-q", "-m", "first")
	base := gitRun(t, repo, "rev-parse", "HEAD")
	marker := filepath.Join(t.TempDir(), "MARKER")
	gitRun(t, repo, "config", "filter.mark.smudge", "touch "+marker+"; cat")
	baseWT := filepath.Join(t.TempDir(), "basewt")
	bin, log := fakeOpengrep(t, t.TempDir(), nil, []string{"a.txt"}, baseWT)
	d := liveDriver(t, bin)
	diff := secscan.Target{ProjectRoot: repo, Scope: policy.FindingScopeDiff, BaseRev: base}

	res, scanned, err := d.ScanFiles(ctx, diff)
	if err != nil || res.Coverage.Outcome != secscan.OutcomeFailed || res.Coverage.Reason != opengrep.ReasonGitFilter || len(scanned.Files) != 0 {
		t.Fatalf("diff run: %+v %v", res.Coverage, err)
	}
	if l := readLog(t, log); l != "" {
		t.Fatalf("the stand-in started on a refused diff run: %s", l)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the filter driver ran")
	}

	res, _, err = d.ScanFiles(ctx, secscan.Target{ProjectRoot: repo, Scope: policy.FindingScopeManual})
	if err != nil || res.Coverage.Outcome != secscan.OutcomeClean {
		t.Fatalf("full run: %+v %v", res.Coverage, err)
	}
	if strings.Contains(readLog(t, log), "--baseline-commit") {
		t.Error("a full run passed --baseline-commit")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the filter driver ran on a full run")
	}

	// The fixture is hostile: checking the base out starts the filter.
	gitRun(t, repo, "worktree", "add", "-q", "--detach", filepath.Join(t.TempDir(), "proof"), base)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("the fixture's filter did not run on a checkout: %v", err)
	}
	// Without the filter the diff run gets past the check and checks out.
	gitRun(t, repo, "config", "--unset", "filter.mark.smudge")
	res, _, err = d.ScanFiles(ctx, diff)
	if err != nil || res.Coverage.Reason == opengrep.ReasonGitFilter || res.Coverage.Outcome == secscan.OutcomeFailed {
		t.Fatalf("diff run without the filter: %+v %v", res.Coverage, err)
	}
	if _, err := os.Stat(baseWT); err != nil {
		t.Errorf("the diff run did not reach the base checkout: %v", err)
	}
}

// snapshotTree is every entry under dir with its mode, size and sha256.
func snapshotTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		fi, err := d.Info()
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		v := fmt.Sprintf("%s %d", fi.Mode(), fi.Size())
		if fi.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(b)
			v += " " + hex.EncodeToString(sum[:])
		}
		out[rel] = v
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestCodeStatusAndDoctorAreReadOnly (audit finding 6): `observer security
// code status` and the doctor row write nothing into the user cache (no
// pack copy, no engine or run directory) and do not hash the unpacked
// tree; they report the recorded state and its age.
func TestCodeStatusAndDoctorAreReadOnly(t *testing.T) {
	setTestHome(t, t.TempDir())
	cache := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", cache)
	binDir := t.TempDir()
	bin, log := fakeOpengrep(t, binDir, nil, nil, "")
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	cfgDir := t.TempDir()
	cfg := filepath.Join(cfgDir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(filepath.Join(cfgDir, "observer.db")) + "\"\n\n[components]\nadd = [\"" + opengrepComponent + "\"]\n"
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	e, err := openCodeEnv(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	secDir := e.secDir
	e.cleanup()
	// An earlier scan's recorded tree for this binary.
	root, err := codeScanRoot()
	if err != nil {
		t.Fatal(err)
	}
	tree := secengine.TreeDir(filepath.Join(root, "engine", "xdg-cache"), secengine.TestedVersion)
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tree, "opengrep.bin"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(bin)
	binSum, fileSum := sha256.Sum256(raw), sha256.Sum256([]byte("x"))
	rec, ok := secengine.NewTreeRecord(hex.EncodeToString(binSum[:]), secengine.TestedVersion, map[string]string{"opengrep.bin": hex.EncodeToString(fileSum[:])}, time.Now().Add(-3*time.Hour))
	if !ok {
		t.Fatal("tree record")
	}
	if err := (codeStateStore{path: filepath.Join(secDir, codeStateFile)}).Save(opengrep.State{Tree: &rec}); err != nil {
		t.Fatal(err)
	}
	stateBefore, _ := os.ReadFile(filepath.Join(secDir, codeStateFile))
	before := snapshotTree(t, cache)

	e, err = openCodeEnv(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeCodeStatus(ctx, &out, e); err != nil {
		t.Fatal(err)
	}
	e.cleanup()
	c := securityCodeDoctorCheck(ctx, cfg)

	after := snapshotTree(t, cache)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Fatalf("the user cache changed:\nbefore %v\nafter  %v", before, after)
	}
	if stateAfter, _ := os.ReadFile(filepath.Join(secDir, codeStateFile)); !bytes.Equal(stateBefore, stateAfter) {
		t.Error("status or doctor rewrote the engine record")
	}
	if !strings.Contains(out.String(), "unpacked tree: same (recorded ") || !strings.Contains(out.String(), "opengrep: "+bin) {
		t.Errorf("status:\n%s", out.String())
	}
	if !strings.HasPrefix(c.Message, "Code rules (Opengrep): unverified") || !slices.ContainsFunc(c.Details, func(s string) bool { return strings.HasPrefix(s, "unpacked tree: same (recorded ") }) {
		t.Errorf("doctor %+v", c)
	}
	if l := readLog(t, log); l != "" {
		t.Errorf("status or doctor started the engine: %s", l)
	}
}
