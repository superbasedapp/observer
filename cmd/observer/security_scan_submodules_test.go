//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depdriver"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
)

// Public release commits (spike CPP-0 (a)).
const (
	subZlib131 = "51b7f2abdade71cd9bb0e7a373ef2610ec6f9daf"
	subCurl    = "c7aef0a945f9b6fb6d3f91716a21dfe2f4ea635f"
	subPng     = "b78804f9a2568b270ebd30eca954ef7447ba92f7"
)

// subPrivate are strings of the test project that must never be sent: its
// submodule urls, hosts, paths and names.
var subPrivate = []string{"corp.example", "secret-team", "third_party", "zlib-fork", "deps/png", ".gitmodules"}

// submoduleQueries records what the check sent through depsSubmoduleQuery.
type submoduleQueries struct {
	mu   sync.Mutex
	sent []string
}

func (q *submoduleQueries) list() []string {
	q.mu.Lock()
	defer q.mu.Unlock()
	return append([]string(nil), q.sent...)
}

// useSubmoduleQueries swaps the check's network call for a fake that
// answers from answers (the canary included unless dropped), fails the
// commits in fail and records every commit it was sent.
func useSubmoduleQueries(t *testing.T, answers map[string][]osvnet.CommitVuln, fail map[string]bool) *submoduleQueries {
	t.Helper()
	q := &submoduleQueries{}
	prev := depsSubmoduleQuery
	depsSubmoduleQuery = func(_ context.Context, commit string) ([]osvnet.CommitVuln, error) {
		q.mu.Lock()
		q.sent = append(q.sent, commit)
		q.mu.Unlock()
		if fail[commit] {
			return nil, errors.New("rate_limited")
		}
		return answers[commit], nil
	}
	t.Cleanup(func() { depsSubmoduleQuery = prev })
	return q
}

// subAnswers are the fake service's answers: the canary's record and one
// per project commit (curl's two records name the same flaw).
func subAnswers() map[string][]osvnet.CommitVuln {
	return map[string][]osvnet.CommitVuln{
		depscan.SubmoduleCanary.Version: {{ID: depscan.SubmoduleCanary.Advisory}},
		subZlib131:                      {{ID: "CVE-2026-22184", Severity: "HIGH"}},
		subCurl:                         {{ID: "CURL-CVE-2022-22576", Aliases: []string{"CVE-2022-22576"}}, {ID: "CVE-2022-22576", Aliases: []string{"CURL-CVE-2022-22576"}}},
		subPng:                          {{ID: "CVE-2018-13785"}},
	}
}

// subShownEnv is an individual node with online checks on and the current
// disclosure accepted.
func subShownEnv() *depsScanEnv {
	shown := secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli", Verified: true}
	return &depsScanEnv{disclose: shown, cfg: onlineCfg(true)}
}

// subProbeResp is a response with the gap the gap probe records for the
// root's .gitmodules.
func subProbeResp() depscan.ChildResponse {
	return depscan.ChildResponse{
		Version: depscan.ProtocolVersion, Compiled: true,
		Gaps: []depscan.Gap{{Ecosystem: "C/C++", Path: ".gitmodules", Reason: "needs_online"}},
	}
}

func writeSubFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

const subRootGitmodules = "[submodule \"zlib\"]\n\tpath = third_party/zlib\n\turl = git@git.corp.example:secret-team/zlib-fork.git\n" +
	"[submodule \"curl\"]\n\tpath = third_party/curl\n\turl = https://git.corp.example/secret-team/curl.git\n"

// useFakeSubmoduleGit swaps the git listing for canned ls-files output by
// directory (relative to root, forward slashes) and counts the calls.
func useFakeSubmoduleGit(t *testing.T, root string, byDir map[string]string) *int {
	t.Helper()
	calls := 0
	prev := depsSubmoduleGit
	depsSubmoduleGit = func(_ context.Context, dir string, _ ...string) ([]byte, bool, error) {
		calls++
		rel, err := filepath.Rel(root, dir)
		if err != nil {
			return nil, false, err
		}
		out, ok := byDir[filepath.ToSlash(rel)]
		if !ok {
			return nil, false, errors.New("not a git work tree")
		}
		return []byte(out), false, nil
	}
	t.Cleanup(func() { depsSubmoduleGit = prev })
	return &calls
}

func runSubmoduleTestGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "GIT_TERMINAL_PROMPT=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// TestSubmoduleCheckSendsOnlyCommitIDs drives the check over a real git
// index: two submodules at the root and one nested in a checked-out
// submodule. The self-test commit goes first, then each pinned commit
// once; no url, host, path or name of the project is ever sent. The
// answers come back at the submodule paths through the shared finding
// path, and the gap probe's .gitmodules gap is dropped.
func TestSubmoduleCheckSendsOnlyCommitIDs(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git binary not available")
	}
	root := t.TempDir()
	runSubmoduleTestGit(t, root, "init", "-q")
	writeSubFile(t, filepath.Join(root, ".gitmodules"), subRootGitmodules)
	runSubmoduleTestGit(t, root, "update-index", "--add", "--cacheinfo", "160000,"+subZlib131+",third_party/zlib")
	runSubmoduleTestGit(t, root, "update-index", "--add", "--cacheinfo", "160000,"+subCurl+",third_party/curl")
	nested := filepath.Join(root, "third_party", "curl")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	runSubmoduleTestGit(t, nested, "init", "-q")
	writeSubFile(t, filepath.Join(nested, ".gitmodules"), "[submodule \"deps/png\"]\n\tpath = deps/png\n\turl = ../../secret-team/png.git\n")
	runSubmoduleTestGit(t, nested, "update-index", "--add", "--cacheinfo", "160000,"+subPng+",deps/png")

	q := useSubmoduleQueries(t, subAnswers(), nil)
	resp := subShownEnv().submoduleMatcher()(context.Background(), root, subProbeResp())

	sent := q.list()
	if len(sent) != 4 || sent[0] != depscan.SubmoduleCanary.Version {
		t.Fatalf("sent %v: want the self-test commit first, then the three pins", sent)
	}
	rest := append([]string(nil), sent[1:]...)
	sort.Strings(rest)
	want := []string{subPng, subZlib131, subCurl}
	sort.Strings(want)
	if strings.Join(rest, ",") != strings.Join(want, ",") {
		t.Fatalf("pins sent %v, want %v", rest, want)
	}
	for _, s := range sent {
		for _, p := range subPrivate {
			if strings.Contains(s, p) {
				t.Fatalf("a query carried %q: %q", p, s)
			}
		}
	}

	res := depdriver.Result(depdriver.Input{DriverID: depscan.ScalibrID, Target: secscan.Target{ProjectRoot: root}, Response: resp})
	at := map[string]int{}
	for _, f := range res.Findings {
		at[f.Location.RelPath]++
	}
	if len(res.Findings) != 3 || at["third_party/zlib"] != 1 || at["third_party/curl"] != 1 || at["third_party/curl/deps/png"] != 1 {
		t.Fatalf("findings by path %v (%d findings)", at, len(res.Findings))
	}
	for _, s := range res.Coverage.Skipped {
		if s.Path == ".gitmodules" {
			t.Fatalf("the covered .gitmodules is still a gap: %+v", res.Coverage.Skipped)
		}
	}
	scanned := false
	for _, e := range res.Coverage.Scanned {
		scanned = scanned || e == depscan.SubmoduleEcosystem
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings || !scanned {
		t.Fatalf("coverage %+v", res.Coverage)
	}
}

// TestSubmoduleCheckNoRequestBeforeAccept: with the disclosure not
// accepted, or online checks off, the check reads nothing and sends
// nothing, and the gap stays.
func TestSubmoduleCheckNoRequestBeforeAccept(t *testing.T) {
	root := t.TempDir()
	writeSubFile(t, filepath.Join(root, ".gitmodules"), subRootGitmodules)
	gitCalls := useFakeSubmoduleGit(t, root, map[string]string{".": "160000 " + subZlib131 + " 0\tthird_party/zlib\x00"})
	q := useSubmoduleQueries(t, subAnswers(), nil)
	for name, e := range map[string]*depsScanEnv{
		"disclosure not accepted": {cfg: onlineCfg(true)},
		"disclosure unverified":   {cfg: onlineCfg(true), disclose: secfeed.Disclosure{Version: secfeed.DisclosureVersion, ShownAt: time.Now(), Surface: "cli"}},
		"online checks off":       {cfg: onlineCfg(false), disclose: subShownEnv().disclose},
	} {
		m := e.submoduleMatcher()
		if m == nil {
			t.Fatalf("%s: an individual node gets the matcher (the gate is walked per project)", name)
		}
		resp := m(context.Background(), root, subProbeResp())
		if len(resp.Gaps) != 1 || len(resp.Ecosystems) != 0 {
			t.Errorf("%s: the response changed: %+v", name, resp)
		}
	}
	if n := len(q.list()); n != 0 || *gitCalls != 0 {
		t.Fatalf("before the accept: %d queries, %d git runs", n, *gitCalls)
	}
}

// TestSubmoduleCheckNeverOnManagedNode: a managed node has no submodule
// check at all (its online matching goes to the org relay, which has no
// commit lookup), even with online checks on and the disclosure accepted.
func TestSubmoduleCheckNeverOnManagedNode(t *testing.T) {
	root := t.TempDir()
	writeSubFile(t, filepath.Join(root, ".gitmodules"), subRootGitmodules)
	gitCalls := useFakeSubmoduleGit(t, root, map[string]string{".": "160000 " + subZlib131 + " 0\tthird_party/zlib\x00"})
	q := useSubmoduleQueries(t, subAnswers(), nil)
	e := subShownEnv()
	e.managed = true
	if e.submoduleMatcher() != nil {
		t.Fatal("a managed node got the submodule check")
	}
	// A matcher built before the tenancy read managed sends nothing once it
	// does.
	early := subShownEnv()
	m := early.submoduleMatcher()
	early.managed = true
	if resp := m(context.Background(), root, subProbeResp()); len(resp.Gaps) != 1 {
		t.Fatalf("the response changed on a managed node: %+v", resp)
	}
	if n := len(q.list()); n != 0 || *gitCalls != 0 {
		t.Fatalf("on a managed node: %d queries, %d git runs", n, *gitCalls)
	}
}

// TestSubmoduleCheckReconfirmsAfterDisclosureChange: a genuine, signed
// accept of the previous disclosure version (which did not name the commit
// ids) keeps the check from sending anything; the new accept opens it.
func TestSubmoduleCheckReconfirmsAfterDisclosureChange(t *testing.T) {
	secDir := filepath.Join(t.TempDir(), "security")
	key := testDepsSigningKey(t, secDir)
	b, err := secfeed.EncodeDisclosure(secfeed.Disclosure{Version: secfeed.DisclosureVersion - 1, ShownAt: time.Now().Add(-time.Hour), Surface: "cli"}, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := writeDepsFile(filepath.Join(secDir, depsDisclosureFile), b); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	writeSubFile(t, filepath.Join(root, ".gitmodules"), subRootGitmodules)
	useFakeSubmoduleGit(t, root, map[string]string{".": "160000 " + subZlib131 + " 0\tthird_party/zlib\x00"})
	q := useSubmoduleQueries(t, subAnswers(), nil)

	e := &depsScanEnv{cfg: onlineCfg(true), disclose: readDepsDisclosure(secDir)}
	if e.onlineBlockedAt(root) != "disclosure_not_shown" {
		t.Fatalf("an accept of the older text opens the gate: %q", e.onlineBlockedAt(root))
	}
	e.submoduleMatcher()(context.Background(), root, subProbeResp())
	if n := len(q.list()); n != 0 {
		t.Fatalf("%d queries on an accept of the older text", n)
	}
	if _, err := recordDepsDisclosure(secDir, "cli", time.Now()); err != nil {
		t.Fatal(err)
	}
	e.disclose = readDepsDisclosure(secDir)
	resp := e.submoduleMatcher()(context.Background(), root, subProbeResp())
	if sent := q.list(); len(sent) != 2 || sent[1] != subZlib131 {
		t.Fatalf("after the new accept: sent %v", sent)
	}
	if len(resp.Gaps) != 0 {
		t.Fatalf("gaps %+v", resp.Gaps)
	}
}

// TestSubmoduleCheckFailures: a self-test that fails sends no project
// commit and drops nothing; a commit whose query fails is a gap while the
// others still report; a project with no .gitmodules sends nothing.
func TestSubmoduleCheckFailures(t *testing.T) {
	root := t.TempDir()
	writeSubFile(t, filepath.Join(root, ".gitmodules"), subRootGitmodules)
	useFakeSubmoduleGit(t, root, map[string]string{".": "160000 " + subZlib131 + " 0\tthird_party/zlib\x00160000 " + subCurl + " 0\tthird_party/curl\x00"})

	q := useSubmoduleQueries(t, subAnswers(), map[string]bool{depscan.SubmoduleCanary.Version: true})
	resp := subShownEnv().submoduleMatcher()(context.Background(), root, subProbeResp())
	if sent := q.list(); len(sent) != 1 {
		t.Fatalf("a failed self-test still sent %v", sent)
	}
	res := depdriver.Result(depdriver.Input{DriverID: depscan.ScalibrID, Target: secscan.Target{ProjectRoot: root}, Response: resp})
	if len(res.Findings) != 0 || res.Coverage.Outcome == secscan.OutcomeClean {
		t.Fatalf("a failed self-test: %+v", res.Coverage)
	}

	q = useSubmoduleQueries(t, subAnswers(), map[string]bool{subCurl: true})
	resp = subShownEnv().submoduleMatcher()(context.Background(), root, subProbeResp())
	res = depdriver.Result(depdriver.Input{DriverID: depscan.ScalibrID, Target: secscan.Target{ProjectRoot: root}, Response: resp})
	failed := false
	for _, s := range res.Coverage.Skipped {
		failed = failed || (s.Path == ".gitmodules" && s.Reason == depscan.ReasonSubmoduleCheckFailed)
	}
	if len(res.Findings) != 1 || res.Findings[0].Location.RelPath != "third_party/zlib" || !failed || len(q.list()) != 3 {
		t.Fatalf("one failed commit: findings %+v skipped %+v sent %v", res.Findings, res.Coverage.Skipped, q.list())
	}

	empty := t.TempDir()
	q = useSubmoduleQueries(t, subAnswers(), nil)
	resp = subShownEnv().submoduleMatcher()(context.Background(), empty, depscan.ChildResponse{Version: depscan.ProtocolVersion, Compiled: true})
	if len(q.list()) != 0 || len(resp.Ecosystems) != 0 || len(resp.Gaps) != 0 {
		t.Fatalf("no .gitmodules: sent %v, response %+v", q.list(), resp)
	}
}

// TestSubmoduleCheckOnlyFromTheScanCommand: the check is attached to a
// driver in one place, depsRunMatchers (security_scan_online.go), behind
// the online gate, and only on an explicit online request: the CLI's
// `observer security scan --online` (security_scan_cmd.go) and the
// dashboard scan's "Also check online" (security_scan_now_deps.go,
// decision P-1 of docs/plans/dashboard-cli-parity-plan-2026-11-06.md, which
// superseded ruling Q9 (a)'s CLI-only rule). The daemon's scheduled loop
// never calls it, so it never sends a commit on its own.
func TestSubmoduleCheckOnlyFromTheScanCommand(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var setters, callers []string
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		b, err := os.ReadFile(n)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), ".submodules = ") || strings.Contains(string(b), "submodules: e.submoduleMatcher") {
			setters = append(setters, n)
		}
		if strings.Contains(string(b), ".depsRunMatchers(") {
			callers = append(callers, n)
		}
	}
	if strings.Join(setters, ",") != "security_scan_online.go" {
		t.Fatalf("the submodule check is set in %v; only depsRunMatchers in security_scan_online.go may set it", setters)
	}
	if strings.Join(callers, ",") != "security_scan_cmd.go,security_scan_now_deps.go" {
		t.Fatalf("depsRunMatchers is called from %v; only the scan command and the dashboard's Scan now deps step may ask for online checks", callers)
	}
}

// TestSubmoduleCheckRefusesALinkedFile: a .gitmodules reached through a
// symbolic link is not read (so nothing is sent for it) and stays a gap.
func TestSubmoduleCheckRefusesALinkedFile(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "elsewhere")
	writeSubFile(t, outside, subRootGitmodules)
	if err := os.Symlink(outside, filepath.Join(root, ".gitmodules")); err != nil {
		t.Skipf("symbolic links not available here: %v", err)
	}
	gitCalls := useFakeSubmoduleGit(t, root, map[string]string{".": "160000 " + subZlib131 + " 0\tthird_party/zlib\x00"})
	q := useSubmoduleQueries(t, subAnswers(), nil)
	resp := subShownEnv().submoduleMatcher()(context.Background(), root, subProbeResp())
	if len(q.list()) != 0 || *gitCalls != 0 {
		t.Fatalf("a linked .gitmodules was read: %d queries, %d git runs", len(q.list()), *gitCalls)
	}
	stays := false
	for _, g := range resp.Gaps {
		stays = stays || (g.Path == ".gitmodules" && g.Reason == "needs_online")
	}
	if !stays {
		t.Fatalf("gaps %+v", resp.Gaps)
	}
}
