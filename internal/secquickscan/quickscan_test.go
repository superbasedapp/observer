package secquickscan

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// fakeAWSKeyID is shaped like an AWS key id and visibly fake. It is not an
// ...EXAMPLE value on purpose: secdetect never fires on an AWS-shaped key
// ending in EXAMPLE (knownExample), and these tests need a hit.
const fakeAWSKeyID = "AKIA" + "FAKEFIXTURE0TEST" // split: GitHub push protection on the public mirror

func diffOf(path string, start int, added ...string) string {
	var b strings.Builder
	b.WriteString("diff --git a/" + path + " b/" + path + "\n--- a/" + path + "\n+++ b/" + path + "\n")
	b.WriteString("@@ -0,0 +" + itoa(start) + "," + itoa(len(added)) + " @@\n")
	for _, l := range added {
		b.WriteString("+" + l + "\n")
	}
	return b.String()
}

func itoa(n int) string { return strconv.Itoa(n) }

type fakeGit struct {
	out   string
	over  bool
	err   error
	calls [][]string
	delay time.Duration
}

func (f *fakeGit) run(ctx context.Context, _ string, _ int, _ time.Duration, args ...string) ([]byte, bool, error) {
	f.calls = append(f.calls, args)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return nil, false, ctx.Err()
		}
	}
	if len(args) > 0 && args[0] == "rev-parse" {
		return []byte("abc\n"), false, f.err
	}
	return []byte(f.out), f.over, f.err
}

func TestScanVerdicts(t *testing.T) {
	cases := []struct {
		name    string
		git     *fakeGit
		form    Form
		verdict Verdict
		reason  UnknownReason
	}{
		{"clean", &fakeGit{out: diffOf("main.go", 3, "func f() {}")}, Form{}, VerdictClean, ReasonNone},
		{"empty diff", &fakeGit{out: ""}, Form{}, VerdictClean, ReasonNone},
		{"blocking", &fakeGit{out: diffOf("cfg/prod.py", 10, "x = 1", "k = \""+fakeAWSKeyID+"\"")}, Form{}, VerdictBlocking, ReasonNone},
		{"git unavailable", &fakeGit{err: errors.New("git: not found")}, Form{}, VerdictUnknown, ReasonGit},
		{"diff over cap", &fakeGit{out: "x", over: true}, Form{}, VerdictUnknown, ReasonDiffOverCap},
		{"deleted file adds nothing", &fakeGit{out: "diff --git a/k b/k\n--- a/k\n+++ /dev/null\n@@ -1 +0,0 @@\n-" + fakeAWSKeyID + "\n"}, Form{}, VerdictClean, ReasonNone},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &Engine{Git: tc.git.run}
			r := e.Scan(context.Background(), Request{Root: "/r", Form: tc.form, DirtySeen: 7})
			if r.Verdict != tc.verdict || r.Reason != tc.reason {
				t.Fatalf("verdict %s/%s, want %s/%s (%+v)", r.Verdict, r.Reason, tc.verdict, tc.reason, r)
			}
			if (r.Verdict == VerdictClean) != (r.CoveredDirty == 7) {
				t.Fatalf("covered dirty %d for verdict %s", r.CoveredDirty, r.Verdict)
			}
		})
	}
}

func TestScanFindingLine(t *testing.T) {
	g := &fakeGit{out: diffOf("cfg/prod.py", 10, "x = 1", "k = \""+fakeAWSKeyID+"\"")}
	r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r"})
	want := []Finding{{Path: "cfg/prod.py", Line: 11, Type: "aws_access_key", Confidence: "high"}}
	if !reflect.DeepEqual(r.Findings, want) {
		t.Fatalf("findings = %+v, want %+v", r.Findings, want)
	}
}

// TestScanCachedByDiffHash: an unchanged clean diff never waits twice;
// a blocking diff is never cached.
func TestScanCachedByDiffHash(t *testing.T) {
	g := &fakeGit{out: diffOf("a.go", 1, "package a")}
	e := &Engine{Git: g.run}
	if r := e.Scan(context.Background(), Request{Root: "/r"}); r.Cached || r.Verdict != VerdictClean {
		t.Fatalf("first = %+v", r)
	}
	if r := e.Scan(context.Background(), Request{Root: "/r"}); !r.Cached || r.Verdict != VerdictClean {
		t.Fatalf("second = %+v, want cached clean", r)
	}
	e.Version = "pack-2"
	if r := e.Scan(context.Background(), Request{Root: "/r"}); r.Cached {
		t.Fatal("a new detector pack reused an old clean answer")
	}
	b := &fakeGit{out: diffOf("k.py", 1, "k = \""+fakeAWSKeyID+"\"")}
	eb := &Engine{Git: b.run}
	eb.Scan(context.Background(), Request{Root: "/r"})
	if r := eb.Scan(context.Background(), Request{Root: "/r"}); r.Cached {
		t.Fatal("a blocking diff was cached")
	}
}

// TestScanBudget: a scan that cannot finish within its budget is unknown.
func TestScanBudget(t *testing.T) {
	g := &fakeGit{out: diffOf("a.go", 1, "x"), delay: 200 * time.Millisecond}
	e := &Engine{Git: g.run, Budget: 20 * time.Millisecond}
	r := e.Scan(context.Background(), Request{Root: "/r"})
	if r.Verdict != VerdictUnknown || r.Reason != ReasonBudget {
		t.Fatalf("verdict %s/%s, want unknown/budget", r.Verdict, r.Reason)
	}
	if r.Elapsed > time.Second {
		t.Fatalf("scan overran its budget: %v", r.Elapsed)
	}
}

func TestScanPushNoUpstream(t *testing.T) {
	g := &fakeGit{err: errors.New("fatal: no upstream")}
	r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r", Form: Form{Push: true}})
	if r.Verdict != VerdictUnknown || r.Reason != ReasonNoUpstream {
		t.Fatalf("push = %+v", r)
	}
}

func TestDiffArgs(t *testing.T) {
	cases := []struct {
		form Form
		want string
	}{
		{Form{}, "diff --cached"},
		{Form{Amend: true}, "diff --cached"},
		{Form{All: true}, "diff HEAD"},
		{Form{Pathspecs: []string{"a.go"}}, "diff HEAD -- a.go"},
		{Form{Push: true}, "log -p --format= -m @{upstream}..HEAD --"},
	}
	for _, tc := range cases {
		var kept []string
		for _, a := range DiffArgs(tc.form) {
			if !strings.HasPrefix(a, "--no-") && !strings.HasPrefix(a, "--diff-filter") && a != "-U0" {
				kept = append(kept, a)
			}
		}
		if got := strings.Join(kept, " "); got != tc.want {
			t.Errorf("DiffArgs(%+v) = %q, want %q", tc.form, got, tc.want)
		}
	}
}

func TestSeamAdapter(t *testing.T) {
	g := &fakeGit{out: diffOf("k.py", 1, "k = \""+fakeAWSKeyID+"\"")}
	qs := (&Engine{Git: g.run}).QuickScanner()
	r, err := qs(context.Background(), hookctx.QuickScanRequest{ProjectRoot: "/r", Form: hookctx.CommitForm{Form: policy.GitWriteCommit, All: true}})
	if err != nil || r.Verdict != hookctx.QuickScanBlocking {
		t.Fatalf("seam = %+v, %v", r, err)
	}
	if len(g.calls) == 0 || !strings.Contains(strings.Join(g.calls[0], " "), "HEAD") {
		t.Fatalf("commit -a did not read the working tree diff: %v", g.calls)
	}
}

// TestScanRealRepository runs the engine through the real gitview envelope
// on a throwaway repository: staged, -a and the first commit.
func TestScanRealRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "-q")
	run("config", "user.email", "t@example.invalid")
	run("config", "user.name", "t")
	e := &Engine{Git: gitview.RunReadOnlyTimeout}
	ctx := context.Background()

	write("a.go", "package a\n")
	run("add", "a.go")
	if r := e.Scan(ctx, Request{Root: dir}); r.Verdict != VerdictClean {
		t.Fatalf("first staged commit = %+v", r)
	}
	if r := e.Scan(ctx, Request{Root: dir, Form: Form{All: true}}); r.Verdict != VerdictClean {
		t.Fatalf("first commit -a on an unborn HEAD = %+v", r)
	}
	run("commit", "-q", "-m", "one")

	write("a.go", "package a\n\nconst k = \""+fakeAWSKeyID+"\"\n")
	if r := e.Scan(ctx, Request{Root: dir}); r.Verdict != VerdictClean {
		t.Fatalf("unstaged change must not be in a plain commit: %+v", r)
	}
	r := e.Scan(ctx, Request{Root: dir, Form: Form{All: true}})
	if r.Verdict != VerdictBlocking || len(r.Findings) != 1 || r.Findings[0].Path != "a.go" || r.Findings[0].Line != 3 {
		t.Fatalf("commit -a = %+v", r)
	}
	if r := e.Scan(ctx, Request{Root: dir, Form: Form{Pathspecs: []string{"a.go"}}}); r.Verdict != VerdictBlocking {
		t.Fatalf("commit a.go = %+v", r)
	}
	run("add", "a.go")
	if r := e.Scan(ctx, Request{Root: dir}); r.Verdict != VerdictBlocking {
		t.Fatalf("staged = %+v", r)
	}
	if r := e.Scan(ctx, Request{Root: dir, Form: Form{Push: true}}); r.Reason != ReasonNoUpstream {
		t.Fatalf("push without upstream = %+v", r)
	}
}

func TestRangeRejectsNonCommitIDs(t *testing.T) {
	g := &fakeGit{}
	for _, f := range []Form{{To: "--output=/tmp/x"}, {To: "HEAD"}, {From: "abc", To: "0123456789"}, {From: "0123456789"}} {
		r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r", Form: f})
		if r.Reason != ReasonBadRequest {
			t.Errorf("%+v = %+v, want bad_request", f, r)
		}
	}
	if len(g.calls) != 0 {
		t.Fatalf("git ran for a bad range: %v", g.calls)
	}
}

// TestCommitScanRealRepository: landed commits are scanned once each,
// human or agent, through the range form.
func TestCommitScanRealRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	commit := func(name, body string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		git("add", name)
		git("commit", "-q", "-m", name)
		return git("rev-parse", "HEAD")
	}
	git("init", "-q")
	git("config", "user.email", "t@example.invalid")
	git("config", "user.name", "t")
	cs := &CommitScan{Engine: &Engine{Git: gitview.RunReadOnlyTimeout}}
	ctx := context.Background()

	h1 := commit("a.go", "package a\n")
	if r, ran := cs.AfterScan(ctx, dir, h1); !ran || r.Verdict() != VerdictClean {
		t.Fatalf("root commit = %+v ran=%v", r, ran)
	}
	if _, ran := cs.AfterScan(ctx, dir, h1); ran {
		t.Fatal("an unchanged head was scanned again")
	}
	commit("b.go", "package a\n")
	h3 := commit("k.py", "k = \""+fakeAWSKeyID+"\"\n")
	r, ran := cs.AfterScan(ctx, dir, h3)
	if !ran || r.Verdict() != VerdictBlocking || len(r.Findings()) != 1 || r.Findings()[0].Path != "k.py" || len(r.Commits) != 2 {
		t.Fatalf("range = %+v ran=%v", r, ran)
	}
	h4 := commit("c.go", "package a\n")
	if r, _ := cs.AfterScan(ctx, dir, h4); r.Verdict() != VerdictClean {
		t.Fatalf("next clean commit = %+v", r)
	}
}

func TestScanObservationsNeverBlock(t *testing.T) {
	g := &fakeGit{out: diffOf("pkg/a_test.go", 3, "\tt.Skip(\"later\")")}
	r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r"})
	if r.Verdict != VerdictClean || len(r.Observations) != 1 || r.Observations[0].RuleID != "S-767" {
		t.Fatalf("result = %+v", r)
	}
}

// TestParseAddedLineLooksLikeHeader (P-003, SEC-C2 milestone 1a): an added
// line whose text starts "++ " reads as "+++ " in the diff; inside a hunk it
// is an added line, never a file header, so a secret after it is found.
func TestParseAddedLineLooksLikeHeader(t *testing.T) {
	g := &fakeGit{out: diffOf("notes.md", 1, "++ /dev/null", "k = \""+fakeAWSKeyID+"\"")}
	r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r"})
	if r.Verdict != VerdictBlocking || len(r.Findings) != 1 || r.Findings[0].Path != "notes.md" || r.Findings[0].Line != 2 {
		t.Fatalf("result = %+v, want one blocking finding at notes.md:2", r)
	}
	g = &fakeGit{out: diffOf("notes.md", 1, "++ b/other.go", "k = \""+fakeAWSKeyID+"\"")}
	r = (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r"})
	if len(r.Findings) != 1 || r.Findings[0].Path != "notes.md" {
		t.Fatalf("a header-shaped added line renamed the file: %+v", r)
	}
}

// TestSeamKeepsFormAndDirectory (P-003, milestone 1b): only a plain commit
// and a push in the project root are scanned; every other form and any
// directory answer unknown with no DirtyCovered, and git never runs.
func TestSeamKeepsFormAndDirectory(t *testing.T) {
	cases := []struct {
		name string
		form hookctx.CommitForm
		scan bool
	}{
		{"commit", hookctx.CommitForm{Form: policy.GitWriteCommit}, true},
		{"commit -a", hookctx.CommitForm{Form: policy.GitWriteCommit, All: true}, true},
		{"push", hookctx.CommitForm{Push: true}, true},
		{"commit -C dir", hookctx.CommitForm{Form: policy.GitWriteCommit, Dir: "sub"}, false},
		{"push -C dir", hookctx.CommitForm{Push: true, Dir: "../other"}, false},
		{"no form", hookctx.CommitForm{}, false},
		{"stash", hookctx.CommitForm{Form: policy.GitWriteStash, FlagOnly: true}, false},
	}
	for _, f := range policy.GitWriteForms() {
		if f != policy.GitWriteCommit {
			cases = append(cases, struct {
				name string
				form hookctx.CommitForm
				scan bool
			}{string(f), hookctx.CommitForm{Form: f}, false})
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g := &fakeGit{out: diffOf("a.go", 1, "package a")}
			r, err := (&Engine{Git: g.run}).QuickScanner()(context.Background(), hookctx.QuickScanRequest{ProjectRoot: "/r", Form: tc.form, DirtySeen: 9})
			if err != nil {
				t.Fatal(err)
			}
			if tc.scan {
				if r.Verdict != hookctx.QuickScanClean || r.DirtyCovered != 9 {
					t.Fatalf("scanned form = %+v, want clean covering 9", r)
				}
				return
			}
			if r.Verdict != hookctx.QuickScanUnknown || r.DirtyCovered != 0 || len(g.calls) != 0 {
				t.Fatalf("unmodelled form = %+v (git calls %v), want unknown, no DirtyCovered, no git", r, g.calls)
			}
		})
	}
}

// TestPushLogArgs (P-003, milestone 1c): a push reads every commit its
// refspecs send, minus the remote's tracking refs; a form it cannot read is
// unknown.
func TestPushLogArgs(t *testing.T) {
	cases := []struct {
		ops    []string
		opaque bool
		want   string // "" = unmodelled
	}{
		{nil, false, "@{upstream}..HEAD --"},
		{[]string{"origin"}, false, "HEAD --not --remotes=origin --"},
		{[]string{"origin", "main"}, false, "main --not --remotes=origin --"},
		{[]string{"origin", "+feat:main", "fix/x:fix/x"}, false, "feat fix/x --not --remotes=origin --"},
		{[]string{"origin", "main", ":old"}, false, "main --not --remotes=origin --"},
		{[]string{"origin", ":old"}, false, ""},
		{[]string{"https://example.invalid/r.git", "main"}, false, ""},
		{[]string{"../other", "main"}, false, ""},
		{[]string{"origin", "HEAD~1:main"}, false, ""},
		{[]string{"origin", "--output=/tmp/x"}, false, ""},
		{[]string{"origin", "main"}, true, ""},
	}
	for _, tc := range cases {
		args, err := pushLogArgs(Form{Push: true, PushOperands: tc.ops, PushOpaque: tc.opaque})
		if tc.want == "" {
			if !errors.Is(err, errUnmodelled) {
				t.Errorf("%v opaque=%v: args %v, want unmodelled", tc.ops, tc.opaque, args)
			}
			continue
		}
		if err != nil {
			t.Errorf("%v: %v", tc.ops, err)
			continue
		}
		got := strings.Join(args[len(logFlags):], " ")
		if got != tc.want {
			t.Errorf("%v: %q, want %q", tc.ops, got, tc.want)
		}
	}
	r := (&Engine{Git: (&fakeGit{}).run}).Scan(context.Background(), Request{Root: "/r", Form: Form{Push: true, PushOpaque: true}})
	if r.Verdict != VerdictUnknown || r.Reason != ReasonUnmodelled {
		t.Fatalf("opaque push = %+v", r)
	}
}

// TestPushAndCommitScanSeeEveryCommit (P-003, milestones 1c and 1d): a
// secret added in one commit and removed in the next is still found by the
// push scan of an explicit refspec and by the commit scan between ticks.
func TestPushAndCommitScanSeeEveryCommit(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	remote, dir := filepath.Join(base, "remote.git"), filepath.Join(base, "work")
	git := func(in string, args ...string) string {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", in}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	git(base, "init", "-q", "--bare", remote)
	git(dir, "init", "-q")
	git(dir, "config", "user.email", "t@example.invalid")
	git(dir, "config", "user.name", "t")
	commit := func(name, body string) string {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		git(dir, "add", name)
		git(dir, "commit", "-q", "-m", name)
		return git(dir, "rev-parse", "HEAD")
	}
	h1 := commit("a.go", "package a\n")
	branch := git(dir, "rev-parse", "--abbrev-ref", "HEAD")
	git(dir, "remote", "add", "origin", remote)
	git(dir, "push", "-q", "origin", branch)
	e := &Engine{Git: gitview.RunReadOnlyTimeout, Scanner: secdetect.Scanner{Identify: func(typ, v string) string { return typ + ":" + strconv.Itoa(len(v)) }}}
	cs := &CommitScan{Engine: e}
	ctx := context.Background()
	if r, _ := cs.AfterScan(ctx, dir, h1); r.Verdict() != VerdictClean {
		t.Fatalf("first tick = %+v", r)
	}
	commit("k.py", "k = \""+fakeAWSKeyID+"\"\n")
	h3 := commit("k.py", "k = None\n")

	push := e.Scan(ctx, Request{Root: dir, Form: Form{Push: true, PushOperands: []string{"origin", branch}}})
	if push.Verdict != VerdictBlocking || len(push.Findings) != 1 || push.Findings[0].Path != "k.py" {
		t.Fatalf("push of a secret added then removed = %+v", push)
	}
	if r, _ := cs.AfterScan(ctx, dir, h3); r.Verdict() != VerdictBlocking || len(r.Commits) != 2 || len(r.Commits[1].Removed) != 1 {
		t.Fatalf("commit scan of a secret added then removed between ticks = %+v", r)
	}
	if r := e.Scan(ctx, Request{Root: dir, Form: Form{Push: true, PushOperands: []string{"origin", ":" + branch}}}); r.Reason != ReasonUnmodelled {
		t.Fatalf("a deletion-only push = %+v, want unknown", r)
	}
}

// TestQuickScanCIRules (SEC-C2 milestone 3): a staged dangerous workflow
// is checked whole from the index; its hits ride beside a clean verdict,
// and a form the scan cannot read counts the workflow unchecked.
func TestQuickScanCIRules(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	git := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = append(os.Environ(), "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	git("init", "-q")
	git("config", "user.email", "t@example.invalid")
	git("config", "user.name", "t")
	if err := os.MkdirAll(filepath.Join(dir, ".github", "workflows"), 0o700); err != nil {
		t.Fatal(err)
	}
	wf := "on: pull_request_target\npermissions: {contents: read}\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n      - run: make test\n"
	if err := os.WriteFile(filepath.Join(dir, ".github", "workflows", "pr.yml"), []byte(wf), 0o600); err != nil {
		t.Fatal(err)
	}
	git("add", ".")
	e := &Engine{Git: gitview.RunReadOnlyTimeout}
	r := e.Scan(context.Background(), Request{Root: dir})
	if r.Verdict != VerdictClean || r.CIUnchecked != 0 {
		t.Fatalf("staged = %+v", r)
	}
	found := false
	for _, c := range r.CI {
		if c.RuleID == "S-771" && c.Path == ".github/workflows/pr.yml" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no S-771 in %+v", r.CI)
	}
	if r := e.Scan(context.Background(), Request{Root: dir, Form: Form{All: true}}); r.CIUnchecked != 1 || len(r.CI) != 0 {
		t.Fatalf("-a without a working-tree reader = %+v", r)
	}
}

// TestScanRetains: the result carries the parsed diff of the files Retain
// accepts (lane SEC-D1FIX2, S-747 at commit), and nothing without Retain.
func TestScanRetains(t *testing.T) {
	g := &fakeGit{out: diffOf("web/package.json", 3, `    "left-pad": "1.3.0",`) + diffOf("main.go", 1, "package main")}
	r := (&Engine{Git: g.run, Retain: func(p string) bool { return strings.HasSuffix(p, "package.json") }}).Scan(context.Background(), Request{Root: "/r"})
	if len(r.Retained) != 1 || r.Retained[0].Path != "web/package.json" || len(r.Retained[0].Added) != 1 {
		t.Fatalf("retained %+v", r.Retained)
	}
	if r := (&Engine{Git: g.run}).Scan(context.Background(), Request{Root: "/r"}); len(r.Retained) != 0 {
		t.Errorf("no Retain retains nothing: %+v", r.Retained)
	}
}
