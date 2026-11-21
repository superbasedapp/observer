//go:build linux && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// boxCloneFake plays a box's git around the hosted harness: the git check,
// the clone, the read of the cloned commit and the return diff against it;
// every other exec goes to the harness.
type boxCloneFake struct {
	hh      *hostedHarness
	gitCode int
	// cloneCode and cloneOut answer the clone (git's exit and its stderr).
	cloneCode int
	cloneOut  string
	commit    string
	diff      string

	mu    sync.Mutex
	order []string
	clone sandboxremote.ExecSpec
	diffs []sandboxremote.ExecSpec
}

const boxCloneURL = "https://github.com/acme/app.git"

func (f *boxCloneFake) exec(b *fakeBox, spec sandboxremote.ExecSpec) (sandboxremote.Process, error) {
	argv := spec.Argv
	step := ""
	switch {
	case len(argv) == 3 && argv[0] == "sh" && strings.Contains(argv[2], "command -v git"):
		step = "git-check"
	case len(argv) > 1 && argv[0] == "git" && argv[1] == "clone":
		step = "clone"
	case slices.Contains(argv, "rev-parse"):
		step = "head"
	case len(argv) > 2 && argv[0] == "git" && slices.Contains(argv, "--cached"):
		step = "diff"
	case len(argv) >= 3 && argv[0] == "sh" && argv[2] == hostedAssembleScript:
		step = "binary"
	}
	if step != "" {
		f.mu.Lock()
		f.order = append(f.order, step)
		f.mu.Unlock()
	}
	switch step {
	case "git-check":
		return newFakeProcess("", f.gitCode), nil
	case "clone":
		f.mu.Lock()
		f.clone = spec
		f.mu.Unlock()
		return newFakeProcess(f.cloneOut, f.cloneCode), nil
	case "head":
		return newFakeProcess(f.commit+"\n", 0), nil
	case "diff":
		f.mu.Lock()
		f.diffs = append(f.diffs, spec)
		f.mu.Unlock()
		return newFakeProcess(f.diff, 0), nil
	}
	return f.hh.exec(b, spec)
}

func (f *boxCloneFake) steps() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.order...)
}

// newBoxCloneRun is a vendor row's run whose delivery is the box-side clone.
func newBoxCloneRun(t *testing.T, vendor string) (*hostedHarness, *boxCloneFake) {
	t.Helper()
	hh := newHostedHarness(t, vendor)
	f := &boxCloneFake{hh: hh, commit: strings.Repeat("c", 40)}
	hh.client.execs = f.exec
	hh.run.plan.Source = string(workspace.SourceCloneRemote)
	hh.run.plan.Delivery = hostedDeliveryRemoteClone
	hh.run.plan.CloneURL = boxCloneURL
	hh.run.plan.Tier = "internet"
	hh.run.plan.ScopeKey = sandboxremote.RemoteCloneScopeKey(boxCloneURL)
	hh.run.plan.Files = nil
	return hh, f
}

// TestHostedBoxCloneVendorRun (lane CLONE, item H7): on a vendor row the box
// checks for git, clones the URL itself as the box user, before the in-box
// observer is uploaded; nothing of this machine's tree is uploaded; the
// cloned commit is kept on the run record and in the clone return record;
// and the saved diff is against that commit, taken in the workspace.
func TestHostedBoxCloneVendorRun(t *testing.T) {
	hh, f := newBoxCloneRun(t, sandboxremote.VendorE2B)
	f.diff = "diff --git a/main.go b/main.go\n+// changed in the box\n"
	code := make(chan int, 1)
	go func() { code <- hh.run.drive(context.Background()) }()
	waitFor(t, func() bool { hh.mu.Lock(); defer hh.mu.Unlock(); return len(hh.ptys) > 0 })
	if c := hostedEndRun(t, hh, code); c != 5 {
		t.Fatalf("exit %d, output %s", c, hh.out.String())
	}
	steps := f.steps()
	if i, j := slices.Index(steps, "git-check"), slices.Index(steps, "clone"); i < 0 || j != i+1 {
		t.Errorf("git is not checked right before the clone: %v", steps)
	}
	if j, k := slices.Index(steps, "clone"), slices.Index(steps, "binary"); k >= 0 && k < j {
		t.Errorf("the binary was uploaded before the clone: %v", steps)
	}
	ws := hh.run.layout.Workspace
	if !slices.Equal(f.clone.Argv, []string{"git", "clone", "--", boxCloneURL, ws}) || f.clone.Env["GIT_TERMINAL_PROMPT"] != "0" || f.clone.AsRoot || f.clone.Stdin || f.clone.PTY {
		t.Errorf("clone exec %+v", f.clone)
	}
	b := hh.client.boxes["box1"]
	for p := range b.files {
		if strings.HasPrefix(p, hh.run.plan.Root+"/") {
			t.Errorf("a file of this machine's tree was uploaded: %s", p)
		}
	}
	if !b.deleted {
		t.Error("the box was not deleted")
	}
	if len(f.diffs) != 1 || f.diffs[0].Cwd != ws || f.diffs[0].Argv[len(f.diffs[0].Argv)-1] != f.commit {
		t.Fatalf("return diff execs %+v", f.diffs)
	}
	diffPath := filepath.Join(hostedStateDir(hh.run.plan.ObserverDir), "returns", "run-h1.diff")
	if got, err := os.ReadFile(diffPath); err != nil || string(got) != f.diff {
		t.Errorf("saved diff %q %v", got, err)
	}
	raw, err := os.ReadFile(hostedCloneReturnPath(hh.run.plan.ObserverDir, "run-h1"))
	if err != nil {
		t.Fatal(err)
	}
	var rec hostedCloneReturn
	if err := json.Unmarshal(raw, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Commit != f.commit || rec.CloneURL != boxCloneURL || rec.Diff != "run-h1.diff" || rec.DiffAgainst != hostedCloneDiffAgainstCommit || rec.Provider != sandboxremote.VendorE2B || rec.Version != hostedCloneReturnVersion {
		t.Errorf("clone return record %+v", rec)
	}
	if fi, _ := os.Stat(hostedCloneReturnPath(hh.run.plan.ObserverDir, "run-h1")); fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode %v", fi.Mode().Perm())
	}
	out := hh.out.String()
	for _, want := range []string{"in the box (never on this machine", "at commit " + f.commit, "a checkout of " + boxCloneURL + " at commit " + f.commit} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q: %s", want, out)
		}
	}
}

// TestHostedBoxCloneRefusalsDeleteTheBox (lane CLONE): a box with no git, or
// a clone that fails (a private repository: no credential is sent), ends the
// launch plainly before the in-box observer is uploaded; the box is deleted
// and there is nothing to bring back (no diff, no clone record).
func TestHostedBoxCloneRefusalsDeleteTheBox(t *testing.T) {
	cases := []struct {
		name      string
		gitCode   int
		cloneCode int
		saw       []string
	}{
		{"git missing", 1, 0, []string{"git-check"}},
		{"clone fails", 0, 128, []string{"git-check", "clone"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hh, f := newBoxCloneRun(t, sandboxremote.VendorE2B)
			f.gitCode, f.cloneCode = c.gitCode, c.cloneCode
			f.cloneOut = "fatal: could not read Username for 'https://github.com': terminal prompts disabled\n"
			if code := hh.run.drive(context.Background()); code == 0 {
				t.Fatal("the launch succeeded")
			}
			if got := f.steps(); !slices.Equal(got, c.saw) {
				t.Errorf("box steps %v, want %v", got, c.saw)
			}
			if !hh.client.boxes["box1"].deleted {
				t.Error("the box was not deleted")
			}
			if !strings.Contains(hh.out.String(), "nothing to bring back") {
				t.Errorf("output %s", hh.out.String())
			}
			if len(f.diffs) != 0 {
				t.Error("a diff was taken of a box that never got the repository")
			}
			if _, err := os.Stat(hostedCloneReturnPath(hh.run.plan.ObserverDir, "run-h1")); err == nil {
				t.Error("a clone return record for a failed clone")
			}
		})
	}
}

// TestHostedBoxCloneErrorsArePlain: the two in-box refusals name what
// happened and the way on, with the closed code first.
func TestHostedBoxCloneErrorsArePlain(t *testing.T) {
	for _, c := range []struct {
		gitCode, cloneCode int
		code, words        string
	}{
		{1, 0, "git_missing", "the box has no git"},
		{0, 128, "clone_failed", "only a public repository clones"},
	} {
		hh, f := newBoxCloneRun(t, sandboxremote.VendorE2B)
		f.gitCode, f.cloneCode = c.gitCode, c.cloneCode
		hh.run.vendor, _ = sandboxremote.VendorFor(sandboxremote.VendorE2B)
		hh.run.layout = hh.run.vendor.Layout(hh.run.plan.Root)
		hh.run.client = hh.client
		hh.run.rec.VendorID = "box1"
		hh.client.boxes["box1"] = &fakeBox{id: "box1", files: map[string][]byte{}}
		err := hh.run.coreBoxClone(context.Background())
		if err == nil || !strings.HasPrefix(err.Error(), c.code+":") || !strings.Contains(err.Error(), c.words) || !hh.run.cloneFailed {
			t.Errorf("%s: %v", c.code, err)
		}
	}
}
