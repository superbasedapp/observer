package landingscan

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/gitview"
)

// TestRunOnARealRepository drives the step over a real repository with every
// local landing shape, through the production read-only git envelope, and
// proves the user's repository is byte-for-byte unchanged afterwards (refs,
// packed-refs, config, the object store listing, info/alternates and
// FETCH_HEAD).
//
//	c1  pushed to origin/main directly             -> landed, exact sha (L1)
//	c4  first commit of branch "sq", squash-merged -> landed, squash (L3)
//	c5  second commit of "sq"                      -> landed, squash (L3)
//	c3  on branch "rb", cherry-picked onto main    -> landed, patch id (L2)
//	c2  on branch "feature", pushed, not merged    -> pushed (L6)
//	c6  on a local branch, never pushed            -> in flight (L8)
func TestRunOnARealRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	t.Setenv("HOME", base)
	t.Setenv("XDG_CONFIG_HOME", base)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	for k, v := range map[string]string{
		"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.com",
		"GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@example.com",
	} {
		t.Setenv(k, v)
	}
	remote := filepath.Join(base, "remote.git")
	user := filepath.Join(base, "user")
	// The harness's own writes (commit, merge, cherry-pick, push, fetch) end
	// by starting automatic maintenance, and git detaches it into the
	// background (gc.autoDetach, and maintenance.autoDetach since git 2.47).
	// On a recent git that background job packs refs or writes into the
	// object store while the landing scan runs, so the before/after snapshot
	// would blame the scan for a write the fixture started. Auto maintenance
	// is turned off for the harness commands only; the scan's own commands
	// run through the production envelope unchanged.
	noAutoMaintenance := []string{
		"-c", "gc.auto=0", "-c", "gc.autoDetach=false",
		"-c", "maintenance.auto=false", "-c", "maintenance.autoDetach=false",
	}
	run := func(dir string, args ...string) string {
		t.Helper()
		full := append(append([]string{"-C", dir}, noAutoMaintenance...), args...)
		cmd := exec.Command("git", full...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
		return strings.TrimSpace(string(out))
	}
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(user, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(msg string) string {
		run(user, "add", "-A")
		run(user, "commit", "-q", "-m", msg)
		return run(user, "rev-parse", "HEAD")
	}

	if err := os.MkdirAll(user, 0o755); err != nil {
		t.Fatal(err)
	}
	run(base, "init", "-q", "--bare", remote)
	run(remote, "symbolic-ref", "HEAD", "refs/heads/main")
	run(user, "init", "-q")
	run(user, "symbolic-ref", "HEAD", "refs/heads/main")
	// The remote reads as a GitHub URL (a local path is not a code host and
	// would be skipped); insteadOf sends the harness's own push and fetch to
	// the local bare repository. The landing step itself never fetches.
	const remoteURL = "https://github.com/acme/widget.git"
	run(user, "config", "url."+remote+".insteadOf", remoteURL)
	run(user, "remote", "add", "origin", remoteURL)

	write("base.txt", "base\n")
	commit("base")
	write("one.txt", "one\n")
	c1 := commit("c1 direct")
	run(user, "push", "-q", "origin", "main")

	run(user, "checkout", "-q", "-b", "sq")
	write("sq.txt", "squash part one\n")
	c4 := commit("c4")
	write("sq.txt", "squash part one\nsquash part two\n")
	write("sq2.txt", "second file\n")
	c5 := commit("c5")
	run(user, "checkout", "-q", "main")
	run(user, "merge", "--squash", "-q", "sq")
	commit("Squash the sq work (#9)")

	run(user, "checkout", "-q", "-b", "rb")
	write("rb.txt", "rebased change\n")
	c3 := commit("c3")
	run(user, "checkout", "-q", "main")
	// main moves on first, so the cherry-pick has a different parent and
	// can never reproduce c3's sha byte for byte (inside one clock second a
	// pick onto the same parent is the same object, an L1 landing).
	write("main-moved.txt", "main moved on\n")
	commit("main moves on")
	run(user, "cherry-pick", c3)
	run(user, "push", "-q", "origin", "main")

	run(user, "checkout", "-q", "-b", "feature")
	write("feature.txt", "feature\n")
	c2 := commit("c2")
	run(user, "push", "-q", "origin", "feature")

	run(user, "checkout", "-q", "main")
	run(user, "checkout", "-q", "-b", "local6")
	write("local.txt", "local only\n")
	c6 := commit("c6")
	run(user, "fetch", "-q", "origin")

	now := time.Now().UTC()
	ids := map[string]int64{c1: 1, c2: 2, c3: 3, c4: 4, c5: 5, c6: 6}
	st := &fakeStore{}
	for sha, id := range ids {
		st.commits = append(st.commits, delivery.Commit{
			ID: id, ProjectID: 1, SHA: sha, CommittedAt: now.Add(-time.Minute), Reachable: true,
			AIContributor: true, PatchFPState: delivery.FPPending, SessionIDs: []string{"s1"},
		})
	}
	sort.Slice(st.commits, func(i, j int) bool { return st.commits[i].ID < st.commits[j].ID })

	before := snapshotGitDir(t, filepath.Join(user, ".git"))

	opts := st.options(&fakeGit{}, now)
	opts.Exec = func(ctx context.Context, dir string, maxBytes int, args ...string) ([]byte, bool, error) {
		return gitview.RunReadOnlyNoLazyFetch(ctx, dir, maxBytes, 30*time.Second, args...)
	}
	opts.ExitCode = func(err error) (int, bool) {
		f, ok := gitview.InspectError(err)
		return f.ExitCode, ok
	}
	opts.ModTime = func(p string) (time.Time, bool) {
		fi, err := os.Stat(p)
		if err != nil {
			return time.Time{}, false
		}
		return fi.ModTime(), true
	}
	// The fingerprints the step persists feed the next read, as the store
	// would.
	opts.Commits = func(context.Context, int64, time.Time) ([]delivery.Commit, error) {
		out := append([]delivery.Commit(nil), st.commits...)
		for i := range out {
			if fp, ok := st.fps[out[i].ID]; ok {
				out[i].PatchFP, out[i].PatchFPState = fp[0], fp[1]
			}
		}
		return out, nil
	}

	res, err := New(opts).Run(context.Background(), Target{ProjectID: 1, RootPath: user, HeadSHA: c6})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Fingerprinted != 6 || res.Remotes != 1 || res.Source != delivery.SourceUserRefs {
		t.Fatalf("result = %+v", res)
	}
	if r := st.remotes[0]; r.DefaultBranch != "main" || r.FetchHeadAt.IsZero() || r.DefaultRefSHA == "" {
		t.Fatalf("remote = %+v", r)
	}

	got := map[int64]delivery.Landing{}
	for _, l := range st.saved {
		got[l.CommitID] = l
	}
	want := []struct {
		id     int64
		rule   string
		status delivery.LandingStatus
		kind   delivery.LandingKind
		pr     int64
	}{
		{1, "L1", delivery.StatusLanded, delivery.KindExactSHA, 0},
		{2, "L6", delivery.StatusPushed, "", 0},
		{3, "L2", delivery.StatusLanded, delivery.KindPatchID, 0},
		{4, "L3", delivery.StatusLanded, delivery.KindSquash, 9},
		{5, "L3", delivery.StatusLanded, delivery.KindSquash, 9},
		{6, "L8", delivery.StatusInFlight, "", 0},
	}
	for _, w := range want {
		l := got[w.id]
		if l.RuleID != w.rule || l.Status != w.status || l.Kind != w.kind || l.PRNumber != w.pr {
			t.Errorf("commit %d: got rule=%s status=%s kind=%s pr=%d, want %s %s %s %d",
				w.id, l.RuleID, l.Status, l.Kind, l.PRNumber, w.rule, w.status, w.kind, w.pr)
		}
	}
	// The squash branch tip was recorded under a hashed name.
	foundTip := false
	for _, tip := range st.tips {
		if tip.RefName == "refs/heads/sq" {
			foundTip = tip.RefNameHash != "" && !strings.Contains(tip.RefNameHash, "sq") && tip.RangeFPState == delivery.FPOK
		}
	}
	if !foundTip {
		t.Fatalf("squash tip not recorded: %+v", st.tips)
	}

	after := snapshotGitDir(t, filepath.Join(user, ".git"))
	if diff := snapshotDiff(before, after); len(diff) > 0 {
		t.Fatalf("the user's repository changed during the landing scan:\n%s", strings.Join(diff, "\n"))
	}
}

// snapshotGitDir fingerprints everything a write into a repository would
// touch: refs (loose and packed), config, every object file's name, the
// alternates file and FETCH_HEAD (content and mtime). The index and logs are
// excluded: a read-only command with --no-optional-locks does not refresh
// the index, but they are not part of the never-write contract either way.
// The result maps each entry's path to its fingerprint, so a failure names
// the entries that changed.
func snapshotGitDir(t *testing.T, gitDir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	add := func(rel string) {
		p := filepath.Join(gitDir, rel)
		b, err := os.ReadFile(p)
		if err != nil {
			out[rel] = "absent"
			return
		}
		fi, _ := os.Stat(p)
		h := sha256.New()
		h.Write([]byte(fi.ModTime().String() + ":"))
		h.Write(b)
		out[rel] = hex.EncodeToString(h.Sum(nil))
	}
	for _, f := range []string{"config", "packed-refs", "info/alternates", "FETCH_HEAD", "HEAD"} {
		add(f)
	}
	for _, sub := range []string{"refs", "objects"} {
		_ = filepath.WalkDir(filepath.Join(gitDir, sub), func(p string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(gitDir, p)
			if sub == "refs" {
				add(rel)
			} else {
				out[rel] = "present"
			}
			return nil
		})
	}
	return out
}

// snapshotDiff lists the entries that differ between two snapshots, sorted.
func snapshotDiff(before, after map[string]string) []string {
	var diff []string
	for k, b := range before {
		a, ok := after[k]
		switch {
		case !ok:
			diff = append(diff, "removed "+k)
		case a != b:
			diff = append(diff, "changed "+k)
		}
	}
	for k := range after {
		if _, ok := before[k]; !ok {
			diff = append(diff, "added   "+k)
		}
	}
	sort.Strings(diff)
	return diff
}
