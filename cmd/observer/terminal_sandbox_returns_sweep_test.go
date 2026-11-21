//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// copySweepFixture is one managed root with a source repository; add makes
// clone-local copies of it whose return is recorded as come back (the copy
// still at the source's HEAD, so the box made no new commit).
type copySweepFixture struct {
	t                 *testing.T
	obs, managed, src string
	head              string
	now               time.Time
	kept              map[string]time.Time
}

func newCopySweepFixture(t *testing.T) *copySweepFixture {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
	f := &copySweepFixture{t: t, obs: filepath.Join(root, "obs"), managed: filepath.Join(root, "workspaces"), src: filepath.Join(root, "src"), now: time.Now().UTC(), kept: map[string]time.Time{}}
	for _, d := range []string{f.obs, f.src, f.managed} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	fixtureGit(t, f.src, "init", "-q")
	_ = os.WriteFile(filepath.Join(f.src, ".gitignore"), []byte("*.log\n"), 0o600)
	_ = os.WriteFile(filepath.Join(f.src, "a.txt"), []byte("one\n"), 0o600)
	fixtureGit(t, f.src, "add", "-A")
	fixtureGit(t, f.src, "commit", "-qm", "one")
	f.head = fixtureGit(t, f.src, "rev-parse", "HEAD")
	return f
}

// add makes copy id whose work came home age ago (state is its recorded
// return), and returns the copy's folder.
func (f *copySweepFixture) add(id string, age time.Duration, state string) string {
	f.t.Helper()
	runDir := filepath.Join(f.managed, id)
	copyDir := filepath.Join(runDir, "src")
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		f.t.Fatal(err)
	}
	fixtureGit(f.t, f.managed, "clone", "-q", "--no-hardlinks", "--", f.src, copyDir)
	meta, _ := workspace.MarshalMeta(workspace.Meta{Source: workspace.SourceCloneLocal, Origin: f.src, RunID: id, CreatedAt: f.now.Add(-age - time.Hour)})
	_ = os.WriteFile(filepath.Join(runDir, "meta.json"), meta, 0o600)
	rec := sandboxLocalReturnRecord{
		V: sandboxLocalReturnVersion, RunID: id, Source: string(workspace.SourceCloneLocal), State: state, Commit: f.head, Commits: 0,
		Request:   &workspace.ReturnRequest{SourceRepo: f.src, CopyDir: copyDir, ManagedRoot: f.managed, RunID: id},
		CreatedAt: f.now.Add(-age - time.Hour), EndedAt: f.now.Add(-age),
	}
	if err := writeSandboxLocalReturn(f.obs, rec); err != nil {
		f.t.Fatal(err)
	}
	return copyDir
}

// sweep runs one age pass of days and records what it removed.
func (f *copySweepFixture) sweep(days int) (removed, stayed []copySweepOutcome) {
	removed, stayed = sweepReturnedCopies(context.Background(), f.obs, f.managed, days, f.now, f.kept, nil)
	return removed, stayed
}

func (f *copySweepFixture) exists(id string) bool {
	_, err := os.Stat(filepath.Join(f.managed, id))
	return err == nil
}

// TestReturnedCopySweep: one case per rule of the age sweep. An old copy
// whose work came back and that holds nothing else is removed and logged; an
// old copy holding work that never came back is kept with the removal
// table's reason (and not hashed again on the next pass); a young copy is
// not looked at; a copy whose return was refused is never touched.
func TestReturnedCopySweep(t *testing.T) {
	f := newCopySweepFixture(t)
	day := 24 * time.Hour
	f.add("RUNoldsafe00000001", 40*day, workspace.CopyReturnNothingNew)
	dirty := f.add("RUNolddirty0000001", 40*day, workspace.CopyReturnReturned)
	_ = os.WriteFile(filepath.Join(dirty, "notes.md"), []byte("draft\n"), 0o600)
	f.add("RUNyoung0000000001", 2*day, workspace.CopyReturnNothingNew)
	f.add("RUNrefused00000001", 90*day, workspace.CopyReturnRefused)

	removed, stayed := f.sweep(30)
	if len(removed) != 1 || removed[0].ID != "RUNoldsafe00000001" || removed[0].Bytes == 0 || removed[0].Origin != f.src {
		t.Fatalf("removed %+v", removed)
	}
	if len(stayed) != 1 || stayed[0].ID != "RUNolddirty0000001" || !strings.Contains(stayed[0].Reason, "not in its last commit") {
		t.Fatalf("kept %+v", stayed)
	}
	if f.exists("RUNoldsafe00000001") || !f.exists("RUNolddirty0000001") || !f.exists("RUNyoung0000000001") || !f.exists("RUNrefused00000001") {
		t.Fatal("the wrong copies went")
	}
	// The source repository is untouched.
	if h := fixtureGit(t, f.src, "rev-parse", "HEAD"); h != f.head {
		t.Fatal("the source's HEAD moved")
	}
	// The kept copy is not checked again within a day, even once it is clean.
	_ = os.Remove(filepath.Join(dirty, "notes.md"))
	if removed, stayed = f.sweep(30); len(removed) != 0 || len(stayed) != 0 {
		t.Fatalf("second pass %+v %+v", removed, stayed)
	}
	f.now = f.now.Add(25 * time.Hour)
	if removed, _ = f.sweep(30); len(removed) != 1 || removed[0].ID != "RUNolddirty0000001" {
		t.Fatalf("after a day %+v", removed)
	}
	// 0 days: nothing is removed, however old.
	if removed, stayed = f.sweep(0); len(removed) != 0 || len(stayed) != 0 || !f.exists("RUNyoung0000000001") {
		t.Fatalf("0 days %+v %+v", removed, stayed)
	}
}

// TestReturnedCopySweepBatchCap: one pass checks at most
// sandboxCopySweepBatch copies, oldest first; the next pass takes the rest.
func TestReturnedCopySweepBatchCap(t *testing.T) {
	f := newCopySweepFixture(t)
	n := sandboxCopySweepBatch + 2
	for i := range n {
		f.add(fmt.Sprintf("RUNcap%012d", i), time.Duration(60-i)*24*time.Hour, workspace.CopyReturnNothingNew)
	}
	removed, _ := f.sweep(30)
	if len(removed) != sandboxCopySweepBatch {
		t.Fatalf("first pass removed %d, want %d", len(removed), sandboxCopySweepBatch)
	}
	if removed[0].ID != "RUNcap000000000000" {
		t.Fatalf("not oldest first: %+v", removed)
	}
	if !f.exists(fmt.Sprintf("RUNcap%012d", n-1)) {
		t.Fatal("the newest went in the first pass")
	}
	if removed, _ = f.sweep(30); len(removed) != 2 {
		t.Fatalf("second pass removed %d, want 2", len(removed))
	}
}

// TestReturnedCopySweepRetentionKey: the loop's entry reads the key; 0 (or
// the module off) runs nothing, and a pass runs at most once an hour.
func TestReturnedCopySweepRetentionKey(t *testing.T) {
	f := newCopySweepFixture(t)
	f.add("RUNkey000000000001", 40*24*time.Hour, workspace.CopyReturnNothingNew)
	oldEnv, oldDays := sandboxReturnsEnv, sandboxCopySweepRetention
	t.Cleanup(func() { sandboxReturnsEnv, sandboxCopySweepRetention = oldEnv, oldDays })
	sandboxReturnsEnv = func(string) (string, string, bool) { return f.obs, f.managed, true }
	days := 0
	sandboxCopySweepRetention = func(string) int { return days }
	sandboxCopySweepers.Delete(f.obs)
	maybeSweepReturnedCopies(context.Background(), f.obs, f.now, nil)
	if !f.exists("RUNkey000000000001") {
		t.Fatal("0 days removed a copy")
	}
	days = 30
	maybeSweepReturnedCopies(context.Background(), f.obs, f.now.Add(time.Minute), nil)
	if !f.exists("RUNkey000000000001") {
		t.Fatal("a second pass within the hour ran")
	}
	maybeSweepReturnedCopies(context.Background(), f.obs, f.now.Add(2*time.Hour), nil)
	if f.exists("RUNkey000000000001") {
		t.Fatal("the due pass did not remove the old clean copy")
	}
	f.add("RUNkey000000000002", 40*24*time.Hour, workspace.CopyReturnNothingNew)
	sandboxReturnsEnv = func(string) (string, string, bool) { return f.obs, f.managed, false }
	maybeSweepReturnedCopies(context.Background(), f.obs, f.now.Add(5*time.Hour), nil)
	if !f.exists("RUNkey000000000002") {
		t.Fatal("the sweep ran with the module off")
	}
}

// TestRemoveSafeCopiesRoute: the panel's one click removes every copy the
// removal table allows, whatever its age, and lists each kept copy with its
// reason; it needs the confirm token.
func TestRemoveSafeCopiesRoute(t *testing.T) {
	f := newCopySweepFixture(t)
	f.add("RUNsafeold00000001", 40*24*time.Hour, workspace.CopyReturnNothingNew)
	f.add("RUNsafenew00000001", time.Hour, workspace.CopyReturnNothingNew)
	dirty := f.add("RUNdirty0000000001", time.Hour, workspace.CopyReturnReturned)
	_ = os.WriteFile(filepath.Join(dirty, "a.txt"), []byte("changed\n"), 0o600)
	f.add("RUNrefused00000001", time.Hour, workspace.CopyReturnRefused)

	old := sandboxReturnsEnv
	sandboxReturnsEnv = func(string) (string, string, bool) { return f.obs, f.managed, true }
	t.Cleanup(func() { sandboxReturnsEnv = old })
	mux := http.NewServeMux()
	for _, r := range sandboxReturnsRoutes("") {
		mux.HandleFunc(r.Pattern, r.Handler)
	}
	req := httptest.NewRequest(http.MethodPost, sandboxReturnsRemoveSafePath, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !f.exists("RUNsafeold00000001") {
		t.Fatalf("no token: %d", w.Code)
	}
	req = httptest.NewRequest(http.MethodPost, sandboxReturnsRemoveSafePath, strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hostedConfirmHeader, strings.Repeat("a", 64))
	req.AddCookie(&http.Cookie{Name: hostedConfirmCookie, Value: strings.Repeat("a", 64)})
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	var res copyBulkResult
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &res) != nil {
		t.Fatalf("click %d %s", w.Code, w.Body.String())
	}
	if len(res.Removed) != 2 || res.Freed <= 0 || len(res.Kept) != 2 || res.Left != 0 {
		t.Fatalf("result %+v", res)
	}
	reasons := map[string]string{}
	for _, k := range res.Kept {
		reasons[k.ID] = k.Reason
	}
	if !strings.Contains(reasons["RUNdirty0000000001"], "changed or missing") || !strings.Contains(reasons["RUNrefused00000001"], "did not come back") {
		t.Fatalf("kept %+v", res.Kept)
	}
	if f.exists("RUNsafeold00000001") || f.exists("RUNsafenew00000001") || !f.exists("RUNdirty0000000001") || !f.exists("RUNrefused00000001") {
		t.Fatal("the wrong copies went")
	}
}
