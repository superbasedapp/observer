//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// The boundary audit's content fingerprints (review finding M3), against a real
// temporary repository: the status line of a file that was already dirty does
// not change when it is edited again, and the audit has to see that.

// assessGit runs git in dir and returns its trimmed output.
func assessGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v %s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func assessWrite(t *testing.T, root, rel, body string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// assessRepo builds a repository with two committed files (a.go, b.go) and the
// state of a developer who is mid-edit: a.go modified, u.txt untracked, and an
// untracked file inside a new directory. It returns the top level.
func assessRepo(t *testing.T) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	repo := t.TempDir()
	assessGit(t, repo, "init", "-q")
	assessGit(t, repo, "config", "core.autocrlf", "false")
	assessGit(t, repo, "config", "commit.gpgsign", "false")
	assessWrite(t, repo, "a.go", "package a // committed\n")
	assessWrite(t, repo, "b.go", "package b // committed\n")
	assessGit(t, repo, "add", "-A")
	assessGit(t, repo, "commit", "-q", "-m", "init")
	assessWrite(t, repo, "a.go", "package a // dirty, before the run\n")
	assessWrite(t, repo, "u.txt", "untracked, before the run\n")
	assessWrite(t, repo, "newdir/n.txt", "untracked in a new directory, before the run\n")
	return repo
}

func assessSnap(t *testing.T, root string, policy secassess.TreePolicy) secassess.TreeSnapshot {
	t.Helper()
	s := securityAssessTakeTree(context.Background(), root, time.Now(), policy)
	if !s.OK {
		t.Fatalf("the snapshot of %s could not be taken", root)
	}
	return s
}

func assessEntry(s secassess.TreeSnapshot, path string) (secassess.TreeEntry, bool) {
	for _, e := range s.Entries {
		if e.Path == path {
			return e, true
		}
	}
	return secassess.TreeEntry{}, false
}

// TestSecurityAssessTreeAudit: one row per way a run can touch a project that
// was already dirty when it started, taken with the real snapshot function.
func TestSecurityAssessTreeAudit(t *testing.T) {
	cases := []struct {
		name   string
		policy secassess.TreePolicy
		edit   func(t *testing.T, repo string)
		want   secassess.AuditVerdict
		tracks []string // Audit.TrackedChanged
		edited []string // Audit.UntrackedEdited
	}{
		{"nothing edited, strict", secassess.TreeStrict, func(*testing.T, string) {}, secassess.AuditNoChange, nil, nil},
		{"nothing edited, untracked reported", secassess.TreeUntrackedReported, func(*testing.T, string) {}, secassess.AuditNoChange, nil, nil},
		{"a dirty tracked file edited again, strict", secassess.TreeStrict, func(t *testing.T, r string) {
			assessWrite(t, r, "a.go", "package a // edited by the agent\n")
		}, secassess.AuditChanged, []string{"a.go"}, nil},
		{"a dirty tracked file edited again, untracked reported", secassess.TreeUntrackedReported, func(t *testing.T, r string) {
			assessWrite(t, r, "a.go", "package a // edited by the agent\n")
		}, secassess.AuditChanged, []string{"a.go"}, nil},
		{"a dirty tracked file rewritten with the same bytes", secassess.TreeStrict, func(t *testing.T, r string) {
			assessWrite(t, r, "a.go", "package a // dirty, before the run\n")
		}, secassess.AuditNoChange, nil, nil},
		{"an untracked file edited, strict", secassess.TreeStrict, func(t *testing.T, r string) {
			assessWrite(t, r, "u.txt", "untracked, rewritten by the agent\n")
		}, secassess.AuditChanged, nil, []string{"u.txt"}},
		{"an untracked file in a new directory edited, strict", secassess.TreeStrict, func(t *testing.T, r string) {
			assessWrite(t, r, "newdir/n.txt", "rewritten by the agent\n")
		}, secassess.AuditChanged, nil, []string{"newdir/n.txt"}},
		{"an untracked file edited, untracked reported", secassess.TreeUntrackedReported, func(t *testing.T, r string) {
			assessWrite(t, r, "u.txt", "untracked, rewritten by the agent\n")
		}, secassess.AuditNoChange, nil, nil},
		{"a clean tracked file edited, strict", secassess.TreeStrict, func(t *testing.T, r string) {
			assessWrite(t, r, "b.go", "package b // edited by the agent\n")
		}, secassess.AuditChanged, []string{"b.go"}, nil},
		{"a dirty file put back to the committed content", secassess.TreeStrict, func(t *testing.T, r string) {
			assessWrite(t, r, "a.go", "package a // committed\n")
		}, secassess.AuditChanged, []string{"a.go"}, nil},
		{"a dirty file deleted", secassess.TreeStrict, func(t *testing.T, r string) {
			if err := os.Remove(filepath.Join(r, "a.go")); err != nil {
				t.Fatal(err)
			}
		}, secassess.AuditChanged, []string{"a.go"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			repo := assessRepo(t)
			before := assessSnap(t, repo, c.policy)
			c.edit(t, repo)
			after := assessSnap(t, repo, c.policy)
			got := secassess.AuditTree(before, after, c.policy)
			if got.Verdict != c.want {
				t.Fatalf("verdict %s (reason %q, uncompared %d), want %s; audit %+v", got.Verdict, got.Reason, got.Uncompared, c.want, got)
			}
			if strings.Join(got.TrackedChanged, ",") != strings.Join(c.tracks, ",") || strings.Join(got.UntrackedEdited, ",") != strings.Join(c.edited, ",") {
				t.Fatalf("tracked %v, untracked edited %v; want %v, %v", got.TrackedChanged, got.UntrackedEdited, c.tracks, c.edited)
			}
		})
	}
}

// TestSecurityAssessTreeFingerprints: what the snapshot records for each kind of
// entry, and that a fingerprint is the git hash of the file's bytes.
func TestSecurityAssessTreeFingerprints(t *testing.T) {
	repo := assessRepo(t)
	assessGit(t, repo, "rm", "-q", "--cached", "b.go") // a staged deletion, and the file is removed below
	if err := os.Remove(filepath.Join(repo, "b.go")); err != nil {
		t.Fatal(err)
	}
	s := assessSnap(t, repo, secassess.TreeStrict)

	want := func(rel string) string {
		return assessGit(t, repo, "hash-object", "--no-filters", "--", rel)[:secassess.FpLen]
	}
	for _, rel := range []string{"a.go", "u.txt", "newdir/n.txt"} {
		e, ok := assessEntry(s, rel)
		if !ok {
			t.Fatalf("%s is not in the snapshot: %+v", rel, s.Entries)
		}
		if e.Fp != want(rel) || len(e.Fp) != secassess.FpLen {
			t.Errorf("%s: fingerprint %q, git hash-object says %q", rel, e.Fp, want(rel))
		}
	}
	// Strict lists the files of an untracked directory one by one.
	if _, ok := assessEntry(s, "newdir/"); ok {
		t.Errorf("an untracked directory is listed as one entry: %+v", s.Entries)
	}
	// A deleted file has the stable "absent" fingerprint, not an error.
	if e, ok := assessEntry(s, "b.go"); !ok || e.Fp != secassess.FpAbsent || !e.Deleted() {
		t.Errorf("b.go = %+v, %v", e, ok)
	}
	// Under the reported-only policy untracked files are neither listed one by one
	// nor fingerprinted, and tracked ones still are.
	r := assessSnap(t, repo, secassess.TreeUntrackedReported)
	if e, ok := assessEntry(r, "a.go"); !ok || e.Fp == "" {
		t.Errorf("a.go = %+v, %v", e, ok)
	}
	if e, ok := assessEntry(r, "newdir/"); !ok || e.Fp != "" {
		t.Errorf("newdir/ = %+v, %v", e, ok)
	}
	if e, ok := assessEntry(r, "u.txt"); !ok || e.Fp != "" {
		t.Errorf("u.txt = %+v, %v", e, ok)
	}
}

// TestSecurityAssessTreeSubfolderRoot: a project that is a folder inside a
// repository still fingerprints its files (status paths are relative to the
// top level, not to the project).
func TestSecurityAssessTreeSubfolderRoot(t *testing.T) {
	repo := assessRepo(t)
	assessWrite(t, repo, "svc/api/h.go", "package api // committed\n")
	assessGit(t, repo, "add", "svc/api/h.go")
	assessGit(t, repo, "commit", "-q", "-m", "svc")
	assessWrite(t, repo, "svc/api/h.go", "package api // dirty, before the run\n")
	root := filepath.Join(repo, "svc")
	before := assessSnap(t, root, secassess.TreeStrict)
	if e, ok := assessEntry(before, "svc/api/h.go"); !ok || e.Fp == "" || len(before.Entries) != 1 {
		t.Fatalf("snapshot of the subfolder = %+v", before.Entries)
	}
	if a := secassess.AuditTree(before, assessSnap(t, root, secassess.TreeStrict), secassess.TreeStrict); a.Verdict != secassess.AuditNoChange {
		t.Fatalf("untouched subfolder: %+v", a)
	}
	assessWrite(t, repo, "svc/api/h.go", "package api // edited by the agent\n")
	a := secassess.AuditTree(before, assessSnap(t, root, secassess.TreeStrict), secassess.TreeStrict)
	if a.Verdict != secassess.AuditChanged || strings.Join(a.TrackedChanged, ",") != "svc/api/h.go" {
		t.Fatalf("edited subfolder file: %+v", a)
	}
}

// TestSecurityAssessTreeNotFingerprinted: a nested repository cannot be hashed
// as a file, so under a strict policy the audit says it could not compare it
// instead of reading no change.
func TestSecurityAssessTreeNotFingerprinted(t *testing.T) {
	repo := assessRepo(t)
	nested := filepath.Join(repo, "vendor", "lib")
	if err := os.MkdirAll(nested, 0o750); err != nil {
		t.Fatal(err)
	}
	assessGit(t, nested, "init", "-q")
	assessWrite(t, nested, "x.go", "package lib\n")
	s := assessSnap(t, repo, secassess.TreeStrict)
	e, ok := assessEntry(s, "vendor/lib/")
	if !ok || e.Fp != "" {
		t.Fatalf("the nested repository = %+v, %v (entries %+v)", e, ok, s.Entries)
	}
	a := secassess.AuditTree(s, assessSnap(t, repo, secassess.TreeStrict), secassess.TreeStrict)
	if a.Verdict != secassess.AuditPartial || a.Reason != secassess.ReasonNotFingerprinted || a.Uncompared != 1 {
		t.Fatalf("audit = %+v", a)
	}
	// Under the reported-only policy untracked content does not count, so the
	// same state has nothing to say.
	r := assessSnap(t, repo, secassess.TreeUntrackedReported)
	if a := secassess.AuditTree(r, assessSnap(t, repo, secassess.TreeUntrackedReported), secassess.TreeUntrackedReported); a.Verdict != secassess.AuditNoChange {
		t.Fatalf("reported-only audit = %+v", a)
	}
}

// TestSecurityAssessTreeCap: more changed paths than the snapshot keeps is
// partly checked, never no change; an edit that is seen still reads changed.
func TestSecurityAssessTreeCap(t *testing.T) {
	repo := assessRepo(t)
	for i := 0; i < secassess.MaxTreeEntries+5; i++ {
		assessWrite(t, repo, "bulk/f"+strconv.Itoa(1000+i)+".txt", "x\n")
	}
	before := assessSnap(t, repo, secassess.TreeStrict)
	if !before.Truncated || len(before.Entries) != secassess.MaxTreeEntries {
		t.Fatalf("%d entries, truncated %v", len(before.Entries), before.Truncated)
	}
	a := secassess.AuditTree(before, assessSnap(t, repo, secassess.TreeStrict), secassess.TreeStrict)
	if a.Verdict != secassess.AuditPartial || a.Reason != secassess.ReasonTruncated {
		t.Fatalf("audit = %+v", a)
	}
	assessWrite(t, repo, "a.go", "package a // edited by the agent\n")
	if a := secassess.AuditTree(before, assessSnap(t, repo, secassess.TreeStrict), secassess.TreeStrict); a.Verdict != secassess.AuditChanged {
		t.Fatalf("an edit past the truncation read %s", a.Verdict)
	}
}

// TestSecurityAssessTreeSymlink: a link is fingerprinted by its target text, so
// a retargeted link is a change (skipped where links cannot be made).
func TestSecurityAssessTreeSymlink(t *testing.T) {
	repo := assessRepo(t)
	link := filepath.Join(repo, "cfg.link")
	if err := os.Symlink("a.go", link); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
	before := assessSnap(t, repo, secassess.TreeStrict)
	e, ok := assessEntry(before, "cfg.link")
	if !ok || e.Fp != secassess.LinkFingerprint("a.go") {
		t.Fatalf("link entry = %+v, %v", e, ok)
	}
	if a := secassess.AuditTree(before, assessSnap(t, repo, secassess.TreeStrict), secassess.TreeStrict); a.Verdict != secassess.AuditNoChange {
		t.Fatalf("untouched link: %+v", a)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b.go", link); err != nil {
		t.Skipf("symbolic links are not available here: %v", err)
	}
	a := secassess.AuditTree(before, assessSnap(t, repo, secassess.TreeStrict), secassess.TreeStrict)
	if a.Verdict != secassess.AuditChanged || strings.Join(a.UntrackedEdited, ",") != "cfg.link" {
		t.Fatalf("retargeted link: %+v", a)
	}
}

// TestSecurityAssessTreeNotARepository: no repository is a snapshot that is not
// OK, which the audit reads as could-not-check, never as no change.
func TestSecurityAssessTreeNotARepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	s := securityAssessTakeTree(context.Background(), dir, time.Now(), secassess.TreeStrict)
	if s.OK {
		t.Fatalf("a folder that is not a repository gave an OK snapshot: %+v", s)
	}
	if a := secassess.AuditTree(s, s, secassess.TreeStrict); a.Verdict != secassess.AuditUnchecked {
		t.Fatalf("audit = %+v", a)
	}
}

// TestSecurityAssessHashPathsBisects: when one path of a batch cannot be read
// the batch is halved until that path stands alone, so it costs only itself; a
// missing git stops at once.
func TestSecurityAssessHashPathsBisects(t *testing.T) {
	hashOf := func(path string) string { return strings.Repeat(string(rune('a'+len(path)%6)), 40) }
	fake := func(bad map[string]bool, calls *int) securityAssessRunGit {
		return func(args ...string) ([]byte, error) {
			*calls++
			if len(args) < 4 || args[0] != "hash-object" || args[1] != "--no-filters" || args[2] != "--" {
				t.Errorf("unexpected arguments %v", args)
			}
			var out strings.Builder
			for _, p := range args[3:] {
				if bad[p] {
					return nil, &gitview.GitError{Args: args, ExitCode: 128, Stderr: "fatal: could not open '" + p + "'"}
				}
				out.WriteString(hashOf(p) + "\n")
			}
			return []byte(out.String()), nil
		}
	}
	paths := []string{"a", "bb", "ccc", "dddd", "eeeee", "ffffff", "g"}
	t.Run("all readable: one command", func(t *testing.T) {
		calls := 0
		got := securityAssessHashPaths(context.Background(), fake(nil, &calls), paths)
		if calls != 1 {
			t.Fatalf("%d commands", calls)
		}
		for i, p := range paths {
			if got[i] != hashOf(p)[:secassess.FpLen] {
				t.Fatalf("%s = %q", p, got[i])
			}
		}
	})
	t.Run("one unreadable path costs only itself", func(t *testing.T) {
		calls := 0
		got := securityAssessHashPaths(context.Background(), fake(map[string]bool{"dddd": true}, &calls), paths)
		for i, p := range paths {
			if p == "dddd" {
				if got[i] != "" {
					t.Fatalf("the unreadable path has fingerprint %q", got[i])
				}
				continue
			}
			if got[i] != hashOf(p)[:secassess.FpLen] {
				t.Fatalf("%s = %q", p, got[i])
			}
		}
		if calls > 2*len(paths) {
			t.Fatalf("%d commands for %d paths", calls, len(paths))
		}
	})
	t.Run("a missing git is not retried", func(t *testing.T) {
		calls := 0
		run := func(...string) ([]byte, error) { calls++; return nil, gitview.ErrGitUnavailable }
		got := securityAssessHashPaths(context.Background(), run, paths)
		if calls != 1 {
			t.Fatalf("%d commands", calls)
		}
		for _, fp := range got {
			if fp != "" {
				t.Fatalf("fingerprints = %v", got)
			}
		}
	})
	t.Run("output that does not match the paths is a failed batch", func(t *testing.T) {
		run := func(args ...string) ([]byte, error) {
			if len(args) > 4 {
				return []byte(strings.Repeat("a", 40) + "\n"), nil // one line for several paths
			}
			return []byte(strings.Repeat("b", 40) + "\n"), nil
		}
		got := securityAssessHashPaths(context.Background(), run, paths[:3])
		for _, fp := range got {
			if fp != strings.Repeat("b", secassess.FpLen) {
				t.Fatalf("fingerprints = %v", got)
			}
		}
	})
	t.Run("an expired budget fingerprints nothing", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		calls := 0
		got := securityAssessHashPaths(ctx, fake(nil, &calls), paths)
		if calls != 0 {
			t.Fatalf("%d commands after the budget", calls)
		}
		for _, fp := range got {
			if fp != "" {
				t.Fatalf("fingerprints = %v", got)
			}
		}
	})
	t.Run("a refused git is not retried", func(t *testing.T) {
		calls := 0
		run := func(...string) ([]byte, error) { calls++; return nil, gitview.ErrHostGitRefused }
		securityAssessHashPaths(context.Background(), run, paths)
		if calls != 1 {
			t.Fatalf("%d commands", calls)
		}
	})
}

func TestSecurityAssessWholeRecords(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"a stream that ends on a record", " M a.go\x00?? b\x00", " M a.go\x00?? b\x00"},
		{"a record cut in the middle", " M a.go\x00?? b/c", " M a.go\x00"},
		{"nothing complete", "?? half", ""},
		{"empty", "", ""},
	}
	for _, c := range cases {
		if got := string(securityAssessWholeRecords([]byte(c.in))); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}
