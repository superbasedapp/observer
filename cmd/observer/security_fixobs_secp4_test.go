//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/commitlog"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// inferRepo is a fix observation seed whose root is a git repository
// holding auth/views.py, with an agent edit adding a CSRF exemption there
// under a prompt about the navbar (S-764 and S-770 inferences).
type inferRepo struct {
	*fixObsSeed
	l   *fixObsLoop
	at  time.Time
	ids map[string]string
}

const inferBase = "def login(r):\n    return r\n"

func newInferRepo(t *testing.T) *inferRepo {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	s := newFixObsSeed(t)
	gitInitMain(t, s.root)
	r := &inferRepo{fixObsSeed: s, at: time.Now().UTC().Truncate(time.Second)}
	r.write(t, "auth/views.py", inferBase)
	r.write(t, "README", "x\n")
	gitRun(t, s.root, "add", "-A")
	gitRun(t, s.root, "commit", "-q", "-m", "base")
	ctx := context.Background()
	s.action(t, models.ActionUserPrompt, "make the navbar blue", "", r.at.Add(-time.Minute), true)
	r.l = &fixObsLoop{st: s.st, logger: discardLogger(), started: r.at}
	r.l.inferNewEdits(ctx)
	s.action(t, models.ActionEditFile, "auth/views.py", `{"file_path":"auth/views.py","old_string":"def login(r):","new_string":"@csrf_exempt\ndef login(r):"}`, r.at, true)
	r.l.inferNewEdits(ctx)
	r.ids = map[string]string{}
	got, err := s.st.ListSecFindings(ctx, store.SecFindingFilter{ProjectRootHash: secposture.ProjectRootHash(s.root)})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range got {
		r.ids[f.Rule.ID] = f.ID
		if !f.FirstSeen.Equal(r.at) {
			t.Fatalf("%s first seen %v, want the edit's time %v", f.Rule.ID, f.FirstSeen, r.at)
		}
	}
	if r.ids["code.s-764"] == "" || r.ids["code.s-770"] == "" {
		t.Fatalf("precondition: inferences %v", r.ids)
	}
	return r
}

func (r *inferRepo) write(t *testing.T, rel, body string) {
	t.Helper()
	p := filepath.Join(r.root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// commit commits the tree and records the commit (the commit scanner's
// rows) at the given offset after the edit.
func (r *inferRepo) commit(t *testing.T, msg string, after time.Duration, files ...string) {
	t.Helper()
	gitRun(t, r.root, "add", "-A")
	gitRun(t, r.root, "commit", "-q", "-m", msg)
	sha := gitRun(t, r.root, "rev-parse", "HEAD")
	at := r.at.Add(after)
	c := commitlog.Commit{SHA: sha, CommittedAt: at, AuthoredAt: at, Subject: msg}
	for _, f := range files {
		c.Files = append(c.Files, commitlog.CommitFile{RelPath: f, Added: 1})
	}
	if _, err := r.st.UpsertCommits(context.Background(), r.pid, []commitlog.Commit{c}, at); err != nil {
		t.Fatal(err)
	}
}

func (r *inferRepo) settle(t *testing.T) {
	t.Helper()
	r.l.settleInferences(context.Background(), r.at.Add(time.Hour))
}

func (r *inferRepo) status(t *testing.T, rule string) policy.FindingStatus {
	t.Helper()
	return findingStatus(t, r.st, r.ids[rule])
}

// TestInferenceClosure is the closure table of lane SEC-P4 decision 13,
// one case per row: no later commit keeps it; a later commit that still
// carries the change keeps it, and so does an unrelated later commit of
// the same file; a later commit that undoes the change closes it (S-764
// once the exemption is gone, S-770, judged against the stored prompt,
// once the file is back as it was); a deleted file closes it.
func TestInferenceClosure(t *testing.T) {
	t.Run("no later commit", func(t *testing.T) {
		r := newInferRepo(t)
		r.settle(t)
		if r.status(t, "code.s-764") != policy.FindingStatusOpen {
			t.Fatal("closed with no later commit")
		}
	})
	t.Run("committed, then undone", func(t *testing.T) {
		r := newInferRepo(t)
		r.write(t, "auth/views.py", "@csrf_exempt\n"+inferBase)
		r.commit(t, "login", time.Minute, "auth/views.py")
		r.settle(t)
		for _, rule := range []string{"code.s-764", "code.s-770"} {
			if r.status(t, rule) != policy.FindingStatusOpen {
				t.Fatalf("%s closed while its commit still raises it", rule)
			}
		}
		// An unrelated change of another part of the file: the committed
		// change since the edit still adds the exemption.
		r.write(t, "auth/views.py", "@csrf_exempt\n"+inferBase+"# note\n")
		r.commit(t, "note", 2*time.Minute, "auth/views.py")
		r.settle(t)
		if r.status(t, "code.s-764") != policy.FindingStatusOpen {
			t.Fatal("an unrelated later commit of the file closed it")
		}
		r.write(t, "auth/views.py", inferBase+"# note\n")
		r.commit(t, "drop the exemption", 3*time.Minute, "auth/views.py")
		r.settle(t)
		if got := r.status(t, "code.s-764"); got != policy.FindingStatusNotReproduced {
			t.Fatalf("S-764 = %s once the exemption was undone, want not_reproduced", got)
		}
		// Scope drift is about the file being changed at all: it stays
		// while the committed change of the file outside the prompt stays.
		if got := r.status(t, "code.s-770"); got != policy.FindingStatusOpen {
			t.Fatalf("S-770 = %s while the file is still changed", got)
		}
		r.write(t, "auth/views.py", inferBase)
		r.commit(t, "restore", 4*time.Minute, "auth/views.py")
		r.settle(t)
		if got := r.status(t, "code.s-770"); got != policy.FindingStatusNotReproduced {
			t.Fatalf("S-770 = %s once the file is back as it was, want not_reproduced", got)
		}
	})
	t.Run("a commit of another file only", func(t *testing.T) {
		r := newInferRepo(t)
		r.write(t, "README", "y\n")
		r.commit(t, "readme", time.Minute, "README")
		r.settle(t)
		if r.status(t, "code.s-764") != policy.FindingStatusOpen {
			t.Fatal("a commit of another file closed it")
		}
	})
	t.Run("the file deleted", func(t *testing.T) {
		r := newInferRepo(t)
		if err := os.Remove(filepath.Join(r.root, "auth", "views.py")); err != nil {
			t.Fatal(err)
		}
		r.settle(t)
		for _, rule := range []string{"code.s-764", "code.s-770"} {
			if got := r.status(t, rule); got != policy.FindingStatusNotReproduced {
				t.Fatalf("%s = %s with its file deleted", rule, got)
			}
		}
	})
	t.Run("a diff not read whole", func(t *testing.T) {
		r := newInferRepo(t)
		r.write(t, "auth/views.py", inferBase+"# note\n")
		r.commit(t, "note", time.Minute, "auth/views.py")
		for _, fake := range []func(context.Context, string, int, ...string) ([]byte, bool, error){
			func(context.Context, string, int, ...string) ([]byte, bool, error) { return nil, true, nil },
			func(context.Context, string, int, ...string) ([]byte, bool, error) {
				return nil, false, errors.New("git failed")
			},
		} {
			r.l.gitDiff = fake
			r.l.inferChecked = nil
			r.settle(t)
			if r.status(t, "code.s-764") != policy.FindingStatusOpen {
				t.Fatal("an unread diff closed it")
			}
		}
		r.l.gitDiff = nil
		r.l.inferChecked = nil
		r.settle(t)
		if r.status(t, "code.s-764") != policy.FindingStatusNotReproduced {
			t.Fatal("the change never landed, yet a later commit of the file kept it")
		}
	})
}

// TestInferenceRaised pins the anchor: the rule and the file.
func TestInferenceRaised(t *testing.T) {
	diff := []byte("diff --git a/auth/views.py b/auth/views.py\n--- a/auth/views.py\n+++ b/auth/views.py\n@@ -1,1 +1,2 @@\n+@csrf_exempt\n def login(r):\n")
	if !inferenceRaised("code.s-764", "auth/views.py", diff, nil) {
		t.Fatal("not raised at its own rule and file")
	}
	if inferenceRaised("code.s-764", "auth/other.py", diff, nil) || inferenceRaised("code.s-765", "auth/views.py", diff, nil) {
		t.Fatal("raised at another file or rule")
	}
	if inferenceRaised("code.s-764", "auth/views.py", []byte(strings.ReplaceAll(string(diff), "+@csrf", " @csrf")), nil) {
		t.Fatal("raised by context lines")
	}
}

// TestInferenceStaysWhileTheTreeHoldsIt is SECP-27's closing rule (lane
// LEFT-SEC milestone 3): a later commit of the file that does not carry the
// edit (a commit of another hunk) leaves the inference open while the
// working tree still holds the edit; once the tree drops it too, with no
// new commit, the next pass closes it.
func TestInferenceStaysWhileTheTreeHoldsIt(t *testing.T) {
	r := newInferRepo(t)
	// Commit only a note; the exemption stays in the tree, uncommitted.
	r.write(t, "auth/views.py", inferBase+"# note\n")
	r.commit(t, "note", time.Minute, "auth/views.py")
	r.write(t, "auth/views.py", "@csrf_exempt\n"+inferBase+"# note\n")
	r.settle(t)
	if got := r.status(t, "code.s-764"); got != policy.FindingStatusOpen {
		t.Fatalf("S-764 = %s while the working tree still holds the exemption, want open", got)
	}
	r.settle(t)
	if got := r.status(t, "code.s-764"); got != policy.FindingStatusOpen {
		t.Fatalf("a second pass closed it: %s", got)
	}
	// The tree drops it with no new commit: closed.
	r.write(t, "auth/views.py", inferBase+"# note\n")
	r.settle(t)
	if got := r.status(t, "code.s-764"); got != policy.FindingStatusNotReproduced {
		t.Fatalf("S-764 = %s once both the commit and the tree lack it, want not_reproduced", got)
	}
}
