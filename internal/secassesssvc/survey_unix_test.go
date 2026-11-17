//go:build unix

package secassesssvc

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secassess"
)

// TestSurveySkipsAFIFO: a FIFO (or any non-regular file) sitting at an
// allow-listed path is skipped at the Lstat and never opened, so the survey
// returns at once instead of blocking on it; the regular files around it are
// still read.
func TestSurveySkipsAFIFO(t *testing.T) {
	root := t.TempDir()
	for _, name := range []string{"package.json", ".env.example", "Procfile"} {
		if err := syscall.Mkfifo(filepath.Join(root, name), 0o600); err != nil {
			t.Skipf("no FIFO here: %v", err)
		}
	}
	surveyWrite(t, root, "go.mod", "module x\n")
	type result struct {
		in  secassess.SurveyInput
		err error
	}
	done := make(chan result, 1)
	go func() {
		in, err := Survey(context.Background(), root)
		done <- result{in, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if got := surveyRels(r.in); !reflect.DeepEqual(got, []string{"go.mod"}) {
			t.Errorf("Files = %v", got)
		}
		if r.in.Truncated {
			t.Error("a FIFO is not a truncation")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the survey blocked on a FIFO")
	}
}

// TestSurveyOpenRefusesALinkSwappedInAfterTheLstat: a symlink that replaces an
// allow-listed regular file between the survey's Lstat and its open (here to a
// .env inside the project) is not read. os.Root alone does not stop it: it
// opens the last element with O_NOFOLLOW itself and, on the link error,
// resolves the link inside the root and opens the target (the control below
// shows the handle really is the .env), so the survey compares the opened
// handle with the file the Lstat saw. A link that was already a link at the
// Lstat is skipped there (TestSurveyFollowsNoSymlinkOut).
func TestSurveyOpenRefusesALinkSwappedInAfterTheLstat(t *testing.T) {
	root := t.TempDir()
	surveyWrite(t, root, ".env", "TOKEN=canary\n")
	surveyWrite(t, root, "Makefile", "run:\n\tgo run .\n")
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	seen, err := r.Lstat("Makefile")
	if err != nil || !seen.Mode().IsRegular() {
		t.Fatalf("Lstat = %v, %v", seen, err)
	}
	// The swap: the regular file becomes a link to the environment file.
	if err := os.Remove(filepath.Join(root, "Makefile")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(".env", filepath.Join(root, "Makefile")); err != nil {
		t.Skipf("no symlinks here: %v", err)
	}
	// Control: the read flags alone reach the .env through the link.
	g, err := r.OpenFile("Makefile", openFlags, 0)
	if err != nil {
		t.Fatalf("os.Root no longer follows an in-project link, so the survey's identity check is belt and braces only: %v", err)
	}
	if st, err := g.Stat(); err != nil || !st.Mode().IsRegular() || os.SameFile(seen, st) {
		t.Errorf("control: the handle behind the swapped-in link is not another regular file (%v, %v)", st, err)
	}
	_ = g.Close()
	if data, over := surveyReadOpened(r, "Makefile", seen, 1<<20); data != nil || over {
		t.Fatalf("the survey read through a link swapped in after the Lstat: %q (over=%v)", data, over)
	}
}
