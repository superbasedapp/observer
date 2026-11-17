package secassesssvc

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSurveyReadOpenedRefusesAnotherFileThanTheOneChecked: the survey reads a
// file only when the handle it opened is the very file its Lstat saw. Handing
// the open half the Lstat of one file and the name of another (what a rename
// or a swapped-in link between the two calls looks like) reads nothing, while
// the matching pair reads the file. No symlink is needed, so this runs on every
// platform.
func TestSurveyReadOpenedRefusesAnotherFileThanTheOneChecked(t *testing.T) {
	root := t.TempDir()
	surveyWrite(t, root, "Makefile", "run:\n\tgo run .\n")
	surveyWrite(t, root, ".env", "TOKEN=canary\n")
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	seen, err := r.Lstat("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := surveyReadOpened(r, "Makefile", seen, 1<<20); string(data) != "run:\n\tgo run .\n" {
		t.Errorf("the matching file was not read: %q", data)
	}
	if data, over := surveyReadOpened(r, ".env", seen, 1<<20); data != nil || over {
		t.Errorf("a different file than the one checked was read: %q (over=%v)", data, over)
	}
}

// TestSurveyReadOpenedRefusesAFileReplacedAfterTheLstat: a regular file that is
// replaced by another regular file between the Lstat and the open (a rename
// over it) is a different file now and is not read. Renaming over a file is
// allowed on every platform the survey runs on, symlink privilege or not.
func TestSurveyReadOpenedRefusesAFileReplacedAfterTheLstat(t *testing.T) {
	root := t.TempDir()
	surveyWrite(t, root, "Makefile", "run:\n\tgo run .\n")
	surveyWrite(t, root, "other", "TOKEN=canary\n")
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	seen, err := r.Lstat("Makefile")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(root, "other"), filepath.Join(root, "Makefile")); err != nil {
		t.Skipf("no rename over a file here: %v", err)
	}
	if data, over := surveyReadOpened(r, "Makefile", seen, 1<<20); data != nil || over {
		t.Errorf("a file swapped in after the check was read: %q (over=%v)", data, over)
	}
}
