//go:build linux && !sbo_omit_terminals_sandbox_openshell_org && !sbo_omit_terminals_sandbox_openshell && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	osorg "github.com/marmutapp/superbased-observer/internal/openshellorg"
)

// TestGuestPacedStdinCreditsWhatTheChildRead (lane G4): the wrapper hands
// its stdin to the child byte-exact, keeps the child's stdout clean, and
// writes credit lines on stderr at line starts, reaching the full count.
func TestGuestPacedStdinCreditsWhatTheChildRead(t *testing.T) {
	data := bytes.Repeat([]byte("0123456789abcdef"), 40000) // 640 000 bytes
	var out, errb bytes.Buffer
	code := pacedStdinRun([]string{"sh", "-c", "cat; printf 'partial' >&2"}, bytes.NewReader(data), &out, &errb)
	if code != 0 || !bytes.Equal(out.Bytes(), data) {
		t.Fatalf("exit %d, stdout %d bytes", code, out.Len())
	}
	var last int64
	f := osorg.NewAckFilter(func(n int64) { last = n })
	rest := f.Feed(errb.Bytes())
	if last != int64(len(data)) {
		t.Errorf("last credit %d, want %d", last, len(data))
	}
	if !strings.Contains(string(rest), "partial") {
		t.Errorf("the child's stderr was lost: %q", rest)
	}
}

// TestGuestPacedStdinExitCode: the child's exit code passes through.
func TestGuestPacedStdinExitCode(t *testing.T) {
	var out, errb bytes.Buffer
	if code := pacedStdinRun([]string{"sh", "-c", "exit 42"}, strings.NewReader(""), &out, &errb); code != 42 {
		t.Errorf("exit %d", code)
	}
}

// TestGuestReceivePart: one row per refusal and the accepted shape.
func TestGuestReceivePart(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join(dir, ".upload.0123456789abcdef.part.3")
	cases := []struct {
		name, n, to string
		in          []byte
		ok          bool
	}{
		{"accepted", "3", good, []byte("abc"), true},
		{"again refused (exclusive)", "3", good, []byte("abc"), false},
		{"not a number", "x", filepath.Join(dir, ".upload.0123456789abcdef.part.x"), nil, false},
		{"number mismatch", "4", filepath.Join(dir, ".upload.0123456789abcdef.part.5"), nil, false},
		{"relative", "1", ".upload.0123456789abcdef.part.1", nil, false},
		{"traversal", "1", dir + "/../x/.upload.0123456789abcdef.part.1", nil, false},
		{"other name", "1", filepath.Join(dir, "passwd"), nil, false},
		{"oversized", "6", filepath.Join(dir, ".upload.0123456789abcdef.part.6"), make([]byte, guestPartMax+1), false},
	}
	for _, tc := range cases {
		err := receivePart(tc.n, tc.to, bytes.NewReader(tc.in))
		if (err == nil) != tc.ok {
			t.Errorf("%s: err %v", tc.name, err)
		}
	}
	if b, _ := os.ReadFile(good); string(b) != "abc" {
		t.Errorf("part content %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, ".upload.0123456789abcdef.part.6")); err == nil {
		t.Error("an oversized part was kept")
	}
	// A symlink is never followed.
	link := filepath.Join(dir, ".upload.0123456789abcdef.part.7")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Fatal(err)
	}
	if err := receivePart("7", link, bytes.NewReader([]byte("x"))); err == nil {
		t.Error("wrote through a symlink")
	}
	// A symlink chain (fix round 1, the 11.4 symlink-chain row): a part name
	// that links to a link that links to a file, and a part directory that
	// is itself a link to an owner-only directory, are both refused.
	victim := filepath.Join(dir, "victim")
	if err := os.WriteFile(victim, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	mid := filepath.Join(dir, "mid")
	chain := filepath.Join(dir, ".upload.0123456789abcdef.part.8")
	if err := os.Symlink(victim, mid); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(mid, chain); err != nil {
		t.Fatal(err)
	}
	if err := receivePart("8", chain, bytes.NewReader([]byte("x"))); err == nil {
		t.Error("wrote through a symlink chain")
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Errorf("the chain's target changed: %q", b)
	}
	linkDir := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, linkDir); err != nil {
		t.Fatal(err)
	}
	if err := receivePart("9", filepath.Join(linkDir, ".upload.0123456789abcdef.part.9"), bytes.NewReader([]byte("x"))); err == nil {
		t.Error("wrote into a directory reached through a symlink")
	}
}

// TestGuestBaselineIsTheCoreFile (OB-084): --baseline writes HEAD to the org
// core's BoxBaselineFile (here redirected to a temp file), the file the org's
// collect reads, and the return verbs read it back.
func TestGuestBaselineIsTheCoreFile(t *testing.T) {
	if osorg.BoxBaselineFile != osorg.BoxRunDir+"/baseline" {
		t.Fatalf("baseline %s is not under the run dir %s", osorg.BoxBaselineFile, osorg.BoxRunDir)
	}
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git")
	}
	repo := t.TempDir()
	for _, a := range [][]string{{"init", "-q"}, {"-c", "user.email=t@example.com", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "x"}} {
		if out, err := exec.Command("git", append([]string{"-C", repo}, a...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", a, err, out)
		}
	}
	old := guestBaselineFile
	guestBaselineFile = filepath.Join(t.TempDir(), "run", "baseline")
	t.Cleanup(func() { guestBaselineFile = old })
	t.Chdir(repo)
	if code := runGuestBaseline(nil); code != 0 {
		t.Fatalf("exit %d", code)
	}
	head, _ := exec.Command("git", "-C", repo, "rev-parse", "HEAD").Output()
	if got := guestBaseline(); got == "" || got != strings.TrimSpace(string(head)) {
		t.Errorf("baseline %q, HEAD %q", got, head)
	}
}
