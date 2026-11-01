package commitlog

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestPatchFingerprintTable pins the states and the properties the delivery
// rules rely on.
func TestPatchFingerprintTable(t *testing.T) {
	t.Parallel()
	const fileA = "diff --git a/a.go b/a.go\nindex 1111111..2222222 100644\n--- a/a.go\n+++ b/a.go\n@@ -1,2 +1,2 @@\n x := 1\n-y := 2\n+y := 3\n"
	const fileB = "diff --git a/b.go b/b.go\nnew file mode 100644\nindex 0000000..3333333\n--- /dev/null\n+++ b/b.go\n@@ -0,0 +1 @@\n+package b\n"
	const binary = "diff --git a/img.png b/img.png\nindex 1111111..2222222 100644\nBinary files a/img.png and b/img.png differ\n"

	fpA, st := PatchFingerprint([]byte(fileA))
	if st != FingerprintOK || len(fpA) != 40 {
		t.Fatalf("single file: (%q, %q)", fpA, st)
	}
	cases := []struct {
		name  string
		diff  string
		state FingerprintState
		same  string // when set, the fingerprint must equal this one's
	}{
		{"empty", "", FingerprintEmpty, ""},
		{"message only", "some commit message\n", FingerprintEmpty, ""},
		{"line numbers moved", strings.Replace(fileA, "@@ -1,2 +1,2 @@", "@@ -40,2 +40,2 @@", 1), FingerprintOK, fileA},
		{"whitespace changed", strings.Replace(fileA, "y := 3", "y  :=\t3", 1), FingerprintOK, fileA},
		{"index line differs", strings.Replace(fileA, "1111111..2222222", "aaaaaaa..bbbbbbb", 1), FingerprintOK, fileA},
		{"leading commit id", "0123456789abcdef0123456789abcdef01234567\n" + fileA, FingerprintOK, fileA},
		{"file order does not matter", fileB + fileA, FingerprintOK, fileA + fileB},
		{"no newline marker ignored", fileA + "\\ No newline at end of file\n", FingerprintOK, fileA},
		{"binary only", binary, FingerprintBinaryOnly, ""},
		{"binary plus text", binary + fileA, FingerprintOK, ""},
		{"too large", strings.Repeat("x", MaxPatchBytes+1), FingerprintTooLarge, ""},
	}
	for _, tc := range cases {
		fp, st := PatchFingerprint([]byte(tc.diff))
		if st != tc.state {
			t.Errorf("%s: state = %q, want %q", tc.name, st, tc.state)
			continue
		}
		if st != FingerprintOK && fp != "" {
			t.Errorf("%s: fingerprint %q returned with state %q", tc.name, fp, st)
		}
		if tc.same != "" {
			want, _ := PatchFingerprint([]byte(tc.same))
			if fp != want {
				t.Errorf("%s: fingerprint %s, want %s", tc.name, fp, want)
			}
		}
	}
	if other, _ := PatchFingerprint([]byte(strings.Replace(fileA, "y := 3", "y := 4", 1))); other == fpA {
		t.Fatal("a different change produced the same fingerprint")
	}
}

func TestPatchFiles(t *testing.T) {
	t.Parallel()
	diff := "diff --git a/a.go b/a.go\n--- a/a.go\n+++ b/a.go\n" +
		"diff --git a/dir/b c.go b/dir/b c.go\n" +
		"diff --git \"a/q\\tx\" \"b/q\\tx\"\n" +
		"diff --git a/a.go b/a.go\n"
	got := PatchFiles([]byte(diff))
	want := []string{"a.go", "dir/b c.go", `q\tx`}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("PatchFiles = %q, want %q", got, want)
	}
}

// TestPatchFingerprintMatchesGitPatchID cross-checks the port against the
// real `git patch-id --stable` on a throwaway repository: plain edits,
// a new file, a deletion, several hunks, a missing final newline, a mode
// change, and a cherry-pick (new sha, same patch). Skipped when git is not
// installed.
func TestPatchFingerprintMatchesGitPatchID(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	dir := t.TempDir()
	env := append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1", "HOME="+dir, "XDG_CONFIG_HOME="+dir,
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
		"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com", "LC_ALL=C")
	git := func(stdin []byte, args ...string) []byte {
		t.Helper()
		cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
		cmd.Env = env
		if stdin != nil {
			cmd.Stdin = bytes.NewReader(stdin)
		}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return out
	}
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	commit := func(msg string) string {
		git(nil, "add", "-A")
		git(nil, "commit", "-q", "--allow-empty", "-m", msg)
		return strings.TrimSpace(string(git(nil, "rev-parse", "HEAD")))
	}

	git(nil, "init", "-q")
	var lines []string
	for i := 0; i < 40; i++ {
		lines = append(lines, "line "+strings.Repeat("x", i%7))
	}
	write("a.txt", strings.Join(lines, "\n")+"\n")
	write("sub/b.go", "package b\n\nfunc B() int { return 1 }\n")
	shas := []string{commit("root")}

	lines[2], lines[30] = "changed two", "changed thirty"
	write("a.txt", strings.Join(lines, "\n")+"\n")
	write("c.txt", "new file\nno newline at end")
	shas = append(shas, commit("multi hunk + new file"))

	if err := os.Remove(filepath.Join(dir, "sub", "b.go")); err != nil {
		t.Fatal(err)
	}
	write("c.txt", "new file\nnow with newline\n")
	shas = append(shas, commit("delete + fix newline"))

	if err := os.Chmod(filepath.Join(dir, "c.txt"), 0o755); err == nil {
		write("d.txt", "\tindented\t \n")
		shas = append(shas, commit("mode change + whitespace"))
	}

	// A cherry-pick onto another branch: new sha, same patch id.
	git(nil, "checkout", "-q", "-b", "side", shas[0])
	write("e.txt", "side file\n")
	commit("side base")
	git(nil, "cherry-pick", shas[1])
	picked := strings.TrimSpace(string(git(nil, "rev-parse", "HEAD")))

	for _, sha := range append(shas, picked) {
		diff := git(nil, "diff-tree", "-p", "--no-renames", "--root", "-r", sha)
		out := strings.Fields(string(git(diff, "patch-id", "--stable")))
		if len(out) == 0 {
			t.Fatalf("%s: git patch-id printed nothing", sha)
		}
		bare := git(nil, "diff-tree", "-p", "--no-renames", "--no-commit-id", "--root", "-r", sha)
		got, st := PatchFingerprint(bare)
		if st != FingerprintOK || got != out[0] {
			t.Errorf("%s: PatchFingerprint = (%s, %s), git patch-id --stable = %s", sha, got, st, out[0])
		}
		// The same diff with the commit id line patch-id also accepts.
		if withID, _ := PatchFingerprint(diff); withID != got {
			t.Errorf("%s: fingerprint changed with the commit id line", sha)
		}
	}
	fpOrig, _ := PatchFingerprint(git(nil, "diff-tree", "-p", "--no-renames", "--no-commit-id", "-r", shas[1]))
	fpPick, _ := PatchFingerprint(git(nil, "diff-tree", "-p", "--no-renames", "--no-commit-id", "-r", picked))
	if fpOrig != fpPick || picked == shas[1] {
		t.Fatalf("cherry-pick: %s vs %s (shas %s, %s)", fpOrig, fpPick, shas[1], picked)
	}

	// The cumulative branch-range diff (rule L3) fingerprints the same way
	// git patch-id does over `diff-tree -p base tip`.
	rng := git(nil, "diff-tree", "-p", "--no-renames", "-r", shas[0], shas[2])
	out := strings.Fields(string(git(rng, "patch-id", "--stable")))
	if got, _ := PatchFingerprint(rng); len(out) == 0 || got != out[0] {
		t.Errorf("range diff: PatchFingerprint = %s, git = %v", got, out)
	}
}
