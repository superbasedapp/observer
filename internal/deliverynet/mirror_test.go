//go:build !windows

package deliverynet

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// gitEnvFor isolates every git call of these tests from the real user's
// global and system configuration.
func gitEnvFor(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_CONFIG_HOME=" + filepath.Join(home, ".config"),
		"GIT_CONFIG_NOSYSTEM=1", "LC_ALL=C", "GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
	}
}

func runIn(t *testing.T, home, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnvFor(home)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

// snapshotGitDir hashes every file and lists every directory under a .git
// directory: refs, packed-refs, config, HEAD, info/alternates, the objects
// listing and everything else. Any write by anyone shows up as a diff.
func snapshotGitDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		if d.IsDir() {
			snap[rel+"/"] = "dir"
			return nil
		}
		b, err := os.ReadFile(p) // #nosec G304 -- a test temp directory
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		fi, _ := d.Info()
		snap[rel] = hex.EncodeToString(sum[:]) + " " + fi.Mode().String()
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func diffSnap(a, b map[string]string) []string {
	var out []string
	for k, v := range a {
		if b[k] != v {
			out = append(out, "changed or removed: "+k)
		}
	}
	for k := range b {
		if _, ok := a[k]; !ok {
			out = append(out, "added: "+k)
		}
	}
	sort.Strings(out)
	return out
}

// TestMirrorNeverTouchesTheUserRepository is the operator ruling "No active
// changes" to the user's repository (D-689, plan 12.2): clone a mirror from
// the user's remote, refresh it after a new remote commit, and assert the
// user repository's .git is byte-identical before and after.
func TestMirrorNeverTouchesTheUserRepository(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	base := t.TempDir()
	home := filepath.Join(base, "home")
	remote := filepath.Join(base, "remote.git")
	user := filepath.Join(base, "user")
	teammate := filepath.Join(base, "teammate")
	for _, d := range []string{home, user, teammate} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	runIn(t, home, base, "init", "-q", "--bare", remote)
	runIn(t, home, remote, "config", "uploadpack.allowFilter", "true")
	runIn(t, home, remote, "symbolic-ref", "HEAD", "refs/heads/main")
	// The user's repository: one commit, origin pointing at the remote.
	runIn(t, home, user, "init", "-q")
	if err := os.WriteFile(filepath.Join(user, "a.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runIn(t, home, user, "add", "a.txt")
	runIn(t, home, user, "commit", "-q", "-m", "one")
	runIn(t, home, user, "remote", "add", "origin", "file://"+remote)
	runIn(t, home, user, "push", "-q", "origin", "HEAD:refs/heads/main")
	first := runIn(t, home, user, "rev-parse", "HEAD")

	before := snapshotGitDir(t, filepath.Join(user, ".git"))

	mirrorRoot := filepath.Join(home, ".observer", "delivery", "mirrors")
	env := map[string]string{"PATH": os.Getenv("PATH"), "HOME": home, "XDG_CONFIG_HOME": filepath.Join(home, ".config"), "GIT_DIR": filepath.Join(user, ".git"), "GIT_WORK_TREE": user}
	c := New(Options{
		MirrorRoot: mirrorRoot, AllowFileRemotes: true,
		Getenv: func(k string) string { return env[k] },
	})
	ctx := context.Background()
	url := "file://" + remote
	dir, err := c.MirrorDir(url)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Clone(ctx, url, dir); err != nil {
		t.Fatalf("clone: %v", err)
	}
	if b, err := c.HeadBranch(ctx, dir); err != nil || b != "main" {
		t.Fatalf("head branch %q %v", b, err)
	}
	if tip, err := c.LocalTip(ctx, dir, "main"); err != nil || tip != first {
		t.Fatalf("tip %s want %s (%v)", tip, first, err)
	}
	if tip, err := c.LsRemote(ctx, url, "refs/heads/main"); err != nil || tip != first {
		t.Fatalf("ls-remote %s %v", tip, err)
	}

	// A teammate pushes a new commit to the remote.
	runIn(t, home, teammate, "clone", "-q", "file://"+remote, ".")
	if err := os.WriteFile(filepath.Join(teammate, "b.txt"), []byte("two\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runIn(t, home, teammate, "add", "b.txt")
	runIn(t, home, teammate, "commit", "-q", "-m", "two")
	runIn(t, home, teammate, "push", "-q", "origin", "HEAD:refs/heads/main")
	second := runIn(t, home, teammate, "rev-parse", "HEAD")

	tip, err := c.LsRemote(ctx, url, "refs/heads/main")
	if err != nil || tip != second {
		t.Fatalf("ls-remote after push %s %v", tip, err)
	}
	if err := c.Refresh(ctx, dir, "main"); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if got, err := c.LocalTip(ctx, dir, "main"); err != nil || got != second {
		t.Fatalf("mirror tip %s want %s (%v)", got, second, err)
	}
	if n, err := c.Size(dir); err != nil || n <= 0 {
		t.Fatalf("size %d %v", n, err)
	}

	after := snapshotGitDir(t, filepath.Join(user, ".git"))
	if d := diffSnap(before, after); len(d) != 0 {
		t.Fatalf("the user repository's .git changed:\n%s", strings.Join(d, "\n"))
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("snapshot mismatch")
	}
	// The user repository never names the mirror as an alternate.
	if _, err := os.Stat(filepath.Join(user, ".git", "objects", "info", "alternates")); err == nil {
		t.Fatal("an alternates file appeared in the user repository")
	}
	// The mirror config holds no credential helper and no hooks dir.
	cfg, err := os.ReadFile(filepath.Join(dir, "config")) // #nosec G304 -- a test temp directory
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(cfg), "credential") || strings.Contains(string(cfg), "@") {
		t.Fatalf("mirror config holds a credential setting or user info:\n%s", cfg)
	}
	if _, err := os.Stat(filepath.Join(dir, "hooks")); err == nil {
		t.Fatal("mirror got a hooks directory (templates must be off)")
	}

	// git is never pointed at the user repository, even when asked to.
	for _, bad := range []string{filepath.Join(user, ".git"), user, filepath.Join(mirrorRoot, "..", "x.git")} {
		if err := c.Refresh(ctx, bad, "main"); KindOf(err) != KindInvalid {
			t.Errorf("Refresh(%s) = %v, want invalid", bad, err)
		}
		if err := c.RemoveMirror(bad); KindOf(err) != KindInvalid {
			t.Errorf("RemoveMirror(%s) = %v, want invalid", bad, err)
		}
	}
	if err := c.Clone(ctx, url, filepath.Join(base, "elsewhere.git")); KindOf(err) != KindInvalid {
		t.Errorf("clone outside the mirror root = %v", err)
	}
	if _, err := os.Stat(filepath.Join(base, "elsewhere.git")); err == nil {
		t.Error("a clone landed outside the mirror root")
	}
	if d := diffSnap(before, snapshotGitDir(t, filepath.Join(user, ".git"))); len(d) != 0 {
		t.Fatalf("the user repository changed after refused calls:\n%s", strings.Join(d, "\n"))
	}

	if err := c.RemoveMirror(dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err == nil {
		t.Fatal("mirror not removed")
	}
}

func TestSanitizeRemoteURL(t *testing.T) {
	c := New(Options{})
	cf := New(Options{AllowFileRemotes: true})
	cases := []struct {
		c    *Client
		in   string
		want string // "" = refused
	}{
		{c, "https://user:ghp_secret@github.com/o/r.git", "https://github.com/o/r.git"},
		{c, "https://x-access-token:tok@github.com/o/r", "https://github.com/o/r"},
		{c, "ssh://git:pw@github.com/o/r.git", "ssh://git@github.com/o/r.git"},
		{c, "git@github.com:o/r.git", "git@github.com:o/r.git"},
		{c, "https://github.com/o/r.git?x=1#f", "https://github.com/o/r.git"},
		{c, "http://github.com/o/r.git", ""},
		{c, "git://github.com/o/r.git", ""},
		{c, "ext::sh -c touch% /tmp/pwned", ""},
		{c, "-uhttps://github.com/o/r", ""},
		{c, "git@github.com:-oProxyCommand=x", ""},
		{c, "file:///tmp/r.git", ""},
		{cf, "file:///tmp/r.git", "file:///tmp/r.git"},
		{c, "", ""},
	}
	for _, tc := range cases {
		got, err := tc.c.SanitizeRemoteURL(tc.in)
		if tc.want == "" {
			if err == nil {
				t.Errorf("SanitizeRemoteURL(%q) = %q, want refused", tc.in, got)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("SanitizeRemoteURL(%q) = %q, %v; want %q", tc.in, got, err, tc.want)
		}
	}
}

func TestMirrorDirIsUserinfoFree(t *testing.T) {
	c := New(Options{MirrorRoot: t.TempDir()})
	a, err := c.MirrorDir("https://u:secret@github.com/o/r.git")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := c.MirrorDir("https://github.com/o/r.git")
	if a != b || strings.Contains(a, "secret") || !reMirrorName.MatchString(filepath.Base(a)) {
		t.Fatalf("%s vs %s", a, b)
	}
}

func TestValidBranch(t *testing.T) {
	cases := map[string]bool{
		"main": true, "release/1.2": true, "feat_x-y": true,
		"": false, "-x": false, "a..b": false, "a b": false, "a/": false, "x.lock": false, "a:b": false, "@{u}": false,
	}
	for in, want := range cases {
		if got := ValidBranch(in); got != want {
			t.Errorf("ValidBranch(%q)=%v want %v", in, got, want)
		}
	}
}
