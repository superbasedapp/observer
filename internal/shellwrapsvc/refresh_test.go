package shellwrapsvc

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// refreshFixture enables wrapping for one CLI row with the fixture's observer,
// then returns a second observer binary (the "moved" install).
func refreshFixture(t *testing.T) (*fixture, shellwrap.Candidate, string, string) {
	t.Helper()
	f := newFixture(t)
	c := routedCLI(t)
	writeFile(t, filepath.Join(f.home, ".bashrc"), "# mine\n", 0o644)
	f.apply([]string{c.ID})
	moved := filepath.Join(f.home, "new-prefix", "bin", "observer")
	writeFile(t, moved, "#!/bin/sh\n", 0o755)
	return f, c, filepath.Join(f.home, ".observer", "shims"), moved
}

func snapshot(t *testing.T, paths ...string) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, p := range paths {
		out[p] = read(t, p)
	}
	return out
}

func TestRefreshStaleRewritesMovedShimsOnly(t *testing.T) {
	f, c, shimDir, moved := refreshFixture(t)
	bashrc := filepath.Join(f.home, ".bashrc")
	cfg := filepath.Join(f.home, ".observer", "config.toml")
	// An operator file in the shim dir, and a symlink to a marked shim:
	// neither is the applier's to rewrite.
	foreign := filepath.Join(shimDir, "mine")
	writeFile(t, foreign, "#!/bin/sh\necho mine\n", 0o755)
	link := filepath.Join(shimDir, "linked")
	if err := os.Symlink(filepath.Join(shimDir, c.Commands[0]), link); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, bashrc, cfg, foreign)
	// The install the shims name is gone (the old prefix was removed).
	if err := os.Remove(f.obs); err != nil {
		t.Fatal(err)
	}

	f.svc.ObserverPath = ""
	f.svc.Executable = func() (string, error) { return moved, nil }
	out, err := f.svc.RefreshStale(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(out.Rewritten) != len(c.Commands) || out.ObserverPath != moved {
		t.Fatalf("rewritten %+v (observer %q)", out.Rewritten, out.ObserverPath)
	}
	for _, cmd := range c.Commands {
		p := filepath.Join(shimDir, cmd)
		got, ok := shellwrap.EmbeddedObserverPath(read(t, p))
		if !ok || got != moved {
			t.Fatalf("%s now runs %q", p, got)
		}
		if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o755 {
			t.Fatalf("%s mode %v", p, fi.Mode().Perm())
		}
	}
	for p, want := range before {
		if read(t, p) != want {
			t.Fatalf("refresh touched %s", p)
		}
	}
	if fi, err := os.Lstat(link); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink replaced: %v %v", fi, err)
	}
	// What the refresh wrote is exactly what enable would write now.
	st, err := f.svc.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, ts := range st.Tools {
		if ts.ID == c.ID && (len(ts.Active) == 0 || len(ts.Stale) != 0) {
			t.Fatalf("after refresh: %+v", ts)
		}
	}
	// Idempotent: a second start changes nothing.
	again, err := f.svc.RefreshStale(context.Background())
	if err != nil || len(again.Rewritten) != 0 {
		t.Fatalf("second refresh: %+v %v", again.Rewritten, err)
	}
}

// TestRefreshStaleKeepsAnotherExistingInstall: a different observer binary
// that still exists (the VS Code bundle, npm, PyPI) is another install, not a
// move - the shims are kept, so installs that each start the daemon never
// flip them back and forth.
func TestRefreshStaleKeepsAnotherExistingInstall(t *testing.T) {
	f, c, shimDir, moved := refreshFixture(t)
	shim := filepath.Join(shimDir, c.Commands[0])
	orig := read(t, shim)
	f.svc.ObserverPath = moved
	out, err := f.svc.RefreshStale(context.Background())
	if err != nil || len(out.Rewritten) != 0 {
		t.Fatalf("refresh: %+v %v", out.Rewritten, err)
	}
	for _, r := range out.Plan.Shims {
		if r.Action != shellwrap.RefreshKept {
			t.Fatalf("%s: %s (%s), want kept", r.FileName, r.Action, r.Reason)
		}
	}
	if read(t, shim) != orig {
		t.Fatal("a shim naming an existing install was rewritten")
	}
	// The injected check is honoured: report the old binary gone -> rewrite.
	f.svc.FileExists = func(string) bool { return false }
	out, err = f.svc.RefreshStale(context.Background())
	if err != nil || len(out.Rewritten) != len(c.Commands) {
		t.Fatalf("refresh with the binary reported gone: %+v %v", out.Rewritten, err)
	}
}

// TestRefreshStaleRefusesANonRunnableObserver: when the running binary was
// replaced or removed after it started, os.Executable reports a path that is
// no longer a regular executable file ("<path> (deleted)" on Linux). The
// refresh must skip - never bake that path into the shims - with the reason
// on the plan.
func TestRefreshStaleRefusesANonRunnableObserver(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, moved string) string
	}{
		{"deleted suffix from /proc/self/exe", func(t *testing.T, moved string) string {
			return moved + " (deleted)"
		}},
		{"path no longer exists", func(t *testing.T, moved string) string {
			if err := os.Remove(moved); err != nil {
				t.Fatal(err)
			}
			return moved
		}},
		{"a directory", func(t *testing.T, moved string) string {
			d := moved + ".d"
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
			return d
		}},
		{"not executable", func(t *testing.T, moved string) string {
			if runtime.GOOS == "windows" {
				t.Skip("no execute bit on Windows")
			}
			if err := os.Chmod(moved, 0o644); err != nil {
				t.Fatal(err)
			}
			return moved
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, c, shimDir, moved := refreshFixture(t)
			shim := filepath.Join(shimDir, c.Commands[0])
			orig := read(t, shim)
			// The install the shims name is gone, so without the guard the
			// refresh WOULD rewrite.
			if err := os.Remove(f.obs); err != nil {
				t.Fatal(err)
			}
			running := tc.setup(t, moved)
			f.svc.ObserverPath = ""
			f.svc.Executable = func() (string, error) { return running, nil }
			out, err := f.svc.RefreshStale(context.Background())
			if err != nil || len(out.Rewritten) != 0 {
				t.Fatalf("refresh: %+v %v", out.Rewritten, err)
			}
			if len(out.Plan.Shims) == 0 {
				t.Fatal("no decisions")
			}
			for _, r := range out.Plan.Shims {
				if r.Action != shellwrap.RefreshSkip || r.Reason != shellwrap.ReasonObserverNotRunnable {
					t.Fatalf("%s: %s (%s), want skip with the not-runnable reason", r.FileName, r.Action, r.Reason)
				}
			}
			if read(t, shim) != orig {
				t.Fatal("a shim was rewritten to a non-runnable observer path")
			}
		})
	}
}

func TestRefreshStaleIsInertWhenDisabled(t *testing.T) {
	f, c, shimDir, moved := refreshFixture(t)
	cfg := filepath.Join(f.home, ".observer", "config.toml")
	text := read(t, cfg)
	if !strings.Contains(text, "enabled = true") {
		t.Fatalf("config:\n%s", text)
	}
	// Recorded off, but a shim is still on disk (e.g. a disable that could
	// not delete it): the daemon must not touch it.
	writeFile(t, cfg, strings.Replace(text, "enabled = true", "enabled = false", 1), 0o600)
	shim := filepath.Join(shimDir, c.Commands[0])
	orig := read(t, shim)
	f.svc.ObserverPath = moved
	out, err := f.svc.RefreshStale(context.Background())
	if err != nil || len(out.Rewritten) != 0 || out.Plan.Inactive == "" {
		t.Fatalf("disabled refresh: %+v %v", out, err)
	}
	if read(t, shim) != orig {
		t.Fatal("disabled refresh rewrote a shim")
	}
}

func TestRefreshStaleNeverRecreatesAMissingShim(t *testing.T) {
	f, _, shimDir, moved := refreshFixture(t)
	// The documented escape hatch: rm -r ~/.observer/shims.
	if err := os.RemoveAll(shimDir); err != nil {
		t.Fatal(err)
	}
	f.svc.ObserverPath = moved
	out, err := f.svc.RefreshStale(context.Background())
	if err != nil || len(out.Rewritten) != 0 {
		t.Fatalf("refresh: %+v %v", out, err)
	}
	if _, err := os.Stat(shimDir); !os.IsNotExist(err) {
		t.Fatalf("refresh recreated the shim dir: %v", err)
	}
}

func TestRefreshStaleSymlinkToRunningBinaryIsCurrent(t *testing.T) {
	f := newFixture(t)
	c := routedCLI(t)
	writeFile(t, filepath.Join(f.home, ".bashrc"), "", 0o644)
	// Enabled through a stable link (a package manager's bin symlink).
	link := filepath.Join(f.home, "stable", "observer")
	if err := os.MkdirAll(filepath.Dir(link), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(f.obs, link); err != nil {
		t.Fatal(err)
	}
	f.svc.ObserverPath = link
	f.apply([]string{c.ID})
	shim := filepath.Join(f.home, ".observer", "shims", c.Commands[0])
	orig := read(t, shim)
	// The daemon runs as the resolved binary: the link still reaches it.
	f.svc.ObserverPath = f.obs
	out, err := f.svc.RefreshStale(context.Background())
	if err != nil || len(out.Rewritten) != 0 {
		t.Fatalf("refresh: %+v %v", out.Rewritten, err)
	}
	if read(t, shim) != orig {
		t.Fatal("a shim reaching the running binary through a symlink was rewritten")
	}
}

func TestRewriteShimRefusesAChangedFile(t *testing.T) {
	f, c, shimDir, _ := refreshFixture(t)
	p := filepath.Join(shimDir, c.Commands[0])
	r := shellwrap.ShimRefresh{FileName: c.Commands[0], Path: p, Before: "something else", Content: "x"}
	if err := rewriteShim(shimDir, r); err == nil {
		t.Fatal("a file changed since planning must not be rewritten")
	}
	r.Before = read(t, p)
	r.Path = filepath.Join(f.home, c.Commands[0])
	if err := rewriteShim(shimDir, r); err == nil {
		t.Fatal("a path outside the shim dir must be refused")
	}
}

func TestHostResolvesWindowsDocumentsLadder(t *testing.T) {
	home := `C:\Users\x`
	fail := func() (string, error) { return "", errors.New("no") }
	cases := []struct {
		name  string
		known func() (string, error)
		shell func() (string, error)
		want  string
	}{
		{"known folder (OneDrive)", func() (string, error) { return `C:\Users\x\OneDrive\Documents`, nil }, fail, `C:\Users\x\OneDrive\Documents`},
		{"registry with %USERPROFILE%", fail, func() (string, error) { return `%USERPROFILE%\OneDrive\Documents`, nil }, `C:\Users\x\OneDrive\Documents`},
		{"both fail", fail, fail, `C:\Users\x\Documents`},
		// nil = the OS lookups; off Windows they fail, leaving the default.
		{"os lookups off windows", nil, nil, `C:\Users\x\Documents`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := Service{
				Home: home, GOOS: "windows",
				Getenv:               func(k string) string { return map[string]string{"USERPROFILE": home}[k] },
				DocumentsKnownFolder: tc.known, DocumentsShellFolder: tc.shell,
			}
			if tc.known == nil && runtime.GOOS == "windows" {
				t.Skip("real OS lookup on a Windows build host")
			}
			h, err := s.Host()
			if err != nil {
				t.Fatal(err)
			}
			if h.DocumentsDir != tc.want {
				t.Fatalf("DocumentsDir %q, want %q", h.DocumentsDir, tc.want)
			}
		})
	}
}
