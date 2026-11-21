package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudsession"
)

// TestApplyRepoPlanRefusesSymlinks: init and remove never write, chmod or
// remove through a symbolic link committed in a hostile repository, whether
// the link is the target file or a directory on the way to it, and the
// planner's reads refuse the same paths. Plain paths still work.
func TestApplyRepoPlanRefusesSymlinks(t *testing.T) {
	probe := t.TempDir()
	if err := os.Symlink(probe, filepath.Join(probe, "link")); err != nil {
		t.Skipf("symbolic links unavailable here: %v", err)
	}
	const outsideContent = "the developer's own file\n"
	cases := []struct {
		name string
		// setup prepares root and outside and returns the change to apply.
		setup func(t *testing.T, root, outside string) cloudsession.FileChange
		// refused is the error fragment; "" means the change applies.
		refused string
	}{
		{
			name: "plain path",
			setup: func(t *testing.T, root, _ string) cloudsession.FileChange {
				return cloudsession.FileChange{Path: ".claude/settings.json", After: "{}\n"}
			},
		},
		{
			name: "target file is a link",
			setup: func(t *testing.T, root, outside string) cloudsession.FileChange {
				csMkdir(t, filepath.Join(root, ".claude"))
				csSymlink(t, filepath.Join(outside, "victim"), filepath.Join(root, ".claude", "settings.json"))
				return cloudsession.FileChange{Path: ".claude/settings.json", Before: outsideContent, Existed: true, After: "{}\n"}
			},
			refused: "symbolic link .claude/settings.json",
		},
		{
			name: "parent directory is a link",
			setup: func(t *testing.T, root, outside string) cloudsession.FileChange {
				csSymlink(t, outside, filepath.Join(root, ".claude"))
				return cloudsession.FileChange{Path: ".claude/victim", Before: outsideContent, Existed: true, After: "{}\n"}
			},
			refused: "symbolic link .claude",
		},
		{
			name: "nested directory is a link",
			setup: func(t *testing.T, root, outside string) cloudsession.FileChange {
				csMkdir(t, filepath.Join(root, ".superbased"))
				csSymlink(t, outside, filepath.Join(root, ".superbased", "cloud-session"))
				return cloudsession.FileChange{Path: ".superbased/cloud-session/victim", Before: outsideContent, Existed: true, After: "#!/bin/sh\n", Executable: true}
			},
			refused: "symbolic link .superbased/cloud-session",
		},
		{
			name: "remove through a linked directory",
			setup: func(t *testing.T, root, outside string) cloudsession.FileChange {
				csSymlink(t, outside, filepath.Join(root, ".github"))
				return cloudsession.FileChange{Path: ".github/victim", Before: outsideContent, Existed: true, Delete: true}
			},
			refused: "symbolic link .github",
		},
		{
			name: "target is a directory",
			setup: func(t *testing.T, root, _ string) cloudsession.FileChange {
				csMkdir(t, filepath.Join(root, ".claude", "settings.json"))
				return cloudsession.FileChange{Path: ".claude/settings.json", Existed: true, After: "{}\n"}
			},
			refused: "not a regular file",
		},
		{
			name: "a parent is a file",
			setup: func(t *testing.T, root, _ string) cloudsession.FileChange {
				if err := os.WriteFile(filepath.Join(root, ".claude"), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
				return cloudsession.FileChange{Path: ".claude/settings.json", After: "{}\n"}
			},
			refused: "not a plain directory",
		},
		{
			name: "escaping path",
			setup: func(t *testing.T, root, _ string) cloudsession.FileChange {
				return cloudsession.FileChange{Path: "../victim", After: "{}\n"}
			},
			refused: "not a path inside the repository",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, outside := t.TempDir(), t.TempDir()
			victim := filepath.Join(outside, "victim")
			if err := os.WriteFile(victim, []byte(outsideContent), 0o600); err != nil {
				t.Fatal(err)
			}
			c := tc.setup(t, root, outside)
			err := applyRepoPlan(root, cloudsession.RepoPlan{Changes: []cloudsession.FileChange{c}})
			if tc.refused == "" {
				if err != nil {
					t.Fatalf("plain change refused: %v", err)
				}
				got, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(c.Path)))
				if rerr != nil || string(got) != c.After {
					t.Fatalf("written %q, %v; want %q", got, rerr, c.After)
				}
				if _, ok, rerr := repoReader(root)(c.Path); rerr != nil || !ok {
					t.Fatalf("plain read: ok=%v %v", ok, rerr)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.refused) {
				t.Fatalf("err = %v, want one naming %q", err, tc.refused)
			}
			got, rerr := os.ReadFile(victim)
			if rerr != nil || string(got) != outsideContent {
				t.Fatalf("file outside the repository changed: %q, %v", got, rerr)
			}
			if fi, serr := os.Stat(victim); serr == nil && fi.Mode().Perm()&0o111 != 0 {
				t.Fatalf("file outside the repository made executable: %v", fi.Mode())
			}
			if _, _, rerr := repoReader(root)(c.Path); rerr == nil || !strings.Contains(rerr.Error(), tc.refused) {
				t.Fatalf("read err = %v, want one naming %q", rerr, tc.refused)
			}
		})
	}
}

func csMkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
}

func csSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}
