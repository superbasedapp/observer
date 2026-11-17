package main

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/defaultworkspace"
)

// needGit skips a test that runs the real `git init` when git is absent.
func needGit(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not on PATH")
	}
}

// TestEnsureDefaultWorkspaceSetsUpConfiguredFolder: start/init create a
// missing configured folder once (folder, marker, its own repository) and
// say so, and are silent after.
func TestEnsureDefaultWorkspaceSetsUpConfiguredFolder(t *testing.T) {
	needGit(t)
	dir := filepath.Join(t.TempDir(), "ws")
	cfg := config.Default()
	cfg.Workspace.DefaultDir = dir
	var out bytes.Buffer
	ensureDefaultWorkspace(context.Background(), &out, cfg)
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		t.Fatalf("folder not created: %v (output %q)", err, out.String())
	}
	if !strings.Contains(out.String(), "created "+dir) {
		t.Fatalf("output %q does not report the creation", out.String())
	}
	if !defaultworkspace.Marked(dir) {
		t.Fatal("marker not written")
	}
	if root, ok := defaultworkspace.RepoRoot(dir); !ok || root != dir {
		t.Fatalf("not its own repository: %q %v", root, ok)
	}
	// No template: the repository carries no hook samples.
	if entries, _ := os.ReadDir(filepath.Join(dir, ".git", "hooks")); len(entries) != 0 {
		t.Fatalf("git init copied hooks: %v", entries)
	}
	out.Reset()
	ensureDefaultWorkspace(context.Background(), &out, cfg)
	if out.Len() != 0 {
		t.Fatalf("a set-up folder must be silent, got %q", out.String())
	}
}

// TestEnsureDefaultWorkspaceWarnsOnRefusal: a folder that breaks a rule is
// one WARN line and nothing is created; the command carries on.
func TestEnsureDefaultWorkspaceWarnsOnRefusal(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		t.Skip("no home folder in this test process")
	}
	cfg := config.Default()
	cfg.Workspace.DefaultDir = home
	var out bytes.Buffer
	ensureDefaultWorkspace(context.Background(), &out, cfg)
	if !strings.HasPrefix(out.String(), "WARN default workspace") {
		t.Fatalf("want a WARN line, got %q", out.String())
	}
}

// TestWorkspaceGitInitNeverTouchesAProject: Ensure never calls git init on
// a repository or a folder that holds files without the marker.
func TestWorkspaceGitInitNeverTouchesAProject(t *testing.T) {
	needGit(t)
	proj := filepath.Join(t.TempDir(), "proj")
	if err := os.MkdirAll(proj, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := workspaceGitInit(context.Background(), proj); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "main.go"), []byte("package main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.Workspace.DefaultDir = proj
	var out bytes.Buffer
	ensureDefaultWorkspace(context.Background(), &out, cfg)
	if !strings.HasPrefix(out.String(), "WARN default workspace") || defaultworkspace.Marked(proj) {
		t.Fatalf("an unmarked repository must be refused and left alone: %q", out.String())
	}
}

// TestWorkspaceGitEnv (review finding 9, 2026-11-12): the workspace's
// `git init` drops every variable that points git at another repository or
// injects configuration, keeps the rest, and turns the system and global
// configuration files off.
func TestWorkspaceGitEnv(t *testing.T) {
	in := []string{
		"PATH=/usr/bin", "HOME=/home/dev",
		"GIT_DIR=/elsewhere/.git", "GIT_WORK_TREE=/elsewhere", "GIT_INDEX_FILE=/x", "GIT_COMMON_DIR=/x",
		"GIT_OBJECT_DIRECTORY=/x", "GIT_TEMPLATE_DIR=/evil-templates",
		"GIT_CONFIG_PARAMETERS='core.hooksPath'='/evil'",
		"GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=core.hooksPath", "GIT_CONFIG_VALUE_0=/evil",
		"GIT_CONFIG=/evil.cfg", "GIT_CONFIG_GLOBAL=/home/dev/.gitconfig", "GIT_CONFIG_SYSTEM=/etc/gitconfig",
		"GIT_CONFIG_NOSYSTEM=0", "git_dir=/lower/.git",
		"GIT_AUTHOR_NAME=Dev",
	}
	got := workspaceGitEnv(in)
	have := map[string]string{}
	for _, kv := range got {
		k, v, _ := strings.Cut(kv, "=")
		if _, dup := have[k]; dup {
			t.Errorf("%s set twice: %v", k, got)
		}
		have[k] = v
	}
	for _, tc := range []struct {
		key     string
		present bool
		value   string
	}{
		{"PATH", true, "/usr/bin"},
		{"HOME", true, "/home/dev"},
		{"GIT_AUTHOR_NAME", true, "Dev"},
		{"GIT_CONFIG_NOSYSTEM", true, "1"},
		{"GIT_CONFIG_GLOBAL", true, os.DevNull},
		{"GIT_DIR", false, ""},
		{"git_dir", false, ""},
		{"GIT_WORK_TREE", false, ""},
		{"GIT_INDEX_FILE", false, ""},
		{"GIT_COMMON_DIR", false, ""},
		{"GIT_OBJECT_DIRECTORY", false, ""},
		{"GIT_TEMPLATE_DIR", false, ""},
		{"GIT_CONFIG_PARAMETERS", false, ""},
		{"GIT_CONFIG_COUNT", false, ""},
		{"GIT_CONFIG_KEY_0", false, ""},
		{"GIT_CONFIG_VALUE_0", false, ""},
		{"GIT_CONFIG", false, ""},
		{"GIT_CONFIG_SYSTEM", false, ""},
	} {
		v, ok := have[tc.key]
		if ok != tc.present || (ok && v != tc.value) {
			t.Errorf("%s: present=%v value=%q, want present=%v value=%q", tc.key, ok, v, tc.present, tc.value)
		}
	}
	if len(in) == 0 || in[0] != "PATH=/usr/bin" {
		t.Errorf("the input was modified: %v", in)
	}
}
