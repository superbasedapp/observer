package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestHostedUploadNonGitDefault (decision SBXD-8): a folder that is not a
// repository uploads by default, a file that leaves the key out keeps the
// default, and false is honoured.
func TestHostedUploadNonGitDefault(t *testing.T) {
	if !Default().Terminal.Sandbox.Hosted.UploadNonGit {
		t.Fatal("upload_non_git is not on by default")
	}
	for body, want := range map[string]bool{
		"[terminal.sandbox.hosted]\nmax_run_minutes = 60\n":   true,
		"[terminal.sandbox.hosted]\nupload_non_git = false\n": false,
	} {
		p := filepath.Join(t.TempDir(), "config.toml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		cfg, err := Load(LoadOptions{GlobalPath: p})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Terminal.Sandbox.Hosted.UploadNonGit != want {
			t.Errorf("%q: upload_non_git = %v", body, cfg.Terminal.Sandbox.Hosted.UploadNonGit)
		}
	}
}

// TestHostedUploadIgnoreValidated: extra ignore patterns are one-line,
// non-empty gitignore patterns, at most 200 of at most 256 characters.
func TestHostedUploadIgnoreValidated(t *testing.T) {
	base := Default().Terminal.Sandbox.Hosted
	ok := base
	ok.UploadIgnore = []string{"*.log", "!dist/", "data/raw/", `\#notes`}
	if err := validateTerminalSandboxHosted(ok); err != nil {
		t.Errorf("valid patterns: %v", err)
	}
	many := make([]string, 201)
	for i := range many {
		many[i] = "a"
	}
	for name, list := range map[string][]string{
		"empty":      {"  "},
		"line break": {"a\nb"},
		"control":    {"a\x07"},
		"comment":    {"# note"},
		"bare bang":  {"!"},
		"bare slash": {"/"},
		"too long":   {strings.Repeat("a", 257)},
		"too many":   many,
	} {
		c := base
		c.UploadIgnore = list
		err := validateTerminalSandboxHosted(c)
		if err == nil || !strings.Contains(err.Error(), "hosted.upload_ignore") {
			t.Errorf("%s: %v", name, err)
		}
	}
}
