//go:build !sbo_omit_terminals && !sbo_omit_security && !sbo_omit_security_trust

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestFU190IDETrustChecksTheFolderItOpens: `observer ide <app> <folder>`
// trust-checks the folder the app opens, not the working directory (the
// FU-177 rig run was refused at its home for a `.factory/settings.json`
// that had nothing to do with the folder). Through the cobra command with
// the real launch gates (guard enforce, security.trust selected) and a fake
// spawn: a finding in the cwd alone no longer refuses, one in the folder
// still does, and with no folder the cwd is still checked.
func TestFU190IDETrustChecksTheFolderItOpens(t *testing.T) {
	t.Setenv(repoTrustCheckedEnv, "")
	unaccepted := map[string]string{
		".claude/settings.json": `{"hooks":{"SessionStart":[{"hooks":[{"type":"command","command":"node .github/setup.js"}]}]}}`,
		".github/setup.js":      "console.log(1)\n",
	}
	clean := map[string]string{"README.md": "# x\n"}

	for _, tc := range []struct {
		name        string
		cwd, folder map[string]string
		noFolder    bool
		wantRefusal bool
		wantSpawned bool
	}{
		{name: "finding in the cwd only", cwd: unaccepted, folder: clean, wantSpawned: true},
		{name: "finding in the folder", cwd: clean, folder: unaccepted, wantRefusal: true},
		{name: "no folder: the cwd is checked", cwd: unaccepted, noFolder: true, wantRefusal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "fake-app")
			if err := os.WriteFile(bin, []byte("#!/bin/sh\n"), 0o755); err != nil { //nolint:gosec // test fixture executable
				t.Fatal(err)
			}
			cfg := filepath.Join(dir, "config.toml")
			body := "[observer]\ndb_path = " + strconv.Quote(filepath.ToSlash(filepath.Join(dir, "obs.db"))) + "\n\n" +
				"[guard]\nenabled = true\nmode = \"enforce\"\n\n" +
				"[components]\nadd = [\"" + repoTrustComponent + "\"]\n\n" +
				"[proxy]\nport = 18779\n\n[launch.tools.vscode]\npath = " + strconv.Quote(bin) + "\n"
			if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Chdir(writeTrustRepo(t, tc.cwd))
			folder := writeTrustRepo(t, tc.folder)

			spawned := false
			prev := ideCmdDeps
			ideCmdDeps = func() ideDeps {
				d := defaultIDEDeps()
				d.spawn = func([]string, string, []string) (*os.Process, error) {
					spawned = true
					return os.FindProcess(os.Getpid())
				}
				d.reachable = func(string, time.Duration) bool { return true }
				return d
			}
			t.Cleanup(func() { ideCmdDeps = prev })

			args := []string{"--config", cfg, "vscode"}
			if !tc.noFolder {
				args = append(args, folder)
			}
			cmd := newIDECmd()
			var out, errb bytes.Buffer
			cmd.SetOut(&out)
			cmd.SetErr(&errb)
			cmd.SetArgs(args)
			err := cmd.Execute()
			if tc.wantRefusal {
				if err == nil || !strings.Contains(err.Error(), "S-701") {
					t.Fatalf("err = %v, want the S-701 refusal\n%s", err, errb.String())
				}
			} else if err != nil {
				t.Fatalf("err = %v\n%s", err, errb.String())
			}
			if spawned != tc.wantSpawned {
				t.Errorf("spawned = %v, want %v", spawned, tc.wantSpawned)
			}
		})
	}
}
