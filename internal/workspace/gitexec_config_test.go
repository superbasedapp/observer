package workspace

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gitexec_config_test.go pins the config half of the return scan (lane
// SBX-P3C audit finding 1, Linux live re-check 4 DEFECT D4): the
// execution-capable key table, the text scan's include/includeIf refusal on
// config and config.worktree, and the effective-config parse.

// TestExecConfigKeyTable is one case per table row family plus the keys a
// clean clone writes, which must never match.
func TestExecConfigKeyTable(t *testing.T) {
	yes := []string{
		"include.path", "includeIf.gitdir:/x/.path", "alias.st", "core.hooksPath", "core.fsmonitor",
		"core.sshCommand", "core.pager", "core.editor", "core.askPass", "core.gitProxy", "core.worktree",
		"uploadpack.packObjectsHook", "pager.log", "filter.evil.clean", "filter.lfs.smudge", "filter.x.process",
		"diff.external", "diff.x.textconv", "merge.x.driver", "credential.helper", "credential.https://h.helper",
		"gpg.program", "gpg.ssh.program", "sequence.editor", "remote.origin.uploadpack", "submodule.m.update",
		"difftool.x.cmd", "web.browser", "protocol.ext.allow",
	}
	no := []string{
		"core.repositoryformatversion", "core.filemode", "core.bare", "core.logallrefupdates",
		"remote.origin.url", "remote.origin.fetch", "branch.main.remote", "branch.main.merge",
		"filter.clean", "diff.x.external", "core.x.editor", "user.name",
	}
	for _, k := range yes {
		if !ExecConfigKey(k) {
			t.Errorf("%s is execution-capable", k)
		}
	}
	for _, k := range no {
		if ExecConfigKey(k) {
			t.Errorf("%s is not execution-capable", k)
		}
	}
}

// TestCopyReturnGitDirViolationsConfigShapes: the text scan names an include
// or includeIf directive and an execution-capable key, in config and in
// config.worktree, in every header spelling the small parser follows; a
// clean clone's config passes.
func TestCopyReturnGitDirViolationsConfigShapes(t *testing.T) {
	clean := "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n[remote \"origin\"]\n\turl = /src\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
	cases := []struct {
		name, file, body, want string
	}{
		{"clean", "config", clean, ""},
		{"include", "config", clean + "[include]\n\tpath = ../inc.cfg\n", "config (include directive)"},
		{"include upper case", "config", clean + "[INCLUDE]\n\tPath = ../inc.cfg\n", "config (include directive)"},
		{"includeIf", "config", clean + "[includeIf \"gitdir:/\"]\n\tpath = ../inc.cfg\n", "config (includeif directive)"},
		{"alias", "config", clean + "[alias]\n\tst = !touch x\n", "config (sets alias.st)"},
		{"hooksPath", "config", clean + "[core]\n\thooksPath = /tmp/h\n", "config (sets core.hookspath)"},
		{"key on the header line", "config", clean + "[core] sshCommand = evil\n", "config (sets core.sshcommand)"},
		{"filter driver", "config", clean + "[filter \"evil\"]\n\tclean = touch x\n", "config (sets filter.clean)"},
		{"old subsection spelling", "config", clean + "[filter.evil]\n\tsmudge = touch x\n", "config (sets filter.smudge)"},
		{"config.worktree include", "config.worktree", "[include]\n\tpath = ../inc.cfg\n", "config.worktree (include directive)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			gitDir := filepath.Join(t.TempDir(), ".git")
			if err := os.MkdirAll(filepath.Join(gitDir, "hooks"), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(gitDir, "config"), []byte(clean), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(gitDir, c.file), []byte(c.body), 0o600); err != nil {
				t.Fatal(err)
			}
			viol, err := CopyReturnGitDirViolations(gitDir)
			if err != nil {
				t.Fatal(err)
			}
			got := strings.Join(viol, "; ")
			if c.want == "" {
				if got != "" {
					t.Fatalf("a clean clone's config was refused: %s", got)
				}
				return
			}
			if !strings.Contains(got, c.want) {
				t.Fatalf("violations %q do not name %q", got, c.want)
			}
		})
	}
}

// TestCopyReturnGitDirViolationsConfigLink: a config that is a link is
// refused by its type and never followed.
func TestCopyReturnGitDirViolationsConfigLink(t *testing.T) {
	dir := t.TempDir()
	gitDir := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "elsewhere"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), filepath.Join(gitDir, "config")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	viol, err := CopyReturnGitDirViolations(gitDir)
	if err != nil || !strings.Contains(strings.Join(viol, ";"), "config (not a regular file)") {
		t.Fatalf("%v %v", viol, err)
	}
}

// TestEffectiveConfigViolations: the runner's own command-line settings are
// never a violation; a file origin setting an execution-capable key is,
// named by its file; unparseable output is an error.
func TestEffectiveConfigViolations(t *testing.T) {
	out := "command line:\x00core.fsmonitor\nfalse\x00command line:\x00core.hookspath\n/dev/null\x00" +
		"file:/w/.git/config\x00core.bare\nfalse\x00file:/w/.git/config\x00include.path\n../inc.cfg\x00" +
		"file:/w/inc.cfg\x00core.fsmonitor\ntouch x\x00"
	viol, err := EffectiveConfigViolations([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	want := "/w/.git/config (sets include.path); /w/inc.cfg (sets core.fsmonitor)"
	if strings.Join(viol, "; ") != want {
		t.Fatalf("got %q want %q", strings.Join(viol, "; "), want)
	}
	if v, err := EffectiveConfigViolations([]byte("command line:\x00core.fsmonitor\nfalse\x00")); err != nil || len(v) != 0 {
		t.Fatalf("the runner's own settings: %v %v", v, err)
	}
	if _, err := EffectiveConfigViolations([]byte("file:/w/.git/config\x00")); err == nil {
		t.Fatal("unpaired output parsed")
	}
	st := CopyConfigListStep("/w")
	if !st.Hardened || !st.NeutralHome || st.Argv[1] != "--git-dir=/w/.git" {
		t.Fatalf("step %+v", st)
	}
}
