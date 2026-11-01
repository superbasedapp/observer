//go:build !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// terminal_sandbox_return_scan_test.go pins the ONE return scan both return
// paths share (lane SBX-P3C audit finding 1, Linux live re-check 4 DEFECT
// D4): every planted shape is refused BEFORE any host git step runs on the
// copy (a recording git runner proves zero calls), on the clone-local path
// (sandboxReturn) and on the clone-remote path (sandboxReturnBare); the copy
// is kept and stamped so Observer never runs host git in it again.

// returnScanShapes are the box-written shapes the text scan refuses.
var returnScanShapes = map[string]struct {
	edit func(t *testing.T, copyDir string)
	want string
}{
	"planted commondir": {
		edit: func(t *testing.T, copyDir string) {
			writeTestFile(t, filepath.Join(copyDir, ".git", "commondir"), "../../elsewhere/.git\n")
		},
		want: "commondir",
	},
	"planted config alias": {
		edit: func(t *testing.T, copyDir string) {
			appendTestFile(t, filepath.Join(copyDir, ".git", "config"), "[alias]\n\tst = !touch HOST-RAN\n")
		},
		want: "alias.st",
	},
	"include path (D4)": {
		edit: func(t *testing.T, copyDir string) {
			writeTestFile(t, filepath.Join(copyDir, "inc.cfg"), "[core]\n\tfsmonitor = touch HOST-RAN\n")
			appendTestFile(t, filepath.Join(copyDir, ".git", "config"), "[include]\n\tpath = ../inc.cfg\n")
		},
		want: "include directive",
	},
	"includeIf (D4)": {
		edit: func(t *testing.T, copyDir string) {
			writeTestFile(t, filepath.Join(copyDir, "inc.cfg"), "[core]\n\tfsmonitor = touch HOST-RAN\n")
			appendTestFile(t, filepath.Join(copyDir, ".git", "config"), "[includeIf \"gitdir:/\"]\n\tpath = ../inc.cfg\n")
		},
		want: "includeif directive",
	},
	"renamed .git with a fresh config including the work tree (D4 ret10)": {
		edit: func(t *testing.T, copyDir string) {
			gitDir := filepath.Join(copyDir, ".git")
			aside := filepath.Join(copyDir, ".git-moved")
			if err := os.Rename(gitDir, aside); err != nil {
				t.Fatal(err)
			}
			if err := os.CopyFS(gitDir, os.DirFS(aside)); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(copyDir, "inc.cfg"), "[core]\n\tfsmonitor = touch HOST-RAN\n")
			appendTestFile(t, filepath.Join(gitDir, "config"), "[include]\n\tpath = ../inc.cfg\n")
		},
		want: "include directive",
	},
	"hooksPath on the header line": {
		edit: func(t *testing.T, copyDir string) {
			appendTestFile(t, filepath.Join(copyDir, ".git", "config"), "[core] hooksPath = /tmp/evil\n")
		},
		want: "core.hookspath",
	},
}

func writeTestFile(t *testing.T, p, s string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func appendTestFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
}

// recordingGit is the fake host git: it records every step and runs none.
type recordingGit struct{ calls [][]string }

func (r *recordingGit) run(_ context.Context, st workspace.Step) ([]byte, error) {
	r.calls = append(r.calls, st.Argv)
	return nil, errors.New("the fake git runs nothing")
}

// TestReturnScanRefusesBeforeAnyGitOnBothPaths is the test of finding 1 and
// D4: on both return paths every shape is refused with zero host git calls,
// the refusal names what was planted and tells the user not to run git
// there, the copy is kept and stamped, and a second return is refused by the
// stamp with zero calls again.
func TestReturnScanRefusesBeforeAnyGitOnBothPaths(t *testing.T) {
	paths := map[string]func(t *testing.T) (workspace.ReturnRequest, func(context.Context, workspace.ReturnRequest, func(context.Context, workspace.Step) ([]byte, error)) error){
		"clone-local": func(t *testing.T) (workspace.ReturnRequest, func(context.Context, workspace.ReturnRequest, func(context.Context, workspace.Step) ([]byte, error)) error) {
			req, _ := returnFixture(t)
			return req, func(ctx context.Context, req workspace.ReturnRequest, run func(context.Context, workspace.Step) ([]byte, error)) error {
				_, err := sandboxReturn(ctx, req, run, nil)
				return err
			}
		},
		"clone-remote": func(t *testing.T) (workspace.ReturnRequest, func(context.Context, workspace.ReturnRequest, func(context.Context, workspace.Step) ([]byte, error)) error) {
			req, _, _ := remoteReturnFixture(t)
			return req, func(ctx context.Context, req workspace.ReturnRequest, run func(context.Context, workspace.Step) ([]byte, error)) error {
				_, err := sandboxReturnBare(ctx, req, run, nil)
				return err
			}
		},
	}
	for pname, mk := range paths {
		for sname, shape := range returnScanShapes {
			t.Run(pname+"/"+sname, func(t *testing.T) {
				req, ret := mk(t)
				shape.edit(t, req.CopyDir)
				var fake recordingGit
				err := ret(context.Background(), req, fake.run)
				if err == nil {
					t.Fatal("a planted copy was returned")
				}
				if len(fake.calls) != 0 {
					t.Fatalf("host git ran before the scan refused: %v", fake.calls)
				}
				if !strings.Contains(err.Error(), shape.want) || !strings.Contains(err.Error(), "do not run git in the kept copy") {
					t.Fatalf("refusal %q does not name %q and the advice", err, shape.want)
				}
				if _, serr := os.Lstat(filepath.Join(req.CopyDir, gitview.HostGitRefusedStamp)); serr != nil {
					t.Fatalf("the refused copy was not stamped: %v", serr)
				}
				if fi, serr := os.Lstat(filepath.Join(req.CopyDir, ".git")); serr != nil || !fi.IsDir() {
					t.Fatalf("the copy was not kept: %v", serr)
				}
				if _, serr := os.Lstat(filepath.Join(req.CopyDir, "HOST-RAN")); serr == nil {
					t.Fatal("the box's command ran")
				}
				// A second return is refused by the stamp alone.
				if err := ret(context.Background(), req, fake.run); err == nil || !strings.Contains(err.Error(), "stamped") || len(fake.calls) != 0 {
					t.Fatalf("second return: %v, calls %v", err, fake.calls)
				}
				// Observer's other host git path refuses the stamped copy too.
				if _, _, gerr := gitview.RunReadOnly(context.Background(), req.CopyDir, 1<<10, "status"); !errors.Is(gerr, gitview.ErrHostGitRefused) {
					t.Fatalf("gitview ran in the stamped copy: %v", gerr)
				}
			})
		}
	}
}

// TestReturnScanReadsTheEffectiveConfig is the second layer of D4: a copy
// whose files pass the text scan is still refused when the config git itself
// reads (here a canned answer of the config list step, the ONE git call made)
// sets an execution-capable key; the return runs no other git step.
func TestReturnScanReadsTheEffectiveConfig(t *testing.T) {
	for _, path := range []string{"clone-local", "clone-remote"} {
		t.Run(path, func(t *testing.T) {
			var req workspace.ReturnRequest
			if path == "clone-local" {
				req, _ = returnFixture(t)
			} else {
				req, _, _ = remoteReturnFixture(t)
			}
			var calls [][]string
			run := func(_ context.Context, st workspace.Step) ([]byte, error) {
				calls = append(calls, st.Argv)
				if !st.Hardened || !st.NeutralHome {
					t.Errorf("the config read is not hardened with a neutral home: %+v", st)
				}
				return []byte("command line:\x00core.fsmonitor\nfalse\x00file:" + req.CopyDir + "/inc.cfg\x00core.fsmonitor\ntouch HOST-RAN\x00"), nil
			}
			var err error
			if path == "clone-local" {
				_, err = sandboxReturn(context.Background(), req, run, nil)
			} else {
				_, err = sandboxReturnBare(context.Background(), req, run, nil)
			}
			if err == nil || !strings.Contains(err.Error(), "inc.cfg (sets core.fsmonitor)") {
				t.Fatalf("err %v", err)
			}
			if len(calls) != 1 || !strings.Contains(strings.Join(calls[0], " "), "config --list --show-origin --includes") {
				t.Fatalf("calls %v: only the config list may run", calls)
			}
			if _, serr := os.Lstat(filepath.Join(req.CopyDir, gitview.HostGitRefusedStamp)); serr != nil {
				t.Fatal("not stamped")
			}
		})
	}
}

// TestReturnScanRealGitListsIncludes runs the real host git config read
// (CopyConfigListStep through runReturnGit) on a copy whose config includes
// a work-tree file: git follows the include, names the included file as the
// origin of core.fsmonitor, and reading the config runs nothing.
func TestReturnScanRealGitListsIncludes(t *testing.T) {
	req, _ := returnFixture(t)
	writeTestFile(t, filepath.Join(req.CopyDir, "inc.cfg"), "[core]\n\tfsmonitor = touch HOST-RAN\n")
	cfg := filepath.Join(req.CopyDir, ".git", "config")
	appendTestFile(t, cfg, "[include]\n\tpath = ../inc.cfg\n")
	out, err := runReturnGit(context.Background(), workspace.CopyConfigListStep(req.CopyDir))
	if err != nil {
		t.Fatalf("config list: %v", err)
	}
	viol, err := workspace.EffectiveConfigViolations(out)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(viol, ";")
	if !strings.Contains(joined, "inc.cfg (sets core.fsmonitor)") || !strings.Contains(joined, "include.path") {
		t.Fatalf("violations %v", viol)
	}
	if _, serr := os.Lstat(filepath.Join(req.CopyDir, "HOST-RAN")); serr == nil {
		t.Fatal("reading the config ran the command")
	}
}
