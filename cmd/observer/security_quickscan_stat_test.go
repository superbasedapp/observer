//go:build !sbo_omit_security

package main

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/gitroute"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
)

// gitRouteHost is a fake WSL host for the quick scan's router: drive D:
// mounted at /mnt/d, interop as given, and git.exe at the usual install
// path when windowsGit is set.
func gitRouteHost(interop, windowsGit bool) gitroute.Env {
	const exe = "/mnt/c/Program Files/Git/cmd/git.exe"
	return gitroute.Env{
		GOOS: "linux",
		ReadMountinfo: func() ([]byte, error) {
			return []byte("1 0 8:1 / / rw - ext4 /dev/sda rw\n" +
				`2 1 0:2 / /mnt/c rw - 9p C:\134 rw,aname=drvfs;path=C:\` + "\n" +
				`3 1 0:3 / /mnt/d rw - 9p D:\134 rw,aname=drvfs;path=D:\` + "\n"), nil
		},
		InteropEnabled: func() bool { return interop },
		PathEnv:        func() string { return "/usr/bin" },
		IsFile:         func(p string) bool { return windowsGit && p == exe },
		IsShim:         func(string) bool { return false },
		Version: func(context.Context, string) (string, error) {
			return "git version 2.53.0.windows.2", nil
		},
	}
}

// withGitRoute swaps the daemon's router and both git runners for the test.
func withGitRoute(t *testing.T, env gitroute.Env,
	host func(ctx context.Context, root string, maxBytes int, timeout time.Duration, env []string, args ...string) ([]byte, bool, error),
	prog func(ctx context.Context, root string, p gitview.Program, maxBytes int, timeout time.Duration, env []string, args ...string) ([]byte, bool, error),
) {
	t.Helper()
	r := gitroute.NewRouter(env)
	prevRouter, prevHost, prevProg := securityGitRouter, securityQuickScanGitRun, securityQuickScanGitProgramRun
	securityGitRouter = func() *gitroute.Router { return r }
	securityQuickScanGitRun, securityQuickScanGitProgramRun = host, prog
	t.Cleanup(func() {
		securityGitRouter, securityQuickScanGitRun, securityQuickScanGitProgramRun = prevRouter, prevHost, prevProg
	})
}

// TestSecurityQuickScanGitRoutes pins R3-86 (and R3-66 under it): on a WSL
// daemon a checkout on a Windows drive is read by git.exe through interop,
// with the root's Windows spelling as -C and the very argv the WSL git
// would get; without a usable git.exe the WSL git reads it with the
// minimal stat check; a Linux-filesystem checkout is unchanged.
func TestSecurityQuickScanGitRoutes(t *testing.T) {
	minimal := []string{"-c", "core.checkStat=minimal", "-c", "core.trustctime=false"}
	diff := []string{"diff", "--no-color", "HEAD"}
	for _, tc := range []struct {
		name               string
		interop, gitExe    bool
		root               string
		wantProg, wantHost []string
		wantDir, wantRoute string
	}{
		{"git.exe on a Windows drive", true, true, "/mnt/d/programsx/repo", diff, nil, `D:\programsx\repo`, policy.QuickScanGitWindows},
		{"interop off: WSL git, minimal stat", false, true, "/mnt/d/programsx/repo", nil, append(append([]string(nil), minimal...), diff...), "", policy.QuickScanGitDrvFs},
		{"no git.exe: WSL git, minimal stat", true, false, "/mnt/d/programsx/repo", nil, append(append([]string(nil), minimal...), diff...), "", policy.QuickScanGitDrvFs},
		{"the Linux filesystem: unchanged", true, true, "/home/dev/repo", nil, diff, "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var gotHost, gotProg []string
			var gotDir string
			withGitRoute(t, gitRouteHost(tc.interop, tc.gitExe),
				func(_ context.Context, _ string, _ int, _ time.Duration, _ []string, args ...string) ([]byte, bool, error) {
					gotHost = args
					return nil, false, nil
				},
				func(_ context.Context, _ string, p gitview.Program, _ int, _ time.Duration, env []string, args ...string) ([]byte, bool, error) {
					if !p.Interop || len(env) != 0 {
						t.Errorf("program run = %+v env %q, want an interop run with no GIT_DIR", p, env)
					}
					gotProg, gotDir = args, p.Dir
					return nil, false, nil
				})
			e := &secquickscan.Engine{Git: securityQuickScanGit}
			res := e.Scan(context.Background(), secquickscan.Request{Root: tc.root, Form: secquickscan.Form{All: true}})
			_ = res
			if tc.wantProg != nil {
				// The engine's own argv for `commit -a`.
				want := secquickscan.DiffArgs(secquickscan.Form{All: true})
				if !slices.Equal(gotProg, want) || gotDir != tc.wantDir || gotHost != nil {
					t.Fatalf("git.exe args %q in %q (host %q); want %q in %q", gotProg, gotDir, gotHost, want, tc.wantDir)
				}
			} else {
				want := append(append([]string(nil), tc.wantHost[:len(tc.wantHost)-len(diff)]...), secquickscan.DiffArgs(secquickscan.Form{All: true})...)
				if !slices.Equal(gotHost, want) || gotProg != nil {
					t.Fatalf("host git args %q (git.exe %q); want %q", gotHost, gotProg, want)
				}
			}
			if res.GitRoute != tc.wantRoute {
				t.Fatalf("Result.GitRoute = %q, want %q", res.GitRoute, tc.wantRoute)
			}
		})
	}
}

// TestSecurityQuickScanGitFallsBack: a git.exe that fails to start, or
// cannot see the repository, is read again by the WSL git (minimal stat)
// and the result says so; git's own answer from git.exe is kept.
func TestSecurityQuickScanGitFallsBack(t *testing.T) {
	for _, tc := range []struct {
		name      string
		progErr   error
		wantHost  bool
		wantRoute string
	}{
		{"git.exe did not start", gitview.ErrGitUnavailable, true, policy.QuickScanGitDrvFsFallback},
		{"dubious ownership", &gitview.GitError{ExitCode: 128, Stderr: "fatal: detected dubious ownership in repository"}, true, policy.QuickScanGitDrvFsFallback},
		{"git's own answer is kept", &gitview.GitError{ExitCode: 128, Stderr: "fatal: bad object deadbeef"}, false, policy.QuickScanGitWindows},
	} {
		t.Run(tc.name, func(t *testing.T) {
			hostCalls := 0
			withGitRoute(t, gitRouteHost(true, true),
				func(_ context.Context, _ string, _ int, _ time.Duration, _ []string, args ...string) ([]byte, bool, error) {
					hostCalls++
					if args[1] != "core.checkStat=minimal" {
						t.Errorf("fallback args = %q, want the minimal stat check", args)
					}
					return []byte{}, false, nil
				},
				func(context.Context, string, gitview.Program, int, time.Duration, []string, ...string) ([]byte, bool, error) {
					return nil, false, tc.progErr
				})
			e := &secquickscan.Engine{Git: securityQuickScanGit}
			res := e.Scan(context.Background(), secquickscan.Request{Root: "/mnt/d/repo"})
			if (hostCalls > 0) != tc.wantHost {
				t.Fatalf("host git ran %d times, want ran=%v", hostCalls, tc.wantHost)
			}
			wantVerdict := secquickscan.VerdictClean
			if !tc.wantHost {
				wantVerdict = secquickscan.VerdictUnknown
			}
			if res.Verdict != wantVerdict || res.GitRoute != tc.wantRoute {
				t.Fatalf("result %s (%s) via %q, want %s via %q", res.Verdict, res.Reason, res.GitRoute, wantVerdict, tc.wantRoute)
			}
		})
	}
}

// TestGitRouteSpellingsMatchPolicy: gitroute's Route values are the closed
// vocabulary policy.QuickScanDetail.Git carries on the wire.
func TestGitRouteSpellingsMatchPolicy(t *testing.T) {
	for route, want := range map[gitroute.Route]string{
		gitroute.RouteWindowsGit:        policy.QuickScanGitWindows,
		gitroute.RouteDrvFsStat:         policy.QuickScanGitDrvFs,
		gitroute.RouteDrvFsAfterWindows: policy.QuickScanGitDrvFsFallback,
		gitroute.RouteHost:              "",
	} {
		if string(route) != want || !policy.ValidQuickScanGit(string(route)) {
			t.Errorf("route %q, policy spelling %q", route, want)
		}
	}
	if secquickscan.GitRouteFallback != string(gitroute.RouteDrvFsAfterWindows) {
		t.Errorf("secquickscan.GitRouteFallback = %q", secquickscan.GitRouteFallback)
	}
}
