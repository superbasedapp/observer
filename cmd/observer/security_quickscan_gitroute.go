//go:build !sbo_omit_security

package main

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/gitroute"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secquickscan"
	"github.com/marmutapp/superbased-observer/internal/shimguard"
)

// security_quickscan_gitroute.go is the daemon side of R3-86: which git the
// commit quick scan reads a repository with. The decision is
// internal/gitroute's (pure, table-driven); this file supplies the host
// reads it needs and runs the plan through the one git exec envelope
// (internal/gitview). On every host but a WSL daemon reading a checkout on
// a Windows drive the plan is the host's own git, exactly as before.

// securityGitRouter returns the daemon's router (one per process; tests
// replace the function).
var securityGitRouter = sync.OnceValue(func() *gitroute.Router {
	return gitroute.NewRouter(securityGitRouteEnv())
})

// securityGitRouteEnv is the router's view of this host.
func securityGitRouteEnv() gitroute.Env {
	return gitroute.Env{
		GOOS:           runtime.GOOS,
		ReadMountinfo:  func() ([]byte, error) { return os.ReadFile("/proc/self/mountinfo") },
		InteropEnabled: wslInteropEnabled,
		PathEnv:        func() string { return os.Getenv("PATH") },
		IsFile: func(p string) bool {
			st, err := os.Stat(p) //nolint:gosec // G703: a git.exe candidate internal/gitroute listed (the interop PATH's DrvFs directories or the fixed Git for Windows install directories), only stat'ed.
			return err == nil && st.Mode().IsRegular()
		},
		IsShim: securityIsShimFile,
		Version: func(ctx context.Context, p string) (string, error) {
			return gitview.ProgramVersion(ctx, gitview.Program{Path: p, Interop: true}, 0)
		},
	}
}

// wslInteropRegistrations are binfmt_misc's WSL interop entries (the
// "-late" one is what newer WSL builds register).
var wslInteropRegistrations = []string{
	"/proc/sys/fs/binfmt_misc/WSLInterop",
	"/proc/sys/fs/binfmt_misc/WSLInterop-late",
}

// wslInteropEnabled reports that WSL interop can start a Windows program:
// one of its binfmt_misc registrations exists and reads "enabled".
func wslInteropEnabled() bool {
	for _, p := range wslInteropRegistrations {
		b, err := os.ReadFile(p) //nolint:gosec // G304: a fixed procfs path.
		if err != nil {
			continue
		}
		first, _, _ := strings.Cut(string(b), "\n")
		if strings.TrimSpace(first) == "enabled" {
			return true
		}
	}
	return false
}

// securityIsShimFile reports an Observer command-wrapping shim: never run
// as git (SHELLWRAP-1).
func securityIsShimFile(p string) bool {
	f, err := os.Open(p) //nolint:gosec // G304: a git.exe candidate the router listed (PATH or the fixed install directories), read only for the shim marker.
	if err != nil {
		return false
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false
	}
	return shimguard.IsShim(head[:n])
}

// securityQuickScanGitProgramRun runs a named git (a seam for tests).
var securityQuickScanGitProgramRun = gitview.RunReadOnlyNoLazyFetchProgram

// securityRunGitPlan runs one quick-scan read as plan says and notes in the
// scan's context which git ran (secquickscan.NoteGitRoute). A Windows-git
// read that fails for an environmental reason (gitroute.Environmental)
// runs again with the plan's fallback, the WSL git; any other failure is
// git's own answer and is returned as it is.
func securityRunGitPlan(ctx context.Context, root string, plan gitroute.Plan, maxBytes int, timeout time.Duration, args []string) ([]byte, bool, error) {
	if plan.Route != gitroute.RouteWindowsGit {
		var env []string
		if gitDir, ok := git.LinkedGitDir(root); ok {
			env = []string{"GIT_DIR=" + gitDir, "GIT_WORK_TREE=" + root}
		}
		full := append(append([]string(nil), plan.ConfigArgs...), args...)
		secquickscan.NoteGitRoute(ctx, string(plan.Route))
		return securityQuickScanGitRun(ctx, root, maxBytes, timeout, env, full...)
	}
	// git.exe follows a linked worktree's `.git` pointer (D:/...) itself:
	// no GIT_DIR, which would be this host's spelling.
	prog := gitview.Program{Path: plan.Program, Dir: plan.Dir, Interop: true}
	out, over, err := securityQuickScanGitProgramRun(ctx, root, prog, maxBytes, timeout, nil, args...)
	if err == nil {
		secquickscan.NoteGitRoute(ctx, string(plan.Route))
		return out, over, nil
	}
	fallback, why := securityGitRouter().Failed(plan, securityGitFailure(ctx, err))
	if !fallback {
		secquickscan.NoteGitRoute(ctx, string(plan.Route))
		return nil, false, err
	}
	slog.Debug("security quick scan: Windows git failed, reading with the WSL git",
		"why", why, "program", plan.Program, "err", err)
	return securityRunGitPlan(ctx, root, *plan.Fallback, maxBytes, timeout, args)
}

// securityGitFailure is err in gitroute's plain fields.
func securityGitFailure(ctx context.Context, err error) gitroute.Failure {
	f := gitroute.Failure{
		Unavailable: errors.Is(err, gitview.ErrGitUnavailable),
		Canceled:    ctx.Err() != nil,
		ExitCode:    -1,
	}
	if gf, ok := gitview.InspectError(err); ok {
		f.ExitCode, f.Stderr, f.TimedOut = gf.ExitCode, gf.Stderr, gf.TimedOut
	}
	return f
}
