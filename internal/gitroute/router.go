package gitroute

import (
	"context"
	"sync"
	"time"
)

// Env is the host a Router reads. Every function is required on a Linux
// host; Now defaults to time.Now. The daemon wires the real reads
// (cmd/observer/security_quickscan_gitroute.go); tests pass fakes.
type Env struct {
	// GOOS is runtime.GOOS. Only "linux" reads anything else.
	GOOS string
	// ReadMountinfo returns /proc/self/mountinfo.
	ReadMountinfo func() ([]byte, error)
	// InteropEnabled reports that WSL interop's binfmt_misc registration
	// is enabled.
	InteropEnabled func() bool
	// PathEnv returns $PATH.
	PathEnv func() string
	// IsFile reports an existing regular file (following a link).
	IsFile func(path string) bool
	// IsShim reports an Observer command-wrapping shim (shimguard's marker),
	// which is never run as git.
	IsShim func(path string) bool
	// Version runs `<path> --version` and returns its output.
	Version func(ctx context.Context, path string) (string, error)
	// Now is the clock.
	Now func() time.Time
}

const (
	// factsTTL is how long the mount table and the interop state are
	// reused before they are read again.
	factsTTL = 5 * time.Minute
	// retryAfter is how long a failed git.exe resolution (none found, or
	// one that stopped starting) is remembered before it is tried again.
	retryAfter = 5 * time.Minute
	// resolveTimeout bounds each `git.exe --version` probe.
	resolveTimeout = 3 * time.Second
)

// Router chooses the plan of each quick-scan git read and remembers, per
// daemon, the host facts and the resolved git.exe. It is safe for
// concurrent use; a nil Router plans the host's own git.
type Router struct {
	env Env

	mu          sync.Mutex
	factsAt     time.Time
	mounts      []Mount // nil: the table could not be read
	interop     bool
	git         string
	gitFailedAt time.Time
}

// NewRouter returns a Router over env.
func NewRouter(env Env) *Router { return &Router{env: env} }

func (r *Router) now() time.Time {
	if r.env.Now != nil {
		return r.env.Now()
	}
	return time.Now()
}

// Plan returns the plan for one git read of root with args. Resolving
// git.exe (the first time a Windows-drive root is read, and again after
// retryAfter when none was usable) runs under ctx.
func (r *Router) Plan(ctx context.Context, root string, args []string) Plan {
	if r == nil {
		return Plan{Route: RouteHost, Why: "no router"}
	}
	if r.env.GOOS != "linux" {
		return Choose(Facts{GOOS: r.env.GOOS}, root, args)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.refreshFacts(now)
	f := Facts{GOOS: r.env.GOOS, Interop: r.interop}
	f.Mount, f.MountOK = mountOf(r.mounts, root)
	if f.MountOK && f.Mount.DrvFs && f.Interop {
		f.WindowsGit = r.windowsGit(ctx, now)
	}
	return Choose(f, root, args)
}

// Prime reads the host facts and, when a Windows drive is mounted and
// interop is on, resolves git.exe, so the first commit's scan does not
// pay for it. It does nothing on another host.
func (r *Router) Prime(ctx context.Context) {
	if r == nil || r.env.GOOS != "linux" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	r.refreshFacts(now)
	if !r.interop {
		return
	}
	if _, ok := driveMount(r.mounts, 'C'); ok || r.mounts == nil {
		r.windowsGit(ctx, now)
	}
}

// Failed classifies a failed read of plan p and reports whether its
// Fallback should run, with the deciding row. A git.exe that did not start
// is forgotten for retryAfter, so the next reads go straight to the WSL
// git instead of failing first.
func (r *Router) Failed(p Plan, f Failure) (bool, string) {
	fallback, why := Environmental(f)
	if fallback && f.Unavailable && r != nil && p.Program != "" {
		r.mu.Lock()
		if r.git == p.Program {
			r.git, r.gitFailedAt = "", r.now()
		}
		r.mu.Unlock()
	}
	return fallback && p.Fallback != nil, why
}

// refreshFacts rereads the mount table and the interop state once they are
// older than factsTTL. Called with r.mu held.
func (r *Router) refreshFacts(now time.Time) {
	if !r.factsAt.IsZero() && now.Sub(r.factsAt) < factsTTL {
		return
	}
	r.factsAt = now
	r.mounts = nil
	if r.env.ReadMountinfo != nil {
		if b, err := r.env.ReadMountinfo(); err == nil {
			if m := ParseMountinfo(b); len(m) > 0 {
				r.mounts = m
			}
		}
	}
	r.interop = r.env.InteropEnabled != nil && r.env.InteropEnabled()
}

// windowsGit returns the resolved git.exe, resolving it when there is none
// and the last failure is older than retryAfter. A resolution cut short by
// ctx is not remembered as a failure. Called with r.mu held.
func (r *Router) windowsGit(ctx context.Context, now time.Time) string {
	if r.git != "" {
		return r.git
	}
	if !r.gitFailedAt.IsZero() && now.Sub(r.gitFailedAt) < retryAfter {
		return ""
	}
	p, done := r.resolve(ctx)
	switch {
	case p != "":
		r.git, r.gitFailedAt = p, time.Time{}
	case done:
		r.gitFailedAt = now
	}
	return p
}

// resolve tries each candidate in order: an existing regular file, not a
// shim, whose --version names a Git for Windows build. done is false when
// ctx ended before every candidate was tried.
func (r *Router) resolve(ctx context.Context) (string, bool) {
	if r.env.PathEnv == nil || r.env.IsFile == nil || r.env.Version == nil {
		return "", true
	}
	for _, c := range Candidates(r.env.PathEnv(), r.mounts) {
		if ctx.Err() != nil {
			return "", false
		}
		if !r.env.IsFile(c) || (r.env.IsShim != nil && r.env.IsShim(c)) {
			continue
		}
		vctx, cancel := context.WithTimeout(ctx, resolveTimeout)
		out, err := r.env.Version(vctx, c)
		cancel()
		if err == nil && IsWindowsGitVersion(out) {
			return c, true
		}
	}
	return "", ctx.Err() == nil
}
