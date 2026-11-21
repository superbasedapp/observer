package gitroute

import (
	"context"
	"errors"
	"testing"
	"time"
)

// fakeHost is a WSL host for the Router: a mount table, interop, a PATH,
// the files that exist, the shims among them and each file's --version.
type fakeHost struct {
	mountinfo  string
	mountErr   error
	interop    bool
	path       string
	files      map[string]bool
	shims      map[string]bool
	versions   map[string]string
	probes     []string
	mountReads int
	now        time.Time
}

func (h *fakeHost) env() Env {
	return Env{
		GOOS: "linux",
		ReadMountinfo: func() ([]byte, error) {
			h.mountReads++
			return []byte(h.mountinfo), h.mountErr
		},
		InteropEnabled: func() bool { return h.interop },
		PathEnv:        func() string { return h.path },
		IsFile:         func(p string) bool { return h.files[p] },
		IsShim:         func(p string) bool { return h.shims[p] },
		Version: func(_ context.Context, p string) (string, error) {
			h.probes = append(h.probes, p)
			v, ok := h.versions[p]
			if !ok {
				return "", errors.New("exec format error")
			}
			return v, nil
		},
		Now: func() time.Time { return h.now },
	}
}

const (
	cmdGit    = "/mnt/c/Program Files/Git/cmd/git.exe"
	mingwGit  = "/mnt/c/Program Files/Git/mingw64/bin/git.exe"
	pathShim  = "/mnt/c/Users/dev/.observer/shims/git.exe"
	linuxDiff = "/mnt/d/repo"
)

func newFakeHost() *fakeHost {
	return &fakeHost{
		mountinfo: liveMountinfo,
		interop:   true,
		path:      "/usr/bin:/mnt/c/Users/dev/.observer/shims:/mnt/c/Program Files/Git/cmd",
		files:     map[string]bool{cmdGit: true, pathShim: true},
		shims:     map[string]bool{pathShim: true},
		versions:  map[string]string{cmdGit: "git version 2.53.0.windows.2", pathShim: "git version 9.9.9.windows.9"},
		now:       time.Unix(1_800_000_000, 0),
	}
}

func TestRouterResolvesOnceAndSkipsShims(t *testing.T) {
	h := newFakeHost()
	r := NewRouter(h.env())
	for i := 0; i < 3; i++ {
		p := r.Plan(context.Background(), linuxDiff, []string{"diff", "HEAD"})
		if p.Route != RouteWindowsGit || p.Program != cmdGit || p.Dir != `D:\repo` {
			t.Fatalf("plan %d = %+v, want git.exe at %s", i, p, cmdGit)
		}
	}
	if len(h.probes) != 1 || h.probes[0] != cmdGit {
		t.Fatalf("probes = %q, want one probe of %s (the shim is never run)", h.probes, cmdGit)
	}
	if h.mountReads != 1 {
		t.Fatalf("mount table read %d times, want once within its TTL", h.mountReads)
	}
	h.now = h.now.Add(factsTTL + time.Second)
	r.Plan(context.Background(), linuxDiff, nil)
	if h.mountReads != 2 {
		t.Fatalf("mount table read %d times after its TTL, want twice", h.mountReads)
	}
}

func TestRouterRejectsANonWindowsGit(t *testing.T) {
	h := newFakeHost()
	h.versions[cmdGit] = "git version 2.53.0"
	r := NewRouter(h.env())
	if p := r.Plan(context.Background(), linuxDiff, nil); p.Route != RouteDrvFsStat {
		t.Fatalf("plan = %+v, want the WSL git (the candidate is not Git for Windows)", p)
	}
}

func TestRouterHostAndPathRows(t *testing.T) {
	h := newFakeHost()
	r := NewRouter(h.env())
	if p := r.Plan(context.Background(), "/home/dev/repo", nil); p.Route != RouteHost {
		t.Fatalf("ext4 plan = %+v, want the host git", p)
	}
	if len(h.probes) != 0 {
		t.Fatalf("an ext4 root resolved git.exe (%q)", h.probes)
	}
	h2 := newFakeHost()
	h2.interop = false
	if p := NewRouter(h2.env()).Plan(context.Background(), linuxDiff, nil); p.Route != RouteDrvFsStat || len(h2.probes) != 0 {
		t.Fatalf("interop off: plan = %+v, probes %q; want the WSL git and no probe", p, h2.probes)
	}
	env := h.env()
	env.GOOS = "windows"
	if p := NewRouter(env).Plan(context.Background(), `D:\repo`, nil); p.Route != RouteHost {
		t.Fatalf("Windows host plan = %+v, want the host git", p)
	}
	var nilRouter *Router
	if p := nilRouter.Plan(context.Background(), linuxDiff, nil); p.Route != RouteHost {
		t.Fatalf("nil router plan = %+v", p)
	}
}

func TestRouterUnreadableMountTableUsesThePrefix(t *testing.T) {
	h := newFakeHost()
	h.mountErr = errors.New("permission denied")
	p := NewRouter(h.env()).Plan(context.Background(), linuxDiff, nil)
	if p.Route != RouteWindowsGit || p.Dir != `D:\repo` {
		t.Fatalf("plan = %+v, want git.exe on the /mnt/<drive> reading", p)
	}
}

func TestRouterFallbackAndNegativeCache(t *testing.T) {
	h := newFakeHost()
	r := NewRouter(h.env())
	p := r.Plan(context.Background(), linuxDiff, nil)
	// git's own answer: kept, git.exe stays.
	if fb, _ := r.Failed(p, Failure{ExitCode: 128, Stderr: "fatal: bad revision"}); fb {
		t.Fatal("a git answer fell back")
	}
	if again := r.Plan(context.Background(), linuxDiff, nil); again.Route != RouteWindowsGit {
		t.Fatalf("after a git answer the plan is %+v", again)
	}
	// git.exe stopped starting: fall back, and skip it for retryAfter.
	if fb, why := r.Failed(p, Failure{Unavailable: true, ExitCode: -1}); !fb || why == "" {
		t.Fatalf("an unavailable git.exe did not fall back (%q)", why)
	}
	probes := len(h.probes)
	if again := r.Plan(context.Background(), linuxDiff, nil); again.Route != RouteDrvFsStat {
		t.Fatalf("within retryAfter the plan is %+v, want the WSL git", again)
	}
	if len(h.probes) != probes {
		t.Fatal("git.exe was probed again within retryAfter")
	}
	h.now = h.now.Add(retryAfter + time.Second)
	if again := r.Plan(context.Background(), linuxDiff, nil); again.Route != RouteWindowsGit {
		t.Fatalf("after retryAfter the plan is %+v, want git.exe again", again)
	}
	// A plan with no fallback never falls back.
	if fb, _ := r.Failed(Plan{Route: RouteDrvFsStat}, Failure{Unavailable: true}); fb {
		t.Fatal("a plan without a fallback fell back")
	}
}

func TestRouterNoGitIsRememberedButACanceledResolveIsNot(t *testing.T) {
	h := newFakeHost()
	h.files = map[string]bool{}
	r := NewRouter(h.env())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if p := r.Plan(ctx, linuxDiff, nil); p.Route != RouteDrvFsStat {
		t.Fatalf("plan = %+v", p)
	}
	if !r.gitFailedAt.IsZero() {
		t.Fatal("a resolution cut short by the caller was remembered as a failure")
	}
	if p := r.Plan(context.Background(), linuxDiff, nil); p.Route != RouteDrvFsStat {
		t.Fatalf("plan = %+v", p)
	}
	if r.gitFailedAt.IsZero() {
		t.Fatal("finding no git.exe was not remembered")
	}
}

func TestRouterPrime(t *testing.T) {
	h := newFakeHost()
	r := NewRouter(h.env())
	r.Prime(context.Background())
	if r.git != cmdGit {
		t.Fatalf("Prime resolved %q, want %s", r.git, cmdGit)
	}
	h2 := newFakeHost()
	h2.interop = false
	NewRouter(h2.env()).Prime(context.Background())
	if len(h2.probes) != 0 {
		t.Fatal("Prime probed git.exe with interop off")
	}
	env := h.env()
	env.GOOS = "darwin"
	(&Router{env: env}).Prime(context.Background())
}
