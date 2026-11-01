package sandbox

import "fmt"

// oneshot.go is the isolation engine's one-shot request shape (sandbox plan
// v2 section 11.1, joint roadmap F0-11, spike JSP-12): a single program run
// with no network for a caller outside the sandbox module (the security
// module's scanner drivers, through internal/isolation). It is NOT the
// terminal shape BuildPlan composes: a terminal binds ~/.observer and the
// workspace read-write, which a scanner run must never get, because the
// security module's posture files and dirty markers live in ~/.observer.
//
// The shape, each property pinned by a test in oneshot_test.go:
//
//  1. no ~/.observer bind at all: ObserverDir is only ever HIDDEN (blinded
//     by the home tmpfs, or masked by its own tmpfs when it lies outside
//     home), and no bind may name it, a path under it written to, or a
//     directory that contains it;
//  2. the project read-only (and the working directory);
//  3. exactly one read-write output directory and one read-write cache
//     directory, neither inside the project nor containing it, nor nested
//     in each other;
//  4. egress none: a private network namespace with loopback only. The
//     request has no network field, so no caller can widen it;
//  5. a new terminal session (--new-session), so the program cannot inject
//     keystrokes into the terminal it was started from (lane sbx-p1a2,
//     audit finding P-006 (4)).
//
// JSP-12 measured this profile (from the real planner) refusing host
// loopback with no route and no DNS, as root and as an unprivileged user,
// including with Ubuntu 20.04's bwrap 0.4.0, and its pid namespace with
// --die-with-parent containing every hostile driver case.

// OneShotRequest is the pure input to BuildOneShot. Every path is absolute
// and already resolved by the caller.
type OneShotRequest struct {
	// Home is the native home directory; it is tmpfs-blinded, so every
	// other tool's credentials and repositories are out of reach.
	Home string
	// ObserverDir is ~/.observer. It is never bound; it is named here only
	// so the planner can hide it when it lies outside Home and refuse any
	// bind that would reach it.
	ObserverDir string
	// ProjectRoot is bound read-only and is the working directory.
	ProjectRoot string
	// OutputDir is the one read-write directory the program writes its
	// result to.
	OutputDir string
	// CacheDir is the one read-write directory the program may keep a
	// cache in.
	CacheDir string
	// ProgramDirs are read-only binds for the program and its companion
	// files (a directory under the blinded home must be re-bound to be
	// runnable). None may be ObserverDir, lie under it or contain it: a
	// program installed under ~/.observer is copied out first.
	ProgramDirs []string
	// MaskPaths are foreign-OS mounts to blind (as in Request).
	MaskPaths []string
	// SocketSweeps, HostMasks and HostMaskKeep hide host sockets and
	// platform interop exactly as for a terminal (Request has the detail).
	SocketSweeps []DirRebuild
	HostMasks    []Overlay
	HostMaskKeep []string
}

// OneShotEgress is the only network tier a one-shot run gets.
const OneShotEgress = EgressNone

// BuildOneShot composes the bwrap argv for a one-shot isolated run. The
// returned Plan renders with Plan.Argv like a terminal plan (no guest
// helper: egress none forwards nothing in). It refuses, rather than emit,
// any argv that would bind ~/.observer, write into the project, or carry a
// path the terminal planner would also refuse.
func BuildOneShot(req OneShotRequest) (Plan, error) {
	prof, err := ResolveEgress(string(OneShotEgress))
	if err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildOneShot: %w", err)
	}
	if err := checkOneShot(req); err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildOneShot: %w", err)
	}

	var pre []string
	add := func(tokens ...string) { pre = append(pre, tokens...) }

	// 1. Read-only root, private pid namespace and /proc, fresh /dev and
	//    /tmp, and the private network namespace (egress none).
	add(flagROBind, "/", "/")
	add(flagUnsharePid)
	add(flagProc, "/proc")
	add(flagDev, "/dev")
	add(flagTmpfs, "/tmp")
	add(flagUnshareNet)

	// 2. Blind the home, then ~/.observer itself when the home tmpfs does
	//    not already cover it.
	add(flagTmpfs, req.Home)
	if !isWithin(req.ObserverDir, req.Home) {
		add(flagTmpfs, req.ObserverDir)
	}

	// 3. Foreign-OS masks and host sockets, as for a terminal.
	for _, m := range req.MaskPaths {
		if err := validateAbs(m, false); err != nil {
			return Plan{}, fmt.Errorf("sandbox.BuildOneShot: mask path: %w", err)
		}
		add(flagTmpfs, m)
	}
	hostIso, err := hostIsolationArgs(Request{SocketSweeps: req.SocketSweeps, HostMasks: req.HostMasks, HostMaskKeep: req.HostMaskKeep})
	if err != nil {
		return Plan{}, fmt.Errorf("sandbox.BuildOneShot: %w", err)
	}
	pre = append(pre, hostIso...)

	// 4. The program, read-only.
	seen := map[string]bool{}
	for _, d := range req.ProgramDirs {
		if seen[d] {
			continue
		}
		seen[d] = true
		add(flagROBindTry, d, d)
	}

	// 5. The project read-only, then the two writable directories.
	add(flagROBind, req.ProjectRoot, req.ProjectRoot)
	add(flagBind, req.OutputDir, req.OutputDir)
	add(flagBind, req.CacheDir, req.CacheDir)

	// 6. Drop host-socket and secret environment, enter the project, detach
	//    from the caller's terminal session and die with the caller.
	pre = append(pre, unsetEnvArgs()...)
	add(flagChdir, req.ProjectRoot)
	add(flagNewSession)
	add(flagDieWithParent)

	return Plan{pre: pre, net: NetRequest{Egress: prof.Mode}, HomeMode: homeModeTmpfs, Egress: prof}, nil
}

// checkOneShot validates every path of a one-shot request and the four
// shape rules.
func checkOneShot(req OneShotRequest) error {
	if err := validateAbs(req.Home, true); err != nil {
		return fmt.Errorf("home: %w", err)
	}
	if err := validateAbs(req.ObserverDir, true); err != nil {
		return fmt.Errorf("observer dir: %w", err)
	}
	if err := validateAbs(req.ProjectRoot, true); err != nil {
		return fmt.Errorf("project root: %w", err)
	}
	for name, p := range map[string]string{"output dir": req.OutputDir, "cache dir": req.CacheDir} {
		if err := validateAbs(p, true); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		if overlaps(p, req.ProjectRoot) {
			return fmt.Errorf("%s %q overlaps the read-only project %q", name, p, req.ProjectRoot)
		}
		if isWithin(req.Home, p) {
			return fmt.Errorf("%s %q contains the whole home", name, p)
		}
	}
	if overlaps(req.OutputDir, req.CacheDir) {
		return fmt.Errorf("output dir %q and cache dir %q overlap", req.OutputDir, req.CacheDir)
	}
	if isWithin(req.Home, req.ProjectRoot) {
		return fmt.Errorf("project root %q contains the whole home", req.ProjectRoot)
	}
	// No bind may reach ~/.observer: neither the project, the two writable
	// directories (at, under or around it) nor a program directory that is
	// it or contains it.
	for name, p := range map[string]string{"project root": req.ProjectRoot, "output dir": req.OutputDir, "cache dir": req.CacheDir} {
		if overlaps(p, req.ObserverDir) {
			return fmt.Errorf("%s %q reaches the observer dir %q", name, p, req.ObserverDir)
		}
	}
	for _, d := range req.ProgramDirs {
		if err := validateAbs(d, false); err != nil {
			return fmt.Errorf("program dir: %w", err)
		}
		if overlaps(d, req.ObserverDir) {
			return fmt.Errorf("program dir %q reaches the observer dir %q", d, req.ObserverDir)
		}
	}
	return nil
}

// overlaps reports whether a equals b or one lies inside the other.
func overlaps(a, b string) bool {
	return isWithin(a, b) || isWithin(b, a)
}
