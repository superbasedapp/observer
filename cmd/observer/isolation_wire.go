//go:build !sbo_omit_isolation

package main

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/isolation"
)

// isolation_wire.go is the cmd seam of the isolation component (sandbox
// plan v2 section 11.1, roadmap F0-11): it injects the one "run this
// isolated" function a consumer outside the sandbox module receives. The
// consumer (the security module's scanner drivers) takes an
// extrun.IsolationFactory and never imports internal/isolation, so either
// component can be omitted from a build.

// isolationComponent is the node catalog id of the isolation engine.
const isolationComponent = "isolation"

// isolationFactoryFor returns the one-shot isolation factory when the
// isolation component is active under the snapshot (ModuleActive: an
// unknown id keeps it off) and the host is Linux (bwrap is Linux-only, WSL2
// included), and nil otherwise. Host facts are resolved per run, so a
// bwrap installed after start is found and a missing one refuses the run
// with ErrNoBwrap rather than running it unisolated.
//
// Consumer: the security module's scanner drivers (security plan phase D1,
// the first consumer of extrun.IsolationFactory) receive this factory from
// the cmd layer when they are wired; nothing in production calls it before
// that lane lands, and the omit build returns nil.
//
// Every path is resolved through symlinks before the planner sees it (lane
// sbx-p1a2, audit finding P-006 (5)): the home and ~/.observer, so the run
// hides the REAL observer directory even when ~/.observer is a link to
// another disk, and the run's own directories, so the planner's overlap
// checks compare resolved paths and a project that is a link into
// ~/.observer is refused rather than bound.
func isolationFactoryFor(snap componentstate.Snapshot, observerDir string, maskPaths []string) extrun.IsolationFactory {
	if !snap.ModuleActive(isolationComponent) || runtime.GOOS != "linux" {
		return nil
	}
	return func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
		host, err := isolationHostFacts(observerDir, maskPaths)
		if err != nil {
			return nil, err
		}
		return newResolvedOneShot(host, d)
	}
}

// isolationMissingOnHost reports whether a factory error means the host
// has no isolation provider at all (no bwrap), as opposed to a provider
// that refused the run. A consumer may run unisolated, labelled, only on
// the first (lane SEC-DEPS3 item 5).
func isolationMissingOnHost(err error) bool { return errors.Is(err, isolation.ErrNoBwrap) }

// isolationAvailable reports whether this host has an isolation provider
// at all (bwrap on the PATH), without preparing anything, so a consumer
// decides between an isolated run and an unisolated, labelled one BEFORE
// it prepares the run (audit finding 2 of lane sec-deps3b). It is the same
// lookup whose failure isolationHostFacts reports as ErrNoBwrap.
func isolationAvailable() bool {
	_, err := lookBwrap()
	return err == nil
}

// lookBwrap finds the bwrap binary on the PATH.
func lookBwrap() (string, error) { return exec.LookPath("bwrap") }

// newResolvedOneShot resolves host.Home, host.ObserverDir and every run
// directory through symlinks and builds the provider over the resolved
// paths. The returned provider accepts the caller's own (unresolved)
// project path as a plan's directory.
func newResolvedOneShot(host isolation.Host, d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
	var err error
	if host.Home, err = resolveThroughLinks(host.Home); err != nil {
		return nil, fmt.Errorf("isolation: home directory: %w", err)
	}
	if host.ObserverDir, err = resolveThroughLinks(host.ObserverDir); err != nil {
		return nil, fmt.Errorf("isolation: observer directory: %w", err)
	}
	rd := extrun.OneShotDirs{ProgramDirs: make([]string, 0, len(d.ProgramDirs))}
	for _, p := range []struct {
		name string
		in   string
		out  *string
	}{{"project", d.Project, &rd.Project}, {"output", d.Output, &rd.Output}, {"cache", d.Cache, &rd.Cache}} {
		if *p.out, err = resolveThroughLinks(p.in); err != nil {
			return nil, fmt.Errorf("isolation: %s directory: %w", p.name, err)
		}
	}
	for _, pd := range d.ProgramDirs {
		r, err := resolveThroughLinks(pd)
		if err != nil {
			return nil, fmt.Errorf("isolation: program directory: %w", err)
		}
		rd.ProgramDirs = append(rd.ProgramDirs, r)
	}
	inner, err := isolation.New(host, rd)
	if err != nil {
		return nil, err
	}
	return resolvedOneShot{inner: inner, project: d.Project, resolved: rd.Project, host: host, dirs: rd}, nil
}

// resolvedOneShot maps a plan's unresolved project directory onto the
// resolved one the provider was built over, and resolves the program path.
type resolvedOneShot struct {
	inner    extrun.IsolationProvider
	project  string
	resolved string
	// host and dirs are what inner was built over, kept so a program whose
	// file is a link can be run through a provider that also binds the
	// link's target directory.
	host isolation.Host
	dirs extrun.OneShotDirs
}

func (r resolvedOneShot) Name() string { return r.inner.Name() }

// Wrap resolves the program's DIRECTORY through links but keeps its file
// name, so argv0 stays the name the caller ran (lane sbx-p2, P-017 (h)): a
// multi-call binary (busybox, a toolbox) picks its applet from argv0, and
// running the link's target instead would run the wrong program. When the
// file itself is a link, the target's directory is bound read-only too, so
// the link resolves inside the run.
func (r resolvedOneShot) Wrap(ctx context.Context, p extrun.Plan) (extrun.Plan, error) {
	if p.Dir != "" && filepath.Clean(p.Dir) == filepath.Clean(r.project) {
		p.Dir = r.resolved
	}
	inner := r.inner
	if filepath.IsAbs(p.Path) {
		if dir, err := resolveThroughLinks(filepath.Dir(p.Path)); err == nil {
			p.Path = filepath.Join(dir, filepath.Base(p.Path))
		}
		if real, err := filepath.EvalSymlinks(p.Path); err == nil && real != p.Path {
			if realDir := filepath.Dir(real); realDir != filepath.Dir(p.Path) {
				dirs := r.dirs
				dirs.ProgramDirs = append(append([]string(nil), r.dirs.ProgramDirs...), realDir)
				withTarget, err := isolation.New(r.host, dirs)
				if err != nil {
					return extrun.Plan{}, err
				}
				inner = withTarget
			}
		}
	}
	return inner.Wrap(ctx, p)
}

// resolveThroughLinks returns p with every symlink resolved. A path that
// does not exist yet (an output directory created later) keeps its missing
// tail on the resolved deepest existing ancestor. Relative and empty paths
// are returned unchanged, for the planner to refuse.
func resolveThroughLinks(p string) (string, error) {
	if p == "" || !filepath.IsAbs(p) {
		return p, nil
	}
	p = filepath.Clean(p)
	real, err := filepath.EvalSymlinks(p)
	if err == nil {
		return real, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return "", err
	}
	parent := filepath.Dir(p)
	if parent == p {
		return p, nil
	}
	rp, err := resolveThroughLinks(parent)
	if err != nil {
		return "", err
	}
	return filepath.Join(rp, filepath.Base(p)), nil
}

// isolationHostFacts resolves the per-host input of a one-shot run: bwrap,
// the home, the host socket masks and sweeps and the foreign-OS mounts.
func isolationHostFacts(observerDir string, maskPaths []string) (isolation.Host, error) {
	bwrap, err := lookBwrap()
	if err != nil {
		return isolation.Host{}, isolation.ErrNoBwrap
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return isolation.Host{}, fmt.Errorf("isolation: home directory: %w", err)
	}
	masks, err := hostSocketMasks(os.Getuid())
	if err != nil {
		return isolation.Host{}, err
	}
	sweeps, err := socketSweeps()
	if err != nil {
		return isolation.Host{}, err
	}
	seen := map[string]bool{}
	var mp []string
	for _, p := range append(foreignMountRoots(), maskPaths...) {
		if p = strings.TrimSpace(p); p != "" && !seen[p] {
			seen[p] = true
			mp = append(mp, p)
		}
	}
	return isolation.Host{
		Bwrap:        bwrap,
		Home:         home,
		ObserverDir:  observerDir,
		MaskPaths:    mp,
		SocketSweeps: sweeps,
		HostMasks:    masks,
		HostMaskKeep: hostMaskKeep(masks),
	}, nil
}
