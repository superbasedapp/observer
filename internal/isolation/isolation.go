package isolation

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"

	"github.com/marmutapp/superbased-observer/internal/extrun"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// ProviderName is what a wrapped run records as its isolation (the
// extrun.Result.Isolation field).
const ProviderName = "isolation.bwrap.oneshot"

// Host is the per-host input the cmd layer resolves once: where bwrap is,
// the home and ~/.observer, and the host sockets and foreign-OS mounts a
// read-only root bind would otherwise leave reachable.
type Host struct {
	// Bwrap is the absolute path of the bwrap executable.
	Bwrap string
	// Home is the native home directory (blinded inside the run).
	Home string
	// ObserverDir is ~/.observer (never bound; hidden inside the run).
	ObserverDir  string
	MaskPaths    []string
	SocketSweeps []sandbox.DirRebuild
	HostMasks    []sandbox.Overlay
	HostMaskKeep []string
}

// OneShot is the extrun.IsolationProvider for one run's directories.
type OneShot struct {
	host Host
	dirs extrun.OneShotDirs
}

// ErrNoBwrap is returned when the host has no usable bwrap path.
var ErrNoBwrap = errors.New("isolation: bwrap is not available on this host")

// New checks host and dirs (the same checks BuildOneShot runs, with no
// program yet) and returns the provider. A request the planner would refuse
// is refused here, before any run starts.
func New(host Host, dirs extrun.OneShotDirs) (*OneShot, error) {
	if host.Bwrap == "" || !filepath.IsAbs(host.Bwrap) {
		return nil, ErrNoBwrap
	}
	o := &OneShot{host: host, dirs: dirs}
	if _, err := sandbox.BuildOneShot(o.request(nil)); err != nil {
		return nil, fmt.Errorf("isolation.New: %w", err)
	}
	return o, nil
}

// Factory returns the extrun.IsolationFactory over one host. The cmd layer
// calls it only while the isolation component is active.
func Factory(host Host) extrun.IsolationFactory {
	return func(d extrun.OneShotDirs) (extrun.IsolationProvider, error) {
		return New(host, d)
	}
}

// Name implements extrun.IsolationProvider.
func (o *OneShot) Name() string { return ProviderName }

// Wrap implements extrun.IsolationProvider: the checked plan's program runs
// inside the one-shot bwrap profile. The program's own directory is bound
// read-only; the run's working directory is the project, so a plan that
// asked for a different directory is refused rather than silently moved.
func (o *OneShot) Wrap(_ context.Context, p extrun.Plan) (extrun.Plan, error) {
	if !filepath.IsAbs(p.Path) {
		return extrun.Plan{}, fmt.Errorf("isolation.Wrap: program %q is not an absolute path", p.Path)
	}
	if p.Dir != "" && filepath.Clean(p.Dir) != filepath.Clean(o.dirs.Project) {
		return extrun.Plan{}, fmt.Errorf("isolation.Wrap: the run asks for directory %q but a one-shot runs in its project %q", p.Dir, o.dirs.Project)
	}
	plan, err := sandbox.BuildOneShot(o.request([]string{filepath.Dir(p.Path)}))
	if err != nil {
		return extrun.Plan{}, fmt.Errorf("isolation.Wrap: %w", err)
	}
	argv := plan.Argv(append([]string{p.Path}, p.Args...))
	if argv == nil {
		return extrun.Plan{}, fmt.Errorf("isolation.Wrap: program %q cannot be passed to bwrap", p.Path)
	}
	out := p
	out.Path = o.host.Bwrap
	out.Args = argv
	out.Dir = o.dirs.Project
	return out, nil
}

// request builds the planner request; extra program directories come first.
func (o *OneShot) request(programDirs []string) sandbox.OneShotRequest {
	dirs := append(append([]string(nil), programDirs...), o.dirs.ProgramDirs...)
	return sandbox.OneShotRequest{
		Home:         o.host.Home,
		ObserverDir:  o.host.ObserverDir,
		ProjectRoot:  o.dirs.Project,
		OutputDir:    o.dirs.Output,
		CacheDir:     o.dirs.Cache,
		ProgramDirs:  dirs,
		MaskPaths:    o.host.MaskPaths,
		SocketSweeps: o.host.SocketSweeps,
		HostMasks:    o.host.HostMasks,
		HostMaskKeep: o.host.HostMaskKeep,
	}
}
