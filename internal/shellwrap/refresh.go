package shellwrap

import (
	"fmt"
	"sort"
	"strings"
)

// Start-time shim refresh. When the observer binary moves (an npm reinstall
// under another prefix, an upgrade that changed install method), every shim
// still names the OLD path, which no longer exists. A shim whose observer is gone falls back to
// `observer` on PATH and then to the real command, so nobody is locked out -
// but the wrapped form silently stops running. `observer start` therefore
// re-points ALREADY-APPLIED shims at the running binary.
//
// The refresh is deliberately narrower than enable. It never creates a shim
// (a missing shim is how `rm -r ~/.observer/shims`, the documented escape
// hatch, stays effective), never adds a tool, never touches a shell start-up
// file, and does nothing at all unless [shell_wrap].enabled is recorded. Its
// only write is replacing a marked shim, for a recorded tool, whose baked
// observer binary is GONE. A baked binary that differs from the running one
// but still exists is another install and is kept: several installs (the VS
// Code extension's bundled binary, npm, PyPI) may each start the daemon, and
// re-pointing on mere difference would flip every shim on each start.

// RefreshAction is what the refresh does with one on-disk shim.
type RefreshAction string

// Refresh actions.
const (
	// RefreshRewrite: re-render the shim with the running observer path.
	RefreshRewrite RefreshAction = "rewrite"
	// RefreshCurrent: the shim already reaches the running binary.
	RefreshCurrent RefreshAction = "current"
	// RefreshKept: the shim runs a DIFFERENT observer binary that still
	// exists (another install - the VS Code extension's bundled binary, npm,
	// PyPI). Only a gone binary counts as moved, so two coexisting installs
	// never flip the shims back and forth.
	RefreshKept RefreshAction = "kept"
	// RefreshSkip: the shim is left alone (Reason says why).
	RefreshSkip RefreshAction = "skip"
)

// RefreshInput is PlanRefresh's input. All I/O happened before the call.
type RefreshInput struct {
	// GOOS is the target OS (selects the shim template and file names).
	GOOS string
	// Enabled is the recorded [shell_wrap].enabled.
	Enabled bool
	// Selected are the recorded tool ids ([shell_wrap.tools] id = true).
	Selected []string
	// ShimDir is the absolute shim directory.
	ShimDir string
	// ObserverPath is the path a fresh shim bakes in: exactly what enable
	// would write today, so a refreshed shim reads as in-sync in status.
	ObserverPath string
	// ResolvedObserver is the running binary with symlinks resolved; an
	// embedded path that resolves to it is current even when spelled
	// differently (a stable symlink such as a package manager's bin link).
	ResolvedObserver string
	// Resolve resolves an embedded path's symlinks ("" or the input on
	// failure). nil = identity.
	Resolve func(p string) string
	// Exists reports whether a baked observer path is still a regular file.
	// nil = every path exists, so the pure default never rewrites.
	Exists func(p string) bool
	// ObserverRunnable reports whether ObserverPath is currently a regular,
	// executable file. The running binary's own path is not proof of that:
	// on Linux os.Executable reads /proc/self/exe, which after the binary is
	// replaced or removed reads "<path> (deleted)", and baking that into a
	// shim would point every wrapped command at a file that does not exist.
	// nil = runnable (the pure default; the service always supplies it).
	ObserverRunnable func(p string) bool
	// Shims are the marked files found in ShimDir.
	Shims []OnDiskShim
}

// ShimRefresh is one on-disk shim's refresh decision.
type ShimRefresh struct {
	FileName string        `json:"file_name"`
	Path     string        `json:"path"`
	ToolID   string        `json:"tool_id"`
	Command  string        `json:"command"`
	Action   RefreshAction `json:"action"`
	Reason   string        `json:"reason"`
	// OldObserverPath is the path the shim bakes in today ("" when it could
	// not be read back).
	OldObserverPath string `json:"old_observer_path,omitempty"`
	// Content is the new file for a rewrite; Before is the file the
	// decision was made against (the applier refuses the write when the
	// file changed in between).
	Content string `json:"-"`
	Before  string `json:"-"`
}

// RefreshPlan is PlanRefresh's result.
type RefreshPlan struct {
	// Inactive says why nothing was considered ("" when shims were).
	Inactive string        `json:"inactive,omitempty"`
	Shims    []ShimRefresh `json:"shims"`
}

// Rewrites returns the shims the plan rewrites.
func (p RefreshPlan) Rewrites() []ShimRefresh {
	var out []ShimRefresh
	for _, s := range p.Shims {
		if s.Action == RefreshRewrite {
			out = append(out, s)
		}
	}
	return out
}

// ReasonObserverNotRunnable is the skip reason when the running observer's
// path is not currently a regular executable file (replaced or deleted since
// it started): a rewrite would bake a dead path into the shim, so it is left
// for the next start (or `observer shell-wrap enable`) from a live binary.
const ReasonObserverNotRunnable = "the running observer binary is not a regular executable file (replaced or deleted since it started) - not re-pointed; the next `observer start` or `observer shell-wrap enable` re-points it"

// refreshCtx is the per-shim state the rule table reads.
type refreshCtx struct {
	in       RefreshInput
	shim     OnDiskShim
	selected map[string]bool
	embedded string
	parsed   bool
	cand     Candidate
	wrapped  bool
}

// refreshRule is one row of the per-shim decision table, walked top-down;
// the first row whose test matches decides.
type refreshRule struct {
	action RefreshAction
	reason string
	match  func(c refreshCtx) bool
}

var refreshRules = []refreshRule{
	{RefreshSkip, "not an observer shim (no marker) - never touched", func(c refreshCtx) bool {
		return !IsShim([]byte(c.shim.Content))
	}},
	{RefreshSkip, "its tool is not in the recorded choice - `observer shell-wrap enable` reconciles it", func(c refreshCtx) bool {
		return !c.selected[c.shim.ToolID]
	}},
	{RefreshSkip, "file name does not match the command it wraps - left for `enable` / `disable`", func(c refreshCtx) bool {
		return !ValidCommandName(c.shim.Command) || c.shim.FileName != ShimFileName(c.shim.Command, c.in.GOOS)
	}},
	{RefreshSkip, "its observer path cannot be read back - left for `enable` / `disable`", func(c refreshCtx) bool {
		return !c.parsed
	}},
	{RefreshCurrent, "already runs this observer binary", func(c refreshCtx) bool {
		return samePath(c.embedded, c.in.ObserverPath, c.in.GOOS) ||
			samePath(c.resolve(c.embedded), c.in.ResolvedObserver, c.in.GOOS)
	}},
	{RefreshSkip, "this command is no longer wrappable here - `observer shell-wrap enable` reconciles it", func(c refreshCtx) bool {
		return !c.wrapped
	}},
	{RefreshKept, "the baked observer binary still exists (another install) - kept; `observer shell-wrap enable` re-points it", func(c refreshCtx) bool {
		return c.in.Exists == nil || c.in.Exists(c.embedded)
	}},
	{RefreshSkip, ReasonObserverNotRunnable, func(c refreshCtx) bool {
		return c.in.ObserverRunnable != nil && !c.in.ObserverRunnable(c.in.ObserverPath)
	}},
	{RefreshRewrite, "the baked observer binary is gone - re-pointed at the running one", func(refreshCtx) bool { return true }},
}

func (c refreshCtx) resolve(p string) string {
	if c.in.Resolve == nil || p == "" {
		return p
	}
	if r := c.in.Resolve(p); r != "" {
		return r
	}
	return p
}

// samePath compares two paths the way the target OS's file system does
// (Windows paths are case-insensitive).
func samePath(a, b, goos string) bool {
	if a == "" || b == "" {
		return false
	}
	if goos == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// PlanRefresh decides, per marked shim on disk, whether the start-time
// refresh rewrites it (only when its baked observer binary is gone). It never plans a shim that is not already on disk and
// plans nothing at all unless shell-wrap is recorded as enabled.
func PlanRefresh(in RefreshInput) (RefreshPlan, error) {
	if !in.Enabled {
		return RefreshPlan{Inactive: "shell-wrap is not enabled", Shims: []ShimRefresh{}}, nil
	}
	if err := checkPath(in.ShimDir); err != nil {
		return RefreshPlan{}, fmt.Errorf("shellwrap: shim dir: %w", err)
	}
	if err := checkPath(in.ObserverPath); err != nil {
		return RefreshPlan{}, fmt.Errorf("shellwrap: observer path: %w", err)
	}
	selected := map[string]bool{}
	for _, id := range in.Selected {
		selected[id] = true
	}
	p := RefreshPlan{Shims: []ShimRefresh{}}
	for _, s := range in.Shims {
		c := refreshCtx{in: in, shim: s, selected: selected}
		c.embedded, c.parsed = EmbeddedObserverPath(s.Content)
		c.cand, c.wrapped = CandidateFor(s.ToolID, in.GOOS)
		c.wrapped = c.wrapped && containsString(c.cand.Commands, s.Command)
		r := ShimRefresh{
			FileName: s.FileName, Path: s.Path, ToolID: s.ToolID, Command: s.Command,
			OldObserverPath: c.embedded, Before: s.Content,
		}
		for _, rule := range refreshRules {
			if rule.match(c) {
				r.Action, r.Reason = rule.action, rule.reason
				break
			}
		}
		if r.Action == RefreshRewrite {
			content, err := renderShim(c.cand.shimSpec(s.Command, in.ObserverPath, in.ShimDir), in.GOOS)
			if err != nil {
				r.Action, r.Reason = RefreshSkip, err.Error()
			} else {
				r.Content = content
			}
		}
		p.Shims = append(p.Shims, r)
	}
	sort.Slice(p.Shims, func(i, j int) bool { return p.Shims[i].FileName < p.Shims[j].FileName })
	return p, nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
