package dashboard

import (
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// gui_launch.go is the dashboard half of the DETACHED IDE / desktop-app launch
// (docs/plans/ide-desktop-launch-plan-2026-09-03.md T2). It is deliberately
// additive: POST /api/terminal/launch keeps its existing behaviour byte-for-
// byte when the request carries no `kind` (or `kind:"terminal"`), and
// GET /api/terminal/sessions keeps every existing key — the GUI surface arrives
// as two NEW keys and one NEW request field.
//
// Install and preflight for a GUI row need no code here at all: both endpoints
// already delegate to the nil-able cmd-side seams (Options.ToolPreflight /
// Options.ToolInstallHint), and those seams gained a second lookup rung for
// GUI ids. That is the point — the dashboard handler stays name-free.

// Errors the cmd adapter maps a GUI launch failure onto, so the handler can
// pick an honest status without importing termsvc.
var (
	// ErrLaunchGUIUnsupported signals the daemon has no GUI-spawn seam wired
	// (501) — the feature is absent on this build/config, the same class as
	// ErrLaunchUnsupported for the PTY seam. Never a silent fallback.
	ErrLaunchGUIUnsupported = errors.New("GUI launch is not configured on this daemon")
	// ErrLaunchGUINotLaunchable signals the id is not an ADVERTISED GUI launch
	// row (400): unknown, UNVERIFIED (no grounded executable), or a product the
	// harness lifecycle policy no longer advertises.
	ErrLaunchGUINotLaunchable = errors.New("no launchable IDE or desktop app with this id")
)

// GUILaunchSpec is the dashboard's server-derived GUI launch request. ID is the
// client's only free input and is a registry MAP KEY (never argv); ProjectRoot
// is the one client-influenced path and is canonicalized + allow-list-checked
// by the application service before the spawn. Deliberately absent, because a
// GUI launch has none of them: Subcommand (there is no `observer <verb>`),
// Model, Sandbox, WorkspaceSource, Rows/Cols (there is no PTY).
type GUILaunchSpec struct {
	ID          string
	ProjectRoot string
}

// GUILaunchResult is what a successful GUI launch returns. There is no handle:
// a detached app has no PTY for the browser to dock, so the response is a
// receipt (what started, with which pid, and whether routing actually reached
// it) rather than a terminal token.
type GUILaunchResult struct {
	RunID       string
	PID         int
	ID          string
	Label       string
	WrapApplied bool
	WrapNote    string
	Notes       []string
}

// GUILaunchableInfo is one row of the New-Terminal picker's "IDE / desktop app"
// group. It is the GUI sibling of LaunchableTool and carries the same two
// INDEPENDENT allow-lists (Allowed = may it launch, Watched = will its sessions
// be captured) plus the wrap honesty fields the operator needs to judge whether
// launching through Observer buys them anything.
type GUILaunchableInfo struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Adapter string `json:"adapter"`
	Surface string `json:"surface"`
	// Allowed mirrors [terminal.launch].allowed_tools membership of the GUI ID
	// — the same list, the same key, the same deny-all default as a terminal
	// tool (an operator allows "vscode" the way they allow "claude-code").
	Allowed bool `json:"allowed"`
	// Watched mirrors [observer.watch].enabled_adapters membership of the
	// CARRYING adapter. A pure editor HOST (VS Code, a JetBrains IDE) has no
	// adapter of its own — the sessions come from whatever extension runs
	// inside it — so there is nothing to watch and nothing to warn about:
	// such a row reports true rather than a meaningless false.
	Watched bool `json:"watched"`
	// WrapKind is the routing-injection mechanism, rendered from the closed
	// registry vocabulary with WrapNone spelled "none" (the zero value is an
	// empty string on the wire otherwise, which reads as "missing" rather than
	// as the deliberate "nothing can be injected").
	WrapKind string `json:"wrap_kind"`
	// WrapReason is the grounded reason a WrapNone row cannot be wrapped, or
	// the caveat text a wrappable row carries. Empty when there is none.
	WrapReason string `json:"wrap_reason"`
	// ProjectDirArgv reports whether the app accepts a project directory as a
	// positional argument. The picker shows its project-root control only for
	// these rows — a directory sent for any other row is ignored with a note.
	ProjectDirArgv bool `json:"project_dir_argv"`
	// Grounded is false for an UNVERIFIED row. Such rows are never advertised,
	// so this is always true on the wire today; it is carried so the field
	// exists if the surface ever lists unverified rows for the record.
	Grounded bool `json:"grounded"`
	// Note is free-text provenance / caveats from the registry row. Always
	// present on the wire (empty string when there is none) rather than
	// omitempty: the picker renders it directly, and an absent key would reach
	// the UI as `undefined`.
	Note string `json:"note"`
	// Hosts lists the adapters whose sessions this launch produces or hosts, so
	// the picker can say what capture a given IDE actually buys. Always a real
	// array on the wire — never null — for the same reason as Note.
	Hosts []string `json:"hosts"`
}

// GUIRunInfo is one row of the live GUI-run list on GET /api/terminal/sessions.
// It is NOT a LaunchInfo: there is no handle, no viewer count, no writer
// holder, no geometry — a detached app has none of those. Exited rows are
// retained for the daemon's lifetime (bounded), because "the app I launched has
// since been closed" is the useful answer.
type GUIRunInfo struct {
	RunID       string    `json:"run_id"`
	ID          string    `json:"id"`
	Label       string    `json:"label"`
	PID         int       `json:"pid"`
	LaunchedAt  time.Time `json:"launched_at"`
	WrapApplied bool      `json:"wrap_applied"`
	WrapNote    string    `json:"wrap_note"`
	// Notes are the launch-composition advisories (the packaged-app / open(1)
	// launcher-stub pid caveat, an ignored project directory) so the run list
	// never shows a bare "exited (1)" for a stub whose app is still running.
	// Always a real array on the wire — never null — like Hosts.
	Notes    []string `json:"notes"`
	Exited   bool     `json:"exited"`
	ExitCode int      `json:"exit_code"`
}

// wrapKindWire renders a registry WrapKind for the wire. The ONLY translation
// is the zero value: integration.WrapNone is the empty string in Go (a
// deliberate zero-value-is-the-floor choice) but an empty JSON string reads as
// "unknown" to a client, so it ships as "none".
func wrapKindWire(k integration.WrapKind) string {
	if k == integration.WrapNone {
		return "none"
	}
	return string(k)
}

// guiLaunchableInfo projects the registry's GUI launch rows onto the picker
// wire shape, filtered to the ADVERTISED ones (a grounded, launchable spec on
// an active product). It is pure over the passed config — the zero config is
// the honest floor (nothing allowed, everything watched), matching what the
// launch and watch paths themselves do with a zero config, exactly like
// launchableToolInfo.
func guiLaunchableInfo(cfg config.Config) []GUILaunchableInfo {
	allowed := make(map[string]bool, len(cfg.Terminal.Launch.AllowedTools))
	for _, t := range cfg.Terminal.Launch.AllowedTools {
		allowed[strings.TrimSpace(t)] = true
	}
	rows := integration.GUILaunchables()
	out := make([]GUILaunchableInfo, 0, len(rows))
	for _, g := range rows {
		if !g.Advertised() {
			continue
		}
		// A pure editor host carries no adapter, so there is no watch-list
		// membership to consult — reporting false would invent a capture gap
		// that does not exist. That rule has ONE owner, diag.GUILaunchWatched,
		// which the `observer start` capture-gap WARN also reads, so this
		// picker flag and that warning can never disagree.
		watched := diag.GUILaunchWatched(cfg, g)
		hosts := g.Spec.Hosts
		if hosts == nil {
			hosts = []string{} // a real array on the wire, never null
		}
		out = append(out, GUILaunchableInfo{
			ID:             g.Spec.ID,
			Label:          g.Spec.Label,
			Adapter:        g.Adapter,
			Surface:        g.Spec.Surface,
			Allowed:        allowed[g.Spec.ID],
			Watched:        watched,
			WrapKind:       wrapKindWire(g.Spec.Wrap.Kind),
			WrapReason:     g.Spec.Wrap.Reason,
			ProjectDirArgv: g.Spec.ProjectDirArgv,
			Grounded:       g.Spec.Grounded,
			Note:           g.Spec.Note,
			Hosts:          hosts,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// guiRuns reads the live GUI-run list through the LaunchManager seam. A nil
// manager yields a non-nil empty slice so the JSON field is always a real
// array (the same contract resolveAllowedProjectRoots follows).
func (s *Server) guiRuns() []GUIRunInfo {
	if s.opts.LaunchManager == nil {
		return []GUIRunInfo{}
	}
	runs := s.opts.LaunchManager.GUIRuns()
	if runs == nil {
		return []GUIRunInfo{}
	}
	return runs
}

// guiLaunchResponse is the POST /api/terminal/launch response for kind "gui".
// It shares no field ordering with terminalLaunchResponse on purpose: there is
// no token to dock, and `kind` is present so a client can dispatch on the
// response the same way it dispatched on the request.
type guiLaunchResponse struct {
	Kind        string   `json:"kind"`
	RunID       string   `json:"run_id"`
	PID         int      `json:"pid"`
	Tool        string   `json:"tool"`
	Label       string   `json:"label"`
	WrapApplied bool     `json:"wrap_applied"`
	WrapNote    string   `json:"wrap_note"`
	Notes       []string `json:"notes,omitempty"`
}

// handleGUILaunch serves the kind:"gui" arm of POST /api/terminal/launch. It is
// reached ONLY from handleTerminalLaunch, AFTER that handler's method check,
// LaunchManager gate, body decode and TerminalFeatureGate — so the GUI arm
// inherits every existing gate and adds only its own.
//
// It refuses the PTY-only request fields outright rather than ignoring them
// (fail-closed, the same reasoning the sandbox validation uses): a caller that
// asked for a sandboxed, model-pinned launch and silently got a bare IDE would
// have been misled about what ran.
func (s *Server) handleGUILaunch(w http.ResponseWriter, body terminalLaunchRequest) {
	id := strings.TrimSpace(body.Tool)
	if id == "" {
		writeErrStatus(w, errors.New("missing tool"), http.StatusBadRequest)
		return
	}
	row, ok := integration.GUILaunchFor(id)
	if !ok || !row.Advertised() {
		writeErrStatus(w, errors.New(id+" is not a launchable IDE or desktop app"), http.StatusBadRequest)
		return
	}
	if field, bad := guiUnsupportedField(body); bad {
		writeErrStatus(w, errors.New(field+" is not applicable to a GUI launch"), http.StatusBadRequest)
		return
	}

	res, err := s.opts.LaunchManager.CreateGUI(GUILaunchSpec{ID: id, ProjectRoot: body.ProjectRoot})
	if err != nil {
		switch {
		case errors.Is(err, ErrLaunchFreshDisabled):
			writeErrStatus(w, err, http.StatusForbidden)
		case errors.Is(err, ErrLaunchToolNotAllowed):
			writeErrStatus(w, err, http.StatusForbidden)
		case errors.Is(err, ErrLaunchProjectRootDenied):
			writeErrStatus(w, err, http.StatusBadRequest)
		case errors.Is(err, ErrLaunchGUINotLaunchable):
			writeErrStatus(w, err, http.StatusBadRequest)
		case errors.Is(err, ErrLaunchGUIUnsupported), errors.Is(err, ErrLaunchUnsupported):
			writeErrStatus(w, err, http.StatusNotImplemented)
		default:
			writeErrStatus(w, errors.New("launch failed: "+err.Error()), http.StatusInternalServerError)
		}
		return
	}
	writeJSON(w, guiLaunchResponse{
		Kind:        string(integration.LaunchKindGUI),
		RunID:       res.RunID,
		PID:         res.PID,
		Tool:        res.ID,
		Label:       res.Label,
		WrapApplied: res.WrapApplied,
		WrapNote:    res.WrapNote,
		Notes:       res.Notes,
	})
	// Kick the watcher for the same reason the PTY launch does: a
	// just-installed IDE's sessions directory may not have existed at daemon
	// start. Fire-and-forget; never blocks the response.
	s.kickWatchRootsRefresh()
}

// guiUnsupportedField reports the first PTY-only request field a GUI launch
// cannot honour. Table-driven (CLAUDE.md #5) so a new terminal-only field is
// one row, not another arm of an if-ladder.
func guiUnsupportedField(body terminalLaunchRequest) (string, bool) {
	checks := []struct {
		name string
		set  bool
	}{
		{"sandbox", body.Sandbox},
		{"model", strings.TrimSpace(body.Model) != ""},
		{"workspace_source", strings.TrimSpace(body.WorkspaceSource) != ""},
		{"workspace_remote", strings.TrimSpace(body.WorkspaceRemote) != ""},
		{"workspace_branch", strings.TrimSpace(body.WorkspaceBranch) != ""},
	}
	for _, c := range checks {
		if c.set {
			return c.name, true
		}
	}
	return "", false
}
