package termsvc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/termfeed"
	"github.com/marmutapp/superbased-observer/internal/termrun"
)

// gui.go is the DETACHED IDE / desktop-app launch half of the terminal service
// (docs/plans/ide-desktop-launch-plan-2026-09-03.md T2). It is deliberately a
// sibling of launch(), not a branch inside it: a GUI launch produces no PTY, so
// it shares the service's IDENTITY and AUTHORIZATION model (run ids, the same
// [terminal.launch] allow-lists, the same recorder, the same status feed) while
// owning none of the PTY machinery (no handle, no OOB channel, no viewer/writer
// leases, no exit-linger classification).
//
// Consequence for state ownership (CLAUDE.md #4): GUI run state lives in its
// OWN map (guiRuns), never in byHandle/byRun/byMeta. Those maps are keyed by a
// PTY handle that a GUI run does not have, and every reader of them
// (Snapshot labeling, the remote-sensitivity gates, PruneEndedHandles) is
// asking a question about a live terminal — which a detached app is not.

// Errors surfaced by the GUI launch gate.
var (
	// ErrGUIUnsupported — the Service was constructed without a GUILauncher.
	// A nil seam means the feature is ABSENT on this daemon (no exec seam was
	// wired), so a GUI launch fails closed rather than degrading into anything
	// else. The dashboard maps it to 501, the same class as ErrNoLauncher's
	// platform-absence answer.
	ErrGUIUnsupported = errors.New("termsvc: GUI launch is not configured on this daemon")
	// ErrGUINotLaunchable — the id is not a GUI launch row, or its row is not
	// advertised (an UNVERIFIED / deprecated / dead product). The dashboard
	// maps it to 400: the client named something that cannot be launched.
	ErrGUINotLaunchable = errors.New("termsvc: no advertised GUI launch row for this id")
)

// guiRunHistory bounds the in-memory GUI run list. Exited rows are RETAINED
// (an operator wants to see that the app they launched has since been closed)
// but only the most recent guiRunHistory runs are kept, so a daemon that
// launches apps all day cannot grow this map without limit. It is a display
// history, not an authority: the durable record is terminal_run.
const guiRunHistory = 50

// GUISpawnRequest is the fully server-derived spawn request the Service hands
// the GUILauncher. Like LaunchRequest, every field is derived from validated
// input — the client contributes only a registry map key (ID) and a project
// root the service has already canonicalized and allow-list-checked.
type GUISpawnRequest struct {
	// RunID is the durable run identity minted for this launch.
	RunID string
	// ID is the GUI launch id (integration.GUILaunchSpec.ID) — the run's Tool.
	ID string
	// Spec is the registry row itself. The launcher resolves the binary and
	// composes the argv/env from it; termsvc neither reads nor interprets its
	// fields beyond the advertised check (CLAUDE.md #2 — the type crosses this
	// one seam and spreads no further).
	Spec integration.GUILaunchSpec
	// ProjectRoot is the canonical, already-validated project root ("" for a
	// bare launch). Whether it reaches argv is the SPEC's decision
	// (ProjectDirArgv), made in internal/guilaunch, not here.
	ProjectRoot string
	// OnExit is fired by the launcher's reaper when the detached child exits.
	// It must be safe to call from any goroutine and may never be called at all
	// (an app the operator leaves running past daemon shutdown).
	OnExit func(runID string, code int)
}

// GUISpawnResult is what a successful SpawnGUI returns: the detached child's
// pid plus the honest wrap verdict the launcher composed.
type GUISpawnResult struct {
	// PID is the detached child's process id (> 0).
	PID int
	// WrapApplied reports whether the routing wrap actually reached the child.
	WrapApplied bool
	// WrapNote is the grounded reason for that verdict, or the caveat that
	// qualifies an applied wrap.
	WrapNote string
	// Notes are launch-composition advisories unrelated to the wrap.
	Notes []string
	// Bin is the resolved launch target, for the operator-facing response
	// ("" for a packaged app addressed only by its AUMID).
	Bin string
}

// GUILauncher spawns a DETACHED GUI application and returns its pid. It is
// satisfied by a cmd adapter over internal/toolresolve + internal/guilaunch +
// the platform spawn files; termsvc owns identity/authorization and never
// resolves a binary, composes an argv, or touches os/exec itself — the exact
// division of labour the PTY Launcher seam already draws.
type GUILauncher interface {
	SpawnGUI(req GUISpawnRequest) (GUISpawnResult, error)
}

// GUIRequest is the dashboard-derived GUI launch request. ID is the only
// required client input and is a registry MAP KEY, never argv; ProjectRoot is
// the one client-influenced path and is canonicalized + allow-list-checked
// here, exactly as LaunchFresh does.
type GUIRequest struct {
	ID          string
	ProjectRoot string
}

// GUILaunchResult is what a GUI launch returns to the dashboard. There is no
// Handle: a detached app has no PTY to dock.
type GUILaunchResult struct {
	RunID       string
	ID          string
	Label       string
	PID         int
	WrapApplied bool
	WrapNote    string
	Notes       []string
	Bin         string
}

// GUIRunInfo is one row of the in-memory GUI run list.
type GUIRunInfo struct {
	RunID       string
	ID          string
	Label       string
	PID         int
	LaunchedAt  time.Time
	WrapApplied bool
	WrapNote    string
	Notes       []string
	Exited      bool
	ExitCode    int
}

// guiRunMeta is the OWNING struct for one GUI run's in-memory state
// (CLAUDE.md #4: one owner per piece of state). It is deliberately separate
// from runMeta — that struct is keyed by a PTY handle and exists to classify a
// live terminal; this one is keyed by run id and exists to list detached apps.
type guiRunMeta struct {
	ID          string
	Label       string
	PID         int
	LaunchedAt  time.Time
	WrapApplied bool
	WrapNote    string
	Notes       []string
	Exited      bool
	ExitCode    int
}

// guiState holds the GUI run map behind its own mutex. A separate lock from
// Service.mu is deliberate: the two states share no invariant (a GUI run can
// never appear in byHandle, and no PTY reader consults guiRuns), so coupling
// them would only widen the terminal hot path's critical section for a feature
// it never touches.
type guiState struct {
	mu   sync.Mutex
	runs map[string]guiRunMeta
	// order is the run ids newest-last, so trimming to guiRunHistory drops the
	// oldest without sorting the whole map.
	order []string
}

// LaunchGUI authorizes and starts a DETACHED IDE / desktop application. It
// fails closed on every authorization miss BEFORE minting a run or spawning a
// process, exactly like LaunchFresh.
//
// The policy is deliberately the SAME [terminal.launch] gate the PTY fresh
// launch uses, keyed by the GUI id: an operator allows "vscode" the way they
// allow "claude-code", in one list, with one config key. A GUI launch starts a
// process on the operator's machine — the very privilege allow_fresh_agent
// exists to gate — so giving it a separate switch would be a second, weaker
// door onto the same capability.
//
// Two gates have no PTY-path equivalent:
//   - the id must resolve to an ADVERTISED GUI row (integration.GUILaunchFor +
//     Advertised), so an UNVERIFIED / deprecated / dead product can never be
//     launched even if an operator allow-listed its id;
//   - the GUILauncher seam must be wired (ErrGUIUnsupported), the same
//     fail-closed nil-seam posture as ErrSandboxUnavailable.
func (s *Service) LaunchGUI(ctx context.Context, req GUIRequest) (GUILaunchResult, error) {
	if s.guiLauncher == nil {
		return GUILaunchResult{}, ErrGUIUnsupported
	}
	if !s.policy.AllowFresh {
		return GUILaunchResult{}, ErrFreshLaunchDisabled
	}
	if !s.policy.toolAllowed(req.ID) {
		return GUILaunchResult{}, fmt.Errorf("%w: %q", ErrToolNotAllowed, req.ID)
	}
	row, ok := integration.GUILaunchFor(req.ID)
	if !ok || !row.Advertised() {
		return GUILaunchResult{}, fmt.Errorf("%w: %q", ErrGUINotLaunchable, req.ID)
	}
	// The SAME validator LaunchFresh uses, called unconditionally so the
	// allow-list semantics can never drift between the two launch shapes. An
	// empty request is already its "no directory" answer ("", nil) — a bare
	// launch is legitimate for every GUI row, since most desktop apps take no
	// directory at all.
	dir, err := ValidateProjectRoot(req.ProjectRoot, s.policy.AllowedProjectRoots)
	if err != nil {
		return GUILaunchResult{}, err
	}

	runID, err := termrun.NewRunID()
	if err != nil {
		return GUILaunchResult{}, fmt.Errorf("termsvc: mint run id: %w", err)
	}
	run := termrun.Run{
		RunID:           runID,
		Tool:            req.ID,
		Kind:            termrun.KindGUI,
		ProjectRootHash: termrun.HashProjectRoot(dir),
		LaunchedAt:      s.now(),
		// No CorrelationTokenHash: a GUI child is not an `observer <verb>`
		// launcher, so there is no trusted out-of-band channel to echo a nonce
		// on. An unusable nonce recorded as if it were live would be a lie.
	}
	// Record BEFORE spawning, the same discipline launch() follows: a recorder
	// failure must never leave a process nothing knows about. The pid and wrap
	// verdict are stamped afterwards (RecordGUISpawn) because they do not
	// exist until the child does.
	if err := s.rec.RecordRun(ctx, run); err != nil {
		return GUILaunchResult{}, fmt.Errorf("termsvc: record run: %w", err)
	}

	res, err := s.guiLauncher.SpawnGUI(GUISpawnRequest{
		RunID:       runID,
		ID:          req.ID,
		Spec:        row.Spec,
		ProjectRoot: dir,
		OnExit:      s.guiRunExited,
	})
	if err != nil {
		// The run exists but never produced a process — close it out so it is
		// not left dangling as "running", exactly as launch() does on a failed
		// Spawn.
		_ = s.rec.EndRun(ctx, runID, s.now(), -1, reasonChildExit)
		return GUILaunchResult{}, err
	}

	run.PID = &res.PID
	run.WrapApplied = res.WrapApplied
	run.WrapNote = res.WrapNote
	if err := s.rec.RecordGUISpawn(ctx, run); err != nil && s.logger != nil {
		// Best-effort: the app IS running, and refusing to report a successful
		// launch because a metadata stamp failed would be the wrong trade. The
		// row keeps its honest NULL pid.
		s.logger.Warn("termsvc: recording the GUI spawn facts failed; the run row keeps a null pid",
			"run", runID, "id", req.ID, "error", err)
	}

	s.guiTrack(runID, guiRunMeta{
		ID:          req.ID,
		Label:       row.Spec.Label,
		PID:         res.PID,
		LaunchedAt:  run.LaunchedAt,
		WrapApplied: res.WrapApplied,
		WrapNote:    res.WrapNote,
		Notes:       res.Notes,
	})
	s.publish(termfeed.Event{
		Kind:  "term:launch:" + string(termrun.KindGUI),
		RunID: runID,
		Tool:  req.ID,
		Trust: termfeed.TrustTrusted,
		At:    s.now(),
	})

	return GUILaunchResult{
		RunID:       runID,
		ID:          req.ID,
		Label:       row.Spec.Label,
		PID:         res.PID,
		WrapApplied: res.WrapApplied,
		WrapNote:    res.WrapNote,
		Notes:       res.Notes,
		Bin:         res.Bin,
	}, nil
}

// guiRunExited is the GUI counterpart of EndRunByHandle: the launcher's reaper
// calls it when a detached child exits. It updates the in-memory row, records
// the exit durably, and publishes a feed event. Keyed by RUN ID (a GUI run has
// no handle), and idempotent — a second report for an already-exited run is a
// no-op, so a racing reaper cannot double-record.
func (s *Service) guiRunExited(runID string, code int) {
	s.gui.mu.Lock()
	meta, tracked := s.gui.runs[runID]
	first := tracked && !meta.Exited
	if first {
		meta.Exited = true
		meta.ExitCode = code
		s.gui.runs[runID] = meta
	}
	s.gui.mu.Unlock()
	if !first {
		// An unknown run (a stale reaper firing after the history trimmed the
		// row) or a duplicate report. Deliberately a no-op, logged rather than
		// swallowed so a missing/doubled producer stays observable.
		if s.logger != nil {
			s.logger.Debug("termsvc: GUI exit for an untracked or already-ended run",
				"run", runID, "code", code, "tracked", tracked)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Best-effort at exit, matching EndRunByHandle: a failed write leaves the
	// row looking still-live, which for a GUI run costs an accurate history
	// entry and nothing else (nothing gates on a GUI run's liveness).
	_ = s.rec.EndRun(ctx, runID, s.now(), code, reasonChildExit)
	s.publish(termfeed.Event{
		Kind:  "term:exit:" + string(termrun.KindGUI),
		RunID: runID,
		Tool:  meta.ID,
		Trust: termfeed.TrustTrusted,
		At:    s.now(),
	})
}

// guiTrack installs a GUI run's in-memory row and trims the history to
// guiRunHistory, oldest first. An exited row is kept (that IS the history) —
// only age evicts.
func (s *Service) guiTrack(runID string, meta guiRunMeta) {
	s.gui.mu.Lock()
	defer s.gui.mu.Unlock()
	if s.gui.runs == nil {
		s.gui.runs = make(map[string]guiRunMeta)
	}
	s.gui.runs[runID] = meta
	s.gui.order = append(s.gui.order, runID)
	for len(s.gui.order) > guiRunHistory {
		delete(s.gui.runs, s.gui.order[0])
		s.gui.order = s.gui.order[1:]
	}
}

// GUIRuns returns this daemon's GUI runs, newest first, including exited ones
// (bounded to the last guiRunHistory launches). It is a READ of in-memory
// state — no store query on the dashboard's session-list path, the same
// contract Snapshot labeling follows for PTY runs. A daemon restart empties it;
// the durable record lives in terminal_run.
func (s *Service) GUIRuns() []GUIRunInfo {
	s.gui.mu.Lock()
	defer s.gui.mu.Unlock()
	out := make([]GUIRunInfo, 0, len(s.gui.runs))
	for runID, m := range s.gui.runs {
		out = append(out, GUIRunInfo{
			RunID:       runID,
			ID:          m.ID,
			Label:       m.Label,
			PID:         m.PID,
			LaunchedAt:  m.LaunchedAt,
			WrapApplied: m.WrapApplied,
			WrapNote:    m.WrapNote,
			Notes:       m.Notes,
			Exited:      m.Exited,
			ExitCode:    m.ExitCode,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].LaunchedAt.Equal(out[j].LaunchedAt) {
			return out[i].RunID > out[j].RunID
		}
		return out[i].LaunchedAt.After(out[j].LaunchedAt)
	})
	return out
}
