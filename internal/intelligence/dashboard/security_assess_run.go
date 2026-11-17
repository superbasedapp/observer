//go:build !sbo_omit_security

package dashboard

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/gitview"
	"github.com/marmutapp/superbased-observer/internal/secassess"
	"github.com/marmutapp/superbased-observer/internal/secassesssvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// security_assess_run.go is the run-level part of the Security assessments
// routes (docs/plans/security-assessments-depth-plan-2026-11-14.md, W0): the
// time box and Stop, the boundary audit's git snapshots, the per-run stored
// evidence and its delete action, and the run row's fields.
//
//	POST /api/security/assessments/stop         ends a run's terminal now
//	POST /api/security/assessments/delete-data  deletes a run's stored evidence
//
// Both are owner-local and need the confirm token; both are on the R-165
// self-approval list, so an agent cannot stop its own run's record or delete
// the evidence of its own run.

// securityAssessTimeBoxKeys maps a kind to its time box setting. A kind with no
// row (the cloud review and the instrumented tests) takes the kind's default.
// One table, not a switch on the kind id; a test pins that every row names a
// launchable kind.
var securityAssessTimeBoxKeys = []struct {
	Kind    secassess.ID
	Minutes func(a config.SecurityAssessmentsConfig) int
}{
	{secassess.ThreatModel, func(a config.SecurityAssessmentsConfig) int { return a.TimeBoxThreatModelMinutes }},
	{secassess.PentestLocal, func(a config.SecurityAssessmentsConfig) int { return a.TimeBoxPentestLocalMinutes }},
	{secassess.RedTeamLocal, func(a config.SecurityAssessmentsConfig) int { return a.TimeBoxRedTeamLocalMinutes }},
}

// securityAssessLimits are the run-level settings in force for one launch.
type securityAssessLimits struct {
	Minutes int
	Action  string
	AuditOn bool
}

// securityAssessLimitsFor resolves the time box, the deadline action and the
// audit switch for a kind from the config block.
func securityAssessLimitsFor(k secassess.Kind, a config.SecurityAssessmentsConfig) securityAssessLimits {
	configured := 0
	for _, row := range securityAssessTimeBoxKeys {
		if row.Kind == k.ID {
			configured = row.Minutes(a)
		}
	}
	action := a.TimeBoxAction
	if action != secassess.TimeBoxAutoClose {
		action = secassess.TimeBoxStopButton
	}
	return securityAssessLimits{Minutes: secassess.ResolveTimeBox(k, configured), Action: action, AuditOn: a.BoundaryAudit}
}

// securityAssessLimitsJS is the "settings in force" block of the plan.
type securityAssessLimitsJS struct {
	TimeBoxMinutes int    `json:"time_box_minutes"`
	TimeBoxAction  string `json:"time_box_action"`
	BoundaryAudit  bool   `json:"boundary_audit"`
	// AuditPolicy says how this kind's boundary audit reads a change.
	AuditPolicy string `json:"audit_policy"`
	AuditLimits string `json:"audit_limits"`
	// RelaxationNote is set when the time box is longer than the relaxation
	// window of a relaxable kind: an approval ends at its own cap.
	RelaxationNote string `json:"relaxation_note,omitempty"`
	// RequestBudget and PaceRPS are the request limits the task tells a
	// penetration test or red team (depth plan W4.6); 0 for a kind without them.
	RequestBudget int `json:"request_budget,omitempty"`
	PaceRPS       int `json:"pace_rps,omitempty"`
}

func securityAssessLimitsView(k secassess.Kind, lim securityAssessLimits, relaxMinutes int) securityAssessLimitsJS {
	js := securityAssessLimitsJS{
		TimeBoxMinutes: lim.Minutes, TimeBoxAction: lim.Action, BoundaryAudit: lim.AuditOn,
		AuditPolicy: string(k.TreePolicy), AuditLimits: secassess.AuditLimits,
	}
	if len(secassess.RelaxationsFor(k.ID)) > 0 && relaxMinutes > 0 && lim.Minutes > relaxMinutes {
		js.RelaxationNote = "approvals end at your cap, " + strconv.Itoa(relaxMinutes) + " minutes in"
	}
	return js
}

// securityAssessTimeJS is the time box and boundary audit part of a run row.
type securityAssessTimeJS struct {
	TimeBoxMinutes int        `json:"time_box_minutes,omitempty"`
	TimeBoxAction  string     `json:"time_box_action,omitempty"`
	Deadline       *time.Time `json:"deadline,omitempty"`
	// OverTimeBox: the run is (or ended) past its deadline.
	OverTimeBox bool `json:"over_time_box,omitempty"`
	// CanStop: the run has a terminal that has not ended, so Stop applies.
	CanStop bool `json:"can_stop,omitempty"`
	// EndWhy is terminal_gone, time_box or stopped.
	EndWhy string `json:"end_why,omitempty"`
	// Audit is the boundary audit verdict word (pending until the run ends,
	// unrecorded for an ended run whose closing check was not taken);
	// AuditWords says it in a sentence.
	Audit       string     `json:"audit,omitempty"`
	AuditWords  string     `json:"audit_words,omitempty"`
	AuditAt     *time.Time `json:"audit_at,omitempty"`
	AuditLimits string     `json:"audit_limits,omitempty"`
	// HasData: the run has stored evidence that Delete removes.
	HasData bool `json:"has_data,omitempty"`
	// HasModel: the run has a stored, checked copy of its model to open (a
	// validation can be on the row after the evidence was deleted).
	HasModel bool `json:"has_model,omitempty"`
}

// The audit words that are not verdicts of the comparison.
const (
	auditPending    = "pending"
	auditUnrecorded = "unrecorded"
)

// securityAssessTimeView derives a run row's time box and audit fields.
func securityAssessTimeView(r secassesssvc.Run, now time.Time, hasData bool) securityAssessTimeJS {
	js := securityAssessTimeJS{TimeBoxMinutes: r.TimeBoxMinutes, EndWhy: r.EndWhy, HasData: hasData}
	if r.TimeBoxMinutes > 0 {
		js.TimeBoxAction = r.TimeBoxAction
		if js.TimeBoxAction == "" {
			js.TimeBoxAction = secassess.TimeBoxStopButton
		}
		start := r.ConfirmedAt
		if start.IsZero() {
			start = r.CreatedAt
		}
		if d := secassess.Deadline(start, r.TimeBoxMinutes); !d.IsZero() {
			js.Deadline = &d
			at := now
			if !r.EndedAt.IsZero() {
				at = r.EndedAt
			}
			js.OverTimeBox = at.After(d)
		}
	}
	js.CanStop = r.IsStarted() && r.Handle != "" && r.EndedAt.IsZero()
	switch {
	case r.Audit != "":
		js.Audit, js.AuditWords, js.AuditLimits = r.Audit, secassess.AuditWords(secassess.AuditVerdict(r.Audit)), secassess.AuditLimits
		if !r.AuditAt.IsZero() {
			t := r.AuditAt
			js.AuditAt = &t
		}
	case !r.IsStarted() || r.TimeBoxMinutes == 0:
		// A held run has not started; a run recorded before the boundary audit
		// has nothing to say.
	case r.EndedAt.IsZero():
		js.Audit, js.AuditWords = auditPending, "Checked when the run ends"
	default:
		js.Audit, js.AuditWords = auditUnrecorded, "Not recorded"
	}
	return js
}

// ---- the boundary audit's git snapshots ----

const (
	// securityAssessSnapshotBudget bounds the whole snapshot; each git command
	// gets at most securityAssessGitTimeout of it.
	securityAssessSnapshotBudget = 8 * time.Second
	securityAssessGitTimeout     = 5 * time.Second
	securityAssessStatusMax      = 1 << 20
	securityAssessRefsMax        = 4 << 20
	securityAssessSmallMax       = 64 << 10
)

// securityAssessTakeTree takes the project's git state: HEAD, the branch, the
// stash count, a digest of the refs and the changed paths, each with a content
// fingerprint where the policy counts it (securityAssessFingerprint). A project
// that is not a repository, a missing git or a timeout gives a snapshot that is
// not OK, never a clean one; a path that could not be fingerprinted keeps no
// fingerprint and so reads as not compared.
func securityAssessTakeTree(ctx context.Context, root string, now time.Time, policy secassess.TreePolicy) secassess.TreeSnapshot {
	snap := secassess.TreeSnapshot{TakenAt: now.UTC()}
	if root == "" {
		return snap
	}
	parent := ctx
	ctx, cancel := context.WithTimeout(ctx, securityAssessSnapshotBudget)
	defer cancel()
	run := func(max int, args ...string) ([]byte, bool, error) {
		return gitview.RunReadOnlyTimeout(ctx, root, max, securityAssessGitTimeout, args...)
	}
	status, truncated, err := run(securityAssessStatusMax, secassess.TreeStatusArgs(policy)...)
	if err != nil {
		return snap
	}
	if truncated {
		// The byte cap cut the stream: the last record may be half a path.
		status = securityAssessWholeRecords(status)
	}
	snap.Entries, snap.Truncated = secassess.ParseStatusZ(status)
	snap.Truncated = snap.Truncated || truncated
	// A repository with no commit has no HEAD: not an error, an empty value.
	if out, _, err := run(securityAssessSmallMax, "rev-parse", "HEAD"); err == nil {
		snap.Head = strings.TrimSpace(string(out))
	}
	if ctx.Err() != nil {
		return secassess.TreeSnapshot{TakenAt: snap.TakenAt}
	}
	if out, _, err := run(securityAssessSmallMax, "rev-parse", "--abbrev-ref", "HEAD"); err == nil {
		snap.Branch = strings.TrimSpace(string(out))
	}
	if out, _, err := run(securityAssessSmallMax, "stash", "list", "--format=%H"); err == nil {
		snap.StashCount = len(strings.Fields(string(out)))
	}
	refs, _, err := run(securityAssessRefsMax, "for-each-ref", "--format=%(refname) %(objectname)")
	if err != nil {
		return secassess.TreeSnapshot{TakenAt: snap.TakenAt}
	}
	sum := sha256.Sum256(refs)
	snap.RefsDigest = hex.EncodeToString(sum[:8])
	snap.OK = true
	// Last, and best effort on its own budget: a snapshot that got this far is
	// valid, and a path the stage does not reach reads as not compared.
	securityAssessFingerprint(parent, root, snap.Entries, policy)
	return snap
}

// securityAssessWriteTree stores a run's tree.json.
func securityAssessWriteTree(side *secassesssvc.SideData, runID string, rec secassess.TreeRecord) error {
	data, err := secassess.FitTreeRecord(rec, secassesssvc.MaxSideTree)
	if err != nil {
		return err
	}
	return side.Put(runID, secassesssvc.SideTree, data)
}

// securityAssessReadTree reads a run's tree.json (an empty record when absent).
func securityAssessReadTree(side *secassesssvc.SideData, runID string) secassess.TreeRecord {
	var rec secassess.TreeRecord
	if data, ok := side.Get(runID, secassesssvc.SideTree); ok {
		_ = json.Unmarshal(data, &rec)
	}
	return rec
}

// securityAssessAtEnd builds the reconcile pass's closing-snapshot port: it
// reads the launch snapshot from the run's side data, takes the closing one,
// compares them under the kind's policy, stores all three and returns the
// verdict. It runs only in the daemon's loop, never inside a list request.
func securityAssessAtEnd(st *store.Store, side *secassesssvc.SideData) func(ctx context.Context, r secassesssvc.Run) (string, time.Time) {
	return func(ctx context.Context, r secassesssvc.Run) (string, time.Time) {
		now := time.Now().UTC()
		k, ok := secassess.KindByID(r.Kind)
		if !ok {
			return string(secassess.AuditUnchecked), now
		}
		rec := securityAssessReadTree(side, r.ID)
		root := ""
		if index, err := securityProjectIndex(ctx, st); err == nil {
			root = index[r.ProjectRootHash].Root
		}
		after := securityAssessTakeTree(ctx, root, now, k.TreePolicy)
		rec.After = &after
		var before secassess.TreeSnapshot
		if rec.Before != nil {
			before = *rec.Before
		}
		audit := secassess.AuditTree(before, after, k.TreePolicy)
		rec.Audit = &audit
		// The verdict stands even when the stored detail cannot be written.
		_ = securityAssessWriteTree(side, r.ID, rec)
		return string(audit.Verdict), now
	}
}

// securityAssessPrepare runs the launch-side steps that precede the terminal:
// the run folder with its .gitignore (a live workspace only: a clone has its own
// copy of the project), the request helper's two files when the plan said it is
// on, and the launch snapshot of the git state. It returns the function that
// undoes the folder and the files if the terminal does not start. The folder
// and the snapshot do not block a launch: a folder that cannot be made is
// logged, and a snapshot that could not be taken reads as could-not-check at
// the end. The helper does: the task the developer read says the files are
// there, so a launch that could not write them returns the error and nothing
// starts.
func (s *Server) securityAssessPrepare(ctx context.Context, l *securityAssessLaunch) (cleanup func(), err error) {
	cleanup = func() {}
	runs := l.runs
	live := l.launch.WorkspaceSource == "" || l.launch.WorkspaceSource == "live"
	if live {
		c, err := secassesssvc.PrepareRunDir(l.ref.Root, l.body.RunID)
		if err != nil {
			if s.opts.Logger != nil {
				s.opts.Logger.Warn("security assessments: run folder not prepared", "error", err)
			}
		} else {
			cleanup = c
		}
	}
	if l.ground.probe.Mode == secassess.HelperOn {
		if !live {
			// A clone has its own copy of the project: the helper written into
			// the live folder would not be in the agent's.
			return cleanup, secassesssvc.ErrProbeRun
		}
		undoDir := cleanup
		files, undoFiles, werr := secassesssvc.WriteProbeFiles(l.ref.Root, secassesssvc.ProbeInput{
			RunID: l.body.RunID, Target: l.verdict.Target, Budget: l.cfg.PentestRequestBudget, PaceRPS: l.cfg.PentestPaceRPS,
			Replay: l.ground.retest.replaySet(),
		})
		if werr != nil {
			undoDir()
			if s.opts.Logger != nil {
				s.opts.Logger.Warn("security assessments: request helper not written", "error", werr)
			}
			return func() {}, werr
		}
		l.helper = files
		cleanup = func() {
			undoFiles()
			undoDir()
		}
	}
	if l.limits.AuditOn && l.kind.TreePolicy != secassess.TreeNotAudited {
		before := securityAssessTakeTree(ctx, l.ref.Root, time.Now(), l.kind.TreePolicy)
		if err := securityAssessWriteTree(runs.Side(), l.body.RunID, secassess.TreeRecord{Before: &before}); err != nil && s.opts.Logger != nil {
			s.opts.Logger.Warn("security assessments: launch snapshot not stored", "error", err)
		}
	}
	return cleanup, nil
}

// securityAssessInitialAudit is the verdict a run records at launch when none
// will be taken: the audit is off, or the kind is not audited.
func securityAssessInitialAudit(k secassess.Kind, lim securityAssessLimits) string {
	switch {
	case !lim.AuditOn:
		return string(secassess.AuditOff)
	case k.TreePolicy == secassess.TreeNotAudited:
		return string(secassess.AuditNotAudited)
	}
	return ""
}

// ---- ports ----

// SecAssessExtra is what the runs' reconcile pass needs beyond the approval
// statements: how to close a terminal, how long to keep stored evidence and
// whether to take the closing snapshot.
type SecAssessExtra struct {
	// Close closes the terminal with the handle (nil: nothing is closed).
	Close func(handle string)
	// RetentionDays reads the evidence retention setting (nil: keep).
	RetentionDays func() int
	// Snapshots makes the pass take each ended run's closing git snapshot.
	// Only the daemon's loop sets it: a snapshot is git I/O and never runs
	// inside a list request.
	Snapshots bool
	// Side is the run record's side data (the store's own when nil).
	Side *secassesssvc.SideData
}

// SecAssessFullPorts is SecAssessPorts plus the run-level ports.
func SecAssessFullPorts(st *store.Store, term TerminalFunc, runs *secassesssvc.Store, x SecAssessExtra) secassesssvc.Ports {
	p := SecAssessPorts(st, term)
	p.Close, p.RetentionDays = x.Close, x.RetentionDays
	if x.Snapshots {
		side := x.Side
		if side == nil {
			side = runs.Side()
		}
		p.AtEnd = securityAssessAtEnd(st, side)
	}
	return p
}

// ---- routes ----

type securityAssessRunBody struct {
	Run string `json:"run"`
}

func (s *Server) securityAssessRunPost(w http.ResponseWriter, r *http.Request) (securityAssessRunBody, bool) {
	var body securityAssessRunBody
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return body, false
	}
	if !requireJSONConfirm(w, r) {
		return body, false
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, securityAssessBodyMax)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return body, false
	}
	return body, true
}

// handleSecurityAssessStop serves POST /api/security/assessments/stop {run}: it
// records that the developer ended the run and closes its terminal. Closing a
// terminal that is already gone is not an error.
func (s *Server) handleSecurityAssessStop(w http.ResponseWriter, r *http.Request) {
	body, ok := s.securityAssessRunPost(w, r)
	if !ok {
		return
	}
	if s.opts.LaunchManager == nil {
		http.Error(w, "stop unavailable - this dashboard runs without the embedded-terminal launcher (run via `observer start`)", http.StatusServiceUnavailable)
		return
	}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	run, found, err := runs.Mutate(body.Run, func(x *secassesssvc.Run) error {
		if x.IsStarted() && x.Handle != "" && x.EndedAt.IsZero() && x.EndWhy == "" {
			x.EndWhy = secassess.EndStopped
		}
		return nil
	})
	// The error first: an unreadable record reports found=false with an error,
	// and that is not an unknown run.
	switch {
	case err != nil:
		s.writeSecurityAssessRunErr(w, err)
		return
	case !found:
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	case !run.IsStarted() || run.Handle == "":
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "the run has no terminal to stop", "code": "not_started"})
		return
	}
	if run.EndedAt.IsZero() {
		s.opts.LaunchManager.Close(run.Handle)
	}
	ctx := r.Context()
	root := ""
	if index, err := securityProjectIndex(ctx, store.New(s.db())); err == nil {
		root = index[run.ProjectRootHash].Root
	}
	writeJSON(w, map[string]any{"run": s.securityAssessRunViewFull(ctx, run, root)})
}

// handleSecurityAssessDeleteData serves POST /api/security/assessments/delete-data
// {run}: it removes the evidence stored for one run (its checked model and git
// snapshots). The run, its report and its findings stay.
func (s *Server) handleSecurityAssessDeleteData(w http.ResponseWriter, r *http.Request) {
	body, ok := s.securityAssessRunPost(w, r)
	if !ok {
		return
	}
	runs := secassesssvc.Shared(secassesssvc.Path(s.opts.DBPath))
	if err := runs.Unreadable(); err != nil {
		s.writeSecurityAssessRunErr(w, err)
		return
	}
	run, found := runs.Get(body.Run)
	if !found {
		http.Error(w, "unknown run", http.StatusNotFound)
		return
	}
	if err := runs.Side().Delete(run.ID); err != nil {
		writeErrStatus(w, err, http.StatusInternalServerError)
		return
	}
	ctx := r.Context()
	root := ""
	if index, err := securityProjectIndex(ctx, store.New(s.db())); err == nil {
		root = index[run.ProjectRootHash].Root
	}
	writeJSON(w, map[string]any{"run": s.securityAssessRunViewFull(ctx, run, root)})
}
