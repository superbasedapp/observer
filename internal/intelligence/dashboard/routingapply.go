//go:build !sbo_omit_proxy_routing

package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/intelligence/modelvalue"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/routingapply"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Channel A apply endpoints (R2.1, §R10): the dashboard frontend over
// the SAME seams the CLI's `observer routing apply` uses
// (internal/routingapply — one owner of the write mechanics, two thin
// frontends).
//
// Consent model (wizard semantics, the `observer init` checklist
// idiom): GET is a pure dry-run preview; every write is ONE file per
// POST, individually confirmed by the operator. The server re-derives
// the plan from current evidence before writing, so the endpoint only
// ever writes evidence-backed changes — a stale or hand-crafted body
// is refused 409, never written. Revert is likewise one file per POST,
// restoring the newest observer backup.
//
// These writes touch claude-code agent files, not observer config —
// claude-code reads them at session spawn, so changes take effect for
// NEW sessions with no observer restart (no restart banner).

// routingApplyChangeJSON is one preview row: the planned edit plus the
// §R7.2 evidence basis (persona profile + global parity deltas for the
// target model).
type routingApplyChangeJSON struct {
	routingapply.Change
	Reason   string                   `json:"reason"`
	Evidence routing.SubagentEvidence `json:"evidence"`
	Deltas   []modelvalue.Delta       `json:"deltas"`
}

// handleRoutingApply serves /api/routing/apply:
//
//   - GET ?tool=&days= → per-tool dry-run preview. claude-code returns
//     the planned per-file diffs with evidence; snippet-mode tools the
//     paste-able native-config block; cursor/copilot the honest
//     advisory-only note.
//   - POST {tool, path, to_model, days} → write ONE planned change
//     (claude-code only). 409 when the change no longer matches the
//     freshly re-derived plan.
func (s *Server) handleRoutingApply(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.serveRoutingApplyPreview(w, r)
	case http.MethodPost:
		s.applyRoutingChange(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) serveRoutingApplyPreview(w http.ResponseWriter, r *http.Request) {
	tool := r.URL.Query().Get("tool")
	mode, ok := routingapply.ToolMode(tool)
	if !ok {
		http.Error(w, fmt.Sprintf("tool must be one of: %s", strings.Join(routingapply.Tools(), ", ")), http.StatusBadRequest)
		return
	}
	days := intArg(r, "days", 30, 1, 36500)

	if mode == routingapply.ModeAdvisory {
		writeJSON(w, map[string]any{
			"tool": tool, "mode": mode, "window_days": days,
			"note": fmt.Sprintf("%s is advisory-only (§R10.2): its model picker is not reliably file-addressable. "+
				"Use the evidence here (or `observer model-value`) and set the picker manually; the router-vs-router "+
				"view on this page shows how its Auto mode compares.", tool),
		})
		return
	}

	rep, err := s.applyEvidenceReport(r.Context(), days)
	if err != nil {
		writeErr(w, err)
		return
	}

	if mode == routingapply.ModeSnippet {
		weak := routingapply.WeakModel(rep.Subagents)
		snippet, _ := routingapply.AdvisorySnippet(tool, weak)
		writeJSON(w, map[string]any{
			"tool": tool, "mode": mode, "window_days": days,
			"weak_model": weak,
			"snippet":    snippet,
			"deltas":     rep.GlobalDeltasFor(weak),
			"note": "Paste-emission tool (§R10.2): observer prints the exact native-config block but does not " +
				"write this tool's files - paste it into the tool's own config.",
		})
		return
	}

	dirs := s.routingAgentDirs(r.Context())
	changes, skipped := routingapply.Plan(dirs, rep.Subagents)
	if skipped == nil {
		skipped = []string{}
	}
	recsByName := map[string]routing.SubagentRecommendation{}
	for _, rec := range rep.Subagents {
		recsByName[rec.Name] = rec
	}
	rows := make([]routingApplyChangeJSON, 0, len(changes))
	for _, c := range changes {
		rec := recsByName[c.Agent]
		rows = append(rows, routingApplyChangeJSON{
			Change: c, Reason: string(rec.Reason), Evidence: rec.Evidence,
			Deltas: rep.GlobalDeltasFor(c.ToModel),
		})
	}
	backups := routingapply.ListBackups(dirs)
	if backups == nil {
		backups = []routingapply.Backup{}
	}
	writeJSON(w, map[string]any{
		"tool": tool, "mode": mode, "window_days": days,
		"agent_dirs": dirs,
		"changes":    rows,
		"skipped":    skipped,
		"backups":    backups,
		"note": "Dry-run preview - nothing is written until you confirm a change. Writes edit only the model: " +
			"frontmatter line (a .bak-observer-<stamp> backup lands next to each file); claude-code picks the " +
			"change up at the next session spawn - no observer restart. Files live on the daemon's host.",
	})
}

func (s *Server) applyRoutingChange(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Tool    string `json:"tool"`
		Path    string `json:"path"`
		ToModel string `json:"to_model"`
		Days    int    `json:"days"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	mode, ok := routingapply.ToolMode(req.Tool)
	if !ok {
		http.Error(w, fmt.Sprintf("tool must be one of: %s", strings.Join(routingapply.Tools(), ", ")), http.StatusBadRequest)
		return
	}
	if mode != routingapply.ModeWritable {
		http.Error(w, fmt.Sprintf("%s is %s per the §R10.2 matrix - only claude-code is written directly; use the preview's snippet/evidence instead", req.Tool, mode), http.StatusBadRequest)
		return
	}
	days := req.Days
	if days <= 0 {
		days = 30
	}
	if days > 36500 {
		days = 36500
	}
	// Re-derive the plan from current evidence: the endpoint writes
	// only what the evidence supports RIGHT NOW. A preview gone stale
	// (file edited, evidence shifted, already applied) refuses 409.
	rep, err := s.applyEvidenceReport(r.Context(), days)
	if err != nil {
		writeErr(w, err)
		return
	}
	changes, _ := routingapply.Plan(s.routingAgentDirs(r.Context()), rep.Subagents)
	idx := slices.IndexFunc(changes, func(c routingapply.Change) bool {
		return c.Path == req.Path && c.ToModel == req.ToModel
	})
	if idx < 0 {
		http.Error(w, "no currently-planned change matches this path + target - the preview is stale (or the change already applied); re-run the preview", http.StatusConflict)
		return
	}
	// W5.1 org-governed feature gate: node.features.routing_apply. Fail-open
	// (nil FeatureGate, or no accepted policy) — checked as late as
	// possible, right before the write, so a denied request never even
	// leaves a stale-preview error path unexplained.
	if s.opts.FeatureGate != nil {
		if allowed, reason := s.opts.FeatureGate(nodeFeatureRoutingApply); !allowed {
			http.Error(w, reason, http.StatusForbidden)
			return
		}
	}
	c := changes[idx]
	stamp := routingapply.Stamp(time.Now())
	if err := routingapply.Write(c, stamp); err != nil {
		writeErr(w, fmt.Errorf("write %s: %w", c.Path, err))
		return
	}
	out := map[string]any{
		"written": true,
		"change":  c,
		"backup":  c.Path + routingapply.BackupPrefix + stamp,
		"note":    "claude-code reads agent files at session spawn - new sessions pick this up; no observer restart needed.",
	}
	// Audit trail (R2.5): best-effort — the write already landed with
	// its backup; a ledger failure is surfaced, never a write failure.
	if err := s.applyAuditLedger().RecordWrite(c, stamp, "dashboard"); err != nil {
		out["ledger_error"] = err.Error()
	}
	writeJSON(w, out)
}

// applyAuditLedger resolves the R2.5 audit ledger — the same
// node-local file the CLI frontend appends to.
func (s *Server) applyAuditLedger() *routingapply.Ledger {
	return routingapply.NewLedger(routingapply.DefaultLedgerPath(s.opts.DBPath))
}

// handleRoutingApplyLedger serves GET /api/routing/apply/ledger?limit=
// — the "what did observer change?" view (R2.5): every Channel A write
// and revert from BOTH frontends, newest first.
func (s *Server) handleRoutingApplyLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	limit := intArg(r, "limit", 50, 1, 1000)
	ledger := s.applyAuditLedger()
	events, skipped, err := ledger.Read()
	if err != nil {
		writeErr(w, err)
		return
	}
	// Newest first for the history view.
	slices.Reverse(events)
	if len(events) > limit {
		events = events[:limit]
	}
	if events == nil {
		events = []routingapply.LedgerEvent{}
	}
	writeJSON(w, map[string]any{
		"events":  events,
		"skipped": skipped,
		"path":    ledger.Path(),
	})
}

// handleRoutingApplyRevert serves POST /api/routing/apply/revert:
//
//   - {path} — restore ONE agent file from its newest observer backup
//     (the per-write consent mirror of the write path). The path must
//     sit directly in a known agent directory — this endpoint never
//     touches arbitrary files.
//   - {all: true} — the unified revert (R2.5): restore EVERY agent
//     file that has an observer backup, matching the CLI's --revert
//     contract. Still one explicit consented operation.
//
// Both arms record into the audit ledger.
func (s *Server) handleRoutingApplyRevert(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Path string `json:"path"`
		All  bool   `json:"all"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, "decode body: "+err.Error(), http.StatusBadRequest)
		return
	}
	dirs := s.routingAgentDirs(r.Context())
	ledger := s.applyAuditLedger()

	if req.All {
		restored, err := routingapply.Revert(dirs)
		var ledgerErr error
		for _, res := range restored {
			if ledgerErr == nil {
				ledgerErr = ledger.RecordRevert(res, "dashboard")
			}
		}
		if err != nil {
			writeErr(w, err)
			return
		}
		out := map[string]any{"restored": len(restored) > 0, "count": len(restored), "files": restored}
		if ledgerErr != nil {
			out["ledger_error"] = ledgerErr.Error()
		}
		writeJSON(w, out)
		return
	}

	if req.Path == "" {
		http.Error(w, "path is required (or pass all=true)", http.StatusBadRequest)
		return
	}
	clean := filepath.Clean(req.Path)
	inKnownDir := slices.ContainsFunc(dirs, func(d string) bool {
		return filepath.Clean(d) == filepath.Dir(clean)
	})
	if !inKnownDir {
		http.Error(w, "path is not inside a known claude-code agent directory", http.StatusBadRequest)
		return
	}
	res, err := routingapply.RevertFile(clean)
	if errors.Is(err, os.ErrNotExist) {
		http.Error(w, "no observer backup exists for this file", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	out := map[string]any{"restored": true, "path": res.Path, "backup": res.Backup}
	if lerr := ledger.RecordRevert(res, "dashboard"); lerr != nil {
		out["ledger_error"] = lerr.Error()
	}
	writeJSON(w, out)
}

// applyEvidenceReport builds the Model Value Report the apply surfaces
// consume — the same seam the CLI uses (LoadModelValueFacts →
// modelvalue.Build), priced by the dashboard's cost engine.
func (s *Server) applyEvidenceReport(ctx context.Context, days int) (*modelvalue.Report, error) {
	st := store.New(s.opts.DB)
	facts, err := st.LoadModelValueFacts(ctx, modelvalue.LoadOptions{WindowDays: days})
	if err != nil {
		return nil, err
	}
	if fn := s.opts.CostEngine.RoutingPriceFn(); fn != nil {
		facts.Price = fn
	}
	rep := modelvalue.Build(facts, modelvalue.Options{})
	return &rep, nil
}

// routingAgentDirs lists the claude-code agent directories the
// dashboard probes: user-level plus every known project root (the
// guardpolicy KnownProjectRoots idiom). The CLI probes user-level +
// CWD instead — the daemon has no meaningful CWD, so the dashboard
// goes strictly broader; every preview row carries its full path.
func (s *Server) routingAgentDirs(ctx context.Context) []string {
	var dirs []string
	if home, err := os.UserHomeDir(); err == nil {
		dirs = append(dirs, filepath.Join(home, ".claude", "agents"))
	}
	st := store.New(s.opts.DB)
	roots, _ := st.ProjectRoots(ctx)
	for _, root := range roots {
		dirs = append(dirs, filepath.Join(root, ".claude", "agents"))
	}
	return dirs
}
