package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Session-handoff endpoints (docs/session-handoff.md, plan §15 P2): thin
// wrappers over the injected handoffsvc runner. GET …/handoff/estimate is
// the modal's read side (carry-mode price table + fork-picker boundaries,
// nothing written); POST …/handoff performs the handoff (writes the
// HANDOFF-*.md doc + the node-local handoffs row).

// handoffTarget is one selectable target tool, straight from the
// integration capability registry — the modal renders honest per-tool
// capability, never a fabricated one.
type handoffTarget struct {
	Tool string `json:"tool"`
	// TranscriptTier is the tool's own readability as a SOURCE ("full",
	// "partial", "" = actions-only) — shown so the picker can hint what a
	// later handoff back out of that tool could carry.
	TranscriptTier string `json:"transcript_tier"`
	// InjectLanes are the grounded delivery lanes (file is the universal
	// floor).
	InjectLanes []string `json:"inject_lanes"`
	// Launchable reports whether this target can be started in the
	// dashboard's embedded web terminal (a grounded LaunchSpec AND the
	// launcher enabled on this dashboard process). The modal shows the
	// "Launch <tool> here" action only when true.
	Launchable bool   `json:"launchable"`
	Note       string `json:"note,omitempty"`
}

type handoffForkJSON struct {
	RequestedIndex int    `json:"requested_index,omitempty"`
	ResolvedIndex  int    `json:"resolved_index"`
	Snapped        bool   `json:"snapped,omitempty"`
	Reason         string `json:"reason,omitempty"`
	ForkTime       string `json:"fork_time,omitempty"`
}

type handoffEstimateRowJSON struct {
	Mode    string  `json:"mode"`
	Tokens  int64   `json:"tokens"`
	CostUSD float64 `json:"cost_usd"`
	Note    string  `json:"note"`
}

type handoffEstimateJSON struct {
	TargetModel string                   `json:"target_model"`
	ForkShare   float64                  `json:"fork_share"`
	Rows        []handoffEstimateRowJSON `json:"rows"`
	// Stay is the plan §9 stay-option comparison (predict band +
	// cachewarm value-at-risk at the source); omitted when ungrounded.
	Stay *handoff.StayEstimate `json:"stay,omitempty"`
}

// handoffResponse is the shared payload of both endpoints. The estimate
// endpoint adds Boundaries + Targets (the modal's pickers); the create
// endpoint adds DocPath/ShortID/HandoffID once something was written.
type handoffResponse struct {
	SessionID      string `json:"session_id"`
	TargetTool     string `json:"target_tool,omitempty"`
	TargetModel    string `json:"target_model"`
	CarryUsed      string `json:"carry_used"`
	DegradeReason  string `json:"degrade_reason,omitempty"`
	ContextWarning string `json:"context_warning,omitempty"`
	// FullCacheAvailable reports whether the source adapter implements the
	// un-excerpted (FullTranscriptReader) read the full_cache carry needs —
	// mirrored straight from handoffsvc.sourceHasFullReader via
	// handoff.EstimateResult.SourceHasFullReader (the single source of
	// truth; never re-derived here). Only claudecode/codex/kimicode/grok
	// are true today. The modal greys out the "Full + cache" option when
	// this is false instead of silently offering a choice that collapses to
	// an identical-to-full doc (docs/session-handoff.md).
	FullCacheAvailable bool                `json:"full_cache_available"`
	Fork               handoffForkJSON     `json:"fork"`
	Estimate           handoffEstimateJSON `json:"estimate"`
	Boundaries         []handoff.Boundary  `json:"boundaries,omitempty"`
	Targets            []handoffTarget     `json:"targets,omitempty"`
	Doc                string              `json:"doc,omitempty"`
	DocPath            string              `json:"doc_path,omitempty"`
	ShortID            string              `json:"short_id,omitempty"`
	HandoffID          int64               `json:"handoff_id,omitempty"`
	GitignoreHint      bool                `json:"gitignore_hint,omitempty"`
	DryRun             bool                `json:"dry_run,omitempty"`
}

// handleSessionHandoffEstimate serves GET /api/session/<id>/handoff/estimate
// (?to= &target_model= &fork= &carry=). Always a dry run: it prices the
// carry table at the requested fork and returns the fork-picker boundary
// rows; nothing is written.
func (s *Server) handleSessionHandoffEstimate(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.BuildHandoff == nil {
		http.Error(w, "handoff unavailable — this dashboard process runs without the handoff service", http.StatusServiceUnavailable)
		return
	}
	q := r.URL.Query()
	fork := handoff.ForkPoint{}
	if v := q.Get("fork"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 {
			http.Error(w, "fork must be a 1-based message index", http.StatusBadRequest)
			return
		}
		fork = handoff.ForkPoint{Kind: handoff.ForkMessageIndex, MessageIndex: n}
	}
	res, err := s.opts.BuildHandoff(r.Context(), handoffsvc.Request{
		SessionID:         sessionID,
		TargetTool:        q.Get("to"),
		TargetModel:       q.Get("target_model"),
		Fork:              fork,
		Carry:             handoff.CarryMode(q.Get("carry")),
		DryRun:            true,
		IncludeBoundaries: true,
	})
	if err != nil {
		writeHandoffError(w, r, err)
		return
	}
	resp := buildHandoffResponse(sessionID, q.Get("to"), res, true)
	resp.Boundaries = res.Boundaries
	resp.Targets = handoffTargets(s.opts.LaunchManager != nil)
	writeJSON(w, resp)
}

// handoffCreateRequest is the POST body.
type handoffCreateRequest struct {
	To          string `json:"to"`
	TargetModel string `json:"target_model"`
	// ForkMessage forks after this 1-based message; 0 = last message.
	ForkMessage int    `json:"fork_message"`
	Carry       string `json:"carry"`
	OutPath     string `json:"out_path"`
	DryRun      bool   `json:"dry_run"`
}

// handleSessionHandoffCreate serves POST /api/session/<id>/handoff — the
// modal's Confirm. Writes HANDOFF-<shortid>.md into the project root (or
// out_path) plus one node-local handoffs row; dry_run:true writes nothing.
func (s *Server) handleSessionHandoffCreate(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.BuildHandoff == nil {
		http.Error(w, "handoff unavailable — this dashboard process runs without the handoff service", http.StatusServiceUnavailable)
		return
	}
	var body handoffCreateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	fork := handoff.ForkPoint{}
	if body.ForkMessage > 0 {
		fork = handoff.ForkPoint{Kind: handoff.ForkMessageIndex, MessageIndex: body.ForkMessage}
	}
	res, err := s.opts.BuildHandoff(r.Context(), handoffsvc.Request{
		SessionID:   sessionID,
		TargetTool:  body.To,
		TargetModel: body.TargetModel,
		Fork:        fork,
		Carry:       handoff.CarryMode(body.Carry),
		OutPath:     body.OutPath,
		DryRun:      body.DryRun,
	})
	if err != nil {
		writeHandoffError(w, r, err)
		return
	}
	resp := buildHandoffResponse(sessionID, body.To, res, body.DryRun)
	resp.Doc = res.Doc
	resp.DocPath = res.DocPath
	resp.HandoffID = res.HandoffID
	resp.GitignoreHint = res.GitignoreHint
	writeJSON(w, resp)
}

func buildHandoffResponse(sessionID, targetTool string, res handoffsvc.Result, dryRun bool) handoffResponse {
	rows := make([]handoffEstimateRowJSON, 0, len(res.Estimate.Rows))
	for _, r := range res.Estimate.Rows {
		rows = append(rows, handoffEstimateRowJSON{
			Mode:    string(r.Mode),
			Tokens:  r.Tokens,
			CostUSD: r.CostUSD,
			Note:    r.Note,
		})
	}
	fork := handoffForkJSON{
		RequestedIndex: res.Fork.RequestedIndex,
		ResolvedIndex:  res.Fork.ResolvedIndex,
		Snapped:        res.Fork.Snapped,
		Reason:         res.Fork.Reason,
	}
	if !res.Fork.ForkTime.IsZero() {
		fork.ForkTime = res.Fork.ForkTime.UTC().Format(time.RFC3339)
	}
	return handoffResponse{
		SessionID:          sessionID,
		TargetTool:         targetTool,
		TargetModel:        res.TargetModel,
		CarryUsed:          string(res.CarryUsed),
		DegradeReason:      res.DegradeReason,
		ContextWarning:     res.ContextWarning,
		FullCacheAvailable: res.Estimate.SourceHasFullReader,
		Fork:               fork,
		Estimate: handoffEstimateJSON{
			TargetModel: res.Estimate.TargetModel,
			ForkShare:   res.Estimate.ForkShare,
			Rows:        rows,
			Stay:        res.Estimate.Stay,
		},
		ShortID: res.ShortID,
		DryRun:  dryRun,
	}
}

// handoffTargets renders the target-tool picker from the integration
// capability registry, sorted by tool name. launchEnabled reflects whether
// this dashboard process has the embedded-terminal launcher wired, so the
// per-target Launchable flag is honest about BOTH the capability and the
// runtime availability. The capability half is integration.TerminalLaunchable
// (grounded LaunchSpec AND an advertised lifecycle), so a deprecated/dead
// product is still listed but never offered as a launch target.
func handoffTargets(launchEnabled bool) []handoffTarget {
	caps := integration.Capabilities()
	sort.Slice(caps, func(i, j int) bool { return caps[i].Tool < caps[j].Tool })
	out := make([]handoffTarget, 0, len(caps))
	for _, c := range caps {
		lanes := c.Handoff.Lanes()
		strs := make([]string, 0, len(lanes))
		for _, l := range lanes {
			strs = append(strs, string(l))
		}
		out = append(out, handoffTarget{
			Tool:           c.Tool,
			TranscriptTier: string(c.Handoff.Transcript),
			InjectLanes:    strs,
			Launchable:     launchEnabled && integration.TerminalLaunchable(c),
			Note:           c.Handoff.Note,
		})
	}
	return out
}

// writeHandoffError maps handoffsvc errors onto HTTP statuses: unknown
// session → 404, everything else (bad carry, unstable fork, disabled
// config) → 400 with the service's own honest message.
func writeHandoffError(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, handoffsvc.ErrSessionNotFound) {
		http.NotFound(w, r)
		return
	}
	http.Error(w, err.Error(), http.StatusBadRequest)
}
