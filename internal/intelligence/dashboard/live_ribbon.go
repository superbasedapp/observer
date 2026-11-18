package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/firstrunstate"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// The live ribbon's read (local dashboard first run §8.2 / §8.5):
// GET /api/live?view=ribbon, an additive mode of the Live route. Per live
// session it returns only what the ribbon renders: identity, the project
// NAME (never a path), one model, a token total, the cost with its basis
// flags, and the timestamps the "running 12 m" / "quiet 4 m" label is read
// from. It never returns an action, a target or a file name. It also carries
// the ribbon's own switch ([dashboard].live_ribbon, read live) and the
// once-per-install first-prompt receipt.
//
// It starts from the time side: candidate session ids come from the rows
// that landed inside the window in actions / api_turns / token_usage, each a
// range scan on that table's timestamp index (idx_actions_ts_cover, which
// also covers session_id, idx_api_turns_timestamp, idx_token_usage_timestamp),
// and only those sessions are joined. It never walks every sessions row.

// ribbonLimit is how many sessions the ribbon read returns, newest activity
// first. active_count carries the full number.
const ribbonLimit = 8

// ribbonReceiptKey is the dismissal key the first-prompt receipt is closed
// with (POST /api/firstrun/seen {"dismiss": ...}).
const ribbonReceiptKey = "first_prompt_receipt"

// receiptMaxAge retires a fired receipt the owner never saw: a "your first
// captured prompt" card days later is no longer that moment.
const receiptMaxAge = 24 * time.Hour

// liveActiveCTE selects the sessions with any activity row at or after the
// bound (three binds, one per table) and their newest activity timestamp.
// Timestamps are RFC3339 UTC strings, so MAX() string comparison is correct.
const liveActiveCTE = `WITH recent(session_id, ts) AS (
	SELECT session_id, timestamp FROM actions WHERE timestamp >= ?
	UNION ALL SELECT session_id, timestamp FROM api_turns WHERE timestamp >= ?
	UNION ALL SELECT session_id, timestamp FROM token_usage WHERE timestamp >= ?
), active(session_id, last_activity) AS (
	SELECT session_id, MAX(ts) FROM recent
	WHERE session_id IS NOT NULL AND session_id <> ''
	GROUP BY session_id
)`

// ribbonQuery is the ribbon's one session read. COUNT(*) OVER () is the
// number of active sessions before the LIMIT.
const ribbonQuery = liveActiveCTE + `
SELECT s.id, s.tool, COALESCE(p.root_path, ''), COALESCE(p.name, ''),
       COALESCE(s.started_at, ''), a.last_activity,
       (SELECT COUNT(*) FROM actions x WHERE x.session_id = s.id),
       COUNT(*) OVER ()
FROM active a
JOIN sessions s ON s.id = a.session_id
LEFT JOIN projects p ON p.id = s.project_id
ORDER BY a.last_activity DESC, s.id
LIMIT ?`

// ribbonSession is one live session as the ribbon shows it.
type ribbonSession struct {
	SessionID string `json:"session_id"`
	Tool      string `json:"tool"`
	// Project is the project's name (its folder's last element), never
	// its path.
	Project string `json:"project,omitempty"`
	// Model is the model of the session's newest turn; ModelCount is how
	// many distinct models it used (the ribbon writes "+1" for two).
	Model      string `json:"model,omitempty"`
	ModelCount int    `json:"model_count"`
	// Tokens is the session's lifetime total over all four buckets
	// (input, output, cache read, cache write).
	Tokens  int64   `json:"tokens"`
	CostUSD float64 `json:"cost_usd"`
	// CostEstimated: at least one turn's cost was not a proxy-recorded
	// cost (transcript tokens, or priced from the price table).
	CostEstimated bool `json:"cost_estimated"`
	// CostRecorded is false when the tool keeps no tokens locally (its
	// integration row's token tier is "none") and none arrived: the ribbon
	// says "cost not recorded" and shows the action count instead.
	CostRecorded bool `json:"cost_recorded"`
	// PriceUnknown: at least one turn's model has no price at all. Its
	// cost counts as nothing in CostUSD; the ribbon never shows it as $0.
	PriceUnknown bool   `json:"price_unknown"`
	Turns        int64  `json:"turns"`
	ActionsTotal int64  `json:"actions_total"`
	StartedAt    string `json:"started_at"`
	LastActivity string `json:"last_activity"`
}

// ribbonReceipt is the one-time "Your first captured prompt" summary. Counts
// and labels only.
type ribbonReceipt struct {
	SessionID     string  `json:"session_id"`
	Tool          string  `json:"tool"`
	Project       string  `json:"project,omitempty"`
	Model         string  `json:"model,omitempty"`
	Tokens        int64   `json:"tokens"`
	CostUSD       float64 `json:"cost_usd"`
	CostEstimated bool    `json:"cost_estimated"`
	CostRecorded  bool    `json:"cost_recorded"`
	PriceUnknown  bool    `json:"price_unknown"`
	Turns         int64   `json:"turns"`
	FilesRead     int64   `json:"files_read"`
	Edits         int64   `json:"edits"`
	Commands      int64   `json:"commands"`
	FiredAt       string  `json:"fired_at,omitempty"`
}

// ribbonResponse is the GET /api/live?view=ribbon body.
type ribbonResponse struct {
	GeneratedAt   string `json:"generated_at"`
	WindowMinutes int    `json:"window_minutes"`
	View          string `json:"view"`
	// Enabled is [dashboard].live_ribbon. Off: no sessions are read.
	Enabled bool `json:"enabled"`
	// ActiveCount is every session active in the window (Sessions holds
	// the newest ribbonLimit of them).
	ActiveCount int             `json:"active_count"`
	Sessions    []ribbonSession `json:"sessions"`
	// Receipt is the first-prompt receipt while it is due (fired, not
	// dismissed, not stale), else absent. Never on demo data.
	Receipt *ribbonReceipt `json:"receipt,omitempty"`
}

// costBasis is how one deduped turn's cost was arrived at.
type costBasis int

const (
	basisRecorded costBasis = iota
	basisEstimated
	basisUnpriced
)

// costBasisRules is the per-turn basis table, walked top-down: the first
// matching row decides.
var costBasisRules = []struct {
	name  string
	match func(dashapi.SpendTurn) bool
	basis costBasis
}{
	{"no recorded cost and no price for the model", func(t dashapi.SpendTurn) bool { return !t.Priced }, basisUnpriced},
	{"a cost the proxy recorded on the API turn", func(t dashapi.SpendTurn) bool { return t.Source == "proxy" && t.Recorded > 0 }, basisRecorded},
	{"transcript tokens, or priced from the table", func(dashapi.SpendTurn) bool { return true }, basisEstimated},
}

func turnCostBasis(t dashapi.SpendTurn) costBasis {
	for _, r := range costBasisRules {
		if r.match(t) {
			return r.basis
		}
	}
	return basisEstimated
}

// toolKeepsTokens reports whether a tool has a local token source, from its
// integration row (never its name): "none" is the audited "no local tokens".
// A tool with no row is assumed to keep them (the ribbon then says "no tokens
// yet" rather than claiming the tool never records cost).
func toolKeepsTokens(tool string) bool {
	c, ok := integration.For(tool)
	return !ok || c.TokenTier.Best != "none"
}

// projectName is the last element of a project root, for either path
// separator, or the stored project name when there is no root.
func projectName(root, name string) string {
	r := strings.TrimRight(strings.TrimSpace(root), `/\`)
	if i := strings.LastIndexAny(r, `/\`); i >= 0 {
		r = r[i+1:]
	}
	if r != "" {
		return r
	}
	return strings.TrimSpace(name)
}

// ribbonRollup folds one session's deduped spend rows into the ribbon's
// numbers and flags.
func ribbonRollup(rs *ribbonSession, turns []dashapi.SpendTurn) {
	models := map[string]bool{}
	var newest time.Time
	for _, t := range turns {
		rs.Turns++
		b := t.Bundle
		rs.Tokens += b.Input + b.Output + b.CacheRead + b.CacheCreation + b.CacheCreation1h
		rs.CostUSD += t.CostUSD
		switch turnCostBasis(t) {
		case basisUnpriced:
			rs.PriceUnknown = true
		case basisEstimated:
			rs.CostEstimated = true
		}
		if t.Model != "" {
			models[t.Model] = true
			if rs.Model == "" || !t.At.Before(newest) {
				rs.Model, newest = t.Model, t.At
			}
		}
	}
	rs.ModelCount = len(models)
	rs.CostRecorded = rs.Turns > 0 || toolKeepsTokens(rs.Tool)
}

// liveRibbonEnabled reads [dashboard].live_ribbon from the config file on
// each request, so a Settings save applies without a restart. An unreadable
// config keeps the ribbon on (the default).
func (s *Server) liveRibbonEnabled() bool {
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return true
	}
	return cfg.Dashboard.LiveRibbon
}

// handleLiveRibbon serves GET /api/live?view=ribbon. The global filters do
// not apply: the ribbon shows what is live on this machine, the same count
// the nav's Live badge shows.
func (s *Server) handleLiveRibbon(w http.ResponseWriter, r *http.Request, windowMin int) {
	now := s.now()
	out := ribbonResponse{
		GeneratedAt:   now.UTC().Format(time.RFC3339Nano),
		WindowMinutes: windowMin,
		View:          "ribbon",
		Enabled:       s.liveRibbonEnabled(),
		Sessions:      []ribbonSession{},
	}
	if !out.Enabled || s.db() == nil {
		writeJSON(w, out)
		return
	}
	since := now.Add(-time.Duration(windowMin) * time.Minute).UTC().Format(time.RFC3339Nano)
	sessions, total, err := s.loadRibbonSessions(r.Context(), since)
	if err != nil {
		writeErr(w, err)
		return
	}
	out.Sessions, out.ActiveCount = sessions, total
	// Demo data never fires, arms or shows the receipt (§8.4 rule 6).
	if s.demoDB.Load() == nil {
		out.Receipt = s.ribbonReceipt(r.Context(), sessions, now)
	}
	writeJSON(w, out)
}

// loadRibbonSessions runs the time-driven active read and folds each
// session's deduped spend rows (the substrate the session detail header and
// the Live page cards sum).
func (s *Server) loadRibbonSessions(ctx context.Context, since string) ([]ribbonSession, int, error) {
	rows, err := s.db().QueryContext(ctx, ribbonQuery, since, since, since, ribbonLimit)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []ribbonSession{}
	total := 0
	for rows.Next() {
		var rs ribbonSession
		var root, name string
		if err := rows.Scan(&rs.SessionID, &rs.Tool, &root, &name, &rs.StartedAt,
			&rs.LastActivity, &rs.ActionsTotal, &total); err != nil {
			return nil, 0, err
		}
		rs.Project = projectName(root, name)
		out = append(out, rs)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	ids := make([]string, 0, len(out))
	for _, rs := range out {
		ids = append(ids, rs.SessionID)
	}
	bySession := map[string][]dashapi.SpendTurn{}
	if len(ids) > 0 {
		if turns, err := s.spendTurns(ctx, time.Time{}, time.Time{}, dashapi.SpendScope{}, ids); err == nil {
			for _, t := range turns {
				bySession[t.SessionID] = append(bySession[t.SessionID], t)
			}
		}
	}
	for i := range out {
		ribbonRollup(&out[i], bySession[out[i].SessionID])
	}
	return out, total, nil
}

// receiptStep is what one ribbon read does with the first-prompt receipt.
type receiptStep int

const (
	receiptNone    receiptStep = iota // nothing to do, nothing to show
	receiptArm                        // record the arm time, show nothing
	receiptTryFire                    // fire it for a qualifying live session, if any
	receiptShow                       // show the fired receipt
)

// receiptFacts is what the step table reads.
type receiptFacts struct {
	stateless bool // no state file (a dashboard without a database path)
	dismissed bool
	armed     bool
	fired     bool
	stale     bool // fired more than receiptMaxAge ago
}

// receiptRules is the first-prompt receipt's step table, walked top-down.
var receiptRules = []struct {
	name string
	when func(receiptFacts) bool
	step receiptStep
}{
	{"no state file: never armed, never shown", func(f receiptFacts) bool { return f.stateless }, receiptNone},
	{"dismissed: done for good", func(f receiptFacts) bool { return f.dismissed }, receiptNone},
	{"first ribbon read: arm", func(f receiptFacts) bool { return !f.armed }, receiptArm},
	{"armed, not fired: look for the first new session", func(f receiptFacts) bool { return !f.fired }, receiptTryFire},
	{"fired long ago and never seen: retired", func(f receiptFacts) bool { return f.stale }, receiptNone},
	{"fired, not dismissed: show", func(receiptFacts) bool { return true }, receiptShow},
}

func receiptStepFor(f receiptFacts) receiptStep {
	for _, r := range receiptRules {
		if r.when(f) {
			return r.step
		}
	}
	return receiptNone
}

// receiptFactsOf reads the step table's inputs from the persisted state.
func receiptFactsOf(st firstrunstate.State, stateless bool, now time.Time) receiptFacts {
	f := receiptFacts{stateless: stateless}
	_, f.dismissed = st.Dismissed[ribbonReceiptKey]
	if st.Receipt != nil {
		f.armed = true
		if st.Receipt.FiredAt != nil {
			f.fired = true
			f.stale = now.Sub(*st.Receipt.FiredAt) > receiptMaxAge
		}
	}
	return f
}

// receiptCandidate picks the session the receipt fires for: of the live
// sessions that STARTED at or after the arm time, the earliest-started one
// that has a turn, or, for a tool that keeps no tokens, an action.
func receiptCandidate(sessions []ribbonSession, armedAt time.Time) (ribbonSession, bool) {
	var best ribbonSession
	var bestStart time.Time
	found := false
	for _, rs := range sessions {
		started, err := time.Parse(time.RFC3339Nano, rs.StartedAt)
		if err != nil || started.Before(armedAt) {
			continue
		}
		ready := rs.Turns > 0 || (!rs.CostRecorded && rs.ActionsTotal > 0)
		if !ready {
			continue
		}
		if !found || started.Before(bestStart) {
			best, bestStart, found = rs, started, true
		}
	}
	return best, found
}

// ribbonReceipt applies the step table and returns the receipt to show, or
// nil. Every failure here is quiet: the receipt is a nicety.
func (s *Server) ribbonReceipt(ctx context.Context, sessions []ribbonSession, now time.Time) *ribbonReceipt {
	store := s.firstRunState()
	st := store.Load()
	stateless := firstrunstate.Path(s.opts.DBPath) == ""
	switch receiptStepFor(receiptFactsOf(st, stateless, now)) {
	case receiptArm:
		_, _ = store.ArmReceipt(now)
		return nil
	case receiptTryFire:
		cand, ok := receiptCandidate(sessions, st.Receipt.ArmedAt)
		if !ok {
			return nil
		}
		rec := s.receiptFor(ctx, cand)
		body, err := json.Marshal(rec)
		if err != nil {
			return nil
		}
		st2, err := store.FireReceipt(cand.SessionID, body, now)
		if err != nil || st2.Receipt == nil || st2.Receipt.FiredAt == nil {
			return nil
		}
		return decodeReceipt(st2.Receipt)
	case receiptShow:
		return decodeReceipt(st.Receipt)
	default:
		return nil
	}
}

// receiptFor builds the receipt summary for one session: its ribbon numbers
// plus how many files it read, edits it made and commands it ran.
func (s *Server) receiptFor(ctx context.Context, rs ribbonSession) ribbonReceipt {
	rec := ribbonReceipt{
		SessionID: rs.SessionID, Tool: rs.Tool, Project: rs.Project, Model: rs.Model,
		Tokens: rs.Tokens, CostUSD: rs.CostUSD, CostEstimated: rs.CostEstimated,
		CostRecorded: rs.CostRecorded, PriceUnknown: rs.PriceUnknown, Turns: rs.Turns,
	}
	rows, err := s.db().QueryContext(ctx,
		`SELECT action_type, COUNT(*) FROM actions WHERE session_id = ? GROUP BY action_type`, rs.SessionID)
	if err != nil {
		return rec
	}
	defer rows.Close()
	for rows.Next() {
		var typ string
		var n int64
		if rows.Scan(&typ, &n) != nil {
			continue
		}
		switch typ {
		case models.ActionReadFile:
			rec.FilesRead += n
		case models.ActionEditFile, models.ActionWriteFile:
			rec.Edits += n
		case models.ActionRunCommand:
			rec.Commands += n
		}
	}
	_ = rows.Err()
	return rec
}

// decodeReceipt reads a fired receipt's persisted summary back, stamping its
// fire time. A body that no longer decodes shows nothing.
func decodeReceipt(r *firstrunstate.Receipt) *ribbonReceipt {
	if r == nil || r.FiredAt == nil || len(r.Body) == 0 {
		return nil
	}
	var rec ribbonReceipt
	if json.Unmarshal(r.Body, &rec) != nil || rec.SessionID == "" {
		return nil
	}
	rec.FiredAt = r.FiredAt.UTC().Format(time.RFC3339)
	return &rec
}
