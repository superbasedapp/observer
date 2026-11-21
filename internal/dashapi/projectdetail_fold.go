package dashapi

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/intelligence/cost"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/projectroi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Project figures fold the cloud twin (cloud-agents lane CA-C1, decision
// CA-D21; plan docs/plans/cloud-agents/cloud-agents-implementation-plan-
// 2026-10-31.md section 10). A remote-only cloud session lives under the
// synthetic project "cloud:<normalized remote>" until a local checkout of the
// same remote exists (CA-D3); from then on store.CloudProjectTwins pairs the
// two. LoadFoldedProjectSpend is the ONE place a project's spend picks up its
// twin: the Overview Spend tile, the Spend tab, the "Where it ran" lane and
// the CLI all read it, so they cannot disagree about which sessions a total
// covers. Nothing is merged in the store.

// FoldedProject names one project whose rows a folded figure includes.
type FoldedProject struct {
	ID       int64  `json:"id"`
	RootPath string `json:"root_path"`
	// Synthetic is true for a "cloud:<remote>" project (CA-D3).
	Synthetic bool `json:"synthetic,omitempty"`
}

// FoldedProjectSpend is a project's priced spend with its synthetic cloud
// twins folded in and duplicates across capture rails resolved by the CA-D12
// token precedence (internal/cloudlane SupersededTurns).
type FoldedProjectSpend struct {
	// All is the requested project plus every folded twin: what the Spend
	// tile, the Spend tab and the location split total.
	All projectSpend
	// Own is the requested project's rows only (with the same precedence
	// applied). The prompt-to-commit ROI proxies read these: a twin has no
	// local checkout, so none of its sessions can link to a commit.
	Own projectSpend
	// Projects lists the requested project first, then each folded twin.
	Projects []FoldedProject
	// Locations maps a session id to its stored execution_location, for
	// stamped sessions only (absent is the honest unknown, never local).
	Locations map[string]string
	// SupersededTurns counts turns a better tier on the same session
	// replaced (kept as evidence, never summed).
	SupersededTurns int
}

// HasTwins reports whether a synthetic cloud project is folded in.
func (f FoldedProjectSpend) HasTwins() bool { return len(f.Projects) > 1 }

// HasOffMachine reports whether any window session ran off this machine.
func (f FoldedProjectSpend) HasOffMachine() bool {
	for _, s := range f.All.Sessions {
		if cloudlane.OffMachine(f.Locations[s.ID]) {
			return true
		}
	}
	return false
}

// ShowsSplit reports whether the location split is worth sending: a twin is
// folded in or a session ran off this machine. A project that only ever ran
// here (or was never stamped) gets no split, so its payload is unchanged.
func (f FoldedProjectSpend) ShowsSplit() bool { return f.HasTwins() || f.HasOffMachine() }

// LoadFoldedProjectSpend loads projectID's spend for [since, until) through
// LoadProjectSpend, folds in each synthetic cloud twin
// (store.CloudProjectTwins, local project = projectID), and drops the turns
// the CA-D12 precedence supersedes on sessions that ran off this machine.
// With no twin and no off-machine session the result's All and Own are
// exactly LoadProjectSpend's.
func LoadFoldedProjectSpend(ctx context.Context, st *store.Store, engine *cost.Engine, projectID int64, since, until time.Time) (FoldedProjectSpend, error) {
	projects, err := foldedProjects(ctx, st, projectID)
	if err != nil {
		return FoldedProjectSpend{}, err
	}
	out := FoldedProjectSpend{Projects: projects, Locations: map[string]string{}}

	var turns []foldTurn
	var sessions []projectroi.Session
	ownSession := map[string]bool{}
	var first projectSpend
	for i, p := range out.Projects {
		sp, err := LoadProjectSpend(ctx, st, engine, p.ID, since, until)
		if err != nil {
			return FoldedProjectSpend{}, fmt.Errorf("dashapi.LoadFoldedProjectSpend: spend %d: %w", p.ID, err)
		}
		if i == 0 {
			first = sp
		}
		for _, t := range sp.Turns {
			turns = append(turns, foldTurn{t: t, own: i == 0})
		}
		for _, s := range sp.Sessions {
			if _, seen := ownSession[s.ID]; seen {
				continue // a session row belongs to one project; never count it twice
			}
			ownSession[s.ID] = i == 0
			sessions = append(sessions, s)
		}
	}

	offIDs, err := loadFoldLocations(ctx, st, sessions, out.Locations)
	if err != nil {
		return FoldedProjectSpend{}, err
	}
	if !out.HasTwins() && len(offIDs) == 0 {
		// Nothing to fold: the figures are LoadProjectSpend's, untouched.
		out.All, out.Own = first, first
		return out, nil
	}
	dropped, err := supersededFoldTurns(ctx, st, turns, offIDs, out.Locations)
	if err != nil {
		return FoldedProjectSpend{}, err
	}

	var allTurns, ownTurns []projectroi.Turn
	for i, tt := range turns {
		if dropped[i] {
			out.SupersededTurns++
			continue
		}
		allTurns = append(allTurns, tt.t)
		if tt.own {
			ownTurns = append(ownTurns, tt.t)
		}
	}
	var ownSessions []projectroi.Session
	for _, s := range sessions {
		if ownSession[s.ID] {
			ownSessions = append(ownSessions, s)
		}
	}
	out.All = pricedSpend(allTurns, sessions)
	out.Own = pricedSpend(ownTurns, ownSessions)
	return out, nil
}

// foldTurn is one loaded turn and whether it belongs to the requested
// project (rather than a folded twin).
type foldTurn struct {
	t   projectroi.Turn
	own bool
}

// foldedProjects is the requested project followed by every synthetic cloud
// project store.CloudProjectTwins pairs with it (local id = projectID).
func foldedProjects(ctx context.Context, st *store.Store, projectID int64) ([]FoldedProject, error) {
	meta, ok, err := st.LoadProjectMeta(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("dashapi.LoadFoldedProjectSpend: project meta: %w", err)
	}
	out := []FoldedProject{{ID: projectID}}
	if ok {
		out[0] = FoldedProject{ID: projectID, RootPath: meta.RootPath, Synthetic: models.IsSyntheticCloudProjectRoot(meta.RootPath)}
	}
	twins, err := st.CloudProjectTwins(ctx)
	if err != nil {
		return nil, fmt.Errorf("dashapi.LoadFoldedProjectSpend: twins: %w", err)
	}
	for _, p := range twins {
		if p.LocalID != projectID {
			continue
		}
		tm, found, err := st.LoadProjectMeta(ctx, p.SyntheticID)
		if err != nil {
			return nil, fmt.Errorf("dashapi.LoadFoldedProjectSpend: twin meta: %w", err)
		}
		if found {
			out = append(out, FoldedProject{ID: p.SyntheticID, RootPath: tm.RootPath, Synthetic: true})
		}
	}
	return out, nil
}

// loadFoldLocations fills locations with every stamped session's
// execution_location and returns the ids that ran off this machine.
func loadFoldLocations(ctx context.Context, st *store.Store, sessions []projectroi.Session, locations map[string]string) ([]string, error) {
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = s.ID
	}
	execs, err := st.LoadSessionExecutions(ctx, ids)
	if err != nil {
		return nil, fmt.Errorf("dashapi.LoadFoldedProjectSpend: executions: %w", err)
	}
	var offIDs []string
	for id, ex := range execs {
		if ex.ExecutionLocation == "" {
			continue
		}
		locations[id] = ex.ExecutionLocation
		if cloudlane.OffMachine(ex.ExecutionLocation) {
			offIDs = append(offIDs, id)
		}
	}
	return offIDs, nil
}

// supersededFoldTurns runs the CA-D12 precedence over turns (same index):
// each transcript-path turn's rail comes from its token_usage.source, looked
// up by its TurnID (the row's source_event_id).
func supersededFoldTurns(ctx context.Context, st *store.Store, turns []foldTurn, offIDs []string, locations map[string]string) ([]bool, error) {
	if len(offIDs) == 0 {
		return make([]bool, len(turns)), nil
	}
	sources, err := st.LoadTokenSources(ctx, offIDs)
	if err != nil {
		return nil, fmt.Errorf("dashapi.LoadFoldedProjectSpend: token sources: %w", err)
	}
	fold := make([]cloudlane.FoldTurn, len(turns))
	for i, tt := range turns {
		src := tt.t.Source
		if src == "jsonl" {
			if s, ok := sources[store.TokenSourceKey{SessionID: tt.t.SessionID, SourceEventID: tt.t.TurnID}]; ok {
				src = s
			}
		}
		fold[i] = cloudlane.FoldTurn{SessionID: tt.t.SessionID, TokenSource: src}
	}
	return cloudlane.SupersededTurns(fold, func(sid string) bool { return cloudlane.OffMachine(locations[sid]) }), nil
}

// LoadTwinAIEdits loads the AI edits of every folded twin (not the requested
// project) for the per-session code/comment split, so a twin session's row
// never reads a 0 that only means "not loaded". truncated reports a cap hit.
func LoadTwinAIEdits(ctx context.Context, st *store.Store, f FoldedProjectSpend, since, until time.Time) ([]projectroi.Edit, bool, error) {
	var out []projectroi.Edit
	truncated := false
	for _, p := range f.Projects[1:] {
		te, tTrunc, err := st.LoadProjectAIEdits(ctx, p.ID, since, until, EditLinkCap)
		if err != nil {
			return nil, false, fmt.Errorf("dashapi.LoadTwinAIEdits: %w", err)
		}
		out = append(out, te...)
		truncated = truncated || tTrunc
	}
	return out, truncated, nil
}

// twinSessionInputs adds the folded twins' prompt counts to promptCounts and
// returns the edits the per-session rows read (the project's own plus the
// twins'). The prompt-to-commit linkage keeps reading the own edits only.
func twinSessionInputs(ctx context.Context, st *store.Store, f FoldedProjectSpend, since, until time.Time, promptCounts map[string]int, edits []projectroi.Edit) (map[string]int, []projectroi.Edit, error) {
	if !f.HasTwins() {
		return promptCounts, edits, nil
	}
	if promptCounts == nil {
		promptCounts = map[string]int{}
	}
	for _, p := range f.Projects[1:] {
		pc, err := st.LoadProjectPromptCounts(ctx, p.ID, since, until)
		if err != nil {
			return nil, nil, fmt.Errorf("dashapi.twinSessionInputs: prompt counts: %w", err)
		}
		for sid, n := range pc {
			promptCounts[sid] += n
		}
	}
	twinEdits, _, err := LoadTwinAIEdits(ctx, st, f, since, until)
	if err != nil {
		return nil, nil, err
	}
	return promptCounts, append(append([]projectroi.Edit(nil), edits...), twinEdits...), nil
}

// pricedSpend rebuilds a projectSpend over kept turns: the unpriced count
// and each session's cost are recomputed from exactly those turns, the same
// rules LoadProjectSpend applies.
func pricedSpend(turns []projectroi.Turn, sessions []projectroi.Session) projectSpend {
	out := projectSpend{Turns: turns, Sessions: make([]projectroi.Session, len(sessions))}
	costBySession := make(map[string]float64, len(sessions))
	for _, t := range turns {
		if !t.Priced {
			out.UnpricedTurns++
		}
		if t.SessionID != "" {
			costBySession[t.SessionID] += t.CostUSD
		}
	}
	for i, s := range sessions {
		s.CostUSD = costBySession[s.ID]
		out.Sessions[i] = s
	}
	return out
}

// LocationLaneInput is the cloudlane input for f: every folded session with
// its location, every kept turn, and the provider ledger rows of the
// off-machine sessions (capped at ledgerCap; truncated says the cap cut
// them). Connector accounts are the caller's to add.
func LocationLaneInput(ctx context.Context, st *store.Store, f FoldedProjectSpend, ledgerCap int) (cloudlane.Input, bool, error) {
	var in cloudlane.Input
	var offIDs []string
	for _, s := range f.All.Sessions {
		loc := f.Locations[s.ID]
		in.Sessions = append(in.Sessions, cloudlane.Session{ID: s.ID, Location: loc})
		if cloudlane.OffMachine(loc) {
			offIDs = append(offIDs, s.ID)
		}
	}
	for _, t := range f.All.Turns {
		in.Turns = append(in.Turns, cloudlane.Turn{
			SessionID: t.SessionID, Input: t.Input, Output: t.Output, CacheRead: t.CacheRead,
			CacheCreation: t.CacheCreation, Reasoning: t.Reasoning,
			CostUSD: t.CostUSD, Priced: t.Priced, Source: t.Source,
		})
	}
	// Provider ledger figures exist only for sessions a connector pulled, so
	// only off-machine sessions are looked up.
	if len(offIDs) == 0 {
		return in, false, nil
	}
	entries, truncated, err := st.ListCloudUsageForSessions(ctx, offIDs, ledgerCap)
	if err != nil {
		return cloudlane.Input{}, false, fmt.Errorf("dashapi.LocationLaneInput: ledger: %w", err)
	}
	for _, e := range entries {
		in.Ledger = append(in.Ledger, cloudlane.LedgerEntry{
			ID: e.ID, SupersedesID: e.SupersedesID, SessionID: e.ScopeSession,
			Connector: e.Connector, Unit: e.Unit, ValueType: e.ValueType,
			MeasurementSource: e.MeasurementSource, MonetaryStatus: e.MonetaryStatus,
			Value: e.Value, ReportedAt: e.ReportedAt,
		})
	}
	return in, truncated, nil
}

// ProjectLedgerCap bounds the ledger rows one project read takes. A hit is
// reported as ledger_truncated so a capped figure never reads as complete.
const ProjectLedgerCap = 5000

// APIProjectSpendLocations is the Spend figures' local/cloud split
// (apiProjectDetailSpend.Locations). Its buckets come from the same folded
// rows as total_usd, so the bucket dollars add up to it; a bucket's missing
// figure is absent (never 0) and every figure carries a coverage value.
// Provider ledger figures stay in their own unit beside the dollars (CA-D11).
type APIProjectSpendLocations struct {
	Buckets []cloudlane.Bucket `json:"buckets"`
	// Folded lists the synthetic cloud projects folded into the totals.
	Folded []FoldedProject `json:"folded,omitempty"`
	// SupersededTurns counts turns the CA-D12 precedence set aside because a
	// better rail reported the same session.
	SupersededTurns int  `json:"superseded_turns,omitempty"`
	LedgerTruncated bool `json:"ledger_truncated,omitempty"`
}

// buildSpendLocations is the split for f, or nil when f shows none.
func buildSpendLocations(ctx context.Context, st *store.Store, f FoldedProjectSpend) (*APIProjectSpendLocations, error) {
	if !f.ShowsSplit() {
		return nil, nil
	}
	in, truncated, err := LocationLaneInput(ctx, st, f, ProjectLedgerCap)
	if err != nil {
		return nil, err
	}
	lane := cloudlane.Build(in)
	out := &APIProjectSpendLocations{Buckets: lane.Buckets, SupersededTurns: f.SupersededTurns, LedgerTruncated: truncated}
	if f.HasTwins() {
		out.Folded = append([]FoldedProject(nil), f.Projects[1:]...)
	}
	return out, nil
}

// twinCaveat is appended to every dollar-denominated ROI tile when a cloud
// twin is folded into the Spend total, so the tile and the total never
// silently cover different sessions.
const twinCaveat = "Cloud sessions filed under the folded cloud project are counted in the Spend total but not here: with no local checkout, they cannot link to a commit."

// stampTwinCaveat names the folded twin on the ROI tiles whose value is in
// dollars (unit "usd" or "usd_per_*"), the only ones the Spend total feeds.
// The note is a sentence of its own after any existing caveat.
func stampTwinCaveat(tiles []apiProjectRoiTile) {
	for i := range tiles {
		u := tiles[i].Unit
		if u != "usd" && !strings.HasPrefix(u, "usd_") {
			continue
		}
		c := strings.TrimSpace(tiles[i].Caveat)
		switch {
		case c == "":
			tiles[i].Caveat = twinCaveat
		case strings.HasSuffix(c, "."):
			tiles[i].Caveat = c + " " + twinCaveat
		default:
			tiles[i].Caveat = c + ". " + twinCaveat
		}
	}
}

// withSessionLocations stamps each per-session row with where it ran (the
// Spend tab's Ran column). A session nothing stamped keeps "" (unknown).
func withSessionLocations(rows []apiProjectSpendBySession, locations map[string]string) []apiProjectSpendBySession {
	for i := range rows {
		rows[i].ExecutionLocation = locations[rows[i].ID]
	}
	return rows
}

// locationWord is the CLI's plain word per bucket (the web's
// ExecutionLocationBadge labels).
var locationWord = map[string]string{
	models.ExecutionLocal:          "local",
	models.ExecutionVendorCloud:    "cloud",
	models.ExecutionCustomerWorker: "worker",
	cloudlane.LocationUnknown:      "unknown",
}

// coverageNote is the CLI's word for a dollar figure's coverage.
var coverageNote = map[cloudlane.Coverage]string{
	cloudlane.CoverageFull:    "",
	cloudlane.CoveragePartial: " (partial)",
	cloudlane.CoverageNone:    " (not priced)",
	cloudlane.CoverageUnknown: " (not reported)",
}

// SpendSplitLines renders the location split as plain lines for the
// `observer project` CLI: dollars per location, provider usage in its own
// unit beside them, the folded twins and any superseded turns. A missing
// figure reads "not reported", never $0.00. Nil in, nil out.
func SpendSplitLines(loc *APIProjectSpendLocations) []string {
	if loc == nil {
		return nil
	}
	var parts, usage []string
	for _, b := range loc.Buckets {
		word := locationWord[b.Location]
		if word == "" {
			word = b.Location
		}
		if b.CostUSD == nil {
			parts = append(parts, word+" not reported")
		} else {
			// no-bare-usd:allow (printed only by `observer project`, a costReportCommands row whose stdout renders under the cost display)
			parts = append(parts, fmt.Sprintf("%s $%.2f%s", word, *b.CostUSD, coverageNote[b.CostCoverage]))
		}
		for _, f := range b.Ledger {
			usage = append(usage, fmt.Sprintf("%s %s %s (%s)", word, strconv.FormatFloat(f.Value, 'f', -1, 64), f.Unit, f.Connector))
		}
	}
	lines := []string{"where it ran: " + strings.Join(parts, ", ")}
	if len(usage) > 0 {
		lines = append(lines, "provider usage, own units (not in the dollar total): "+strings.Join(usage, ", "))
	}
	for _, p := range loc.Folded {
		lines = append(lines, "includes cloud project "+p.RootPath)
	}
	if loc.SupersededTurns > 0 {
		lines = append(lines, fmt.Sprintf("%d turns set aside: a better rail reported the same session", loc.SupersededTurns))
	}
	if loc.LedgerTruncated {
		lines = append(lines, "provider usage is partial: only the newest 5,000 reports were read")
	}
	return lines
}
