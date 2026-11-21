package dashboard

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudlane"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// "Where it ran" (cloud-agents arc, lane CA-B5; plan section 8 of
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md):
// the Sessions list filter on sessions.execution_location, the per-project
// cloud lane, and the Projects list's synthetic-cloud-project grouping. The
// columns are written only by store.SetSessionExecution; everything here
// reads.

// executionFilterUnknown is the filter value for sessions nothing stamped a
// location on (the NULL column). It is a filter value, not a vocabulary
// entry: models.KnownExecutionLocation rejects it.
const executionFilterUnknown = "unknown"

// executionFilterSQL is the one table the `execution_location` list filter
// dispatches on: a row per accepted value, each a fixed SQL fragment over the
// sessions alias `s`. A vocabulary value matches exactly; "unknown" matches
// the NULL column. Anything else is absent from the table and FAILS OPEN to
// no filter (the surface filter's rule: a stale bookmark still renders the
// list, never a 400 and never "match nothing").
var executionFilterSQL = func() map[string]string {
	m := map[string]string{executionFilterUnknown: "s.execution_location IS NULL"}
	for _, loc := range models.ExecutionLocations() {
		m[loc] = "s.execution_location = '" + loc + "'"
	}
	return m
}()

// sessionExecutionFilter resolves the `execution_location=<value>` query
// param of GET /api/sessions to a WHERE fragment, or "" for no filter.
// Matching is case-insensitive on input; the stored value is lowercase by
// construction (SetSessionExecution validates against the vocabulary).
func sessionExecutionFilter(r *http.Request) string {
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("execution_location")))
	return executionFilterSQL[v]
}

// cloudLaneLedgerCap bounds the ledger rows one lane request reads. A hit is
// reported as ledger_truncated so a capped figure never reads as complete.
const cloudLaneLedgerCap = dashapi.ProjectLedgerCap

// apiCloudLaneProject names one project whose sessions the lane covers.
type apiCloudLaneProject struct {
	ID       int64  `json:"id"`
	RootPath string `json:"root_path"`
	// Synthetic is true for a "cloud:<remote>" project (CA-D3): a remote-only
	// session's home until a local checkout of the same remote appears.
	Synthetic bool `json:"synthetic,omitempty"`
}

// apiCloudLaneResponse is GET /api/project/{id}/cloud.
type apiCloudLaneResponse struct {
	cloudlane.Lane
	// Projects lists every project folded into this lane: the requested one
	// first, then each synthetic cloud twin with the same normalized remote.
	Projects []apiCloudLaneProject `json:"projects"`
	// FoldedInto is set when the requested project is itself a synthetic
	// cloud project that now has a local twin: the lane for both lives on
	// that project, and the page links there.
	FoldedInto      *apiCloudLaneProject `json:"folded_into,omitempty"`
	LedgerTruncated bool                 `json:"ledger_truncated,omitempty"`
	// SupersededTurns counts turns the CA-D12 precedence set aside because a
	// better rail reported the same session (lane CA-C1).
	SupersededTurns int    `json:"superseded_turns,omitempty"`
	Since           string `json:"since"`
	Until           string `json:"until"`
	WindowDays      int    `json:"window_days"`
}

// cloudTwinIndex is the Projects page's view of store.CloudProjectTwins:
// which synthetic projects fold under which local project.
type cloudTwinIndex struct {
	twinsOf    map[int64][]int64 // local id -> synthetic ids
	foldedInto map[int64]int64   // synthetic id -> local id
}

func loadCloudTwinIndex(ctx context.Context, st *store.Store) (cloudTwinIndex, error) {
	pairs, err := st.CloudProjectTwins(ctx)
	if err != nil {
		return cloudTwinIndex{}, err
	}
	idx := cloudTwinIndex{twinsOf: map[int64][]int64{}, foldedInto: map[int64]int64{}}
	for _, p := range pairs {
		idx.twinsOf[p.LocalID] = append(idx.twinsOf[p.LocalID], p.SyntheticID)
		idx.foldedInto[p.SyntheticID] = p.LocalID
	}
	return idx, nil
}

// handleProjectCloudLane serves GET /api/project/{id}/cloud?days=N: the
// project's sessions, tokens, dollars and provider ledger figures bucketed
// by where each session ran, each figure with its coverage. Tokens and
// dollars come from the SAME folded per-turn pipeline as the Overview Spend
// tile and the Spend tab (dashapi.LoadFoldedProjectSpend, lane CA-C1), so
// the lane's buckets add up to their total for the same window, folded
// cloud twins included (named in Projects); the lane never prices anything.
func (s *Server) handleProjectCloudLane(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	meta, ok := requireProject(ctx, w, r, st, projectID)
	if !ok {
		return
	}
	since, until, days := projectDetailWindow(r)

	twins, err := loadCloudTwinIndex(ctx, st)
	if err != nil {
		writeErr(w, err)
		return
	}
	resp := apiCloudLaneResponse{
		Since: since.UTC().Format(time.RFC3339), Until: until.UTC().Format(time.RFC3339), WindowDays: days,
	}
	if local, folded := twins.foldedInto[projectID]; folded {
		if lm, found, err := st.LoadProjectMeta(ctx, local); err == nil && found {
			resp.FoldedInto = &apiCloudLaneProject{ID: local, RootPath: lm.RootPath}
		}
	}
	// The lane reads the SAME folded spend as the Overview Spend tile and the
	// Spend tab (dashapi.LoadFoldedProjectSpend: the project plus its cloud
	// twins, CA-D12 precedence applied), so its buckets add up to their total.
	folded, err := dashapi.LoadFoldedProjectSpend(ctx, st, s.opts.CostEngine, projectID, since, until)
	if err != nil {
		writeErr(w, err)
		return
	}
	for i, p := range folded.Projects {
		root := p.RootPath
		if i == 0 {
			root = meta.RootPath
		}
		resp.Projects = append(resp.Projects, apiCloudLaneProject{
			ID: p.ID, RootPath: root, Synthetic: models.IsSyntheticCloudProjectRoot(root),
		})
	}
	resp.SupersededTurns = folded.SupersededTurns
	in, truncated, err := dashapi.LocationLaneInput(ctx, st, folded, cloudLaneLedgerCap)
	if err != nil {
		writeErr(w, err)
		return
	}
	resp.LedgerTruncated = truncated
	accounts, err := st.ListCloudConnectorAccounts(ctx, "")
	if err != nil {
		writeErr(w, err)
		return
	}
	for _, a := range accounts {
		// The display e-mail and account id stay off this payload: the badge
		// needs only which connector and how complete its collection is.
		in.Accounts = append(in.Accounts, cloudlane.Account{
			Connector: a.Connector, Provider: a.Provider,
			CoverageState: a.CoverageState, LastErrorClass: a.LastErrorClass,
		})
	}

	resp.Lane = cloudlane.Build(in)
	writeJSON(w, resp)
}

// attachProjectExecution fills the Projects list's where-it-ran fields on
// rows: each project's execution mix (only for a project with a stamped
// session) and the synthetic-twin pairing from store.CloudProjectTwins (the
// one merge rule of plan section 4.3). fields returns pointers to one row's
// id and the three fields, so the list's row type stays local to its
// handler. Read-only: nothing is merged or rewritten in the store.
func attachProjectExecution[T any](ctx context.Context, st *store.Store, rows []T,
	fields func(*T) (id int64, mix *map[string]int, twinOf *int64, twins *[]int64),
) error {
	mixes, err := st.LoadProjectExecutionMix(ctx)
	if err != nil {
		return err
	}
	twins, err := loadCloudTwinIndex(ctx, st)
	if err != nil {
		return err
	}
	for i := range rows {
		id, mix, twinOf, twinList := fields(&rows[i])
		if m, ok := mixes[id]; ok {
			out := make(map[string]int, len(m))
			for loc, n := range m {
				key := loc
				if key == "" {
					key = executionFilterUnknown
				}
				out[key] += n
			}
			*mix = out
		}
		*twinOf = twins.foldedInto[id]
		*twinList = twins.twinsOf[id]
	}
	return nil
}
