package dashboard

import (
	"net/http"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// sandboxRefusalsPage is the response of GET /api/sandbox/refusals.
// NextBefore, when non-zero, is the before value of the next (older) page.
// Dropped maps each run of the page (and the run_id filter) to the
// refusals dropped before they could be written (lane OC, audit findings
// O3-W2 and OC-A2), and Uncertain to the refusals that may be the run's,
// dropped while its box id was not recorded yet and the box they claimed
// was not remembered (audit finding OC-A1; counted against every run
// waiting for its box id then, so it can over-count): a run listed in
// either is incomplete even when its rows look whole; a run absent from
// both dropped none.
type sandboxRefusalsPage struct {
	Refusals   []store.SandboxEgressRefusal `json:"refusals"`
	NextBefore int64                        `json:"next_before,omitempty"`
	Dropped    map[string]int               `json:"dropped,omitempty"`
	Uncertain  map[string]int               `json:"uncertain,omitempty"`
	// LinkLost maps a run to the part of its dropped count its host helper
	// could not send to the daemon (the link down, or the daemon busy), and
	// EgressClosed to the new requests refused while its link was down
	// under require_refusal_audit (tracker F-012, audit findings N4-A4 and
	// FU5-A4; migration 233). Absent for a run with none.
	LinkLost     map[string]int `json:"link_lost,omitempty"`
	EgressClosed map[string]int `json:"egress_closed,omitempty"`
	// Evicted maps a run to its oldest rows removed to keep it under the
	// per-run total bound (store.SandboxEgressRefusalMaxPerRun; tracker
	// F-009, audit finding N1-A4). Absent for a run under the bound.
	Evicted map[string]int `json:"evicted,omitempty"`
}

// handleSandboxRefusals serves GET /api/sandbox/refusals (OpenShell build
// plan 05 section 3.1, lane N1): the sandbox egress refusal audit, newest
// first, one bounded page. Filters: run_id (the stored terminal run, or
// the relay run of a run with no stored row) and project (the run's
// project root, exact); both may be given. Paging: limit (default
// store.SandboxEgressRefusalDefaultPage, capped at
// store.SandboxEgressRefusalMaxPage) and before (the next_before of the
// previous page). LOCAL-ONLY (registered with the Local class): the rows
// name the hosts a sandboxed agent tried to reach and the project root,
// the same disclosure class as /api/terminal/sandbox/config. It is a read
// of the one store seam (internal/store/sandboxegress.go) and never
// writes.
func (s *Server) handleSandboxRefusals(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	limit := intArg(r, "limit", store.SandboxEgressRefusalDefaultPage, 1, store.SandboxEgressRefusalMaxPage)
	var before int64
	if raw := q.Get("before"); raw != "" {
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			http.Error(w, "before must be a non-negative integer", http.StatusBadRequest)
			return
		}
		before = n
	}
	rows, err := store.New(s.db()).ListSandboxEgressRefusals(r.Context(), store.SandboxEgressRefusalQuery{
		RunID: q.Get("run_id"), ProjectRoot: q.Get("project"), Before: before, Limit: limit,
	})
	if err != nil {
		writeErr(w, err)
		return
	}
	page := sandboxRefusalsPage{Refusals: rows}
	if len(rows) == limit {
		page.NextBefore = rows[len(rows)-1].ID
	}
	runs := []string{q.Get("run_id")}
	for _, row := range rows {
		runs = append(runs, row.RunID)
	}
	dropped, err := store.New(s.db()).SandboxEgressRefusalDrops(r.Context(), runs)
	if err != nil {
		writeErr(w, err)
		return
	}
	for run, d := range dropped {
		if d.Dropped > 0 {
			if page.Dropped == nil {
				page.Dropped = map[string]int{}
			}
			page.Dropped[run] = d.Dropped
		}
		if d.Uncertain > 0 {
			if page.Uncertain == nil {
				page.Uncertain = map[string]int{}
			}
			page.Uncertain[run] = d.Uncertain
		}
		if d.LinkLost > 0 {
			if page.LinkLost == nil {
				page.LinkLost = map[string]int{}
			}
			page.LinkLost[run] = d.LinkLost
		}
		if d.EgressClosed > 0 {
			if page.EgressClosed == nil {
				page.EgressClosed = map[string]int{}
			}
			page.EgressClosed[run] = d.EgressClosed
		}
		if d.Evicted > 0 {
			if page.Evicted == nil {
				page.Evicted = map[string]int{}
			}
			page.Evicted[run] = d.Evicted
		}
	}
	writeJSON(w, page)
}
