package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/componentsvc"
	"github.com/marmutapp/superbased-observer/internal/feasibility"
	"github.com/marmutapp/superbased-observer/internal/feasibility/nodefeas"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// components_manage.go is the dashboard side of the component gate (modular
// packaging plan section 7, phase P1, lane MP-DASH): the route guard that
// answers 404 component_not_installed for a route of an inactive component,
// and the Settings > Components API over the one writer internal/componentsvc
// (the same service `observer components` runs, so the page and the CLI
// cannot disagree).
//
// The guard is a no-op until a ComponentsService is wired, and an install
// with no [components] block resolves every compiled component active, so an
// existing install answers every route exactly as before.

// coreComponent is the owner of every route no optional component claims.
const coreComponent = "core"

// routePrefixOwners is the merged prefix table: every node component's
// catalog Routes (the one owner of route ownership: the dashboard's former
// override table was folded into the catalog, T-670), then each command
// job's route owned by the component that owns the verb the job spawns.
// Longest prefix wins, so a catalog row can carve a sub-route out of
// another row's prefix (terminals.ssh's /api/terminal/ssh under terminals'
// /api/terminal). Every prefix is pinned by
// TestRoutePrefixOwnersAreRegistered, so a stale one fails loudly.
// Built once; the catalog is static.
var routePrefixOwners = sync.OnceValue(func() map[string]string {
	out := map[string]string{}
	verbOwner := map[string]string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		for _, r := range c.Routes {
			out[strings.TrimSuffix(r, "/")] = c.ID
		}
		if c.Class == components.ClassCore {
			continue
		}
		for _, v := range c.Verbs {
			verbOwner[v] = c.ID
		}
	}
	// A command job runs `observer <verb> ...`, which the CLI verb gate
	// refuses (exit 3) while the verb's component is inactive. Owning the
	// job route by the same component answers 404 component_not_installed
	// before a subprocess starts, so the page and the CLI agree (T-671:
	// e.g. the Security > MCP jobs belong to agentaccess.relay, the
	// pricing sync job to egress.pricing-feed). A job of a core verb stays
	// core.
	for name, job := range commandJobs {
		if len(job.argv) == 0 {
			continue
		}
		if id, ok := verbOwner[job.argv[0]]; ok {
			out["/api/jobs/"+name] = id
		}
	}
	return out
})

// routeComponent resolves the component a mux pattern belongs to: the
// longest owning prefix on a path-segment boundary, else core. A Go 1.22
// method prefix ("GET /x") and a {wildcard} tail do not change the owner.
func routeComponent(pattern string) string {
	path := strings.TrimSpace(pattern)
	if _, rest, ok := strings.Cut(path, " "); ok {
		path = strings.TrimSpace(rest)
	}
	owners := routePrefixOwners()
	best, bestLen := coreComponent, -1
	for prefix, id := range owners {
		if !pathHasPrefix(path, prefix) {
			continue
		}
		if len(prefix) > bestLen {
			best, bestLen = id, len(prefix)
		}
	}
	return best
}

// pathHasPrefix reports whether path is prefix or lies under it on a
// segment boundary ("/api/cache" owns "/api/cache/status", not
// "/api/cachewarm").
func pathHasPrefix(path, prefix string) bool {
	if prefix == "" {
		return false
	}
	if path == prefix || path == prefix+"/" {
		return true
	}
	return strings.HasPrefix(path, prefix+"/")
}

// componentCache holds the live component snapshot the guard consults and
// the set the daemon started with. The live snapshot is re-resolved at most
// once per componentCacheTTL (a hand edit of config.toml shows within that)
// and at once after a dashboard apply.
type componentCache struct {
	mu      sync.Mutex
	svc     ComponentsService
	snap    componentstate.Snapshot
	at      time.Time
	valid   bool
	started []string
	// startedKnown is false when no service was wired at start (the guard
	// is then off and no restart note is shown).
	startedKnown bool
}

const componentCacheTTL = 3 * time.Second

// recordStart binds the service and records the active set this process
// started with. A nil service leaves the cache off.
func (c *componentCache) recordStart(svc ComponentsService) {
	if svc == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.svc = svc
	if snap, err := svc.State(context.Background()); err == nil {
		c.started = snap.ActiveIDs()
		c.startedKnown = true
		c.snap, c.at, c.valid = snap, time.Now(), true
	}
}

// live returns the current snapshot. ok is false when no service is wired
// (the guard is off). A state that cannot be read resolves the legacy
// everything-active snapshot: the same fail-open posture as every other
// component gate on an unreadable config.
func (c *componentCache) live(ctx context.Context) (componentstate.Snapshot, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.svc == nil {
		return componentstate.Snapshot{}, false
	}
	if c.valid && time.Since(c.at) < componentCacheTTL {
		return c.snap, true
	}
	snap, err := c.svc.State(ctx)
	if err != nil {
		snap = componentstate.Legacy()
	}
	c.snap, c.at, c.valid = snap, time.Now(), true
	return snap, true
}

// invalidate drops the cached snapshot (after a dashboard apply).
func (c *componentCache) invalidate() {
	c.mu.Lock()
	c.valid = false
	c.mu.Unlock()
}

// componentGuard wraps a route's handler: while the route's component is
// not active it answers 404 with componentstate.NotActiveBody and never
// reaches the handler. Core routes, and every route while no service is
// wired, are returned unchanged.
func (s *Server) componentGuard(comp string, h http.HandlerFunc) http.HandlerFunc {
	if comp == coreComponent || comp == "" || s.opts.Components == nil {
		return h
	}
	return func(w http.ResponseWriter, r *http.Request) {
		snap, ok := s.comps.live(r.Context())
		if ok && !snap.Active(comp) {
			writeJSONStatus(w, http.StatusNotFound, snap.NotActive(comp))
			return
		}
		h(w, r)
	}
}

// componentsStateResponse is GET /api/components/state.
type componentsStateResponse struct {
	// Wired is false when this dashboard has no component service (the
	// standalone test harness, an embedder): the page then says so.
	Wired bool `json:"wired"`
	// View is the one state shape `observer components status --json` prints.
	View componentstate.View `json:"view"`
	// StartedActive is the active set the daemon started with; null when
	// unknown.
	StartedActive []string `json:"started_active"`
	// Pending lists components whose state differs from what the daemon
	// started with: their background work changes at the next restart.
	Pending []componentPending `json:"pending"`
	// InactiveRoutes are the registered API routes of inactive components
	// (the SPA skips those fetches, like concealed routes).
	InactiveRoutes []string `json:"inactive_routes"`
	// Purgeable lists the components with a reviewed purge plan.
	Purgeable []string `json:"purgeable"`
	// Feasibility is one verdict per component (D-514): an option that
	// cannot be chosen here carries the reason, the fix and the step, so
	// the page shows it disabled with the reason (internal/feasibility).
	Feasibility []feasibility.Verdict `json:"feasibility"`
	// SecuritySelected lists the security components (the root and its
	// children) this daemon's one opt-in rule selects
	// (Options.SecuritySelected, cmd/observer/security_optin.go): an
	// opt-in child is listed only when a [components] block names it, not
	// merely because it is compiled and active. The Code security Settings
	// card shows a child's rows only when it is listed. No rule wired lists
	// none (fail closed).
	SecuritySelected []string `json:"security_selected"`
}

// componentPending is one component whose live state differs from the
// daemon's start set.
type componentPending struct {
	ID string `json:"id"`
	// Change is "activate" or "deactivate".
	Change string `json:"change"`
}

func (s *Server) handleComponentsState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	resp := componentsStateResponse{Pending: []componentPending{}, InactiveRoutes: []string{}, Purgeable: []string{}}
	snap, ok := s.comps.live(r.Context())
	if !ok {
		// Not wired: report the legacy everything-active view so the page
		// can still list what this build contains.
		snap = componentstate.Legacy()
	}
	resp.Wired = ok
	resp.View = s.componentView(snap)
	resp.Feasibility = nodefeas.ComponentVerdicts(snap.Result.Decisions, snap.Selected)
	resp.SecuritySelected = []string{}
	for _, c := range components.ForBinary(components.BinaryNode) {
		if store.HasPurgePlan(c.ID) {
			resp.Purgeable = append(resp.Purgeable, c.ID)
		}
		if isSecurityComponent(c.ID) && s.opts.SecuritySelected != nil && s.opts.SecuritySelected(snap, c.ID) {
			resp.SecuritySelected = append(resp.SecuritySelected, c.ID)
		}
	}
	sort.Strings(resp.SecuritySelected)
	if ok {
		s.comps.mu.Lock()
		started, known := append([]string(nil), s.comps.started...), s.comps.startedKnown
		s.comps.mu.Unlock()
		if known {
			resp.StartedActive = started
			was := map[string]bool{}
			for _, id := range started {
				was[id] = true
			}
			now := map[string]bool{}
			for _, id := range snap.ActiveIDs() {
				now[id] = true
				if !was[id] {
					resp.Pending = append(resp.Pending, componentPending{ID: id, Change: "activate"})
				}
			}
			for _, id := range started {
				if !now[id] {
					resp.Pending = append(resp.Pending, componentPending{ID: id, Change: "deactivate"})
				}
			}
			sort.Slice(resp.Pending, func(i, j int) bool { return resp.Pending[i].ID < resp.Pending[j].ID })
		}
		if m := s.routeComponents.Load(); m != nil {
			for pattern, comp := range *m {
				if comp != coreComponent && !viewActive(resp.View, comp) {
					resp.InactiveRoutes = append(resp.InactiveRoutes, pattern)
				}
			}
			sort.Strings(resp.InactiveRoutes)
		}
	}
	writeJSON(w, resp)
}

// componentView is the component view the page shows: the daemon's view
// with the optional modules' own rules (Options.ComponentStateView, so a
// removed sandbox root and its drivers read as off, P-057), else core's.
func (s *Server) componentView(snap componentstate.Snapshot) componentstate.View {
	if s.opts.ComponentStateView != nil {
		return s.opts.ComponentStateView(snap)
	}
	return snap.View()
}

// viewActive reports whether id is active in v; an id the view does not
// list (a component outside this binary) is not.
func viewActive(v componentstate.View, id string) bool {
	for _, r := range v.Components {
		if r.ID == id {
			return r.State == components.StateActive
		}
	}
	return false
}

// isSecurityComponent reports whether id is the security module root or one
// of its children, the ids GET /api/components/state reports selection for.
func isSecurityComponent(id string) bool {
	return id == "security" || strings.HasPrefix(id, "security.")
}

// componentsOr503 returns the wired service, or answers 503 itself.
func (s *Server) componentsOr503(w http.ResponseWriter) ComponentsService {
	if s.opts.Components == nil {
		writeJSONStatus(w, http.StatusServiceUnavailable, map[string]string{
			"error":   "components_unavailable",
			"message": "This dashboard has no component service. Run `observer components` from a terminal, or open the dashboard of `observer start`.",
		})
		return nil
	}
	return s.opts.Components
}

// decodeComponentsBody reads a bounded JSON body into v, answering 400 on a
// malformed one.
func decodeComponentsBody(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": "malformed request body: " + err.Error()})
		return false
	}
	return true
}

// componentsChangeRequest is the body of preview and apply.
type componentsChangeRequest struct {
	Change componentsvc.Change `json:"change"`
	// Fingerprint (apply only) must equal the preview's fingerprint.
	Fingerprint string `json:"fingerprint"`
	// SkipTeardown (apply only) writes the selection and leaves every write
	// a deactivated component made in place.
	SkipTeardown bool `json:"skip_teardown"`
}

func (s *Server) handleComponentsPreview(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	svc := s.componentsOr503(w)
	if svc == nil {
		return
	}
	var req componentsChangeRequest
	if !decodeComponentsBody(w, r, &req) {
		return
	}
	p, err := svc.Preview(r.Context(), req.Change)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "preview_failed", "message": err.Error()})
		return
	}
	writeJSON(w, p)
}

func (s *Server) handleComponentsApply(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	svc := s.componentsOr503(w)
	if svc == nil {
		return
	}
	var req componentsChangeRequest
	if !decodeComponentsBody(w, r, &req) {
		return
	}
	// An apply always names the preview it confirms: the page never writes
	// a selection the operator did not see.
	if strings.TrimSpace(req.Fingerprint) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "fingerprint_required", "message": "preview the change first; apply names the preview's fingerprint"})
		return
	}
	res, err := svc.Apply(r.Context(), req.Change, componentsvc.ApplyOptions{
		ExpectFingerprint: req.Fingerprint, SkipTeardown: req.SkipTeardown, Principal: "dashboard",
	})
	s.comps.invalidate()
	switch {
	case errors.Is(err, componentsvc.ErrStalePreview):
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "stale_preview", "message": err.Error(), "preview": res.Preview})
		return
	case errors.Is(err, componentsvc.ErrManagedByOrg):
		// An org-managed node (ledger MODPKG-7, ruling D-434): the
		// organization decides, the preview lists each refused part.
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "managed_by_org", "message": err.Error(), "preview": res.Preview})
		return
	case err != nil:
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "apply_refused", "message": err.Error()})
		return
	}
	writeJSON(w, res)
}

// componentsTeardownRequest is the body of POST /api/components/teardown.
type componentsTeardownRequest struct {
	IDs    []string `json:"ids"`
	DryRun bool     `json:"dry_run"`
}

func (s *Server) handleComponentsTeardown(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	svc := s.componentsOr503(w)
	if svc == nil {
		return
	}
	var req componentsTeardownRequest
	if !decodeComponentsBody(w, r, &req) {
		return
	}
	if len(req.IDs) == 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "ids_required", "message": "name at least one component"})
		return
	}
	outs, err := svc.RunTeardown(r.Context(), req.IDs, req.DryRun)
	if err != nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "teardown_refused", "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"dry_run": req.DryRun, "outcomes": nonNilOutcomes(outs)})
}

// componentsPurgePreviewRequest is the body of POST /api/components/purge/preview.
type componentsPurgePreviewRequest struct {
	Component string `json:"component"`
}

func (s *Server) handleComponentsPurgePreview(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	svc := s.componentsOr503(w)
	if svc == nil {
		return
	}
	var req componentsPurgePreviewRequest
	if !decodeComponentsBody(w, r, &req) {
		return
	}
	plan, err := svc.PurgePreview(r.Context(), strings.TrimSpace(req.Component))
	if err != nil {
		writePurgeErr(w, err)
		return
	}
	// The plan is persisted (a node-local row valid 15 minutes): audited
	// like every other write, metadata only.
	s.recordManageAudit(r, "components.purge_preview", fmt.Sprintf("component=%s plan=%s", plan.Component, plan.ID))
	writeJSON(w, plan)
}

// componentsPurgeExecuteRequest is the body of POST /api/components/purge/execute.
type componentsPurgeExecuteRequest struct {
	PlanID string `json:"plan_id"`
}

func (s *Server) handleComponentsPurgeExecute(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	svc := s.componentsOr503(w)
	if svc == nil {
		return
	}
	var req componentsPurgeExecuteRequest
	if !decodeComponentsBody(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.PlanID) == "" {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "plan_id_required", "message": "preview the purge first; execute names the plan id"})
		return
	}
	res, err := svc.PurgeExecute(r.Context(), strings.TrimSpace(req.PlanID))
	if err != nil {
		writePurgeErr(w, err)
		return
	}
	writeJSON(w, res)
}

// writePurgeErr maps a purge refusal onto a status: no database is 503, an
// unknown plan 404, everything the operator can act on (no reviewed plan,
// an active component, an expired or consumed plan) 409, with the
// service's own sentence.
func writePurgeErr(w http.ResponseWriter, err error) {
	status, code := http.StatusConflict, "purge_refused"
	switch {
	case errors.Is(err, componentsvc.ErrPurgeUnavailable):
		status, code = http.StatusServiceUnavailable, "purge_unavailable"
	case errors.Is(err, store.ErrPurgePlanNotFound):
		status, code = http.StatusNotFound, "plan_not_found"
	case errors.Is(err, store.ErrNoPurgePlan):
		code = "no_purge_plan"
	case errors.Is(err, store.ErrPurgePlanNotExecutable):
		code = "plan_not_executable"
	}
	writeJSONStatus(w, status, map[string]string{"error": code, "message": err.Error()})
}

func nonNilOutcomes(outs []componentsvc.StepOutcome) []componentsvc.StepOutcome {
	if outs == nil {
		return []componentsvc.StepOutcome{}
	}
	return outs
}
