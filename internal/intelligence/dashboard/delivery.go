package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/delivery"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// delivery.go serves the commit to PR to merge routes (D-689,
// docs/projects-page.md "Delivery"):
//
//	GET    /api/project/{id}/delivery           View   the Delivery tab
//	POST   /api/project/{id}/delivery/check     Local  "Check now"
//	GET|PUT /api/project/{id}/delivery/settings Local  mirror opt-in + schedule
//	GET    /api/session/{id}/delivery           View   (session sub-route)
//	GET|POST /api/delivery/links                Local  code hosts: list, connect
//	DELETE /api/delivery/links/{id}             Local  disconnect
//	POST   /api/delivery/links/{id}/test        Local  test a connection
//	GET    /api/delivery/mirrors                View   mirrors with size and cap
//	DELETE /api/delivery/mirrors/{id}           Local  delete a mirror
//
// Reads come straight from the store's delivery seam. Every write is Local
// with the confirm token (it reaches the network, the keychain or the
// disk) and goes through Options.DeliveryService, the one seam onto
// internal/deliverysvc. Composition is dashapi.ComposeProjectDelivery.

// deliveryCheckWait / deliveryCheckLimit mirror the "Rescan now" bounds: a
// check that clones a mirror can take minutes, so the request answers 202
// after the wait and the pass finishes on a detached context.
const (
	deliveryCheckWait  = 20 * time.Second
	deliveryCheckLimit = 5 * time.Minute
	deliveryBodyLimit  = 16 << 10
)

// errDeliveryUnavailable is the 503 body when no service is wired.
var errDeliveryUnavailable = errors.New("the delivery service is not running in this process; restart the daemon with `observer start`")

// writeDeliveryErr maps a service error to its status and closed kind.
func writeDeliveryErr(w http.ResponseWriter, err error) {
	var de *dashapi.DeliveryError
	if errors.As(err, &de) {
		writeJSONStatus(w, de.Status, map[string]string{"error": de.Message, "kind": de.Kind})
		return
	}
	writeErr(w, err)
}

// decodeDeliveryBody reads a small JSON body into v.
func decodeDeliveryBody(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, deliveryBodyLimit)
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		writeErrStatus(w, errors.New("invalid JSON body"), http.StatusBadRequest)
		return false
	}
	return true
}

// pathID parses a positive {id} path value.
func pathID(r *http.Request) (int64, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	return id, err == nil && id > 0
}

// handleProjectDelivery serves GET /api/project/{id}/delivery.
func (s *Server) handleProjectDelivery(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
		return
	}
	since, until, days := projectDetailWindow(r)
	in, err := s.loadProjectDelivery(ctx, st, projectID, since, until)
	if err != nil {
		writeErr(w, err)
		return
	}
	in.WindowDays = days
	writeJSON(w, dashapi.ComposeProjectDelivery(in))
}

// loadProjectDelivery loads every input of the Delivery tab.
func (s *Server) loadProjectDelivery(ctx context.Context, st *store.Store, projectID int64, since, until time.Time) (dashapi.ProjectDeliveryInput, error) {
	in := dashapi.ProjectDeliveryInput{
		ProjectID: projectID, Now: time.Now().UTC(), LocalEnabled: s.opts.Delivery.Local,
		CountLikely: s.opts.Delivery.CountLikely, CanCheck: s.opts.DeliveryService != nil,
		PRCommits: map[int64][]delivery.PRCommit{},
	}
	var err error
	if in.Remotes, err = st.LoadProjectRemotes(ctx, projectID); err != nil {
		return in, err
	}
	if in.Links, err = st.ListProviderLinks(ctx); err != nil {
		return in, err
	}
	if in.Mirrors, err = st.ListDeliveryMirrors(ctx); err != nil {
		return in, err
	}
	if in.Settings, err = st.GetDeliveryProjectSettings(ctx, projectID); err != nil {
		return in, err
	}
	if in.Landings, err = st.LoadProjectLandings(ctx, projectID, since, until); err != nil {
		return in, err
	}
	if in.Ownership, err = st.LoadCommitOwnership(ctx, projectID, since, until, s.commitLinkWindow(), store.OwnershipCaps{
		Prompts: dashapi.PromptLinkCap, Edits: dashapi.EditLinkCap, Commits: dashapi.CommitLinkCap,
	}); err != nil {
		return in, err
	}
	if in.PRs, err = st.LoadProjectPullRequests(ctx, projectID, since); err != nil {
		return in, err
	}
	for _, p := range in.PRs {
		pcs, err := st.LoadPullRequestCommits(ctx, p.ID)
		if err != nil {
			return in, err
		}
		in.PRCommits[p.ID] = pcs
	}
	return in, nil
}

// deliveryCheckResponse is POST /api/project/{id}/delivery/check's body.
type deliveryCheckResponse struct {
	Done   bool                         `json:"done"`
	Error  string                       `json:"error,omitempty"`
	Kind   string                       `json:"kind,omitempty"`
	Result *dashapi.DeliveryCheckResult `json:"result,omitempty"`
}

// handleProjectDeliveryCheck serves POST /api/project/{id}/delivery/check:
// one forced pass (provider calls for a connected GitHub remote, a mirror
// refresh for an opted-in project, then the landing evaluation).
func (s *Server) handleProjectDeliveryCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	st := store.New(s.db())
	if _, ok := requireProject(r.Context(), w, r, st, projectID); !ok {
		return
	}
	svc := s.opts.DeliveryService
	if svc == nil {
		writeErrStatus(w, errDeliveryUnavailable, http.StatusServiceUnavailable)
		return
	}
	checkCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), deliveryCheckLimit)
	type outcome struct {
		res dashapi.DeliveryCheckResult
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		defer cancel()
		res, err := svc.CheckProject(checkCtx, projectID)
		done <- outcome{res, err}
	}()
	timer := time.NewTimer(deliveryCheckWait)
	defer timer.Stop()
	var resp deliveryCheckResponse
	select {
	case o := <-done:
		resp.Done = true
		if o.err != nil {
			resp.Error = o.err.Error()
			var de *dashapi.DeliveryError
			if errors.As(o.err, &de) {
				resp.Kind = de.Kind
			}
		} else {
			res := o.res
			resp.Result = &res
		}
	case <-timer.C:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_ = json.NewEncoder(w).Encode(resp)
		return
	case <-r.Context().Done():
		return
	}
	writeJSON(w, resp)
}

// deliverySettingsRequest is PUT /api/project/{id}/delivery/settings.
type deliverySettingsRequest struct {
	MirrorEnabled   bool `json:"mirror_enabled"`
	ScheduleMinutes int  `json:"schedule_minutes"`
}

// handleProjectDeliverySettings serves GET and PUT
// /api/project/{id}/delivery/settings: the per-project mirror opt-in and
// refresh schedule (0 = "Check now" only, else at least 30 minutes).
func (s *Server) handleProjectDeliverySettings(w http.ResponseWriter, r *http.Request) {
	projectID, ok := parseProjectID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ctx := r.Context()
	st := store.New(s.db())
	switch r.Method {
	case http.MethodGet:
		if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
			return
		}
		ps, err := st.GetDeliveryProjectSettings(ctx, projectID)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, dashapi.DeliverySettingsWire(ps))
	case http.MethodPut:
		if !requireJSONConfirm(w, r) {
			return
		}
		if _, ok := requireProject(ctx, w, r, st, projectID); !ok {
			return
		}
		var req deliverySettingsRequest
		if !decodeDeliveryBody(w, r, &req) {
			return
		}
		if !dashapi.ValidDeliverySchedule(req.ScheduleMinutes) {
			writeErrStatus(w, errors.New("schedule_minutes must be 0 (Check now only) or between 30 minutes and one week"), http.StatusBadRequest)
			return
		}
		if !req.MirrorEnabled {
			req.ScheduleMinutes = 0
		}
		if err := st.SetDeliveryProjectSettings(ctx, delivery.ProjectSettings{
			ProjectID: projectID, MirrorEnabled: req.MirrorEnabled, ScheduleMinutes: req.ScheduleMinutes, UpdatedAt: time.Now().UTC(),
		}); err != nil {
			writeErr(w, err)
			return
		}
		ps, err := st.GetDeliveryProjectSettings(ctx, projectID)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, dashapi.DeliverySettingsWire(ps))
	default:
		w.Header().Set("Allow", "GET, PUT")
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

// handleSessionDelivery serves GET /api/session/{id}/delivery, the session
// Commits card's delivery lines. A sub-route of /api/session/ classed like
// /commits, and refused like it when the organization hides Projects.
func (s *Server) handleSessionDelivery(w http.ResponseWriter, r *http.Request, id string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	id = strings.TrimSpace(id)
	if id == "" {
		http.Error(w, "session id required", http.StatusBadRequest)
		return
	}
	if s.opts.Governance != nil {
		if eff := s.opts.Governance(r.Context()); eff.VisibilityActive() && eff.IsNavSectionHidden(string(SectionProjects)) {
			writeGovernanceRefusal(w, http.StatusNotFound, "governance_hidden", string(SectionProjects), eff,
				"This page is managed by your organization and is not available on this machine.")
			return
		}
	}
	ctx := r.Context()
	st := store.New(s.db())
	win, exists, err := st.LookupSessionWindow(ctx, id, time.Now().UTC())
	if err != nil {
		writeErr(w, err)
		return
	}
	if !exists {
		http.NotFound(w, r)
		return
	}
	if win.ProjectID <= 0 {
		writeJSON(w, dashapi.ComposeSessionDelivery(id, 0, s.opts.Delivery.Local, nil, nil, nil))
		return
	}
	remotes, err := st.LoadProjectRemotes(ctx, win.ProjectID)
	if err != nil {
		writeErr(w, err)
		return
	}
	links, err := st.ListProviderLinks(ctx)
	if err != nil {
		writeErr(w, err)
		return
	}
	rows, err := st.LoadSessionLandings(ctx, id)
	if err != nil {
		writeErr(w, err)
		return
	}
	writeJSON(w, dashapi.ComposeSessionDelivery(id, win.ProjectID, s.opts.Delivery.Local, remotes, links, rows))
}

// handleDeliveryLinks serves GET (list) and POST (connect)
// /api/delivery/links. Local: the list names the connected account, and a
// connect writes the OS keychain and calls the code host.
func (s *Server) handleDeliveryLinks(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := store.New(s.db())
	switch r.Method {
	case http.MethodGet:
		links, err := st.ListProviderLinks(ctx)
		if err != nil {
			writeErr(w, err)
			return
		}
		repos, err := st.ListDeliveryRepos(ctx)
		if err != nil {
			writeErr(w, err)
			return
		}
		served := dashapi.CountServedRepos(links, repos)
		resp := dashapi.APIDeliveryLinksResponse{
			ServiceAvailable: s.opts.DeliveryService != nil,
			PollMinutes:      s.opts.Delivery.PollMinutes,
			Links:            make([]dashapi.APIDeliveryLink, 0, len(links)),
		}
		for _, l := range links {
			resp.Links = append(resp.Links, dashapi.DeliveryLinkWire(l, served[l.ID]))
		}
		writeJSON(w, resp)
	case http.MethodPost:
		if !requireJSONConfirm(w, r) {
			return
		}
		svc := s.opts.DeliveryService
		if svc == nil {
			writeErrStatus(w, errDeliveryUnavailable, http.StatusServiceUnavailable)
			return
		}
		var req dashapi.DeliveryConnectRequest
		if !decodeDeliveryBody(w, r, &req) {
			return
		}
		l, err := svc.Connect(ctx, req)
		if err != nil {
			writeDeliveryErr(w, err)
			return
		}
		writeJSON(w, dashapi.DeliveryLinkWire(l, 0))
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, "GET or POST only", http.StatusMethodNotAllowed)
	}
}

// handleDeliveryLink serves DELETE /api/delivery/links/{id} (disconnect:
// the keychain entry, the link and its stored PRs).
func (s *Server) handleDeliveryLink(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	svc := s.opts.DeliveryService
	if svc == nil {
		writeErrStatus(w, errDeliveryUnavailable, http.StatusServiceUnavailable)
		return
	}
	if err := svc.Disconnect(r.Context(), id); err != nil {
		writeDeliveryErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}

// handleDeliveryLinkTest serves POST /api/delivery/links/{id}/test.
func (s *Server) handleDeliveryLinkTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	svc := s.opts.DeliveryService
	if svc == nil {
		writeErrStatus(w, errDeliveryUnavailable, http.StatusServiceUnavailable)
		return
	}
	l, err := svc.TestLink(r.Context(), id)
	if err != nil {
		writeDeliveryErr(w, err)
		return
	}
	writeJSON(w, dashapi.DeliveryLinkWire(l, 0))
}

// handleDeliveryMirrors serves GET /api/delivery/mirrors.
func (s *Server) handleDeliveryMirrors(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	ctx := r.Context()
	var (
		used, capBytes int64
		mirrors        []delivery.Mirror
		err            error
	)
	if svc := s.opts.DeliveryService; svc != nil {
		used, capBytes, mirrors, err = svc.MirrorUsage(ctx)
	} else {
		mirrors, err = store.New(s.db()).ListDeliveryMirrors(ctx)
		for _, m := range mirrors {
			used += m.SizeBytes
		}
		capBytes = int64(s.opts.Delivery.MirrorCapMB) << 20
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	resp := dashapi.APIDeliveryMirrorsResponse{
		ServiceAvailable: s.opts.DeliveryService != nil, UsedBytes: used, CapBytes: capBytes,
		Mirrors: make([]dashapi.APIDeliveryMirror, 0, len(mirrors)),
	}
	for _, m := range mirrors {
		resp.Mirrors = append(resp.Mirrors, dashapi.DeliveryMirrorWire(m))
	}
	writeJSON(w, resp)
}

// handleDeliveryMirror serves DELETE /api/delivery/mirrors/{id}: removes
// the mirror's directory under ~/.observer/delivery/mirrors, then its row.
func (s *Server) handleDeliveryMirror(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		w.Header().Set("Allow", http.MethodDelete)
		http.Error(w, "DELETE only", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	id, ok := pathID(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	svc := s.opts.DeliveryService
	if svc == nil {
		writeErrStatus(w, errDeliveryUnavailable, http.StatusServiceUnavailable)
		return
	}
	if err := svc.DeleteMirror(r.Context(), id); err != nil {
		writeDeliveryErr(w, err)
		return
	}
	writeJSON(w, map[string]bool{"ok": true})
}
