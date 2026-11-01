package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/planlimits"
	"github.com/marmutapp/superbased-observer/internal/planlimitssvc"
)

// Plans & limits API (internal/planlimitssvc, docs/plans-and-limits.md).
//
// Every route is owner-local (CapabilityLocal): the page adds and removes
// credentials, so even its read is refused to a remote principal. Writes
// carry the double-submit confirm token GET /api/plans mints, except the
// status line feed, which `observer statusline` posts over loopback with
// numbers only. No response ever carries a secret: accounts list the NAMES
// of their keychain entries, never the values.

// planCatalogSource is one source row as the add flow renders it.
type planCatalogSource struct {
	ID           string                 `json:"id"`
	Kind         planlimits.SourceKind  `json:"kind"`
	Rung         planlimits.Rung        `json:"rung"`
	Experimental bool                   `json:"experimental"`
	Auth         planlimits.AuthMethod  `json:"auth"`
	Passive      bool                   `json:"passive"`
	Secrets      []planCatalogSecret    `json:"secrets"`
	Params       []planCatalogParam     `json:"params"`
	Command      string                 `json:"command,omitempty"`
	DocURL       string                 `json:"doc_url,omitempty"`
	Reads        []planCatalogLocalRead `json:"reads,omitempty"`
}

type planCatalogSecret struct {
	Key      string `json:"key"`
	Required bool   `json:"required"`
}

type planCatalogParam struct {
	Key      string   `json:"key"`
	Required bool     `json:"required"`
	Choices  []string `json:"choices,omitempty"`
	Numeric  bool     `json:"numeric,omitempty"`
}

// planCatalogLocalRead names a vendor-local file an experimental source
// reads, so the page can say exactly what it touches.
type planCatalogLocalRead struct {
	Base string `json:"base"`
	Path string `json:"path"`
	Item string `json:"item,omitempty"`
}

// planCatalogProvider is one provider with its sources in ladder order.
type planCatalogProvider struct {
	ID              string                  `json:"id"`
	Group           string                  `json:"group"`
	HasExperimental bool                    `json:"has_experimental"`
	Coverage        planlimits.Coverage     `json:"coverage"`
	Auth            []planlimits.AuthMethod `json:"auth"`
	Shows           []string                `json:"shows"`
	Gap             string                  `json:"gap,omitempty"`
	Tools           []string                `json:"tools,omitempty"`
	Sources         []planCatalogSource     `json:"sources"`
}

// planCatalog projects the pure registry for the add flow.
func planCatalog() []planCatalogProvider {
	out := make([]planCatalogProvider, 0, len(planlimits.Providers))
	for _, p := range planlimits.Providers {
		cp := planCatalogProvider{
			ID: p.ID, Group: p.Group, HasExperimental: planlimitssvc.HasExperimental(p.ID),
			Coverage: planlimits.CoverageOf(p.ID), Auth: planlimits.AuthMethodsOf(p.ID),
			Shows: append([]string{}, p.Shows...), Gap: p.Gap, Tools: p.Tools, Sources: []planCatalogSource{},
		}
		if cp.Auth == nil {
			cp.Auth = []planlimits.AuthMethod{}
		}
		for _, src := range planlimits.SourcesFor(p.ID) {
			cs := planCatalogSource{
				ID: src.ID, Kind: src.Kind, Rung: src.Rung(), Experimental: src.Experimental(), Auth: planlimits.AuthOf(src.Kind),
				Passive: src.Passive, Command: src.Command, DocURL: src.DocURL,
				Secrets: []planCatalogSecret{}, Params: []planCatalogParam{},
			}
			for _, sp := range src.Secrets {
				cs.Secrets = append(cs.Secrets, planCatalogSecret{Key: sp.Key, Required: sp.Required})
			}
			for _, pp := range src.Params {
				cs.Params = append(cs.Params, planCatalogParam{Key: pp.Key, Required: pp.Required, Choices: pp.Choices, Numeric: pp.Numeric})
			}
			for _, l := range src.Local {
				cs.Reads = append(cs.Reads, planCatalogLocalRead{Base: l.Base, Path: l.Rel, Item: l.Item})
			}
			cp.Sources = append(cp.Sources, cs)
		}
		out = append(out, cp)
	}
	return out
}

// plansUnavailable answers 503 when the daemon did not wire the service.
func (s *Server) plansUnavailable(w http.ResponseWriter) bool {
	if s.opts.Plans != nil {
		return false
	}
	writeErrStatus(w, errors.New("plans and limits are not running in this process"), http.StatusServiceUnavailable)
	return true
}

// writePlansErr maps a service error to a status and plain message.
func writePlansErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, planlimitssvc.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, planlimitssvc.ErrNeedsOptIn):
		status = http.StatusConflict
	case errors.Is(err, planlimitssvc.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, planlimitssvc.ErrKeychainFails):
		status = http.StatusServiceUnavailable
	}
	msg := strings.TrimPrefix(err.Error(), "planlimits: ")
	writeErrStatus(w, errors.New(msg), status)
}

// handlePlans serves GET /api/plans: the page model, the add-flow catalog and
// the confirm token. Opening the page shortens the poll cadence for a while.
func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.plansUnavailable(w) {
		return
	}
	s.opts.Plans.MarkPageOpen()
	v, err := s.opts.Plans.Status(r.Context())
	if err != nil {
		writePlansErr(w, err)
		return
	}
	writeJSON(w, map[string]any{
		"view":          v,
		"catalog":       planCatalog(),
		"confirm_token": setConfirmCookie(w, r),
	})
}

// handlePlanAccounts serves POST /api/plans/accounts: add an account.
func (s *Server) handlePlanAccounts(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.plansUnavailable(w) {
		return
	}
	var req planlimitssvc.AddRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
		return
	}
	info, err := s.opts.Plans.AddAccount(r.Context(), req)
	if err != nil {
		writePlansErr(w, err)
		return
	}
	s.recordManageAudit(r, "plans_account_add", fmt.Sprintf("provider=%s source=%s account=%s", info.Provider, info.Source, info.ID))
	// A first reading right away, so the card fills while the page is open.
	res, _ := s.opts.Plans.Refresh(r.Context(), info.ID)
	writeJSON(w, map[string]any{"account": info, "refresh": res})
}

// planAccountUpdate is the body of POST /api/plans/accounts/{id}.
type planAccountUpdate struct {
	Label   *string           `json:"label,omitempty"`
	Params  map[string]string `json:"params,omitempty"`
	Secrets map[string]string `json:"secrets,omitempty"`
	Enabled *bool             `json:"enabled,omitempty"`
}

// handlePlanAccount serves the per-account routes:
//
//	GET  /api/plans/accounts/{id}/history  recent readings and runs
//	POST /api/plans/accounts/{id}          edit (label, params, secrets, enabled)
//	POST /api/plans/accounts/{id}/remove   delete it and its keychain entries
//	POST /api/plans/accounts/{id}/refresh  read it now
func (s *Server) handlePlanAccount(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/plans/accounts/"), "/")
	id, verb, _ := strings.Cut(rest, "/")
	if id == "" || strings.Contains(verb, "/") {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodGet && verb == "history" {
		if s.plansUnavailable(w) {
			return
		}
		snaps, runs, err := s.opts.Plans.History(r.Context(), id, intArg(r, "days", 7, 1, 90))
		if err != nil {
			writePlansErr(w, err)
			return
		}
		type run struct {
			StartedAt time.Time `json:"started_at"`
			EndedAt   time.Time `json:"ended_at"`
			Outcome   string    `json:"outcome"`
			Detail    string    `json:"detail,omitempty"`
		}
		outRuns := make([]run, 0, len(runs))
		for _, rr := range runs {
			outRuns = append(outRuns, run{StartedAt: rr.StartedAt, EndedAt: rr.EndedAt, Outcome: rr.Outcome, Detail: rr.Detail})
		}
		if snaps == nil {
			snaps = []planlimits.Snapshot{}
		}
		writeJSON(w, map[string]any{"snapshots": snaps, "runs": outRuns})
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	if s.plansUnavailable(w) {
		return
	}
	ctx := r.Context()
	switch verb {
	case "":
		var body planAccountUpdate
		if err := decodeJSONBody(r, &body); err != nil {
			writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
			return
		}
		info, err := s.opts.Plans.UpdateAccount(ctx, id, planlimitssvc.UpdateRequest(body))
		if err != nil {
			writePlansErr(w, err)
			return
		}
		s.recordManageAudit(r, "plans_account_edit", "account="+id)
		writeJSON(w, map[string]any{"account": info})
	case "remove":
		if err := s.opts.Plans.RemoveAccount(ctx, id); err != nil {
			writePlansErr(w, err)
			return
		}
		s.recordManageAudit(r, "plans_account_remove", "account="+id)
		writeJSON(w, map[string]any{"ok": true})
	case "refresh":
		res, err := s.opts.Plans.Refresh(ctx, id)
		if err != nil {
			writePlansErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"refresh": res})
	default:
		http.NotFound(w, r)
	}
}

// handlePlanOptIn serves POST /api/plans/optin {provider, on}.
func (s *Server) handlePlanOptIn(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.plansUnavailable(w) {
		return
	}
	var body struct {
		Provider string `json:"provider"`
		On       bool   `json:"on"`
	}
	if err := decodeJSONBody(r, &body); err != nil {
		writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
		return
	}
	if err := s.opts.Plans.SetOptIn(r.Context(), body.Provider, body.On); err != nil {
		writePlansErr(w, err)
		return
	}
	s.recordManageAudit(r, "plans_experimental", fmt.Sprintf("provider=%s on=%t", body.Provider, body.On))
	writeJSON(w, map[string]any{"ok": true})
}

// handlePlanStatusLine serves POST /api/plans/statusline: one numbers-only
// reading from `observer statusline` (planlimits.StatusLineForward). It lands
// in the module's own table, never in limit_snapshots.
func (s *Server) handlePlanStatusLine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "application/json") {
		http.Error(w, "unsupported media type: application/json required", http.StatusUnsupportedMediaType)
		return
	}
	if s.plansUnavailable(w) {
		return
	}
	var f planlimits.StatusLineForward
	if err := decodeJSONBody(r, &f); err != nil {
		writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
		return
	}
	if err := s.opts.Plans.IngestStatusLine(r.Context(), f); err != nil {
		writePlansErr(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handlePlanProbe serves POST /api/plans/probe: the add flow's Test button.
// It runs the source once with the typed values and stores nothing. A
// failure answers 200 with an outcome code, never the vendor's error text.
func (s *Server) handlePlanProbe(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.plansUnavailable(w) {
		return
	}
	var req planlimitssvc.AddRequest
	if err := decodeJSONBody(r, &req); err != nil {
		writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
		return
	}
	if !planlimits.AccountSourceAllowed(req.Provider, req.Source) {
		writeErrStatus(w, errors.New("this provider cannot use that source"), http.StatusBadRequest)
		return
	}
	snap, err := s.opts.Plans.Probe(r.Context(), planlimitssvc.ProbeRequest{
		Provider: req.Provider, Source: req.Source, Params: req.Params, Secrets: req.Secrets,
	})
	switch {
	case err == nil:
		writeJSON(w, map[string]any{"ok": true, "snapshot": snap})
	case errors.Is(err, planlimitssvc.ErrInvalid), errors.Is(err, planlimitssvc.ErrNeedsOptIn):
		writePlansErr(w, err)
	default:
		writeJSON(w, map[string]any{"ok": false, "outcome": planlimits.OutcomeCode(err)})
	}
}
