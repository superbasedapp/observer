package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/availcompose"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/staffauth"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// staffavail.go is the staff console's availability issue step and per-org
// component control (managed-SaaS M6.3; lane fix/sr-17-staff-control;
// ledger STAFF-8, SECPOOL-6). Staff preview the envelope the inputs compose
// into, against the newest issued one, and ask for it to be issued (a
// reason, a fresh passkey assertion, CSRF; logged in staff_actions in the
// same transaction). The worker signs, stores and delivers it
// (internal/cloudserver/availwork); the staff process never reaches the
// signer. A request the worker cannot pick up (its availability loops off)
// would refuse every later issue, so ops and admin can cancel a pending one
// (the same reason, passkey and log rules). A per-org component
// (org.security first) is turned on or off for one org by rewriting that
// component's input (availcompose.Toggle), which takes effect on the org's
// host once an envelope is issued.

// staffIssueStore is the store seam of the issue step. The production store
// implements it; a store that does not answers the routes not_available.
type staffIssueStore interface {
	StaffAvailabilityIssueState(ctx context.Context) (store.AvailabilityIssueState, error)
	RequestAvailabilityIssue(ctx context.Context, staffID string, in store.AvailabilityIssueInput, now time.Time) (store.AvailabilityIssueRequest, error)
	CancelAvailabilityIssue(ctx context.Context, staffID, requestID, reason string, now time.Time) (store.AvailabilityIssueRequest, error)
	SetOrgComponentInput(ctx context.Context, staffID, orgID, component string, on bool, reason string, now time.Time) (store.OrgComponentChange, error)
}

// staffIssue returns the issue seam and the console read seam, or answers
// 501 and false.
func (s *Server) staffIssue(w http.ResponseWriter) (staffIssueStore, staffConsoleStore, bool) {
	is, ok := s.staff.db.(staffIssueStore)
	cs, ok2 := s.staff.db.(staffConsoleStore)
	if !ok || !ok2 {
		writeErr(w, http.StatusNotImplemented, "not_available", "this staff console store cannot issue the availability envelope")
		return nil, nil, false
	}
	return is, cs, true
}

func (s *Server) hasStaffIssueStore() bool {
	_, ok := s.staff.db.(staffIssueStore)
	return ok && s.hasStaffConsoleStore()
}

// staffPreview is GET /staff/api/availability/preview.
type staffPreview struct {
	BaseVersion  int64                           `json:"base_version"`
	InputsDigest string                          `json:"inputs_digest"`
	Body         *pc.AvailabilityBody            `json:"body"`
	Problems     []string                        `json:"problems"`
	Changes      []availcompose.Change           `json:"changes"`
	Pending      *store.AvailabilityIssueRequest `json:"pending"`
	LastRequest  *store.AvailabilityIssueRequest `json:"last_request"`
	Deliveries   []store.AvailabilityDelivery    `json:"deliveries"`
}

// availabilityFacts is what the preview and the org components read: the
// inputs and the newest issued envelope's version and body (nil when none
// was issued, or when it no longer decodes).
type availabilityFacts struct {
	inputs []availcompose.Input
	raw    []store.AvailabilityInputRow
	base   int64
	prev   *pc.AvailabilityBody
}

func (s *Server) readAvailabilityFacts(ctx context.Context, cs staffConsoleStore) (availabilityFacts, error) {
	rows, err := s.staff.db.ListAvailabilityInputs(ctx)
	if err != nil {
		return availabilityFacts{}, err
	}
	f := availabilityFacts{raw: rows, inputs: make([]availcompose.Input, 0, len(rows))}
	for _, r := range rows {
		f.inputs = append(f.inputs, availcompose.Input{Section: r.Section, Key: r.Key, Value: r.Value, Reason: r.Reason, Author: r.Author})
	}
	doc, err := cs.StaffAvailabilityDocument(ctx)
	switch {
	case errors.Is(err, store.ErrNotFound):
	case err != nil:
		return availabilityFacts{}, err
	default:
		f.base = doc.Version
		if b, derr := availcompose.DecodeBody(doc.Body); derr == nil {
			f.prev = &b
		}
	}
	return f, nil
}

// buildPreview composes the next envelope and diffs it against the newest.
func (s *Server) buildPreview(ctx context.Context, is staffIssueStore, cs staffConsoleStore) (staffPreview, error) {
	f, err := s.readAvailabilityFacts(ctx, cs)
	if err != nil {
		return staffPreview{}, err
	}
	p := staffPreview{BaseVersion: f.base, InputsDigest: availcompose.Digest(f.inputs), Problems: []string{}, Changes: []availcompose.Change{}}
	composed, err := availcompose.Compose(f.inputs, s.now())
	switch {
	case err != nil:
		p.Problems = append(p.Problems, err.Error())
	case len(composed.Problems) > 0:
		for _, pr := range composed.Problems {
			p.Problems = append(p.Problems, pr.String())
		}
	default:
		p.Body = &composed.Body
		p.Changes = availcompose.Diff(f.prev, &composed.Body)
	}
	st, err := is.StaffAvailabilityIssueState(ctx)
	if err != nil {
		return staffPreview{}, err
	}
	p.Pending, p.LastRequest, p.Deliveries = st.Pending, st.Last, st.Deliveries
	if p.Deliveries == nil {
		p.Deliveries = []store.AvailabilityDelivery{}
	}
	return p, nil
}

func (s *Server) handleStaffAvailabilityPreview(w http.ResponseWriter, r *http.Request) {
	is, cs, ok := s.staffIssue(w)
	if !ok {
		return
	}
	p, err := s.buildPreview(r.Context(), is, cs)
	if err != nil {
		s.log.Error("cloudserver/api: staff availability preview", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not compose the availability preview")
		return
	}
	writeJSON(w, http.StatusOK, p)
}

// staffIssueBody is POST /staff/api/availability/issue.
type staffIssueBody struct {
	Reason       string `json:"reason"`
	InputsDigest string `json:"inputs_digest"`
	BaseVersion  int64  `json:"base_version"`
}

// issueRefusal is one row of the issue table: a preview fact that refuses a
// request before it is recorded, walked top down.
type issueRefusal struct {
	status  int
	code    string
	message string
	refuse  func(p staffPreview, b staffIssueBody) bool
}

var issueRefusals = []issueRefusal{
	{
		http.StatusBadRequest, "invalid_inputs", "some inputs cannot be composed; fix or remove them first",
		func(p staffPreview, _ staffIssueBody) bool { return len(p.Problems) > 0 },
	},
	{
		http.StatusConflict, "inputs_changed", "the inputs or the issued envelope changed since your preview; review the new diff",
		func(p staffPreview, b staffIssueBody) bool {
			return b.InputsDigest != p.InputsDigest || b.BaseVersion != p.BaseVersion
		},
	},
	{
		http.StatusConflict, "issue_pending", "another issue request is waiting for the worker",
		func(p staffPreview, _ staffIssueBody) bool { return p.Pending != nil },
	},
	{
		http.StatusConflict, "nothing_to_issue", "the inputs compose into the envelope already issued",
		func(p staffPreview, _ staffIssueBody) bool { return len(p.Changes) == 0 },
	},
}

func (s *Server) handleStaffAvailabilityIssue(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	is, cs, ok := s.staffIssue(w)
	if !ok {
		return
	}
	var body staffIssueBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	reason, err := staffauth.ValidateReason(body.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "reason_required", "a reason is required for every staff change: "+err.Error())
		return
	}
	preview, err := s.buildPreview(r.Context(), is, cs)
	if err != nil {
		s.log.Error("cloudserver/api: staff availability issue preview", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not compose the availability preview")
		return
	}
	for _, ref := range issueRefusals {
		if ref.refuse(preview, body) {
			writeErr(w, ref.status, ref.code, ref.message)
			return
		}
	}
	req, err := is.RequestAvailabilityIssue(r.Context(), p.StaffID, store.AvailabilityIssueInput{
		Reason: reason, InputsDigest: preview.InputsDigest, BaseVersion: preview.BaseVersion, Changes: len(preview.Changes),
	}, s.now())
	switch {
	case errors.Is(err, store.ErrIssuePending):
		writeErr(w, http.StatusConflict, "issue_pending", "another issue request is waiting for the worker")
		return
	case err != nil:
		s.log.Error("cloudserver/api: staff availability issue", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not record the issue request")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"request_id": req.RequestID, "state": req.State})
}

// staffCancelBody is POST /staff/api/availability/issue/{id}/cancel.
type staffCancelBody struct {
	Reason string `json:"reason"`
}

// handleStaffAvailabilityIssueCancel cancels a pending issue request: it
// becomes failed with error class cancelled, logged in staff_actions in the
// same transaction. Only a pending request can be cancelled (409 not_pending
// otherwise: the worker finished it, or someone cancelled it first).
func (s *Server) handleStaffAvailabilityIssueCancel(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	is, _, ok := s.staffIssue(w)
	if !ok {
		return
	}
	var body staffCancelBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	reason, err := staffauth.ValidateReason(body.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "reason_required", "a reason is required for every staff change: "+err.Error())
		return
	}
	req, err := is.CancelAvailabilityIssue(r.Context(), p.StaffID, r.PathValue("id"), reason, s.now())
	switch {
	case errors.Is(err, store.ErrIssueInvalid):
		writeErr(w, http.StatusNotFound, "not_found", "no such issue request")
		return
	case errors.Is(err, store.ErrIssueNotPending):
		writeErr(w, http.StatusConflict, "not_pending", "that issue request is no longer pending")
		return
	case err != nil:
		s.log.Error("cloudserver/api: staff availability issue cancel", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not cancel the issue request")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request_id": req.RequestID, "state": req.State, "error_class": req.ErrorClass})
}

// staffOrgComponentRow is one row of GET /staff/api/orgs/{id}/components.
type staffOrgComponentRow struct {
	Component string          `json:"component"`
	Title     string          `json:"title"`
	Issued    bool            `json:"issued"`
	Next      bool            `json:"next"`
	Input     json.RawMessage `json:"input"`
	Toggle    staffToggle     `json:"toggle"`
}

// staffToggle is what the row's one button does.
type staffToggle struct {
	On    bool            `json:"on"`
	Value json.RawMessage `json:"value"`
	Error string          `json:"error"`
}

// staffOrg checks that the org exists (404 otherwise).
func (s *Server) staffOrgExists(w http.ResponseWriter, r *http.Request, cs staffConsoleStore, orgID string) bool {
	if _, err := cs.StaffOrgDetail(r.Context(), orgID); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeErr(w, http.StatusNotFound, "not_found", "no such org")
			return false
		}
		s.log.Error("cloudserver/api: staff org", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the org")
		return false
	}
	return true
}

func (s *Server) handleStaffOrgComponents(w http.ResponseWriter, r *http.Request) {
	_, cs, ok := s.staffIssue(w)
	if !ok {
		return
	}
	orgID := r.PathValue("id")
	if !s.staffOrgExists(w, r, cs, orgID) {
		return
	}
	f, err := s.readAvailabilityFacts(r.Context(), cs)
	if err != nil {
		s.log.Error("cloudserver/api: staff org components", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the availability inputs")
		return
	}
	rows := []staffOrgComponentRow{}
	for _, c := range availcompose.OrgComponents() {
		var input json.RawMessage
		for _, in := range f.raw {
			if in.Section == availcompose.SectionComponents && in.Key == c.ID {
				input = in.Value
			}
		}
		next := availcompose.InputOffered(c.ID, input, orgID)
		row := staffOrgComponentRow{
			Component: c.ID, Title: c.Title, Issued: availcompose.Offered(f.prev, c.ID, orgID), Next: next, Input: input,
			Toggle: staffToggle{On: !next},
		}
		t, err := availcompose.Toggle(c.ID, input, orgID, !next)
		if err != nil {
			row.Toggle.Error = err.Error()
		} else {
			row.Toggle.Value = t.Value
		}
		rows = append(rows, row)
	}
	writeJSON(w, http.StatusOK, map[string]any{"org_id": orgID, "base_version": f.base, "components": rows})
}

// staffOrgComponentBody is PUT /staff/api/orgs/{id}/components/{component}.
type staffOrgComponentBody struct {
	On     *bool  `json:"on"`
	Reason string `json:"reason"`
}

func (s *Server) handleStaffOrgComponentSet(w http.ResponseWriter, r *http.Request) {
	p, _ := staffPrincipalFrom(r.Context())
	is, cs, ok := s.staffIssue(w)
	if !ok {
		return
	}
	var body staffOrgComponentBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body); err != nil || body.On == nil {
		writeErr(w, http.StatusBadRequest, "bad_request", `the body must be {"on": true|false, "reason": "..."}`)
		return
	}
	reason, err := staffauth.ValidateReason(body.Reason)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "reason_required", "a reason is required for every staff change: "+err.Error())
		return
	}
	component, orgID := r.PathValue("component"), r.PathValue("id")
	if !availcompose.IsOrgComponent(component) {
		writeErr(w, http.StatusNotFound, "not_found", "no such per-org component")
		return
	}
	if !s.staffOrgExists(w, r, cs, orgID) {
		return
	}
	ch, err := is.SetOrgComponentInput(r.Context(), p.StaffID, orgID, component, *body.On, reason, s.now())
	switch {
	case errors.Is(err, store.ErrNoChange):
		writeErr(w, http.StatusConflict, "no_change", "the org is already in that state")
		return
	case errors.Is(err, availcompose.ErrToggle), errors.Is(err, availcompose.ErrInvalidInput):
		writeErr(w, http.StatusBadRequest, "invalid_input", err.Error())
		return
	case err != nil:
		s.log.Error("cloudserver/api: staff org component", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not write the component input")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"section": availcompose.SectionComponents, "key": component, "value": ch.Value, "previous": ch.Previous,
	})
}
