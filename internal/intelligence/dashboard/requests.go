package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/accessgrant"
	"github.com/marmutapp/superbased-observer/internal/budgetwarnfile"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// requests.go - the node dashboard's Requests page (request-grants design
// §1.2, phase G6): a developer asks the org for a higher budget, a guard
// exemption, a tool, a model or a feature, sees exactly what will be sent,
// and follows the answer. Every action here is also a CLI command
// (`observer request ...`, `observer requests`).

// requestTypeView is one row of the request-type table as the dialog needs it.
type requestTypeView struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`
	Grantable   bool     `json:"grantable"`
	Required    []string `json:"required,omitempty"`
	MaxSeconds  int64    `json:"max_seconds,omitempty"`
	MaxRule     string   `json:"max_rule"`
	DefaultSecs int64    `json:"default_seconds"`
	// Landing is where a decision lands; "answer" means the organization
	// answers with a note and nothing changes on this machine (T-437).
	Landing string `json:"landing"`
}

func requestTypeViews() []requestTypeView {
	out := make([]requestTypeView, 0, len(accessgrant.RequestTypes))
	for _, t := range accessgrant.RequestTypes {
		v := requestTypeView{
			ID: t.ID, Label: t.Label, Grantable: t.Grantable(), MaxRule: string(t.Max), Landing: string(t.Landing),
			MaxSeconds: int64(t.MaxDuration / time.Second), DefaultSecs: int64(accessgrant.DefaultDuration / time.Second),
		}
		for _, f := range t.Required {
			v.Required = append(v.Required, string(f))
		}
		out = append(out, v)
	}
	return out
}

// requestsPageResponse is GET /api/requests.
type requestsPageResponse struct {
	Available     bool                   `json:"available"`
	Enrolled      bool                   `json:"enrolled"`
	OrgName       string                 `json:"org_name,omitempty"`
	ShipsRaw      bool                   `json:"ships_raw"`
	Requests      []orgclient.OrgRequest `json:"requests"`
	RequestsError string                 `json:"requests_error,omitempty"`
	Queued        []store.OutboxRequest  `json:"queued"`
	Grants        store.AccessGrantsView `json:"grants"`
	GrantsCached  bool                   `json:"grants_cached"`
	Types         []requestTypeView      `json:"types"`
	// Budgets are the org budgets this machine is governed by (from the
	// budget rail), each with what was measured against it this period: the
	// budget picker on a budget request (T-523), never a typed id.
	Budgets []requestBudgetView `json:"budgets"`
	Now     int64               `json:"now_ns"`
}

func (s *Server) handleRequests(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleRequestsList(w, r)
	case http.MethodPost:
		s.handleRequestsCreate(w, r, false)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleRequestsList(w http.ResponseWriter, r *http.Request) {
	// The page's writes (create, withdraw, cancel) echo the owner-local
	// confirm token this GET mints (review M3-05); the SPA reads the cookie.
	setConfirmCookie(w, r)
	out := requestsPageResponse{
		Requests: []orgclient.OrgRequest{}, Queued: []store.OutboxRequest{},
		Grants: store.AccessGrantsView{Grants: []store.AccessGrantView{}}, Types: requestTypeViews(),
		Budgets: []requestBudgetView{},
		Now:     time.Now().UnixNano(),
	}
	svc := s.opts.Requests
	if svc == nil {
		writeJSON(w, out)
		return
	}
	out.Available = true
	ctx := r.Context()
	st, err := svc.Status(ctx)
	if err != nil || !st.Enrolled {
		writeJSON(w, out)
		return
	}
	out.Enrolled, out.OrgName = true, st.OrgName
	out.ShipsRaw = svc.RequestContextShipsRaw(ctx)
	if reqs, err := svc.ListMyOrgRequests(ctx); err != nil {
		out.RequestsError = "the organization could not be reached; showing what this machine holds"
	} else if reqs != nil {
		out.Requests = reqs
	}
	if q, err := svc.QueuedAccessRequests(ctx); err == nil {
		out.Queued = q
	}
	if g, ok, err := svc.AccessGrantsView(ctx); err == nil {
		out.Grants, out.GrantsCached = g, ok
	}
	if b := svc.RequestableBudgets(); b != nil {
		var windows []budgetwarnfile.Window
		if f := s.budgetStatusFile(); f != nil {
			windows = f.Windows
		}
		out.Budgets = requestBudgetViews(b, windows, time.Now())
	}
	writeJSON(w, out)
}

// requestBody is the dialog's POST.
type requestBody struct {
	Request      orgcontract.AccessRequestCreate `json:"request"`
	OptInExcerpt bool                            `json:"opt_in_excerpt"`
}

// requestPreview is POST /api/requests/preview: the exact JSON that would be
// sent, plus the local pre-check (the org re-validates with its own limits).
type requestPreview struct {
	Request  orgcontract.AccessRequestCreate `json:"request"`
	JSON     string                          `json:"json"`
	Problems []accessgrant.Problem           `json:"problems"`
}

func (s *Server) prepareRequest(w http.ResponseWriter, r *http.Request) (orgcontract.AccessRequestCreate, []accessgrant.Problem, bool) {
	svc := s.opts.Requests
	if svc == nil {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "not_enrolled", "message": "requests go to an organization; this node is not enrolled"})
		return orgcontract.AccessRequestCreate{}, nil, false
	}
	var body requestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": "invalid JSON body"})
		return orgcontract.AccessRequestCreate{}, nil, false
	}
	prepared, err := svc.PrepareAccessRequest(r.Context(), body.Request, body.OptInExcerpt)
	if errors.Is(err, orgclient.ErrNotEnrolled) {
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "not_enrolled", "message": "requests go to an organization; this node is not enrolled"})
		return orgcontract.AccessRequestCreate{}, nil, false
	}
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "bad_request", "message": err.Error()})
		return orgcontract.AccessRequestCreate{}, nil, false
	}
	var problems []accessgrant.Problem
	if prepared.RequestType != "" {
		payload := orgcontract.AccessRequestPayload{}
		if prepared.Payload != nil {
			payload = *prepared.Payload
		}
		var norm accessgrant.Normalized
		norm, problems = accessgrant.Validate(accessgrant.Request{
			Type: prepared.RequestType, Payload: payload, DurationS: prepared.RequestedDurationS,
			Uses: prepared.RequestedUses, SubjectKind: prepared.SubjectKind, Machine: prepared.MachineIdentity,
			Justification: prepared.Message,
		}, accessgrant.DefaultSettings())
		// A grant in force on this machine that already covers the ask is
		// the answer: the preview says which, and nothing is sent (the org
		// refuses the same request with the same sentence).
		if len(problems) == 0 {
			if g, covered := svc.AlreadyGranted(r.Context(), norm); covered {
				problems = append(problems, accessgrant.AlreadyGrantedProblem(g, false))
			}
		}
	}
	if problems == nil {
		problems = []accessgrant.Problem{}
	}
	return prepared, problems, true
}

func (s *Server) handleRequestsPreview(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	prepared, problems, ok := s.prepareRequest(w, r)
	if !ok {
		return
	}
	raw, _ := json.MarshalIndent(prepared, "", "  ")
	writeJSON(w, requestPreview{Request: prepared, JSON: string(raw), Problems: problems})
}

func (s *Server) handleRequestsCreate(w http.ResponseWriter, r *http.Request, _ bool) {
	// Review M3-05: sending a request to the org carries the confirm token.
	if !requireJSONConfirm(w, r) {
		return
	}
	prepared, problems, ok := s.prepareRequest(w, r)
	if !ok {
		return
	}
	if len(problems) > 0 {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "bad_request", "message": accessgrant.Error(problems), "problems": problems})
		return
	}
	got, queued, err := s.opts.Requests.SendOrQueueAccessRequest(r.Context(), prepared)
	var refused *orgclient.RequestRefusedError
	switch {
	case errors.As(err, &refused):
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "refused", "message": refused.Error(), "problems": refused.Problems})
		return
	case errors.Is(err, orgclient.ErrOrgRequestCapReached):
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_open", "message": "you already have the maximum number of open requests to this organization"})
		return
	case errors.Is(err, store.ErrOutboxFull):
		writeJSONStatus(w, http.StatusTooManyRequests, map[string]string{"error": "outbox_full", "message": "the organization is unreachable and the queue of unsent requests is full"})
		return
	case err != nil:
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "send_failed", "message": err.Error()})
		return
	}
	if queued > 0 {
		writeJSONStatus(w, http.StatusAccepted, map[string]any{"queued_id": queued, "message": "the organization is unreachable; the request is queued and will be sent on the next sync"})
		return
	}
	writeJSONStatus(w, http.StatusCreated, map[string]any{"request": got})
}

// handleRequestsSub serves /api/requests/{id}/withdraw,
// /api/requests/queued/{id}/cancel and /api/requests/prefill.
func (s *Server) handleRequestsSub(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/requests/"), "/")
	parts := strings.Split(rest, "/")
	switch {
	case rest == "preview":
		s.handleRequestsPreview(w, r)
	case rest == "prefill":
		s.handleRequestsPrefill(w, r)
	case len(parts) == 2 && parts[1] == "withdraw":
		s.handleRequestWithdraw(w, r, parts[0])
	case len(parts) == 3 && parts[0] == "queued" && parts[2] == "cancel":
		s.handleQueuedCancel(w, r, parts[1])
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleRequestWithdraw(w http.ResponseWriter, r *http.Request, rawID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 || s.opts.Requests == nil {
		http.NotFound(w, r)
		return
	}
	switch err := s.opts.Requests.WithdrawOrgRequest(r.Context(), id); {
	case errors.Is(err, orgclient.ErrRequestNotFound):
		http.NotFound(w, r)
	case errors.Is(err, orgclient.ErrRequestNotOpen):
		writeJSONStatus(w, http.StatusConflict, map[string]string{"error": "not_open", "message": "the request is no longer open"})
	case err != nil:
		writeJSONStatus(w, http.StatusBadGateway, map[string]string{"error": "withdraw_failed", "message": err.Error()})
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *Server) handleQueuedCancel(w http.ResponseWriter, r *http.Request, rawID string) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	id, err := strconv.ParseInt(rawID, 10, 64)
	if err != nil || id <= 0 || s.opts.Requests == nil {
		http.NotFound(w, r)
		return
	}
	ok, err := s.opts.Requests.CancelQueuedAccessRequest(r.Context(), id)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal", "message": err.Error()})
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleRequestsPrefill builds a request draft from one guard event (the
// Security page's "Request access" action, design §1.2): the rule, the
// operand hash, the command class and the project, with the exact preselected
// breadth (D-092). The excerpt rides in the context block and is shaped by
// PrepareAccessRequest like any other.
func (s *Server) handleRequestsPrefill(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	if q.Get("event_id") == "" && q.Get("rule") != "" && s.opts.DB != nil {
		s.handleRequestsPrefillByRule(w, r, q.Get("rule"), q.Get("session"))
		return
	}
	id, err := strconv.ParseInt(q.Get("event_id"), 10, 64)
	if err != nil || id <= 0 || s.opts.DB == nil {
		http.NotFound(w, r)
		return
	}
	draft, ok, err := store.New(s.opts.DB).GuardEventRequestDraft(r.Context(), id)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal", "message": err.Error()})
		return
	}
	if !ok {
		http.NotFound(w, r)
		return
	}
	writeJSON(w, map[string]any{"request": draft})
}

// prefillSessionMaxBytes bounds the session id a deep link may carry (a
// vendor session id is a UUID or a short slug; anything longer is not one).
const prefillSessionMaxBytes = 256

// handleRequestsPrefillByRule serves the guard deny line's deep link,
// /requests?rule=R&session=S (request-grants G4): the newest event for the
// rule in that session, else a rule-wide draft. Both values arrive from a
// URL anyone could craft, so they are bounded and refused when they carry
// control characters; the draft is only ever shown in the request form,
// nothing is sent until the developer presses Send.
func (s *Server) handleRequestsPrefillByRule(w http.ResponseWriter, r *http.Request, rule, session string) {
	rule, session = strings.TrimSpace(rule), strings.TrimSpace(session)
	if !prefillParamOK(rule, accessgrant.MaxRuleIDBytes) || !prefillParamOK(session, prefillSessionMaxBytes) {
		writeJSONStatus(w, http.StatusBadRequest, map[string]string{"error": "invalid", "message": "rule or session is malformed"})
		return
	}
	draft, err := store.New(s.opts.DB).GuardRuleRequestDraft(r.Context(), rule, session)
	if err != nil {
		writeJSONStatus(w, http.StatusInternalServerError, map[string]string{"error": "internal", "message": err.Error()})
		return
	}
	writeJSON(w, map[string]any{"request": draft})
}

// prefillParamOK accepts a bounded, control-character-free value.
func prefillParamOK(v string, maxBytes int) bool {
	if len(v) > maxBytes {
		return false
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}
