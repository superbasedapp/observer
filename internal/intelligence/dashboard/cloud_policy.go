package dashboard

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_policy.go serves the node dashboard's standing Cloud Intelligence
// policy surface (value-upgrade plan of record,
// docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md §W2): the
// one-click Turn on / Turn off actions (thin wrappers over `observer cloud
// enable` / `observer cloud disable`, run through the SAME CloudCommandRunner
// seam every other action route in this package uses) and the content-free
// "What we sent" ledger read (a pure store read, no subprocess).

// CloudEnableRequest is the body of POST /api/cloud/enable.
type CloudEnableRequest struct {
	EvidenceSettings json.RawMessage `json:"evidence_settings,omitempty"`
	WithExcerpts     bool            `json:"with_excerpts"`
	Background       bool            `json:"background"`
}

// handleCloudEnable serves POST /api/cloud/enable: runs `observer cloud
// enable --yes --source dashboard [--with-excerpts] [--no-background]`.
// Refused (409) while a sign-in or sync is running — the same guard
// handleCloudConsent uses, since both would race this on the credential
// store / outbox.
func (s *Server) handleCloudEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	var req CloudEnableRequest
	if err := cloudDecodeJSON(r, &req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	if c.loginRunning() {
		http.Error(w, "a sign-in is running — wait for it to finish (or time out) before turning on Cloud Intelligence", http.StatusConflict)
		return
	}
	if c.syncRunning() {
		http.Error(w, "a sync is running — wait for it to finish before turning on Cloud Intelligence", http.StatusConflict)
		return
	}
	args := []string{"--yes", "--source", "dashboard"}
	if req.WithExcerpts {
		args = append(args, "--with-excerpts")
	}
	if !req.Background {
		args = append(args, "--no-background")
	}
	if req.EvidenceSettings != nil {
		settings, err := store.ParseCloudEvidenceSettings(string(req.EvidenceSettings))
		if err != nil || settings == nil {
			http.Error(w, "invalid evidence settings", http.StatusBadRequest)
			return
		}
		raw, _ := settings.JSON()
		args = append(args, "--evidence-settings", raw)
	}
	output, ok2, exitErr := c.runOnce(r.Context(), "enable", args, cloudConsentStepTimeout)
	writeJSON(w, CloudActionResponse{OK: ok2, Output: output, ExitError: exitErr})
}

// handleCloudDisable serves POST /api/cloud/disable: runs `observer cloud
// disable --yes --source dashboard`. Same running-action guards as enable.
func (s *Server) handleCloudDisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	if c.loginRunning() {
		http.Error(w, "a sign-in is running — wait for it to finish (or time out) before turning off Cloud Intelligence", http.StatusConflict)
		return
	}
	if c.syncRunning() {
		http.Error(w, "a sync is running — wait for it to finish before turning off Cloud Intelligence", http.StatusConflict)
		return
	}
	output, ok2, exitErr := c.runOnce(r.Context(), "disable", []string{"--yes", "--source", "dashboard"}, cloudConsentStepTimeout)
	writeJSON(w, CloudActionResponse{OK: ok2, Output: output, ExitError: exitErr})
}

// --- ledger ------------------------------------------------------------------

// CloudLedgerReceiptView is one consent receipt on the ledger. Content-free.
type CloudLedgerReceiptView struct {
	EvidenceSettingsJSON string  `json:"evidence_settings_json,omitempty"`
	ID                   string  `json:"id"`
	Purpose              string  `json:"purpose"`
	GrantMode            string  `json:"grant_mode"`
	Endpoint             string  `json:"endpoint,omitempty"`
	CreatedAt            string  `json:"created_at,omitempty"`
	ReviewAt             *string `json:"review_at,omitempty"`
	InvalidatedAt        *string `json:"invalidated_at,omitempty"`
	Live                 bool    `json:"live"`
}

// CloudLedgerItemView is one outbox item bound to a receipt.
type CloudLedgerItemView struct {
	ID         string `json:"id"`
	SessionID  string `json:"session_id,omitempty"`
	Kind       string `json:"kind"`
	State      string `json:"state"`
	RetryCount int    `json:"retry_count"`
	LastError  string `json:"last_error,omitempty"`
	CreatedAt  string `json:"created_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// CloudLedgerResultView is the current enrichment result for a receipt's
// session, if any. Content-free: provenance and counts only — never the
// result body.
type CloudLedgerResultView struct {
	ID         string  `json:"id"`
	SessionID  string  `json:"session_id"`
	ModelRoute string  `json:"model_route,omitempty"`
	Tokens     int     `json:"tokens"`
	CostUSD    float64 `json:"cost_usd"`
	ReceivedAt string  `json:"received_at,omitempty"`
}

// CloudLedgerEntryView is one row of GET /api/cloud/ledger.
type CloudLedgerEntryView struct {
	Receipt CloudLedgerReceiptView `json:"receipt"`
	Items   []CloudLedgerItemView  `json:"items"`
	Result  *CloudLedgerResultView `json:"result,omitempty"`
}

// CloudLedgerResponse is the payload for GET /api/cloud/ledger.
type CloudLedgerResponse struct {
	Entries       []CloudLedgerEntryView `json:"entries"`
	TotalReceipts int                    `json:"total_receipts"`
}

// cloudLedgerDefaultLimit / cloudLedgerMaxLimit bound GET /api/cloud/ledger's
// ?limit= query parameter.
const (
	cloudLedgerDefaultLimit = 200
	cloudLedgerMaxLimit     = 1000
)

// handleCloudLedger serves GET /api/cloud/ledger: every consent receipt
// recorded on this device, newest first, with the outbox items queued under
// it and the current enrichment result for its session (if any). Pure store
// read (FF1) — no subprocess, content-free.
func (s *Server) handleCloudLedger(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.cloudAccountSeams(w); !ok {
		return
	}
	limit := cloudLedgerDefaultLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			limit = n
		}
	}
	if limit > cloudLedgerMaxLimit {
		limit = cloudLedgerMaxLimit
	}
	st := store.New(s.db())
	rows, total, err := st.ListCloudLedger(r.Context(), limit)
	if err != nil {
		writeErr(w, err)
		return
	}
	entries := make([]CloudLedgerEntryView, 0, len(rows))
	for _, e := range rows {
		rv := CloudLedgerReceiptView{
			EvidenceSettingsJSON: e.Receipt.EvidenceSettingsJSON,
			ID:                   e.Receipt.ID,
			Purpose:              e.Receipt.Purpose,
			GrantMode:            e.Receipt.GrantMode,
			Endpoint:             e.Receipt.Endpoint,
			CreatedAt:            cloudRFC3339(e.Receipt.CreatedAt),
			Live:                 e.Receipt.Live,
		}
		if e.Receipt.ReviewAt != nil {
			v := cloudRFC3339(*e.Receipt.ReviewAt)
			rv.ReviewAt = &v
		}
		if e.Receipt.InvalidatedAt != nil {
			v := cloudRFC3339(*e.Receipt.InvalidatedAt)
			rv.InvalidatedAt = &v
		}
		items := make([]CloudLedgerItemView, 0, len(e.Items))
		for _, it := range e.Items {
			items = append(items, CloudLedgerItemView{
				ID:         it.ID,
				SessionID:  it.SessionID,
				Kind:       it.Kind,
				State:      it.State,
				RetryCount: it.RetryCount,
				LastError:  it.LastError,
				CreatedAt:  cloudRFC3339(it.CreatedAt),
				UpdatedAt:  cloudRFC3339(it.UpdatedAt),
			})
		}
		var result *CloudLedgerResultView
		if e.Result != nil {
			result = &CloudLedgerResultView{
				ID:         e.Result.ID,
				SessionID:  e.Result.SessionID,
				ModelRoute: e.Result.ModelRoute,
				Tokens:     e.Result.Tokens,
				CostUSD:    e.Result.CostUSD,
				ReceivedAt: cloudRFC3339(e.Result.ReceivedAt),
			}
		}
		entries = append(entries, CloudLedgerEntryView{Receipt: rv, Items: items, Result: result})
	}
	writeJSON(w, CloudLedgerResponse{Entries: entries, TotalReceipts: total})
}
