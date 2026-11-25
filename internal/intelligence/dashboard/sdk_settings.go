package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/configschema"
	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
	"github.com/marmutapp/superbased-observer/internal/settingsgate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Plane A build-out lane B6 (W2-7 ruling D18, W2-8 ruling D19):
//
//	GET    /api/sdk/destination                L  the SDK discovery body
//	                                              (contract destination.md
//	                                              section 4; never the key)
//	GET    /api/sdk/receiver                   V  the local OTLP receiver's bind
//	                                              state (review E-72)
//	POST   /api/sdk/credential                 L  sign in: mint the SDK key
//	DELETE /api/sdk/credential                 L  sign out: revoke + remove
//	                                              (an admin-issued key: remove)
//	POST   /api/sdk/credential/key             L  install an SDK key an admin
//	                                              issued (`observer sdk
//	                                              use-key`; the key in the
//	                                              body, never echoed)
//	GET    /api/config/proposals               L  settings an agent asked for
//	POST   /api/config/proposals/{id}/resolve  L  mark one approved/rejected
//
// Approving a proposal is the page doing the normal checked write first
// (PUT /api/config/keys, through every guard that route has: governance,
// the tier gate, the confirm token, validation, read-back), then resolving
// it here as approved; this route marks it approved only when the value is
// in force, so "approved" is true by check, not by convention.

// handleSDKDestination serves GET /api/sdk/destination.
func (s *Server) handleSDKDestination(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	cfg := config.Default()
	if s.opts.ConfigPath != "" {
		loaded, err := loadConfigForDashboard(s.opts.ConfigPath)
		if err != nil {
			writeErr(w, err)
			return
		}
		cfg = loaded
	}
	var st sdkcredsvc.Status
	if s.opts.SDK.Status != nil {
		st = s.opts.SDK.Status()
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, sdkcredsvc.BuildDiscoveryWithOrg(cfg, st, "http://"+r.Host, s.sdkOrgDashboard(r.Context())))
}

// sdkOrgDashboard is what the enrolment row says about the organization's
// own dashboard, for the discovery body's online.dashboard_url (SDK
// quickstart plan 3.8). Not enrolled, or no database: the zero value, and
// the field stays "".
func (s *Server) sdkOrgDashboard(ctx context.Context) sdkcredsvc.OrgDashboard {
	if s.opts.DB == nil {
		return sdkcredsvc.OrgDashboard{}
	}
	enr, err := store.New(s.opts.DB).LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return sdkcredsvc.OrgDashboard{}
	}
	return sdkcredsvc.OrgDashboardFrom(enr.OrgID, enr.OnlineURL, enr.OrgServerURL)
}

// handleOTLPReceiver serves GET /api/sdk/receiver: what the daemon last
// recorded about its local OTLP receiver (review E-72), so the AI Apps pages
// can say when the port was taken and every span sent here is lost, not
// only `observer doctor`. {"state":"unknown"} when nothing is recorded.
func (s *Server) handleOTLPReceiver(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	st := OTLPReceiverState{State: "unknown"}
	if s.opts.SDK.Receiver != nil {
		if got, ok := s.opts.SDK.Receiver(); ok && got.State != "" {
			st = got
		}
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, st)
}

// handleSDKCredential serves POST (sign in) and DELETE (sign out)
// /api/sdk/credential. Both need the confirm token: signing in lets apps send
// data off this machine.
func (s *Server) handleSDKCredential(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost, http.MethodDelete:
	default:
		http.Error(w, "POST or DELETE", http.StatusMethodNotAllowed)
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	if r.Method == http.MethodPost {
		if s.opts.SDK.SignIn == nil {
			http.Error(w, "SDK sign-in is not available in this build", http.StatusNotImplemented)
			return
		}
		st, err := s.opts.SDK.SignIn(r.Context())
		if err != nil {
			writeJSONStatus(w, http.StatusBadGateway, map[string]any{"error": "sign_in_failed", "message": err.Error()})
			return
		}
		s.recordManageAudit(r, "sdk_sign_in", "key_id="+st.KeyID)
		writeJSON(w, map[string]any{"status": st})
		return
	}
	if s.opts.SDK.SignOut == nil {
		http.Error(w, "SDK sign-out is not available in this build", http.StatusNotImplemented)
		return
	}
	n, err := s.opts.SDK.SignOut(r.Context())
	s.recordManageAudit(r, "sdk_sign_out", "revoked="+strconv.Itoa(n))
	out := map[string]any{"revoked": n}
	if err != nil {
		out["warning"] = err.Error()
	}
	writeJSON(w, out)
}

// sdkInstallKeyBodyLimit bounds the install body: a key is at most 512
// bytes and an address a few hundred.
const sdkInstallKeyBodyLimit = 4 << 10

// handleSDKInstallKey serves POST /api/sdk/credential/key: the dashboard
// form of `observer sdk use-key`. Owner-local (CapabilityLocal), confirm
// token required (installing a key lets apps send data off this machine),
// the key in the JSON body only (never a URL or a query), and never in the
// answer, the audit row or a log: the answer is the key's status, which
// carries no key. A refusal's message never quotes the key (sdkcredsvc's
// errors name the broken rule only).
func (s *Server) handleSDKInstallKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		// A key in a query string lands in browser history and access logs;
		// refuse the request whatever it carries, and never read it.
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "query_not_allowed", "message": "send the SDK key in the JSON body, never in the address"})
		return
	}
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.SDK.InstallKey == nil {
		http.Error(w, "installing an SDK key is not available in this build", http.StatusNotImplemented)
		return
	}
	var body struct {
		Key        string `json:"key"`
		GatewayURL string `json:"gateway_url"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, sdkInstallKeyBodyLimit)).Decode(&body); err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "bad_request", "message": `the body must be {"key": "<key_id>.<secret>", "gateway_url": "https://..."}`})
		return
	}
	st, err := s.opts.SDK.InstallKey(body.Key, body.GatewayURL)
	body.Key = ""
	if err != nil {
		writeJSONStatus(w, http.StatusBadRequest, map[string]any{"error": "install_failed", "message": err.Error()})
		return
	}
	s.recordManageAudit(r, "sdk_use_key", "key_id="+st.KeyID+" gateway="+st.KeyGatewayURL)
	writeJSON(w, map[string]any{"status": st})
}

// handleConfigProposals serves GET /api/config/proposals (?all=1 includes
// decided ones) and POST /api/config/proposals/{id}/resolve.
func (s *Server) handleConfigProposals(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/config/proposals"), "/")
	if rest == "" {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		rows, err := store.New(s.opts.DB).ListSettingsProposals(r.Context(), r.URL.Query().Get("all") == "", 100)
		if err != nil {
			writeErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"proposals": rows, "confirm_token": setConfirmCookie(w, r)})
		return
	}
	idStr, verb, _ := strings.Cut(rest, "/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 || verb != "resolve" {
		http.NotFound(w, r)
		return
	}
	if !requireConfirmToken(w, r) {
		return
	}
	var body struct {
		Decision string `json:"decision"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&body); err != nil {
		http.Error(w, "body must be {\"decision\": \"approved\"|\"rejected\"}", http.StatusBadRequest)
		return
	}
	s.resolveConfigProposal(w, r, id, body.Decision)
}

func (s *Server) resolveConfigProposal(w http.ResponseWriter, r *http.Request, id int64, decision string) {
	st := store.New(s.opts.DB)
	p, err := st.GetSettingsProposal(r.Context(), id)
	if errors.Is(err, store.ErrSettingsProposalNotFound) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		writeErr(w, err)
		return
	}
	switch decision {
	case store.SettingsProposalRejected:
	case store.SettingsProposalApproved:
		// E-50: an old proposal is not approved (rejecting it still works).
		// Whether the setting changed by hand since it was filed is the
		// page's check before its write (the value is in force by now).
		if c := settingsgate.CheckApproval(settingsgate.ProposalFacts{CreatedAt: p.CreatedAt}, time.Now()); c.Code == settingsgate.ApprovalCodeExpired {
			writeJSONStatus(w, http.StatusConflict, map[string]any{"error": c.Code, "message": c.Message})
			return
		}
		if ok, msg := s.proposalInForce(p); !ok {
			writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "not_in_force", "message": msg})
			return
		}
	default:
		http.Error(w, "decision must be approved or rejected", http.StatusBadRequest)
		return
	}
	err = st.DecideSettingsProposal(r.Context(), id, decision, "dashboard", time.Now())
	switch {
	case errors.Is(err, store.ErrSettingsProposalDecided):
		writeJSONStatus(w, http.StatusConflict, map[string]any{"error": "already_decided", "message": "this proposal was already decided"})
		return
	case err != nil:
		writeErr(w, err)
		return
	}
	s.recordManageAudit(r, "settings_proposal_"+decision, "id="+strconv.FormatInt(id, 10)+" key="+p.Key)
	p, _ = st.GetSettingsProposal(r.Context(), id)
	writeJSON(w, map[string]any{"proposal": p})
}

// proposalInForce reports whether the config file holds the proposal's
// value now (the approve step's check).
func (s *Server) proposalInForce(p store.SettingsProposal) (bool, string) {
	if s.opts.ConfigPath == "" {
		return false, "no config file to check"
	}
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		return false, err.Error()
	}
	leaf, ok := configschema.Lookup(p.Key)
	if !ok {
		return false, "unknown config key " + p.Key
	}
	raw, _ := json.Marshal(p.Value)
	want, err := configschema.ParseValue(leaf, raw)
	if err != nil {
		return false, err.Error()
	}
	if !reflect.DeepEqual(normalizeLeafValue(configschema.Get(&cfg, leaf)), normalizeLeafValue(want)) {
		return false, "the config does not hold the proposed value yet; save it first (PUT /api/config/keys), then resolve"
	}
	return true, ""
}

// normalizeLeafValue makes a Get value and a ParseValue value comparable
// (ints come back as the field's own type from Get, int64 from ParseValue).
func normalizeLeafValue(v any) any {
	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return rv.Int()
	case reflect.Float32, reflect.Float64:
		return rv.Float()
	case reflect.Slice:
		if rv.Len() == 0 {
			return []string{}
		}
		if ss, ok := v.([]string); ok {
			return ss
		}
		out := make([]string, rv.Len())
		for i := range out {
			out[i] = rv.Index(i).String()
		}
		return out
	case reflect.Map:
		if rv.Len() == 0 {
			return map[string]string{}
		}
		out := map[string]string{}
		for _, k := range rv.MapKeys() {
			out[k.String()] = rv.MapIndex(k).String()
		}
		return out
	case reflect.String:
		return rv.String()
	}
	return v
}
