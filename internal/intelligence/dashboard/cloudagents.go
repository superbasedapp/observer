package dashboard

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudagentssvc"
)

// Cloud agents API (internal/cloudagentssvc, docs/cloud-agents.md): the
// Settings > Connected tools > Cloud agents card
// (web/src/pages/settings/CloudAgentsCard.tsx). Every route is owner-local
// (CapabilityLocal):
// connecting an account makes this machine run the user's own vendor CLI or
// call a vendor API with the user's key, so even the read is refused to a
// remote principal. Writes carry the double-submit confirm token GET
// /api/cloud-agents mints. The connector is always picked from the catalog
// the GET returns, never free text: an id that is not in it is a 400.
//
// An API connector (cursor-cloud, devin, openhands-cloud; catalog
// needs_key) takes its key in the POST body ("key") and its declared
// parameters in "params" (Devin: {"org_id": ...}). The key goes to the
// keychain and nowhere else: it is not echoed in a response, an error, the
// audit row or a log line, and it never appears in a URL.
//
//	GET  /api/cloud-agents                          page model, connector catalog, confirm token
//	POST /api/cloud-agents/test     {connector[,key,params]}  probe, link nothing
//	POST /api/cloud-agents/connect  {connector[,key,params]}  probe, link, first sync
//	POST /api/cloud-agents/sync                     pull every linked account now
//	POST /api/cloud-agents/accounts/{id}/sync       pull now
//	POST /api/cloud-agents/accounts/{id}/disconnect unlink (pulled sessions stay)
//	POST /api/cloud-agents/accounts/{id}/users      the user picker of an account whose key sees other people's sessions (catalog chooses_user; a bounded vendor read)
//	POST /api/cloud-agents/accounts/{id}/user {user_id}  record the account's own user, then sync
//
// A connector whose key sees other people's sessions (catalog chooses_user:
// Devin, OpenHands Cloud and Warp today; the routes take any such connector,
// never a name) lists every member's or teammate's sessions; its account
// pulls nothing until the developer picks
// their own user from the users route's list (CLOUDAGENTS-6). The user id
// must be one the picker offered in shape (the connector's grammar); it is
// a picker, never a free-text field.

// cloudAgentsUnavailable answers 503 when the daemon did not wire the
// service.
func (s *Server) cloudAgentsUnavailable(w http.ResponseWriter) bool {
	if s.opts.CloudAgents != nil {
		return false
	}
	writeErrStatus(w, errors.New("cloud agents are not running in this process"), http.StatusServiceUnavailable)
	return true
}

// writeCloudAgentsErr maps a service error to a status and a short message.
func writeCloudAgentsErr(w http.ResponseWriter, err error) {
	status := http.StatusInternalServerError
	switch {
	case errors.Is(err, cloudagentssvc.ErrNotFound):
		status = http.StatusNotFound
	case errors.Is(err, cloudagentssvc.ErrInvalid):
		status = http.StatusBadRequest
	case errors.Is(err, cloudagentssvc.ErrKeychain), errors.Is(err, cloudagentssvc.ErrKeychainDelete):
		status = http.StatusServiceUnavailable
	}
	msg := strings.TrimPrefix(err.Error(), "cloudagents: ")
	writeErrStatus(w, errors.New(msg), status)
}

// handleCloudAgents serves GET /api/cloud-agents.
func (s *Server) handleCloudAgents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.cloudAgentsUnavailable(w) {
		return
	}
	v, err := s.opts.CloudAgents.Status(r.Context())
	if err != nil {
		writeCloudAgentsErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"view": v, "confirm_token": setConfirmCookie(w, r)})
}

// cloudAgentsConnectorBody is the body of the test and connect routes. Key
// is an API connector's key: it is handed to the service and dropped.
type cloudAgentsConnectorBody struct {
	Connector string            `json:"connector"`
	Key       string            `json:"key"`
	Params    map[string]string `json:"params"`
}

func (s *Server) decodeCloudAgentsConnector(w http.ResponseWriter, r *http.Request) (cloudAgentsConnectorBody, bool) {
	if !requireConfirmToken(w, r) {
		return cloudAgentsConnectorBody{}, false
	}
	if s.cloudAgentsUnavailable(w) {
		return cloudAgentsConnectorBody{}, false
	}
	var body cloudAgentsConnectorBody
	if err := decodeJSONBody(r, &body); err != nil {
		writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
		return cloudAgentsConnectorBody{}, false
	}
	return body, true
}

func (b cloudAgentsConnectorBody) credentials() cloudagentssvc.Credentials {
	return cloudagentssvc.Credentials{Key: b.Key, Params: b.Params}
}

// handleCloudAgentsTest serves POST /api/cloud-agents/test.
func (s *Server) handleCloudAgentsTest(w http.ResponseWriter, r *http.Request) {
	body, ok := s.decodeCloudAgentsConnector(w, r)
	if !ok {
		return
	}
	res, err := s.opts.CloudAgents.TestWith(r.Context(), body.Connector, body.credentials())
	if err != nil {
		writeCloudAgentsErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"probe": res})
}

// handleCloudAgentsConnect serves POST /api/cloud-agents/connect: probe,
// link and a first sync, so the page fills while it is open.
func (s *Server) handleCloudAgentsConnect(w http.ResponseWriter, r *http.Request) {
	body, ok := s.decodeCloudAgentsConnector(w, r)
	if !ok {
		return
	}
	res, acct, err := s.opts.CloudAgents.ConnectWith(r.Context(), body.Connector, body.credentials())
	if err != nil {
		writeCloudAgentsErr(w, err)
		return
	}
	out := map[string]any{"probe": res, "account": acct}
	if acct != nil {
		s.recordManageAudit(r, "cloud_agents_connect", fmt.Sprintf("connector=%s account=%d", acct.Connector, acct.ID))
		sync, err := s.opts.CloudAgents.SyncAccount(r.Context(), acct.ID)
		if err != nil && !cloudagentssvc.IsCollectionError(err) {
			writeCloudAgentsErr(w, err)
			return
		}
		out["sync"] = sync
	}
	writeJSON(w, out)
}

// handleCloudAgentsSyncAll serves POST /api/cloud-agents/sync, the
// dashboard twin of `observer cloud-agents sync` with no account id: one pass
// of every linked account, in turn. A vendor-side failure is recorded on its
// account and carried in that account's result (error_class); only a local
// error answers non-200. With no account linked it makes no call and answers
// an empty list.
func (s *Server) handleCloudAgentsSyncAll(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.cloudAgentsUnavailable(w) {
		return
	}
	res, err := s.opts.CloudAgents.SyncAll(r.Context())
	if err != nil {
		writeCloudAgentsErr(w, err)
		return
	}
	if res == nil {
		res = []cloudagentssvc.SyncResult{}
	}
	writeJSON(w, map[string]any{"syncs": res})
}

// handleCloudAgentsAccount serves the per-account POST routes.
func (s *Server) handleCloudAgentsAccount(w http.ResponseWriter, r *http.Request) {
	if !requireConfirmToken(w, r) {
		return
	}
	if s.cloudAgentsUnavailable(w) {
		return
	}
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/cloud-agents/accounts/"), "/")
	idText, verb, _ := strings.Cut(rest, "/")
	id, err := strconv.ParseInt(idText, 10, 64)
	if err != nil || id <= 0 {
		writeErrStatus(w, errors.New("unknown account"), http.StatusNotFound)
		return
	}
	switch verb {
	case "sync":
		res, err := s.opts.CloudAgents.SyncAccount(r.Context(), id)
		if err != nil && !cloudagentssvc.IsCollectionError(err) {
			writeCloudAgentsErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"sync": res})
	case "disconnect":
		if err := s.opts.CloudAgents.Disconnect(r.Context(), id); err != nil {
			writeCloudAgentsErr(w, err)
			return
		}
		s.recordManageAudit(r, "cloud_agents_disconnect", fmt.Sprintf("account=%d", id))
		writeJSON(w, map[string]any{"ok": true})
	case "users":
		uc, err := s.opts.CloudAgents.UserCandidates(r.Context(), id)
		if err != nil {
			writeCloudAgentsErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"users": uc})
	case "user":
		var body struct {
			UserID string `json:"user_id"`
		}
		if err := decodeJSONBody(r, &body); err != nil {
			writeErrStatus(w, errors.New("the request body is not valid JSON"), http.StatusBadRequest)
			return
		}
		acct, err := s.opts.CloudAgents.ChooseVendorUser(r.Context(), id, body.UserID)
		if err != nil {
			writeCloudAgentsErr(w, err)
			return
		}
		s.recordManageAudit(r, "cloud_agents_choose_user", fmt.Sprintf("account=%d", id))
		sync, err := s.opts.CloudAgents.SyncAccount(r.Context(), id)
		if err != nil && !cloudagentssvc.IsCollectionError(err) {
			writeCloudAgentsErr(w, err)
			return
		}
		writeJSON(w, map[string]any{"account": acct, "sync": sync})
	default:
		writeErrStatus(w, errors.New("unknown account action"), http.StatusNotFound)
	}
}
