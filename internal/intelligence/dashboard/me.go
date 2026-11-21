package dashboard

import (
	"net/http"
	"os"
	"os/user"
	"time"

	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/machineid"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// me.go serves the three READ-ONLY routes behind the dashboard's You page
// (docs/you-page.md): the AI tool accounts seen on this machine, this
// machine's identity as the org would see it, and which keychain services
// Observer has written. Every other You section reads a route that already
// exists. None of these routes returns a secret: the machine routes carry only
// the hashed fingerprint, and the credentials route carries a presence word.

// handleMeToolAccounts serves GET /api/me/tool-accounts.
func (s *Server) handleMeToolAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	tools := []store.MeToolAccounts{}
	if s.opts.DB != nil {
		got, err := store.New(s.opts.DB).LoadMeToolAccounts(r.Context())
		if err != nil {
			writeErr(w, err)
			return
		}
		if got != nil {
			tools = got
		}
	}
	writeJSON(w, map[string]any{"tools": tools})
}

// meMachineResponse is GET /api/me/machine.
type meMachineResponse struct {
	// Fingerprint is the org-salted value when enrolled (what the org sees),
	// else a display-only value; empty when the machine is unbindable.
	Fingerprint string `json:"fingerprint"`
	// Source is os, seed, hostname or none: where the identity came from.
	Source string `json:"source"`
	// OrgBound is true when Fingerprint is the value the enrolled org holds.
	OrgBound bool `json:"org_bound"`
	// Host and OSUser name this machine and the account the daemon runs as
	// (empty when the OS does not say).
	Host   string `json:"host,omitempty"`
	OSUser string `json:"os_user,omitempty"`
}

// handleMeMachine serves GET /api/me/machine.
func (s *Server) handleMeMachine(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	orgID := ""
	if s.opts.OrgClient != nil {
		if st, err := s.opts.OrgClient.Status(r.Context()); err == nil && st.Enrolled {
			orgID = st.OrgID
		}
	}
	info, err := machineid.Describe(orgID)
	if err != nil {
		writeErr(w, err)
		return
	}
	host, _ := os.Hostname()
	osUser := ""
	if u, uerr := user.Current(); uerr == nil {
		osUser = u.Username
	}
	writeJSON(w, meMachineResponse{Fingerprint: info.Fingerprint, Source: string(info.Source), OrgBound: info.OrgBound, Host: host, OSUser: osUser})
}

// meCredentialRow is one keychain service Observer writes.
type meCredentialRow struct {
	Service string `json:"service"`
	Purpose string `json:"purpose"`
	// Owner is the dashboard path that manages it.
	Owner string `json:"owner"`
	// Presence is present, absent, unknown (the record names depend on what
	// was added), unavailable (the OS keychain could not be read) or
	// not_checked.
	Presence string `json:"presence"`
}

// handleMeCredentials serves GET /api/me/credentials. Without ?check=1 it
// lists the services and touches no keychain; with it, each service with
// fixed record names is looked up and only a presence word comes back.
func (s *Server) handleMeCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	check := r.URL.Query().Get("check") == "1"
	infos := keystore.Services()
	var presence []keystore.Presence
	if check {
		presence = keystore.CheckPresenceAll(infos)
	}
	rows := make([]meCredentialRow, 0, len(infos))
	for i, in := range infos {
		p := "not_checked"
		if check {
			p = string(presence[i])
		}
		rows = append(rows, meCredentialRow{Service: in.Service, Purpose: in.Purpose, Owner: in.Owner, Presence: p})
	}
	writeJSON(w, map[string]any{"checked": check, "services": rows})
}

// meAggregateResponse is GET /api/me/aggregate-share: the opt-in community
// aggregate rail's switch and consent receipt, read-only. Withdrawing is not
// served here.
type meAggregateResponse struct {
	// Available is false when this build does not carry the
	// egress.aggregate-share component (Options.AggregateShareStatus nil).
	Available bool `json:"available"`
	// Enabled is [aggregate_share].enabled (default off).
	Enabled bool `json:"enabled"`
	// Status is the consent check: valid, disabled, missing, or a changed
	// schema / endpoint / registry that suspends sharing until re-consent.
	Status string `json:"status,omitempty"`
	// ConsentedAt, Actor and SchemaVersion come from the current receipt;
	// absent when no receipt exists.
	ConsentedAt   string `json:"consented_at,omitempty"`
	Actor         string `json:"actor,omitempty"`
	SchemaVersion int    `json:"schema_version,omitempty"`
}

// handleMeAggregateShare serves GET /api/me/aggregate-share through the
// AggregateShareStatus seam, so the dashboard imports no package of the
// optional egress.aggregate-share component.
func (s *Server) handleMeAggregateShare(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.AggregateShareStatus == nil {
		writeJSON(w, meAggregateResponse{})
		return
	}
	st, err := s.opts.AggregateShareStatus(r.Context())
	if err != nil {
		writeErr(w, err)
		return
	}
	resp := meAggregateResponse{Available: true, Enabled: st.Enabled, Status: st.Status, Actor: st.Actor, SchemaVersion: st.SchemaVersion}
	if !st.ConsentedAt.IsZero() {
		resp.ConsentedAt = st.ConsentedAt.UTC().Format(time.RFC3339)
	}
	writeJSON(w, resp)
}
