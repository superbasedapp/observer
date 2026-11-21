package dashboard

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud_account.go is the NODE dashboard's Cloud ACCOUNT surface — the
// "sign-in button somewhere prominent" (operator directive 2026-09-03): sign-in
// state on GET /api/cloud/status, the Sign in / Sign out actions behind
// POST /api/cloud/login, GET /api/cloud/login/state and POST /api/cloud/logout,
// and the "Sync now" action behind POST /api/cloud/sync + GET
// /api/cloud/sync/state (operator directive: every `observer cloud` CLI verb
// needs a dashboard equivalent) — the dashboard equivalent of
// `observer cloud sync`.
//
// # Zero-egress by construction
//
// This package links NOTHING from the cloud lane — not cloudclient / cloudpop /
// cloudcred (pinned by tests/invariant/cloud_egress_test.go) and not even the
// consent-gated internal/cloudgateway seam. Both halves are INJECTED from
// cmd/observer as plain funcs through CloudAccountSeams (the same
// `cmd/observer/*_wire.go` discipline as Governance / BuildHandoff):
//
//   - CloudSignInProbe answers "is a sign-in stored on this device?" exactly the
//     way `observer cloud status` does — a LOCAL keychain read, no network.
//   - CloudCommandRunner runs ONE `observer cloud <verb>` as a SUBPROCESS of the
//     running binary, precisely the way cmd/observer/cloudautosync.go spawns
//     `cloud sync`. The child is the exact consent-gated CLI a human types;
//     the daemon itself makes no network call and holds no credential handle.
//
// The login subprocess prints the AuthKit authorize URL before it blocks on the
// loopback callback; the state machine below captures that URL from the
// child's output so the page can offer "Open sign-in page" as a link when the
// automatic browser open does not reach the operator (headless / remote
// desktop / the WSL hop failing). One login at a time: a second POST while one
// is running returns the current state rather than spawning a second listener
// on the fixed 127.0.0.1:9797 port.
//
// Sync follows the SAME one-at-a-time shape (its own in-memory run, guarded by
// the same mutex): POST /api/cloud/sync spawns `observer cloud sync` unless one
// is already running (a second POST then returns the current state, 200, not a
// second spawn) or a sign-in is currently running (409 — the two would race on
// the credential store / outbox). It refuses 409 up front when no sign-in is
// stored — sync cannot succeed without one. GET /api/cloud/sync/state reports
// the run plus the store-derived LastResultAt (the same fact
// CloudStatusResponse.LastResultAt reports) so the card needs no second fetch.
//
// Nil seams (Options.CloudAccount == nil — `observer dashboard` embedders and
// tests that never set it) leave the status payload without a `sign_in` block
// and make the action routes answer 503 with honest copy.

// --- routes ------------------------------------------------------------------

// registerCloudAccountRoutes registers the five action routes. All are Local
// (owner-loopback-only, never remotely reachable): sign-in opens a browser and
// stores a credential on THIS machine, sign-out clears one, sync drains the
// outbox and pulls results — all machine-reaching mutations by definition —
// and the login state carries the PKCE authorize URL, which a remote viewer
// has no business seeing. reg is dashboard.go's local registration closure,
// passed in so this file adds one line there.
func (s *Server) registerCloudAccountRoutes(reg func(pattern string, cap Capability, section Section, h http.HandlerFunc)) {
	reg("/api/cloud/login", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudLogin)
	reg("/api/cloud/login/state", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudLoginState)
	reg("/api/cloud/logout", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudLogout)
	reg("/api/cloud/sync", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudSync)
	reg("/api/cloud/sync/state", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudSyncState)
	// cloud_consent.go: the preview / per-session-consent / standing-grant
	// management / delete-account surface (operator directive: every
	// `observer cloud` verb needs a dashboard equivalent, and the session card
	// gets buttons instead of copy-paste CLI blocks).
	reg("/api/cloud/preview", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudPreview)
	reg("/api/cloud/consent", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudConsent)
	reg("/api/cloud/consent/grants", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudConsentGrants)
	reg("/api/cloud/consent/grant", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudConsentGrant)
	reg("/api/cloud/consent/revoke", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudConsentRevoke)
	reg("/api/cloud/delete-account", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudDeleteAccount)
	// cloud_policy.go: the standing Turn on / Turn off actions (thin wrappers
	// over `observer cloud enable`/`disable`) and the content-free "What we
	// sent" ledger read (value-upgrade plan §W2).
	reg("/api/cloud/enable", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudEnable)
	reg("/api/cloud/disable", CapabilityLocal, SectionSettings.WithSettings("cloud"), s.handleCloudDisable)
	reg("/api/cloud/ledger", CapabilityView, SectionSettings.WithSettings("cloud"), s.handleCloudLedger)
	// cloud_events.go: the Sessions-page toast/banner poll (value-upgrade
	// plan §W3) — a pure store read, same class as /api/cloud/status.
	reg("/api/cloud/events", CapabilityView, SectionSettings.WithSettings("cloud"), s.handleCloudEvents)
	// cloud_digests.go: the weekly project digests `observer cloud sync`
	// has pulled back (value-upgrade plan §W5) — a pure store read, same
	// class as /api/cloud/status.
	reg("/api/cloud/digests", CapabilityView, SectionSettings.WithSettings("cloud"), s.handleCloudDigests)
}

// cloudAccountUnavailable is the 503 copy when no runner is wired.
const cloudAccountUnavailable = "cloud account actions are not available on this dashboard (no `observer cloud` runner is wired - run `observer start`, or use `observer cloud login` / `observer cloud logout` / `observer cloud sync` in a terminal)"

// cloudAccountSeams returns the seams when the action routes can work.
func (s *Server) cloudAccountSeams(w http.ResponseWriter) (*CloudAccountSeams, bool) {
	c := s.opts.CloudAccount
	if c == nil || c.Run == nil {
		http.Error(w, cloudAccountUnavailable, http.StatusServiceUnavailable)
		return nil, false
	}
	return c, true
}

// cloudOrgEnrolledMessage is the 409 body when a personal sign-in is refused
// because this node is org-enrolled — enterprise-first: an enrolled node's
// sessions are stamped authority='org' and are excluded from personal cloud
// enrichment (internal/store/dataauthority.go, internal/cloudevidence), so a
// personal sign-in here would complete but enrich nothing.
const cloudOrgEnrolledMessage = "org-enrolled: personal sign-in is managed by your organization and is unavailable on this machine"

// orgEnrolled reports whether this node is currently enrolled in an org,
// reading the SAME local seam handleEnrolmentStatus uses (Options.OrgClient) —
// a local credential/state read, no network call. A nil OrgClient (solo-local
// install) or a status error is treated as "not enrolled" so a transient probe
// failure never blocks a legitimate personal sign-in.
func (s *Server) orgEnrolled(ctx context.Context) (enrolled bool, orgName string) {
	if s.opts.OrgClient == nil {
		return false, ""
	}
	st, err := s.opts.OrgClient.Status(ctx)
	if err != nil || !st.Enrolled {
		return false, ""
	}
	return true, st.OrgName
}

// cloudLoginManagedRefusal reports whether a personal sign-in is refused
// here: only on a machine an ORGANIZATION manages, whose identity and
// content belong to the organization. Getting started v2 lifted the refusal
// for an individual connection (a personal dashboard or an individual team
// connection): there the sign-in is the person's own SuperBased account,
// the same one `observer connect` signs in with, and signing in never moves
// data. An enrolment whose kind cannot be read stays refused (fail closed),
// as before.
func (s *Server) cloudLoginManagedRefusal(ctx context.Context) bool {
	enrolled, _ := s.orgEnrolled(ctx)
	if !enrolled {
		return false
	}
	return s.enrolmentTenancy(ctx) != orgcontract.TenancyIndividual
}

// handleCloudLogin serves POST /api/cloud/login: spawns `observer cloud login`
// (one at a time) and returns the login state. A missing client id is refused
// up front with the honest "set [cloud].workos_client_id or WORKOS_CLIENT_ID"
// line — the CLI would only print how to configure and exit 0, which the page
// could not tell from a sign-in. A second POST while one runs returns the
// current state (200) rather than a second spawn. An org-enrolled node refuses
// with 409 BEFORE any subprocess is spawned when an organization manages it
// — enterprise-first (see cloudOrgEnrolledMessage, cloudLoginManagedRefusal).
func (s *Server) handleCloudLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	if s.cloudLoginManagedRefusal(r.Context()) {
		writeJSONStatus(w, http.StatusConflict, map[string]string{
			"error":   "org_enrolled",
			"message": cloudOrgEnrolledMessage,
		})
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	if c.Probe != nil {
		st, err := c.Probe()
		if err != nil {
			writeErr(w, err)
			return
		}
		if !st.ClientIDConfigured {
			http.Error(w, "no WorkOS client id is configured - enter it under Advanced in Settings > Account ([cloud].workos_client_id) and save, or set the WORKOS_CLIENT_ID environment variable, then try again", http.StatusConflict)
			return
		}
	}
	st, err := c.StartLogin(s.now())
	if err != nil && !errors.Is(err, dashapi.ErrCloudLoginRunning) {
		writeErr(w, err)
		return
	}
	writeJSON(w, st)
}

// handleCloudLoginState serves GET /api/cloud/login/state.
func (s *Server) handleCloudLoginState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if _, ok := s.cloudAccountSeams(w); !ok {
		return
	}
	writeJSON(w, s.opts.CloudAccount.State())
}

// CloudLogoutResponse is the payload for POST /api/cloud/logout.
type CloudLogoutResponse struct {
	OK      bool   `json:"ok"`
	Message string `json:"message,omitempty"`
}

// handleCloudLogout serves POST /api/cloud/logout: runs `observer cloud logout`
// synchronously (best-effort server revocation, then local clear — the CLI's
// own semantics) and reports its output.
func (s *Server) handleCloudLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	msg, err := c.Logout(r.Context())
	if errors.Is(err, dashapi.ErrCloudLoginRunning) {
		http.Error(w, "a sign-in is running - wait for it to finish (or time out) before signing out", http.StatusConflict)
		return
	}
	resp := CloudLogoutResponse{OK: err == nil, Message: msg}
	if err != nil {
		resp.Message = strings.TrimSpace("sign-out failed: " + err.Error() + " " + msg)
	}
	writeJSON(w, resp)
}

// cloudNotSignedInMessage is the 409 body when sync is refused because no
// sign-in is stored — sync cannot succeed without one.
const cloudNotSignedInMessage = "Not signed in. Sign in above before syncing."

// handleCloudSync serves POST /api/cloud/sync: spawns `observer cloud sync`
// (one at a time — the dashboard equivalent of the CLI verb, operator
// directive that every `observer cloud` verb needs a dashboard equivalent).
// Refused up front, before any subprocess: a sign-in is currently running
// (409 — the two would race on the credential store/outbox), or no sign-in is
// stored at all (409 — sync cannot succeed without one). A second POST while a
// sync is already running returns the current state (200) rather than a
// second spawn, mirroring handleCloudLogin.
func (s *Server) handleCloudSync(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", http.StatusMethodNotAllowed)
		return
	}
	sessionID, err := decodeCloudSyncSession(w, r)
	if err != nil {
		http.Error(w, "invalid sync request: "+err.Error(), http.StatusBadRequest)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	if c.LoginRunning() {
		http.Error(w, "a sign-in is running - wait for it to finish (or time out) before syncing", http.StatusConflict)
		return
	}
	if c.Probe != nil {
		st, err := c.Probe()
		if err != nil {
			writeErr(w, err)
			return
		}
		if !st.APITokenPresent && !st.WorkOSSignInPresent {
			http.Error(w, cloudNotSignedInMessage, http.StatusConflict)
			return
		}
	}
	st, err := c.StartSync(s.now(), sessionID)
	if errors.Is(err, dashapi.ErrCloudSyncScopeConflict) {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	if err != nil && !errors.Is(err, dashapi.ErrCloudSyncRunning) {
		writeErr(w, err)
		return
	}
	writeJSON(w, st)
}

// handleCloudSyncState serves GET /api/cloud/sync/state.
func (s *Server) handleCloudSyncState(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	c, ok := s.cloudAccountSeams(w)
	if !ok {
		return
	}
	writeJSON(w, c.SyncState(r.Context(), store.New(s.db())))
}
