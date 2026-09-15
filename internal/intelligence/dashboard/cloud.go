package dashboard

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloud.go serves the NODE dashboard's Cloud Intelligence surfaces (plan of
// record docs/plans/cloud-intelligence-azure-foundry-plan-of-record-2026-08-30.md
// §6 "CI-P5" node bullet). Both endpoints render node-local state ONLY — nothing
// here talks to the hosted service. Store-derived facts are read here; the
// LOCAL sign-in presence (keychain read, no network) and the Sign in / Sign
// out actions come through the injected seams in cloud_account.go, so this
// package still links nothing from the cloud network + credential lane
// (§CI-P2: `observer cloud` owns it; the daemon spawns that CLI).
//
// Aggregate reads (receipt/outbox/result counts, per-session outbox) go through
// exported context-aware methods on internal/store (beside cloudlocal.go), NOT
// ad-hoc SQL here — the §7.7 "one store seam per database" invariant (FF1). The
// handler only decides how to DEGRADE: every seam call that errors (e.g. a
// pre-migration-097 schema with no cloud tables) leaves the field at its
// empty/zero value so the surface renders its honest optional-feature state
// instead of a 500. The seam returns errors; the handler chooses empty. The
// cloud_* tables are NODE-LOCAL (never on the org-push wire).

// cloudManualDescriptor describes the shared consent-gated manual and scheduled paths.
const cloudManualDescriptor = "Choose a session to enrich, or enable automatic enrichment in Settings. Every upload requires consent; scheduled enrichment and sync run while the node daemon is running."

// CloudStatusResponse is the payload for GET /api/cloud/status — the Cloud
// Intelligence config-section status card: store-derived facts plus, when the
// cmd/observer seam is wired, the local sign-in presence (SignIn).
type CloudStatusResponse struct {
	// Active is true when the node-local store shows the feature has been used
	// (any consent receipt, outbox item, result, or a saved result cursor).
	// It is NOT a sign-in state — an unconfigured node with no cloud activity
	// reads Active=false, which drives the honest "optional feature" empty copy.
	Active bool `json:"active"`
	// ReceiptsTotal / ReceiptsLive are consent-receipt counts (live = not yet
	// invalidated).
	ReceiptsTotal int `json:"receipts_total"`
	ReceiptsLive  int `json:"receipts_live"`
	// OutboxByState maps each outbox state to its count. reconfirmation_required
	// is surfaced explicitly by the UI as a distinct chip.
	OutboxByState map[string]int `json:"outbox_by_state"`
	OutboxTotal   int            `json:"outbox_total"`
	// SendableCount is the pending+failed_retryable subset (the manual drain
	// set), read through the store seam so it matches `observer cloud status`.
	SendableCount int `json:"sendable_count"`
	// ResultsTotal / LastResultAt describe synced enrichment results.
	ResultsTotal int    `json:"results_total"`
	LastResultAt string `json:"last_result_at,omitempty"`
	// HasSynced is true once `observer cloud sync` has advanced the result
	// cursor at least once.
	HasSynced bool `json:"has_synced"`
	// AllowanceKnown is always false this arc: the free-tier allowance is
	// reported by the server at sync and is NOT stored node-side, so the UI
	// renders an honest placeholder rather than a fabricated number.
	AllowanceKnown bool `json:"allowance_known"`
	// Descriptor is the static manual-only honesty statement.
	Descriptor string `json:"descriptor"`
	// SignIn is the LOCAL sign-in state (credential presence + backend +
	// whether a client id resolves), read through the injected
	// CloudSignInProbe the way `observer cloud status` reads it — a keychain
	// read, never a network call. Omitted entirely when Options.CloudAccount
	// is not wired (embedders / tests), so the UI degrades to its old
	// "state lives with the CLI" copy rather than a fabricated "not signed in".
	SignIn *CloudSignInView `json:"sign_in,omitempty"`
	// Policy is the developer's own standing enrichment policy (`observer
	// cloud enable` / `observer cloud disable`, migration 115) — which level
	// the background path may mint per-session receipts under, and whether
	// background enrichment runs at all. nil means no row has ever been
	// recorded (the developer has never run `observer cloud enable`).
	Policy *CloudEnrichPolicyView `json:"policy"`
	// Disclosure is the provider-retention disclosure, verbatim
	// (cloudcontract.ProviderPostureDisclosure), rendered wherever the enable
	// flow states it.
	Disclosure string `json:"disclosure"`
	// PolicyVersion is the privacy-policy version the disclosure was
	// published under (cloudcontract.ProviderPosturePolicyVersion).
	PolicyVersion string `json:"policy_version"`
	// LastSync is the outcome of the most recent `observer cloud sync` run
	// (migration 117's cloud_sync_last singleton, dashboard-spawned/
	// auto-sync/manual all write the same row) — nil when it has never run.
	LastSync *CloudSyncLastView `json:"last_sync"`
	// ProviderState is a simple, honest derivation from LastSync: "waiting"
	// iff the last sync reported waiting_provider > 0, "accepting" iff it
	// reported results > 0 or sent > 0 with waiting_provider == 0, else
	// "unknown" (never synced, or the last sync moved nothing either way).
	ProviderState string `json:"provider_state"`
	// Plan is the account plan the most recent `observer cloud sync`
	// observed via GET /v1/usage (migration 118's cloud_sync_last plan
	// columns) — nil when unknown (no sync has ever reported one, or every
	// usage fetch so far has failed).
	Plan *CloudPlanView `json:"plan"`
}

// CloudPlanView renders the account plan facts the last successful usage
// fetch observed. DigestWeekly / ResultsRetentionDays stay nilable all the
// way to the wire: nil means "this device does not know", never a
// fabricated false/zero (value-upgrade plan §W5 honesty rule).
type CloudPlanView struct {
	Name                 string `json:"name"`
	Label                string `json:"label"`
	DailyCap             *int   `json:"daily_cap,omitempty"`
	MonthlyCap           *int   `json:"monthly_cap,omitempty"`
	DigestWeekly         *bool  `json:"digest_weekly"`
	ResultsRetentionDays *int   `json:"results_retention_days"`
	// AsOf is the finished_at of the sync run this plan was observed on.
	AsOf string `json:"as_of,omitempty"`
}

// CloudSyncLastView renders internal/store.CloudSyncLast for the dashboard.
type CloudSyncLastView struct {
	StartedAt       string `json:"started_at"`
	FinishedAt      string `json:"finished_at"`
	OK              bool   `json:"ok"`
	Sent            int    `json:"sent"`
	WaitingProvider int    `json:"waiting_provider"`
	Reconfirm       int    `json:"reconfirm"`
	Failed          int    `json:"failed"`
	Results         int    `json:"results"`
	SignInExpired   bool   `json:"sign_in_expired"`
	ErrorClass      string `json:"error_class,omitempty"`
}

// cloudProviderState derives GET /api/cloud/status's honest "provider_state"
// from the last sync outcome (nil = never synced ⇒ "unknown").
func cloudProviderState(last *CloudSyncLastView) string {
	if last == nil {
		return "unknown"
	}
	if last.WaitingProvider > 0 {
		return "waiting"
	}
	if last.Results > 0 || last.Sent > 0 {
		return "accepting"
	}
	return "unknown"
}

// CloudEnrichPolicyView renders internal/store.CloudEnrichPolicy for the
// dashboard.
type CloudEnrichPolicyView struct {
	EvidenceSettings *store.CloudEvidenceSettings `json:"evidence_settings"`
	Level            string                       `json:"level"`
	Background       bool                         `json:"background"`
	PolicyVersion    string                       `json:"policy_version"`
	Source           string                       `json:"source"`
	UpdatedAt        string                       `json:"updated_at,omitempty"`
	Since            string                       `json:"since,omitempty"`
}

// handleCloudStatus serves GET /api/cloud/status. Read-only node-local facts,
// all read through the internal/store seam (FF1). Each seam call degrades to
// its empty/zero value on error so the surface renders honest optional-feature
// state instead of a 500.
func (s *Server) handleCloudStatus(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	st := store.New(s.db())
	resp := CloudStatusResponse{
		OutboxByState:  map[string]int{},
		AllowanceKnown: false,
		Descriptor:     cloudManualDescriptor,
		Disclosure:     cloudcontract.ProviderPostureDisclosure,
		PolicyVersion:  cloudcontract.ProviderPosturePolicyVersion,
	}

	// The developer's own standing enrichment policy (migration 115). nil
	// stays nil (never recorded) on any error, incl. a pre-115 schema.
	if policy, ok, err := st.GetCloudEnrichPolicy(ctx); err == nil && ok {
		resp.Policy = &CloudEnrichPolicyView{
			Level:            string(policy.Level),
			EvidenceSettings: policy.EvidenceSettings,
			Background:       policy.Background,
			PolicyVersion:    policy.PolicyVersion,
			Source:           policy.Source,
			UpdatedAt:        cloudRFC3339(policy.UpdatedAt),
			Since:            cloudRFC3339(policy.Since),
		}
	}

	// Consent receipts: total + live (not invalidated).
	if total, live, err := st.CloudReceiptCounts(ctx); err == nil {
		resp.ReceiptsTotal = total
		resp.ReceiptsLive = live
	}

	// Outbox counts grouped by every state (incl. reconfirmation_required and
	// the terminal states ListSendableCloudOutbox omits).
	if byState, total, err := st.CloudOutboxCountsByState(ctx); err == nil {
		resp.OutboxByState = byState
		resp.OutboxTotal = total
	}

	// Sendable subset through the store seam so the number matches the CLI's
	// `observer cloud status` "outbox (sendable)" line exactly.
	if items, err := st.ListSendableCloudOutbox(ctx); err == nil {
		resp.SendableCount = len(items)
	}

	// Results: count + newest received_at (RFC3339Nano UTC strings, so MAX is
	// chronological).
	if total, last, err := st.CloudResultsSummary(ctx); err == nil {
		resp.ResultsTotal = total
		resp.LastResultAt = last
	}

	if has, err := st.HasCloudResultCursor(ctx); err == nil {
		resp.HasSynced = has
	}

	// The last `observer cloud sync` outcome (migration 117). nil stays nil
	// on any error, incl. a pre-117 schema — the honest "never" state.
	if last, ok, err := st.GetCloudSyncLast(ctx); err == nil && ok {
		resp.LastSync = &CloudSyncLastView{
			StartedAt:       cloudRFC3339(last.StartedAt),
			FinishedAt:      cloudRFC3339(last.FinishedAt),
			OK:              last.OK,
			Sent:            last.Sent,
			WaitingProvider: last.WaitingProvider,
			Reconfirm:       last.Reconfirm,
			Failed:          last.Failed,
			Results:         last.Results,
			SignInExpired:   last.SignInExpired,
			ErrorClass:      last.ErrorClass,
		}
		// W5 (migration 118): the account plan the run observed via GET
		// /v1/usage. nil when the run never resolved a plan name (an older
		// row, or a usage fetch that has never yet succeeded) — never
		// fabricated.
		if last.PlanName != "" {
			resp.Plan = &CloudPlanView{
				Name: last.PlanName, Label: last.PlanLabel,
				DailyCap: last.DailyCap, MonthlyCap: last.MonthlyCap,
				DigestWeekly:         cloudIntPtrToBoolPtr(last.DigestWeekly),
				ResultsRetentionDays: last.ResultsRetentionDays,
				AsOf:                 cloudRFC3339(last.FinishedAt),
			}
		}
	}
	resp.ProviderState = cloudProviderState(resp.LastSync)

	resp.Active = resp.ReceiptsTotal > 0 || resp.OutboxTotal > 0 || resp.ResultsTotal > 0 || resp.HasSynced
	// Sign-in presence through the injected seam (cloud_account.go). nil-safe:
	// an unwired dashboard omits the block.
	resp.SignIn = s.opts.CloudAccount.signInView()
	writeJSON(w, resp)
}

// CloudOutboxView is one outbox row for the session surface (any state). It
// carries NO envelope body — the outbox never stores one.
type CloudOutboxView struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	RetryCount int    `json:"retry_count"`
	LastError  string `json:"last_error,omitempty"`
	ReceiptID  string `json:"receipt_id"`
	CreatedAt  string `json:"created_at,omitempty"`
	UpdatedAt  string `json:"updated_at,omitempty"`
}

// CloudReceiptView is a consent receipt bound to the session (referenced by one
// of its outbox items). Content-free: purpose + invalidation state only.
type CloudReceiptView struct {
	ID          string `json:"id"`
	Purpose     string `json:"purpose,omitempty"`
	Invalidated bool   `json:"invalidated"`
	CreatedAt   string `json:"created_at,omitempty"`
}

// CloudOverrideView is one user edit over a result field. The user value always
// wins on read (plan §6 CI-P5); the UI renders it as the effective value with a
// "your edit" mark over the AI suggestion.
type CloudOverrideView struct {
	UserValue string `json:"user_value"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// CloudResultView is the newest (non-superseded) enrichment result for the
// session plus its per-field overrides. Result is the validated, AI-suggested
// session_enrichment payload (title, taxonomy_tags, suggested_tags, …) passed
// through as raw JSON so this handler stays agnostic of the enrichment schema;
// the frontend applies override-wins per field and stamps the AI-source mark.
type CloudResultView struct {
	SchemaVersion string                       `json:"schema_version,omitempty"`
	ReceivedAt    string                       `json:"received_at,omitempty"`
	ModelRoute    string                       `json:"model_route,omitempty"`
	Result        json.RawMessage              `json:"result"`
	Overrides     map[string]CloudOverrideView `json:"overrides,omitempty"`
}

// CloudSessionResponse is the payload for GET /api/cloud/session/{id}. It renders
// the session's data-authority classification, its eligibility for personal
// cloud enrichment, any receipts/outbox items bound to it, and the newest
// enrichment result with overrides applied (override wins). An org/unknown
// session is reported as Excluded with an honest reason — never a broken button.
type CloudSessionResponse struct {
	SessionID string `json:"session_id"`
	// CloudSessionID is the pseudonym (e.g. "cs_...") this device already
	// minted for the session in cloud_session_map, if any — the ONLY
	// identifier the cloud service itself ever sees for this session; the
	// local uuid (SessionID) never leaves this machine. Omitted (never
	// minted here) when the session has never been enrolled for cloud
	// enrichment, so this handler stays read-only.
	CloudSessionID   string `json:"cloud_session_id,omitempty"`
	Authority        string `json:"authority"`
	AuthorityVersion int    `json:"authority_version,omitempty"`
	Eligible         bool   `json:"eligible"`
	// Excluded is true (with ExcludedReason set) whenever the session is not
	// eligible — org-owned or unknown authority. The UI renders an honest
	// excluded state rather than an enrich affordance.
	Excluded       bool                           `json:"excluded"`
	ExcludedReason string                         `json:"excluded_reason,omitempty"`
	Receipts       []CloudReceiptView             `json:"receipts"`
	Outbox         []CloudOutboxView              `json:"outbox"`
	Result         *CloudResultView               `json:"result,omitempty"`
	Progress       *store.CloudEnrichmentProgress `json:"progress"`
}

// handleCloudSession serves GET /api/cloud/session/{id}. Sub-route pattern
// distinct from /api/session/. Read-only node-local facts.
func (s *Server) handleCloudSession(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/cloud/session/")
	id = strings.Trim(id, "/")
	if id == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	db := s.db()
	st := store.New(db)

	resp := CloudSessionResponse{
		SessionID: id,
		Authority: "unknown",
		Receipts:  []CloudReceiptView{},
		Outbox:    []CloudOutboxView{},
	}

	// Cloud pseudonym, if this device already minted one — read-only (never
	// mints). Degrades to omitted on any error (incl. a pre-097 schema with
	// no cloud_session_map table), matching every other seam call below.
	if pseudonym, ok, perr := st.LookupCloudSessionPseudonym(ctx, id); perr == nil && ok {
		resp.CloudSessionID = pseudonym
	}

	// Authority classification. found=false means unknown authority (a pre-096
	// legacy row, a NULL stamp, or a missing session) — all ineligible.
	cls, found, err := st.SessionAuthority(ctx, id)
	if err != nil {
		http.Error(w, "load session authority: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if found {
		resp.Authority = string(cls.Authority)
		resp.AuthorityVersion = cls.Version
	}
	eligible, err := st.EligibleForPersonalCloud(ctx, id)
	if err != nil {
		http.Error(w, "load eligibility: "+err.Error(), http.StatusInternalServerError)
		return
	}
	resp.Eligible = eligible
	if !eligible {
		resp.Excluded = true
		switch resp.Authority {
		case "org":
			resp.ExcludedReason = "org-owned session — excluded from personal cloud enrichment"
		default:
			resp.ExcludedReason = "unknown data authority (org-owned or captured before classification) — excluded from personal cloud enrichment"
		}
	}

	// Outbox items bound to this session (any state), through the store seam
	// (FF1). Degrades to empty on error.
	if items, oerr := st.ListCloudOutboxForSession(ctx, id); oerr == nil {
		receiptIDs := map[string]struct{}{}
		for _, it := range items {
			resp.Outbox = append(resp.Outbox, CloudOutboxView{
				ID:         it.ID,
				State:      string(it.State),
				RetryCount: it.RetryCount,
				LastError:  it.LastError,
				ReceiptID:  it.ReceiptID,
				CreatedAt:  cloudRFC3339(it.CreatedAt),
				UpdatedAt:  cloudRFC3339(it.UpdatedAt),
			})
			if it.ReceiptID != "" {
				receiptIDs[it.ReceiptID] = struct{}{}
			}
		}
		// Receipts binding the session, resolved through the store seam (one
		// per distinct receipt id referenced by the session's outbox).
		for _, v := range resp.Outbox {
			if _, ok := receiptIDs[v.ReceiptID]; !ok {
				continue
			}
			delete(receiptIDs, v.ReceiptID)
			rcpt, ok, rerr := st.GetCloudConsentReceipt(ctx, v.ReceiptID)
			if rerr != nil || !ok {
				continue
			}
			resp.Receipts = append(resp.Receipts, CloudReceiptView{
				ID:          rcpt.ID,
				Purpose:     rcpt.Purpose,
				Invalidated: rcpt.InvalidatedAt != nil,
				CreatedAt:   cloudRFC3339(rcpt.CreatedAt),
			})
		}
	}

	// Newest result + overrides (override wins). Absent → no result card.
	res, overrides, ok, rerr := st.GetCloudSessionResult(ctx, id)
	if rerr == nil && ok {
		rv := &CloudResultView{
			SchemaVersion: res.SchemaVersion,
			ReceivedAt:    cloudRFC3339(res.ReceivedAt),
			ModelRoute:    res.Provenance.ModelRoute,
			Result:        json.RawMessage(res.ResultJSON),
		}
		if len(overrides) > 0 {
			rv.Overrides = map[string]CloudOverrideView{}
			for field, o := range overrides {
				rv.Overrides[field] = CloudOverrideView{
					UserValue: o.UserValue,
					UpdatedAt: cloudRFC3339(o.UpdatedAt),
				}
			}
		}
		resp.Result = rv
	}

	resp.Progress = s.cloudEnrichmentProgress(ctx, st, []string{id})[id]
	writeJSON(w, resp)
}

// cloudRFC3339 renders a time as RFC3339 UTC, or "" for the zero time so the
// handler never emits "0001-01-01…" for an unset stamp.
func cloudRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// cloudIntPtrToBoolPtr converts store.CloudSyncLast.DigestWeekly's 0/1 *int
// representation (matching migration 118's INTEGER column) to the wire's
// *bool — nil stays nil (unknown), never a fabricated false.
func cloudIntPtrToBoolPtr(p *int) *bool {
	if p == nil {
		return nil
	}
	v := *p != 0
	return &v
}
