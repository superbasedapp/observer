package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/orgdeletion"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// portal_deletion.go is the console's org deletion and the account
// deletion's org precheck (managed-SaaS plan 07 M6.9 and M7a.1; cloud
// 0120). An owner opens a cooling-off deletion of an org and may cancel it
// until the window ends; every member sees its state; the worker's deletion
// driver (internal/cloudserver/orgdeletion) does the rest. The account
// deletion route itself is the existing POST /portal/api/deletion-requests;
// this file adds its precheck and the 409 the store answers when the
// account's orgs block it.

// The console's codes for this file.
const (
	accountDeletionBlockedCode = "account_deletion_blocked"
	// personalOrgRefusal: a personal org is deleted with its account, never
	// from the team deletion route (FR-11).
	personalOrgRefusal = "personal_org"
	// billingCancelUnavailableRefusal: the team has a live subscription and
	// this deployment cannot cancel it at Paddle (no API key), so the
	// deletion is refused up front instead of blocking at cancel_billing
	// after the window (FR-1).
	billingCancelUnavailableRefusal = "billing_cancel_unavailable"
)

// mountPortalDeletion registers the deletion routes on mux.
func (s *Server) mountPortalDeletion(mux *http.ServeMux) {
	mux.Handle("GET /portal/api/orgs/{id}/deletion", s.portalAuth(http.HandlerFunc(s.handlePortalOrgDeletion)))
	mux.Handle("POST /portal/api/orgs/{id}/deletion", s.portalAuth(http.HandlerFunc(s.handlePortalOrgDeletionRequest)))
	mux.Handle("DELETE /portal/api/orgs/{id}/deletion", s.portalAuth(http.HandlerFunc(s.handlePortalOrgDeletionCancel)))
	mux.Handle("GET /portal/api/account/deletion-precheck", s.portalAuth(http.HandlerFunc(s.handlePortalAccountDeletionPrecheck)))
}

// orgDeletionJSON is one deletion request.
type orgDeletionJSON struct {
	RequestID     string `json:"request_id"`
	State         string `json:"state"`
	Step          string `json:"step"`
	Origin        string `json:"origin"`
	RequestedAt   string `json:"requested_at"`
	PurgeAfter    string `json:"purge_after"`
	CanceledAt    string `json:"canceled_at,omitempty"`
	DoneAt        string `json:"done_at,omitempty"`
	BlockedReason string `json:"blocked_reason,omitempty"`
	CanCancel     bool   `json:"can_cancel"`
}

// orgDeletionPreviewJSON is what an owner's request would do now.
type orgDeletionPreviewJSON struct {
	CanRequest     bool   `json:"can_request"`
	Refusal        string `json:"refusal"`
	CoolingOffDays int    `json:"cooling_off_days"`
	PurgeAfter     string `json:"purge_after"`
	// LiveSubscription reports a subscription the deletion cancels so it
	// stops renewing (orgdeletion.Subscription.MayBill: a refunded or
	// charged-back one too, which Paddle still renews).
	LiveSubscription bool     `json:"live_subscription"`
	Members          int      `json:"members"`
	Kept             []string `json:"kept"`
	// Reauth is the re-authentication a request needs (FR-23):
	// "step_up" (the WorkOS step-up leg; a passkey used in this session in
	// the last five minutes also counts), "broker_token" (dev sign-in) or
	// "unavailable".
	Reauth string `json:"reauth"`
}

// orgDeletionViewJSON is GET /portal/api/orgs/{id}/deletion.
type orgDeletionViewJSON struct {
	Deletion *orgDeletionJSON       `json:"deletion"`
	Preview  orgDeletionPreviewJSON `json:"preview"`
	// DepartureNotices are the times members of the org deleted their
	// SuperBased account in the last 90 days (admins only): their own
	// identity provider may still list them.
	DepartureNotices []string `json:"departure_notices,omitempty"`
}

// keptAfterDeletion names what an org deletion keeps (W16-D9: the usage
// counts behind the invoices for 10 years; the deletion record itself).
var keptAfterDeletion = []string{"usage_counts", "deletion_record"}

func optTime(t *time.Time) string {
	if t == nil {
		return ""
	}
	return rfc3339(*t)
}

func deletionJSON(v store.OrgDeletionView, owner bool) *orgDeletionJSON {
	return &orgDeletionJSON{
		RequestID: v.RequestID, State: v.State, Step: v.Step, Origin: v.Origin,
		RequestedAt: rfc3339(v.RequestedAt), PurgeAfter: rfc3339(v.PurgeAfter),
		CanceledAt: optTime(v.CanceledAt), DoneAt: optTime(v.DoneAt), BlockedReason: v.BlockedReason,
		CanCancel: owner && v.State == orgdeletion.StateCoolingOff,
	}
}

// billingCancelAvailable reports that this deployment can cancel a Paddle
// subscription when a deletion reaches cancel_billing: the Paddle API client
// is configured (SBCI_PADDLE_API_KEY_FILE; the worker's cancel uses the
// worker's key, which the cloud kit mounts beside serve's).
func (s *Server) billingCancelAvailable() bool { return s.paddlePortal != nil }

// orgDeletionRefusal is the deciding refusal of an owner's request now, ""
// when it may be requested: one row per check, top-down (the preview and the
// request route share it).
func (s *Server) orgDeletionRefusal(org store.MyOrg, open, cancels bool) string {
	rules := []struct {
		refuse bool
		code   string
	}{
		{org.ConsoleRole != store.ConsoleOwner, "not_owner"},
		{org.Kind == store.OrgPersonal, personalOrgRefusal},
		{open, "deletion_open"},
		{!deletableStatus(org.Status), "org_not_deletable"},
		{cancels && !s.billingCancelAvailable(), billingCancelUnavailableRefusal},
	}
	for _, r := range rules {
		if r.refuse {
			return r.code
		}
	}
	return ""
}

// deletableStatus reports an org status an owner may delete from.
func deletableStatus(st platformcontract.TenantState) bool {
	return st == platformcontract.StateActive || st == platformcontract.StateSuspended
}

// orgWindow is the cooling-off window an owner's request opens now, and
// whether the deletion's cancel_billing step will cancel the org's
// subscription (orgdeletion.Subscription.MayBill: a refunded or charged-back
// one too, which Paddle still renews). The window follows the paid plan
// (Live); the cancellation follows what Paddle may still bill.
func (s *Server) orgWindow(r *http.Request, accountID, orgID string) (window time.Duration, cancels bool) {
	var sub orgdeletion.Subscription
	if ps, err := s.store.PortalOrgSubscription(r.Context(), accountID, orgID); err == nil {
		sub = orgdeletion.Subscription{ID: ps.SubscriptionID, Status: ps.Status}
	}
	last, err := s.store.OrgLastSeatDay(r.Context(), accountID, orgID)
	if err != nil {
		s.log.Warn("cloudserver/api: org last seat day", "err", err)
		last = s.now() // fail toward the longer window
	}
	window = orgdeletion.CoolingOff(orgdeletion.CoolingFacts{Origin: orgdeletion.OriginOwner, LiveSubscription: sub.Live(), LastSeatDay: last, Now: s.now()})
	return window, sub.MayBill()
}

// loadOrgForDeletion reads the caller's view of the org, answering 404 when
// it is not visible.
func (s *Server) loadOrgForDeletion(w http.ResponseWriter, r *http.Request, accountID string) (store.MyOrg, bool) {
	org, err := s.store.GetOrg(r.Context(), accountID, r.PathValue("id"))
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "org not found")
		return store.MyOrg{}, false
	}
	if err != nil {
		s.log.Error("cloudserver/api: get org for deletion", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the org")
		return store.MyOrg{}, false
	}
	return org, true
}

// handlePortalOrgDeletion answers the deletion state and the preview.
func (s *Server) handlePortalOrgDeletion(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	org, ok := s.loadOrgForDeletion(w, r, p.AccountID)
	if !ok {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	owner := org.ConsoleRole == store.ConsoleOwner
	view := orgDeletionViewJSON{Preview: orgDeletionPreviewJSON{Kept: keptAfterDeletion}}
	v, found, err := s.store.OrgDeletionStatus(r.Context(), p.AccountID, org.OrgID)
	if err != nil {
		s.log.Error("cloudserver/api: org deletion status", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the deletion")
		return
	}
	open := found && v.Step != string(orgdeletion.StepDone)
	if found {
		view.Deletion = deletionJSON(v, owner)
	}
	window, cancels := s.orgWindow(r, p.AccountID, org.OrgID)
	view.Preview.CoolingOffDays = int(window / (24 * time.Hour))
	view.Preview.PurgeAfter = rfc3339(s.now().Add(window))
	view.Preview.LiveSubscription = cancels
	view.Preview.Reauth = orgdeletion.ReauthKind(s.portalDevAuth(), s.portalWorkOSEnabled)
	if members, err := s.store.ListOrgMembers(r.Context(), p.AccountID, org.OrgID); err == nil {
		view.Preview.Members = len(members)
	}
	view.Preview.Refusal = s.orgDeletionRefusal(org, open, cancels)
	view.Preview.CanRequest = view.Preview.Refusal == ""
	if org.ConsoleRole == store.ConsoleOwner || org.ConsoleRole == store.ConsoleAdmin {
		if ns, err := s.store.OrgDepartureNotices(r.Context(), p.AccountID, org.OrgID); err == nil {
			for _, t := range ns {
				view.DepartureNotices = append(view.DepartureNotices, rfc3339(t))
			}
		}
	}
	writeJSON(w, http.StatusOK, view)
}

// orgDeletionRequestBody is POST /portal/api/orgs/{id}/deletion.
type orgDeletionRequestBody struct {
	ConfirmSlug string `json:"confirm_slug"`
	// BrokerToken re-presents the dev sign-in credential (dev-auth only).
	BrokerToken string `json:"broker_token"`
	// StepUpAuthorizationID is the one-use authorization the WorkOS step-up
	// leg minted for the deletion action (FR-23); consumed with the open.
	StepUpAuthorizationID string `json:"step_up_authorization_id"`
}

// orgDeletionRefusals maps the definer function's outcomes to the console's
// answer.
var orgDeletionRefusals = map[string]struct {
	status int
	msg    string
}{
	"not_owner":         {http.StatusForbidden, "Only an owner of this team can delete it."},
	"deletion_open":     {http.StatusConflict, "This team already has a deletion in progress."},
	"org_not_deletable": {http.StatusConflict, "This team cannot be deleted in its current state."},
	"not_cancellable":   {http.StatusConflict, "The cooling-off window has ended: the deletion has started and can no longer be canceled."},
	"none":              {http.StatusNotFound, "This team has no deletion to cancel."},
	personalOrgRefusal:  {http.StatusConflict, "A personal organization is deleted with your account. Delete your account from Privacy instead."},
	billingCancelUnavailableRefusal: {
		http.StatusConflict,
		"This team has an active subscription that can't be canceled automatically right now. Cancel it from the team's billing page first, then delete the team.",
	},
}

func (s *Server) writeOrgDeletionRefusal(w http.ResponseWriter, err error) bool {
	var ref *store.OrgDeletionRefusal
	if !errors.As(err, &ref) {
		return false
	}
	a, ok := orgDeletionRefusals[ref.Outcome]
	if !ok {
		a = orgDeletionRefusals["org_not_deletable"]
	}
	writeErr(w, a.status, ref.Outcome, a.msg)
	return true
}

// handlePortalOrgDeletionRequest opens an owner's cooling-off deletion. Every
// refusal that needs no re-authentication answers first, so a step-up is
// never spent on a request that would be refused; then the step-up table
// (orgdeletion.DecideStepUp, FR-23) decides what proves the person is
// present, and a consumed authorization commits with the open or not at all.
func (s *Server) handlePortalOrgDeletionRequest(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	var body orgDeletionRequestBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "bad_request", "invalid JSON body")
		return
	}
	org, ok := s.loadOrgForDeletion(w, r, p.AccountID)
	if !ok {
		return
	}
	if org.ConsoleRole != store.ConsoleOwner {
		writeErr(w, http.StatusForbidden, "not_owner", orgDeletionRefusals["not_owner"].msg)
		return
	}
	if !strings.EqualFold(strings.TrimSpace(body.ConfirmSlug), org.Slug) {
		writeErr(w, http.StatusBadRequest, "confirm_mismatch", "Type the team's address exactly to confirm.")
		return
	}
	window, cancels := s.orgWindow(r, p.AccountID, org.OrgID)
	if code := s.orgDeletionRefusal(org, false, cancels); code != "" {
		if code == billingCancelUnavailableRefusal {
			s.audit(r.Context(), p.AccountID, "org_deletion_refused_billing_cancel_unavailable")
		}
		a := orgDeletionRefusals[code]
		writeErr(w, a.status, code, a.msg)
		return
	}
	if !s.orgDeletionStepUp(w, r, p, body, org.OrgID, s.now().Add(window)) {
		return
	}
	s.audit(r.Context(), p.AccountID, "org_deletion_requested")
	v, _, err := s.store.OrgDeletionStatus(r.Context(), p.AccountID, org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the deletion")
		return
	}
	writeJSON(w, http.StatusAccepted, deletionJSON(v, true))
}

// orgDeletionStepUp applies the step-up table and, when it allows the
// request, opens the deletion (consuming the authorization in the same
// transaction when one is presented). It answers and returns false on any
// refusal or failure.
func (s *Server) orgDeletionStepUp(w http.ResponseWriter, r *http.Request, p portalPrincipal, body orgDeletionRequestBody, orgID string, purgeAfter time.Time) bool {
	ctx := r.Context()
	facts := orgdeletion.StepUpFacts{
		DevAuth:                s.portalDevAuth(),
		WorkOSStepUp:           !s.portalDevAuth() && s.portalWorkOSEnabled,
		BrokerTokenPresented:   strings.TrimSpace(body.BrokerToken) != "",
		AuthorizationPresented: strings.TrimSpace(body.StepUpAuthorizationID) != "",
		Now:                    s.now(),
	}
	if enrolled, at, err := s.store.SessionPasskeyUse(ctx, p.AccountID, p.SessionID); err == nil {
		facts.PasskeyEnrolled, facts.PasskeyAt = enrolled, at
	} else {
		s.log.Warn("cloudserver/api: session passkey use", "err", err) // fail toward asking for a step-up
	}
	verdict := orgdeletion.DecideStepUp(facts)
	switch verdict {
	case orgdeletion.StepUpRefuseReauth:
		writeErr(w, http.StatusUnauthorized, "reauth_required", "Re-enter your credential to confirm deleting the team.")
		return false
	case orgdeletion.StepUpRefuseStepUp:
		writeErr(w, http.StatusForbidden, "step_up_required",
			"re-authenticate at /portal/auth/workos/start?purpose=step_up&action=deletion before deleting the team")
		return false
	case orgdeletion.StepUpRefuseUnavailable:
		writeErr(w, http.StatusNotImplemented, "provider_not_configured",
			"Re-authentication is not available on this deployment, so a team cannot be deleted from the console yet.")
		return false
	case orgdeletion.StepUpVerifyBroker:
		id, err := s.verifier.Verify(ctx, body.BrokerToken)
		if err != nil {
			s.audit(ctx, p.AccountID, "org_deletion_reauth_failed")
			writeErr(w, http.StatusUnauthorized, "reauth_required", "Re-enter your credential to confirm deleting the team.")
			return false
		}
		if acct, err := s.store.AccountForIdentity(ctx, id.Provider, id.Subject); err != nil || acct != p.AccountID {
			s.audit(ctx, p.AccountID, "org_deletion_reauth_mismatch")
			writeErr(w, http.StatusForbidden, "reauth_mismatch", "credential does not match the signed-in account")
			return false
		}
	}
	var err error
	if verdict == orgdeletion.StepUpConsumeAuthorization {
		_, err = s.store.OpenOrgDeletionWithStepUp(ctx, p.AccountID, orgID, purgeAfter,
			store.OrgDeletionStepUp{SessionID: p.SessionID, AuthorizationID: body.StepUpAuthorizationID}, s.now())
	} else {
		_, err = s.store.OpenOrgDeletion(ctx, p.AccountID, orgID, purgeAfter)
	}
	switch {
	case err == nil:
		s.audit(ctx, p.AccountID, "org_deletion_step_up_"+string(verdict))
		return true
	case errors.Is(err, store.ErrStepUpInvalid):
		s.audit(ctx, p.AccountID, "org_deletion_step_up_invalid")
		writeErr(w, http.StatusForbidden, "step_up_invalid",
			"that re-authentication is expired, already used, or was not issued for this session")
		return false
	case s.writeOrgDeletionRefusal(w, err):
		return false
	}
	s.log.Error("cloudserver/api: open org deletion", "err", err)
	writeErr(w, http.StatusInternalServerError, "internal", "could not record the deletion")
	return false
}

// handlePortalOrgDeletionCancel cancels a cooling-off deletion.
func (s *Server) handlePortalOrgDeletionCancel(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	org, ok := s.loadOrgForDeletion(w, r, p.AccountID)
	if !ok {
		return
	}
	if err := s.store.CancelOrgDeletion(r.Context(), p.AccountID, org.OrgID); err != nil {
		if s.writeOrgDeletionRefusal(w, err) {
			return
		}
		s.log.Error("cloudserver/api: cancel org deletion", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not cancel the deletion")
		return
	}
	s.audit(r.Context(), p.AccountID, "org_deletion_canceled")
	v, _, err := s.store.OrgDeletionStatus(r.Context(), p.AccountID, org.OrgID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the deletion")
		return
	}
	writeJSON(w, http.StatusOK, deletionJSON(v, true))
}

// orgRefJSON names one org.
type orgRefJSON struct {
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// blockerJSON is one org that blocks an account deletion.
type blockerJSON struct {
	Code        string `json:"code"`
	OrgID       string `json:"org_id"`
	Slug        string `json:"slug"`
	DisplayName string `json:"display_name"`
}

// accountPrecheckJSON is GET /portal/api/account/deletion-precheck.
type accountPrecheckJSON struct {
	CanDelete          bool          `json:"can_delete"`
	Blockers           []blockerJSON `json:"blockers"`
	PersonalOrg        *orgRefJSON   `json:"personal_org"`
	MembershipsRemoved []orgRefJSON  `json:"memberships_removed"`
	// SubscriptionsCanceled is how many live subscriptions the deletion
	// cancels at Paddle before it deletes anything (ORGDEL-7), and
	// BillingCancelAvailable whether this deployment can: with a
	// subscription to cancel and no way to, the deletion is refused
	// (billing_cancel_unavailable) and the console asks the customer to
	// cancel from the billing page first. can_delete stays the orgs' answer;
	// the deletion route itself answers the billing refusal with its message
	// before any re-authentication.
	SubscriptionsCanceled  int  `json:"subscriptions_canceled"`
	BillingCancelAvailable bool `json:"billing_cancel_available"`
}

func blockersJSON(bs []orgdeletion.Blocker) []blockerJSON {
	out := make([]blockerJSON, 0, len(bs))
	for _, b := range bs {
		out = append(out, blockerJSON{Code: string(b.Code), OrgID: b.OrgID, Slug: b.Slug, DisplayName: b.DisplayName})
	}
	return out
}

// handlePortalAccountDeletionPrecheck answers what deleting the account does
// with its orgs and its subscriptions, and what blocks it.
func (s *Server) handlePortalAccountDeletionPrecheck(w http.ResponseWriter, r *http.Request) {
	p, _ := portalPrincipalFrom(r.Context())
	plan, err := s.store.AccountDeletionPlan(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: account deletion plan", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check the account's teams")
		return
	}
	billing, err := s.store.AccountDeletionBilling(r.Context(), p.AccountID)
	if err != nil {
		s.log.Error("cloudserver/api: account deletion billing", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not check the account's billing")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	out := accountPrecheckJSON{
		CanDelete: plan.CanDelete(), Blockers: blockersJSON(plan.Blockers), MembershipsRemoved: []orgRefJSON{},
		SubscriptionsCanceled: billing.Cancel, BillingCancelAvailable: billing.CancelAvailable,
	}
	if po := plan.PersonalOrg; po != nil {
		out.PersonalOrg = &orgRefJSON{OrgID: po.OrgID, Slug: po.Slug, DisplayName: po.DisplayName}
	}
	for _, m := range plan.Removed {
		out.MembershipsRemoved = append(out.MembershipsRemoved, orgRefJSON{OrgID: m.OrgID, Slug: m.Slug, DisplayName: m.DisplayName})
	}
	writeJSON(w, http.StatusOK, out)
}

// accountDeletionBlockedJSON is the 409 body: the error shape plus the
// blockers.
type accountDeletionBlockedJSON struct {
	Error    string        `json:"error"`
	Code     string        `json:"code"`
	Blockers []blockerJSON `json:"blockers"`
}

// writeAccountDeletionBlocked answers 409 account_deletion_blocked.
func writeAccountDeletionBlocked(w http.ResponseWriter, bs []orgdeletion.Blocker) {
	writeJSON(w, http.StatusConflict, accountDeletionBlockedJSON{
		Code: accountDeletionBlockedCode,
		Error: "Your account owns or pays for a team that would be left without an owner. " +
			"Make another member owner, move the billing, or delete the team, then delete your account.",
		Blockers: blockersJSON(bs),
	})
}

// refuseDeletionBlockedByOrgs answers 409 and returns false when the
// account's orgs block its deletion (the early check, before a step-up the
// store would refuse anyway). A failed read lets the request through to the
// store's own check.
func (s *Server) refuseDeletionBlockedByOrgs(w http.ResponseWriter, r *http.Request, accountID string) bool {
	plan, err := s.store.AccountDeletionPlan(r.Context(), accountID)
	if err != nil {
		s.log.Error("cloudserver/api: account deletion plan", "err", err)
		return true
	}
	if !plan.CanDelete() {
		s.audit(r.Context(), accountID, "deletion_refused_org_blockers")
		writeAccountDeletionBlocked(w, plan.Blockers)
		return false
	}
	return true
}

// accountDeletionBlocked answers the store's refusal; false when err is not
// that refusal.
func (s *Server) accountDeletionBlocked(w http.ResponseWriter, r *http.Request, accountID string, err error) bool {
	var blocked *store.AccountDeletionBlockedError
	if !errors.As(err, &blocked) {
		return false
	}
	s.audit(r.Context(), accountID, "deletion_refused_org_blockers")
	writeAccountDeletionBlocked(w, blocked.Blockers)
	return true
}

// deletionLister is the staff store's deletion read (store.ListDeletions).
type deletionLister interface {
	ListDeletions(ctx context.Context, limit int) ([]store.DeletionStatusRow, error)
}

// staffDeletionJSON is one deletion on the staff console.
type staffDeletionJSON struct {
	Kind           string `json:"kind"`
	RequestID      string `json:"request_id"`
	OrgID          string `json:"org_id,omitempty"`
	State          string `json:"state"`
	Step           string `json:"step"`
	Origin         string `json:"origin,omitempty"`
	BlockedReason  string `json:"blocked_reason,omitempty"`
	Attempts       int    `json:"attempts"`
	LastErrorClass string `json:"last_error_class,omitempty"`
	CreatedAt      string `json:"created_at"`
	UpdatedAt      string `json:"updated_at"`
	NextAttemptAt  string `json:"next_attempt_at"`
	PurgeAfter     string `json:"purge_after,omitempty"`
	DoneAt         string `json:"done_at,omitempty"`
}

// handleStaffDeletions is the staff status of every deletion: open first.
func (s *Server) handleStaffDeletions(w http.ResponseWriter, r *http.Request) {
	lister, ok := s.staff.db.(deletionLister)
	if !ok {
		writeErr(w, http.StatusNotImplemented, "not_available", "deletion status is not available on this store")
		return
	}
	limit := 100
	if v := r.URL.Query().Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 500 {
			writeErr(w, http.StatusBadRequest, "bad_request", "limit must be 1..500")
			return
		}
		limit = n
	}
	rows, err := lister.ListDeletions(r.Context(), limit)
	if err != nil {
		s.log.Error("cloudserver/api: staff deletions", "err", err)
		writeErr(w, http.StatusInternalServerError, "internal", "could not read the deletions")
		return
	}
	out := make([]staffDeletionJSON, 0, len(rows))
	for _, d := range rows {
		out = append(out, staffDeletionJSON{
			Kind: d.Kind, RequestID: d.RequestID, OrgID: d.OrgID, State: d.State, Step: d.Step, Origin: d.Origin,
			BlockedReason: d.BlockedReason, Attempts: d.Attempts, LastErrorClass: d.LastErrorClass,
			CreatedAt: rfc3339(d.CreatedAt), UpdatedAt: rfc3339(d.UpdatedAt), NextAttemptAt: rfc3339(d.NextAttemptAt),
			PurgeAfter: optTime(d.PurgeAfter), DoneAt: optTime(d.DoneAt),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"deletions": out})
}
