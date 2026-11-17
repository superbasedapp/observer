package cloudmetrics

import (
	"slices"
	"strings"
)

// Label values for an input outside its closed table.
const (
	// AuditUnlisted is the event label of an audit event this package does
	// not list. The api package's TestAuditEventsAreListed keeps it at zero;
	// a non-zero value means a new audit() call site was added without a row
	// here.
	AuditUnlisted = "unlisted"
	// Other is the label value of every other closed label's unknown input.
	Other = "other"
)

// auditEvents is the closed table of the security audit event names the api
// package's audit() seam writes (security_audit_events.event_type), sorted.
// The api package's TestAuditEventsAreListed walks every audit() call site
// and fails on a name (or a name family below) missing here.
var auditEvents = []string{
	"auth_missing_bearer",
	"auth_pop_failed",
	"auth_pop_replay",
	"auth_token_invalid",
	"community_grant_rule_absent",
	"community_rejected_account_closed",
	"community_rejected_binding_incomplete",
	"community_rejected_cross_device_conflict",
	"community_rejected_dictionary",
	"community_rejected_digest_tamper",
	"community_rejected_generation_stale",
	"community_rejected_grant_missing",
	"community_rejected_grant_revoked",
	"community_rejected_grant_terms",
	"community_rejected_invalid",
	"community_rejected_noncanonical",
	"community_rejected_out_of_domain",
	"community_rejected_too_large",
	"community_rejected_unknown_cohort",
	"community_rejected_unknown_metric",
	"community_rejected_window_not_current",
	"connect_approved",
	"connect_attach_grant_delivered",
	"connect_code_miss",
	"connect_declined",
	"connect_not_now",
	"connect_poll_pop_failed",
	"connect_poll_replay",
	"connect_request_created",
	"connect_signin_delivered",
	"connect_signin_refused",
	"deletion_refused_org_blockers",
	"deletion_refused_pays_for_org",
	"deletion_requested",
	"device_logout",
	"device_personal_org_ensured",
	"exchange_account_suspended",
	"exchange_bad_signature",
	"exchange_device_approval_required",
	"exchange_device_revoked",
	"exchange_identity_invalid",
	"exchange_ok",
	"export_assembled",
	"export_downloaded",
	"job_rejected_admission_attestation",
	"job_rejected_admission_credential",
	"job_rejected_admission_unwired",
	"job_rejected_authority",
	"job_rejected_digest_tamper",
	"job_rejected_evidence_budget",
	"job_rejected_kill_switch",
	"job_rejected_out_of_purpose",
	"org_deletion_canceled",
	"org_deletion_reauth_failed",
	"org_deletion_reauth_mismatch",
	"org_deletion_refused_billing_cancel_unavailable",
	"org_deletion_requested",
	"org_deletion_step_up_invalid",
	"paddle_checkout_intent_created",
	"paddle_org_checkout_intent_created",
	"paddle_org_portal_session_created",
	"paddle_portal_session_created",
	"paddle_webhook_signature_invalid",
	"plan_route_unavailable",
	"portal_consent_choices_set",
	"portal_csrf_failed",
	"portal_deletion_requested",
	"portal_device_approved",
	"portal_device_revoked",
	"portal_export_reauth_account_mismatch",
	"portal_export_reauth_failed",
	"portal_export_step_up_invalid",
	"portal_login_account_suspended",
	"portal_login_identity_invalid",
	"portal_login_ok",
	"portal_logout",
	"portal_org_create_capped",
	"portal_org_create_invite_only",
	"portal_org_created",
	"portal_org_renamed",
	"portal_origin_refused",
	"portal_passkey_assert_failed",
	"portal_passkey_counter_regressed",
	"portal_passkey_register_failed",
	"portal_passkey_registered",
	"portal_passkey_removed",
	"portal_passkey_removed_last",
	"portal_personal_org_ensured",
	"portal_reauth_account_mismatch",
	"portal_reauth_failed",
	"portal_recovery_code_locked_attempt",
	"portal_recovery_code_lockout",
	"portal_recovery_code_refused",
	"portal_recovery_codes_replaced",
	"portal_second_factor_passkey",
	"portal_second_factor_recovery_code",
	"portal_sessions_revoked_all",
	"portal_step_up_account_mismatch",
	"portal_step_up_invalid",
	"portal_workos_code_rejected",
	"portal_workos_misconfigured",
	"portal_workos_provider_error",
	"portal_workos_redirect_mismatch",
	"portal_workos_state_mismatch",
	"portal_workos_token_invalid",
	"portal_workos_transaction_replay",
	"rate_limited_account",
	"rate_limited_device",
	"rate_limited_structural",
	"result_correction_conflict",
	"signin_personal_org_ensured",
	"structural_rejected_account_closed",
	"structural_rejected_binding_incomplete",
	"structural_rejected_dictionary",
	"structural_rejected_digest_tamper",
	"structural_rejected_generation_stale",
	"structural_rejected_grant_missing",
	"structural_rejected_grant_revoked",
	"structural_rejected_grant_terms",
	"structural_rejected_invalid",
	"structural_rejected_noncanonical",
	"structural_rejected_revision_conflict",
	"structural_rejected_too_large",
	"workos_account_access_revoked",
	"workos_account_profile_refreshed",
	"workos_session_revoked",
	"workos_webhook_signature_invalid",
	"workos_webhook_subject_missing",
}

// auditFamilies are the audit event names the api package builds from a
// fixed prefix and a server-side suffix (a Paddle event type and outcome, a
// grant action, a step-up verdict, ...). Each counts under its family label
// (the prefix plus "*"): the suffix never reaches a label. Longest prefix
// first, so a narrower family wins; an exact name above always wins.
var auditFamilies = []string{
	"community_contribution_stored_grant_",
	"result_correction_replayed_",
	"result_correction_applied_",
	"portal_step_up_granted_",
	"org_deletion_step_up_",
	"structural_snapshot_",
	"portal_workos_start_",
	"portal_mfa_refused_",
	"paddle_",
}

// AuditEventLabel returns the closed label value for an audit event name: the
// name itself when listed, its family label ("<prefix>*") when it starts with
// a family prefix, else AuditUnlisted.
func AuditEventLabel(event string) string {
	if _, ok := slices.BinarySearch(auditEvents, event); ok {
		return event
	}
	for _, p := range auditFamilies {
		if strings.HasPrefix(event, p) && len(event) > len(p) {
			return p + "*"
		}
	}
	return AuditUnlisted
}

// AuditEventLabels returns every label value AuditEventLabel can answer, in
// render order (the listed names, the families, then AuditUnlisted).
func AuditEventLabels() []string {
	out := make([]string, 0, len(auditEvents)+len(auditFamilies)+1)
	out = append(out, auditEvents...)
	fams := make([]string, 0, len(auditFamilies))
	for _, p := range auditFamilies {
		fams = append(fams, p+"*")
	}
	slices.Sort(fams)
	out = append(out, fams...)
	return append(out, AuditUnlisted)
}

// AuditFamilyPrefixes returns the family prefixes (a copy), for the api
// package's call-site test.
func AuditFamilyPrefixes() []string { return slices.Clone(auditFamilies) }

// Paddle webhook delivery results (sbci_paddle_webhook_deliveries_total
// result label).
const (
	// WebhookAccepted: a verified delivery acknowledged 200 (any outcome,
	// including a refused binding or a duplicate).
	WebhookAccepted = "accepted"
	// WebhookRefused: a delivery answered 4xx or 501 before any processing
	// (an invalid signature, an unconfigured route, an oversize body, a bad
	// envelope, a rate limit).
	WebhookRefused = "refused"
	// WebhookFailed: a verified delivery the store could not process (5xx;
	// Paddle redelivers).
	WebhookFailed = "failed"
)

// webhookReasons is the closed reason table per result. The accepted reasons
// are the store's BillingIntake outcomes (internal/cloudserver/store
// paddle*.go; the api package's TestWebhookOutcomesAreListed keeps them in
// step); the refused and failed ones are the webhook's own answers.
var webhookReasons = map[string][]string{
	WebhookAccepted: {
		"account_not_found", "acknowledged", "applied", "binding_refused", "bound_terminal",
		"duplicate", "ignored", "not_billable", "not_owner", "refused_second_live", "stale",
		"status_only", "terminal_kept", "terminal_pending", "unattributed", "unknown_price", Other,
	},
	WebhookRefused: {
		"bad_envelope", "body_too_large", "not_configured", "rate_limited", "signature_invalid", Other,
	},
	WebhookFailed: {"processing_failed", Other},
}

// webhookResults is the render order of the result label.
var webhookResults = []string{WebhookAccepted, WebhookRefused, WebhookFailed}

// WebhookLabels returns the closed (result, reason) pair for a delivery: an
// unknown result counts as refused/other, an unknown reason as other.
func WebhookLabels(result, reason string) (string, string) {
	reasons, ok := webhookReasons[result]
	if !ok {
		return WebhookRefused, Other
	}
	if !slices.Contains(reasons, reason) {
		return result, Other
	}
	return result, reason
}

// bindingRefusalReasons is the closed table of the store's binding refusal
// reasons (BillingIntake.Reason; the bindRefusal* constants in
// internal/cloudserver/store/paddle_lifecycle.go, kept in step by the api
// package's TestBindingRefusalReasonsAreListed).
var bindingRefusalReasons = []string{
	"account_not_billable", "account_not_found", "account_not_uuid", "intent_price_mismatch",
	"missing_nonce", "no_account", "no_live_intent", "org_not_billable", "scope_mismatch",
	"second_live", "unknown_price", Other,
}

// BindingRefusalLabel returns the closed reason label of a binding refusal.
func BindingRefusalLabel(reason string) string {
	if slices.Contains(bindingRefusalReasons, reason) {
		return reason
	}
	return Other
}

// Deletion block kinds (orgdeletion.BlockEvent.Kind).
var deletionKinds = []string{"account", "org"}

// deletionBlockReasons is the closed table of the deletion driver's block
// reasons (orgdeletion.Reason* plus the driver's own enum words), kept in
// step by cmd/observer-cloud's TestDeletionBlockReasonsAreListed.
var deletionBlockReasons = []string{
	"billing_cancel_refused", "billing_seam_unwired", "deactivation_overdue", "deactivation_refused",
	"followup_unverified", "host_purge_overdue", "host_refused", "identity_seam_unwired",
	"org_missing", "unknown_step", Other,
}

// DeletionBlockLabels returns the closed (kind, reason) pair of a block.
func DeletionBlockLabels(kind, reason string) (string, string) {
	if !slices.Contains(deletionKinds, kind) {
		kind = Other
	}
	if !slices.Contains(deletionBlockReasons, reason) {
		reason = Other
	}
	return kind, reason
}

// DeletionBlockReasons returns the closed reason table (a copy), for the
// call-site test.
func DeletionBlockReasons() []string { return slices.Clone(deletionBlockReasons) }

// BindingRefusalReasons returns the closed reason table (a copy).
func BindingRefusalReasons() []string { return slices.Clone(bindingRefusalReasons) }

// WebhookReasons returns the closed reasons of one result (a copy).
func WebhookReasons(result string) []string { return slices.Clone(webhookReasons[result]) }
