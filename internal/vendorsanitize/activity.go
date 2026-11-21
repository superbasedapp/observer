package vendorsanitize

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/vendorapi"
)

// Activity allowlists (lane F11). Each row is added with the driver that
// lands it and reviewed against the vendor's documented fields; a namespace
// or class with no row is refused (fail closed), exactly like a resource
// type.

// auditDetail is the per-audit-namespace detail allowlist.
var auditDetail = map[string][]string{
	// cursor.admin.audit_logs: the documented event_data members of the
	// "Get Audit Logs" example plus the event's ip_address and
	// application_type. Never a key, a token or a prompt.
	"cursor.audit": {
		"application_type", "ip_address", "success", "login_type", "user_email", "role", "source", "team_id",
		"invited_by_email", "invited_by_user_id", "invite_id",
	},
	// github.audit.org_pull and .enterprise_pull (lane L8, T-611): the
	// documented target members of an audit-log-event (org, repo, team,
	// user, business), the repository visibility and the operation type.
	// Never a hashed token, token scopes, a key fingerprint or a message.
	"github.audit": {"org", "repo", "team", "user", "visibility", "business", "operation_type"},
	// openai.platform.audit_logs (lane ENTAPI-D1, T-610): the actor shape, the
	// session IP, the key tracking id and type, the service account and the
	// project id. The per-type event detail object is never read beyond its
	// id (which travels as the target). The key fields are named key_type and
	// key_tracking_id: an attribute name containing "api_key" is refused as
	// secret-shaped by vendorapi.Validate, and the value is a tracking id.
	"openai.audit": {
		"actor_type", "ip_address", "key_type", "key_tracking_id", "service_account_id", "project_id",
	},
	// cognition.devin_v3.audit_logs (lane ENTAPI-L16, T-619): the documented
	// AuditLogResponse ids (org, user, service user and its name). The open
	// data object is never decoded (closed DTO), so nothing of it can land.
	"cognition.audit": {"org_id", "user_id", "service_user_id", "service_user_name"},
	// xai.mgmt.audit_events (lane ENTAPI-L16B, T-708): the user id and the
	// documented free-form English description (bounded like every value: over
	// 24 words or with a control character it is dropped, a typed secret is
	// redacted). The user's names and profile image are never read.
	"xai.audit": {"user_id", "description"},
	// aws.cloudtrail.q_developer_events (lane ENTAPI-L16D, T-713): the event
	// source, the read-only flag and the first resource's type. AccessKeyId
	// and the CloudTrailEvent document (request parameters, response
	// elements) are never decoded, so nothing of them can land.
	"aws.cloudtrail": {"event_source", "read_only", "resource_type"},
	// google.codeassist.audit_logs (lane ENTAPI-L16D, T-713): the audit log
	// type (activity or data_access), the service, the status code and the
	// monitored resource type. The caller IP, user agent, request and
	// response payloads are never decoded.
	"google.cloud_audit": {"log_type", "service_name", "status_code", "resource_type"},
}

// usageFlags is the per-join-namespace usage flag allowlist.
var usageFlags = map[string][]string{
	// cursor.admin.usage_events (lane ENTAPI-D3, T-692): the two documented
	// booleans that describe how the call ran. The billing breakdown travels
	// in typed columns (UsageBilling, T-630), never as a flag.
	"cursor.usage": {"is_headless", "billing_basis"},
	// cognition.devin_v3.org_sessions (cloud agents arc, lane CA-C3): the ACU
	// row of a session carries no flag; the namespace is reviewed so the
	// row lands (charged in ACUs, never converted, CA-D11).
	"cognition.session": {},
}

// snapshotBody is the per-snapshot-class body allowlist.
var snapshotBody = map[string][]string{
	// cursor.admin.spend (lane ENTAPI-D3): one member's current-cycle spend
	// and limits. Never the member's display name.
	"cursor.member_spend": {
		"cycle_start", "user_id", "role", "spend_cents", "overall_spend_cents", "fast_premium_requests",
		"hard_limit_override_dollars", "monthly_limit_dollars", "effective_per_user_limit_dollars",
	},
	// microsoft.m365.reports_usage_user_detail (lane ENTAPI-D3): the report
	// refresh date, the report period and the per-app last-activity dates of
	// one licensed user. Never the display name.
	"microsoft.copilot_user_activity": {
		"report_refresh_date", "report_period", "last_activity_date", "copilot_chat_last_activity_date",
		"teams_last_activity_date", "word_last_activity_date", "excel_last_activity_date",
		"powerpoint_last_activity_date", "outlook_last_activity_date", "onenote_last_activity_date",
		"loop_last_activity_date",
	},
	// openrouter.mgmt.credits (lane ENTAPI-L16C, T-710): the account's lifetime
	// purchased and used credits in micro-dollars, nothing else.
	"openrouter.credits": {"unit", "total_credits", "total_usage"},
	// opencode.console.budgets_api (lane ENTAPI-L16C, T-710): one member's
	// effective monthly budget (state custom, default or unlimited; the limit
	// in microcents), the month's spend in microcents, exceeded, the reset time
	// and the override's update time. The subject is the member's e-mail.
	"opencode.member_budget": {
		"user_id", "limit_state", "limit_micro_cents", "spent_micro_cents", "exceeded", "resets_at", "updated_at",
	},
	// charm.hyper.credits_api: the team's Hypercredit balance and its unit
	// (hypercredits, never money).
	"charm.hyper_balance": {"balance", "unit"},
	// prime.billing.wallet (lane ENTAPI-L16D, T-713): the team wallet balance
	// and the remaining grant credits per documented category, in
	// micro-dollars, and the billing row count. Never a billing row, a
	// resource id or a grant label.
	"prime.wallet": {
		"unit", "balance", "total_billings", "sandbox_credits_remaining", "credits_remaining_training",
		"credits_remaining_sandboxes", "credits_remaining_inference",
	},
	// cursor.cloudagent.agents (cloud agents arc, lane CA-C3): one cloud
	// agent's status, times, latest run id and environment type, what the
	// org cloud-session projection reads. Never the agent's name (the
	// vendor derives it from the prompt) and never its URL.
	"cursor.cloud_agent": {"status", "created_at", "updated_at", "latest_run_id", "env_type"},
	// cursor.cloudagent.meta (cloud agents arc, lane CA-C8): the key's kind
	// (user or no_user) and, for a user key, the owner's numeric user id and
	// folded e-mail, the identity the org projection attributes the key's
	// agents to. Never the key name and never the user's names.
	"cursor.cloud_agent_key": {"key_kind", "user_id", "user_email"},
	// cursor.admin.cloud_agent_owners (cloud agents arc, lane CA-C8): one
	// (cloud agent id, identity) pair the Admin API stated, the identity
	// being a member's folded e-mail or a service account id. An identity
	// value only: no token count, no cent amount and no conversation id is
	// on the row.
	"cursor.cloud_agent_owner": {"cloud_agent_id", "identity_kind", "identity"},
	// cognition.devin_v3.org_sessions (cloud agents arc, lane CA-C3): one
	// Devin session's status and status detail, times, origin, the org, the
	// user or service user who ran it (the identity the projection resolves),
	// lineage ids and counts, the first pull request's URL and state (the
	// repository the projection files the session under) and the Teams-only
	// on-demand USD figure in its own unit. Never the title and never the
	// session URL.
	"cognition.devin_session": {
		"status", "status_detail", "created_at", "updated_at", "origin", "org_id", "user_id", "service_user_id",
		"parent_session_id", "playbook_id", "automation_id", "child_session_count", "pull_request_count",
		"pr_url", "pr_state", "on_demand_usage_usd",
	},
}

// HasAuditAllowlist reports whether an audit namespace has a reviewed row.
func HasAuditAllowlist(ns string) bool {
	_, ok := auditDetail[ns]
	return ok
}

// identityValue checks a value that keys or attributes a row (an event id,
// a join value, an actor identity, a fact dimension): it cannot be redacted
// without changing what the row means, so secret or content material in it,
// or a length above vendorapi.MaxIDLen (the limit ValidateActivity enforces
// on every such field), quarantines the ROW (VCONN-5, T-695; it used to
// refuse the whole page, so one vendor value stalled the surface).
func identityValue(v string) bool {
	return v == "" || (len(v) <= vendorapi.MaxIDLen && !hasSecret(v) && !contentLike(v))
}

// cleanName applies the value rules to an optional free-text name that
// ValidateActivity bounds at max bytes: a value it would refuse is dropped,
// never left to refuse the page.
func cleanName(v string, max int, rep *Report) string {
	if v == "" {
		return ""
	}
	c, ok := cleanValue(v, rep)
	if !ok {
		return ""
	}
	if len(c) > max {
		rep.DroppedValues++
		return ""
	}
	return c
}

// allIdentity reports whether every value passes identityValue.
func allIdentity(vs ...string) bool {
	for _, v := range vs {
		if !identityValue(v) {
			return false
		}
	}
	return true
}

// activity sanitizes the activity landings of a page into out. A landing
// namespace or class with no reviewed row refuses the page; a row whose key
// fails identityValue is quarantined.
func activity(p vendorapi.Page, out *vendorapi.Page, rep *Report) error {
	out.Audit = nil
	for i, e := range p.Audit {
		allow, ok := auditDetail[e.Namespace]
		if !ok {
			return fmt.Errorf("%w: audit event %d has a namespace with no allowlist row", ErrRefused, i)
		}
		if !identityValue(e.EventID) || !identityValue(e.ActorIdentity) || !identityValue(e.AgentSessionID) || !identityValue(e.Action) {
			rep.quarantine(false)
			continue
		}
		e.Target = cleanName(e.Target, vendorapi.MaxTargetLen, rep)
		e.Detail = cleanAttrs(e.Detail, allow, rep)
		out.Audit = append(out.Audit, e)
	}
	out.Usage = nil
	for i, u := range p.Usage {
		allow, ok := usageFlags[u.JoinNamespace]
		if !ok {
			return fmt.Errorf("%w: usage row %d has a join namespace with no allowlist row", ErrRefused, i)
		}
		if !allIdentity(u.JoinValue, u.Identity, u.SourceAccount, u.Model, u.SessionRef) {
			rep.quarantine(false)
			continue
		}
		u.Flags = cleanAttrs(u.Flags, allow, rep)
		if u.Billing != nil {
			b := *u.Billing
			for _, s := range []*string{&b.Category, &b.ServiceAccountName, &b.AutomationID} {
				*s = cleanName(*s, vendorapi.MaxIDLen, rep)
			}
			u.Billing = &b
		}
		out.Usage = append(out.Usage, u)
	}
	out.Facts = nil
	for _, f := range p.Facts {
		if !allIdentity(f.Identity, f.ModelRaw, f.Feature, f.RepoHash, f.TrafficSegment, f.CoverageDomain, f.SourceTZ) {
			rep.quarantine(false)
			continue
		}
		out.Facts = append(out.Facts, f)
	}
	out.Snapshots = nil
	for i, s := range p.Snapshots {
		allow, ok := snapshotBody[s.Class]
		if !ok {
			return fmt.Errorf("%w: snapshot %d has a class with no allowlist row", ErrRefused, i)
		}
		if !identityValue(s.Subject) {
			rep.quarantine(false)
			continue
		}
		s.Body = cleanAttrs(s.Body, allow, rep)
		out.Snapshots = append(out.Snapshots, s)
	}
	out.Retractions = nil
	for _, r := range p.Retractions {
		if !identityValue(r.JoinValue) {
			rep.quarantine(false)
			continue
		}
		out.Retractions = append(out.Retractions, r)
	}
	return nil
}
