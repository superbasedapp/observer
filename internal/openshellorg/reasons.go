package openshellorg

// Reason is a closed refusal or outcome reason. Every route, mint, event and
// end report of the org-hosted OpenShell gateway answers with one of these
// values and nothing else (g1-design.md sections 3.5, 3.6, 4.6, 5.4, 7.6 and
// 7.7). The empty Reason means "no refusal".
type Reason string

// The closed reason set.
const (
	ReasonNone Reason = ""

	// Mint rules T0 to T5 (section 5.4) and the fetch.
	ReasonProofInvalid      Reason = "proof_invalid"
	ReasonOff               Reason = "org_openshell_off"
	ReasonDraining          Reason = "org_openshell_draining"
	ReasonNodeNotManaged    Reason = "node_not_managed"
	ReasonSigninRequired    Reason = "org_signin_required"
	ReasonSigninExpired     Reason = "org_signin_expired"
	ReasonSigninRevoked     Reason = "org_signin_revoked"
	ReasonMemberNotAllowed  Reason = "member_not_allowed"
	ReasonPurposeInvalid    Reason = "purpose_invalid"
	ReasonRequestInvalid    Reason = "request_invalid"
	ReasonMemberMismatch    Reason = "member_mismatch"
	ReasonCollectUnknown    Reason = "collect_unknown"
	ReasonCollectNotYours   Reason = "collect_not_yours"
	ReasonCollectFailedOnly Reason = "collect_failed_admin_only"

	// T5b: every node input only narrows the org's values.
	ReasonInputWidensOrg            Reason = "input_widens_org"
	ReasonRemoteCloneHostsMissing   Reason = "remote_clone_hosts_missing"
	ReasonRemoteCloneHostsDisjoint  Reason = "remote_clone_hosts_disjoint"
	ReasonCloneURLInvalid           Reason = "clone_url_invalid"
	ReasonCloneRepositoryNotAllowed Reason = "clone_repository_not_allowed"
	ReasonRemoteCloneNeedsEgress    Reason = "remote_clone_needs_egress"
	ReasonBlockedCIDRsMissing       Reason = "org_blocked_cidrs_missing"
	// ReasonHostAddrsInvalid: an internet run whose org's sandbox host
	// addresses hold an entry the compile cannot take (a CIDR, or not an
	// address at all). The host list is a deny-side input, so the mint
	// refuses rather than drop the entry (OB-085).
	ReasonHostAddrsInvalid Reason = "org_host_addrs_invalid"
	// ReasonHostAddrsMissing: an internet run whose org lists no sandbox
	// host addresses (sandbox_host_addrs empty). Like the blocked ranges it
	// is a deny-side input the gateway does not report, so an empty list is
	// refused, never compiled as "no carve-out" (OB-092 ruling on RC1-A2).
	ReasonHostAddrsMissing     Reason = "org_host_addrs_missing"
	ReasonInternetTierNotBuilt Reason = "internet_tier_not_built"

	// T6 and T7r quotas (section 7.3).
	ReasonQuotaConcurrent    Reason = "quota_concurrent"
	ReasonQuotaDailyMinutes  Reason = "quota_daily_minutes"
	ReasonQuotaOrgConcurrent Reason = "quota_org_concurrent"
	ReasonQuotaBoxes         Reason = "quota_boxes"

	// T6, T7, T7x, T7r and E1.
	ReasonRunUnknown           Reason = "run_unknown"
	ReasonRunExists            Reason = "run_exists"
	ReasonRunNotYours          Reason = "run_not_yours"
	ReasonRunHeld              Reason = "run_held"
	ReasonRunNotHeld           Reason = "run_not_held"
	ReasonHoldExpired          Reason = "hold_expired"
	ReasonSpecChangedSinceHold Reason = "spec_changed_since_hold"
	ReasonReturnWithheld       Reason = "return_withheld"
	ReasonTeardownNeedsCollect Reason = "teardown_needs_collect"
	ReasonReturnNotTaken       Reason = "return_not_taken"
	ReasonHoldUnavailable      Reason = "hold_unavailable"

	// T7h, the laptop-relay opt-in (section 3.7).
	ReasonLaptopRelayNotOptedIn Reason = "laptop_relay_not_opted_in"
	ReasonLaptopRelayForbidden  Reason = "laptop_relay_forbidden"

	// T8, the gateway sync (section 7.1).
	ReasonGatewayUnsound     Reason = "org_gateway_unsound"
	ReasonGatewayStateStale  Reason = "org_gateway_state_stale"
	ReasonIllegalTransition  Reason = "illegal_transition"
	ReasonRPCNotAllowed      Reason = "rpc_not_allowed"
	ReasonFrontKeyUnknown    Reason = "front_key_unknown"
	ReasonRunTokenInvalid    Reason = "run_token_invalid"
	ReasonProviderNotReady   Reason = "provider_not_ready"
	ReasonDeviceCodeUnknown  Reason = "device_code_unknown"
	ReasonDeviceCodePending  Reason = "device_code_pending"
	ReasonDeviceCodeExpired  Reason = "device_code_expired"
	ReasonDeviceCodeConsumed Reason = "device_code_consumed"
	// ReasonGatewayAdmissionLimit is the gateway's own refusal of a member's
	// call past its per-caller daily admission budget (FX3 item 2,
	// F-L3P4-6; admission.go), as the node names it.
	ReasonGatewayAdmissionLimit Reason = "gateway_admission_limit"
	// ReasonGitProfileMissing refuses a private clone whose git_providers
	// row names a provider profile the gateway does not have (FX3 item 4,
	// F-L6P4-2); the admin page names the profile.
	ReasonGitProfileMissing Reason = "git_provider_profile_missing"
)

// allReasons is the closed set, in declaration order.
var allReasons = []Reason{
	ReasonProofInvalid, ReasonOff, ReasonDraining, ReasonNodeNotManaged,
	ReasonSigninRequired, ReasonSigninExpired, ReasonSigninRevoked,
	ReasonMemberNotAllowed, ReasonPurposeInvalid, ReasonRequestInvalid,
	ReasonMemberMismatch, ReasonCollectUnknown, ReasonCollectNotYours,
	ReasonCollectFailedOnly,
	ReasonInputWidensOrg, ReasonRemoteCloneHostsMissing,
	ReasonRemoteCloneHostsDisjoint, ReasonCloneURLInvalid,
	ReasonCloneRepositoryNotAllowed, ReasonRemoteCloneNeedsEgress,
	ReasonBlockedCIDRsMissing, ReasonHostAddrsInvalid, ReasonHostAddrsMissing, ReasonInternetTierNotBuilt,
	ReasonQuotaConcurrent, ReasonQuotaDailyMinutes, ReasonQuotaOrgConcurrent,
	ReasonQuotaBoxes,
	ReasonRunUnknown, ReasonRunExists, ReasonRunNotYours, ReasonRunHeld,
	ReasonRunNotHeld, ReasonHoldExpired, ReasonSpecChangedSinceHold,
	ReasonReturnWithheld, ReasonTeardownNeedsCollect, ReasonReturnNotTaken,
	ReasonHoldUnavailable,
	ReasonLaptopRelayNotOptedIn, ReasonLaptopRelayForbidden,
	ReasonGatewayUnsound, ReasonGatewayStateStale, ReasonIllegalTransition,
	ReasonRPCNotAllowed, ReasonFrontKeyUnknown, ReasonRunTokenInvalid,
	ReasonProviderNotReady,
	ReasonDeviceCodeUnknown, ReasonDeviceCodePending, ReasonDeviceCodeExpired,
	ReasonDeviceCodeConsumed, ReasonGatewayAdmissionLimit, ReasonGitProfileMissing,
}

// AllReasons returns the closed reason set (a copy).
func AllReasons() []Reason {
	out := make([]Reason, len(allReasons))
	copy(out, allReasons)
	return out
}

// Valid reports whether r is a member of the closed set. The empty reason is
// not a member: it means "no refusal".
func (r Reason) Valid() bool {
	for _, k := range allReasons {
		if k == r {
			return true
		}
	}
	return false
}
