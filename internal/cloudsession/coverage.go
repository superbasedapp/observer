package cloudsession

import (
	"fmt"
	"time"
)

// coverage.go is the Rail S coverage vocabulary: what one flush learned about
// whether the sandbox's rows reach their destination. The states are the
// plan's coverage vocabulary (cloud-agents plan section 8; lane CA-B1 owns
// the cross-rail table in internal/cloudagents), the reasons are this rail's
// own. Both are closed sets; ClassifyDelivery is a table walked top-down.

// CoverageState is one coverage state, spelled as the plan names it.
type CoverageState string

// The coverage states a flush can record.
const (
	CoverageVerified           CoverageState = "verified"
	CoveragePartialHistory     CoverageState = "partial_history"
	CoverageDelayedReporting   CoverageState = "delayed_reporting"
	CoverageNotEstablished     CoverageState = "not_established"
	CoveragePermissionRequired CoverageState = "permission_required"
)

// CoverageReason says why a flush recorded its state.
type CoverageReason string

// The coverage reasons.
const (
	// ReasonDelivered: every envelope this flush sent was accepted.
	ReasonDelivered CoverageReason = "delivered"
	// ReasonRowsPending: accepted, but the flush hit its envelope cap.
	ReasonRowsPending CoverageReason = "rows_pending"
	// ReasonNetworkBlocked: the sandbox's egress proxy refused the CONNECT
	// to the destination host (a Claude Code cloud environment on a network
	// level that does not list the host answers 403 at CONNECT, CA-A2).
	ReasonNetworkBlocked CoverageReason = "network_blocked"
	// ReasonTokenRefused: the destination answered 401 or 403.
	ReasonTokenRefused CoverageReason = "token_refused"
	// ReasonDestinationRefused: any other final refusal (413, 400, ...).
	ReasonDestinationRefused CoverageReason = "destination_refused"
	// ReasonUnreachable: no answer, 408, 429 or 5xx; a later flush may work.
	ReasonUnreachable CoverageReason = "unreachable"
	// ReasonNotConfigured: no destination URL or ship token in the sandbox.
	ReasonNotConfigured CoverageReason = "not_configured"
	// ReasonHookBlockChanged: the owned hook block differs from the
	// session's baseline (guard.go); delivery is held.
	ReasonHookBlockChanged CoverageReason = "hook_block_changed"
	// ReasonHookBlockUncommitted: the owned hook block is not committed at
	// the repository's HEAD, so there is nothing to verify it against.
	ReasonHookBlockUncommitted CoverageReason = "hook_block_uncommitted"
)

// reasonRow is one row of the reason table: the state a reason implies and
// the sentence shown for it (%s is the destination host, when it has one).
type reasonRow struct {
	reason  CoverageReason
	state   CoverageState
	message string
}

// reasons is THE reason table.
var reasons = []reasonRow{
	{ReasonDelivered, CoverageVerified, "Verified: the last flush was accepted by %s"},
	{ReasonRowsPending, CoveragePartialHistory, "Partial history: %s accepted the last flush and more rows wait for the next one"},
	{ReasonNetworkBlocked, CoverageNotEstablished, "Not established: environment network level blocks %s (on the Limited level add the host under Allowed domains, or choose Full)"},
	{ReasonTokenRefused, CoveragePermissionRequired, "Permission required: %s refused the ship token"},
	{ReasonDestinationRefused, CoverageNotEstablished, "Not established: %s refused the envelope"},
	{ReasonUnreachable, CoverageDelayedReporting, "Delayed reporting: %s did not take the envelope; the rows wait for the next flush"},
	{ReasonNotConfigured, CoverageNotEstablished, "Not established: the sandbox has no destination or ship token configured"},
	{ReasonHookBlockChanged, CoveragePartialHistory, "Partial history: the committed cloud-session hook block changed during this session; delivery is held until it is restored"},
	{ReasonHookBlockUncommitted, CoverageNotEstablished, "Not established: the cloud-session hooks are not committed at HEAD, so this session's capture cannot be verified"},
}

func reasonFor(r CoverageReason) (reasonRow, bool) {
	for _, row := range reasons {
		if row.reason == r {
			return row, true
		}
	}
	return reasonRow{}, false
}

// CoverageReasons returns every reason, in table order.
func CoverageReasons() []CoverageReason {
	out := make([]CoverageReason, len(reasons))
	for i, r := range reasons {
		out[i] = r.reason
	}
	return out
}

// DeliveryOutcome is what the delivery half of one flush observed.
type DeliveryOutcome struct {
	// Attempted reports that at least one envelope was sent.
	Attempted bool
	// Failed reports that a delivery failed (the flush stops at the first).
	Failed bool
	// NetworkBlocked reports a refusal at the egress proxy's CONNECT.
	NetworkBlocked bool
	// Status is the destination's HTTP status on a failure (0: no answer).
	Status int
	// Retryable reports that a later flush may succeed.
	Retryable bool
	// Pending reports that rows remain in the local database.
	Pending bool
}

// deliveryRule is one row of the delivery classification table.
type deliveryRule struct {
	reason CoverageReason
	when   func(DeliveryOutcome) bool
}

// deliveryRules is THE delivery classification table, walked top-down.
var deliveryRules = []deliveryRule{
	{ReasonNetworkBlocked, func(o DeliveryOutcome) bool { return o.Failed && o.NetworkBlocked }},
	{ReasonTokenRefused, func(o DeliveryOutcome) bool { return o.Failed && (o.Status == 401 || o.Status == 403) }},
	{ReasonUnreachable, func(o DeliveryOutcome) bool { return o.Failed && o.Retryable }},
	{ReasonDestinationRefused, func(o DeliveryOutcome) bool { return o.Failed }},
	{ReasonRowsPending, func(o DeliveryOutcome) bool { return o.Pending }},
	{ReasonDelivered, func(DeliveryOutcome) bool { return true }},
}

// ClassifyDelivery returns the reason a delivery outcome records. ok=false
// when nothing was attempted: a flush with nothing to send learns nothing
// about the destination, so the recorded coverage stays as it was.
func ClassifyDelivery(o DeliveryOutcome) (reason CoverageReason, ok bool) {
	if !o.Attempted {
		return "", false
	}
	for _, r := range deliveryRules {
		if r.when(o) {
			return r.reason, true
		}
	}
	return ReasonDelivered, true
}

// Coverage is the recorded coverage of one agent in this sandbox. The flush
// persists it next to its counter; `observer cloud-session status` prints it.
// It holds no secret and no content: a host name, an opaque vendor session
// id and enum values.
type Coverage struct {
	State     CoverageState  `json:"state"`
	Reason    CoverageReason `json:"reason"`
	Host      string         `json:"host,omitempty"`
	VendorRef string         `json:"vendor_ref,omitempty"`
	Trigger   Trigger        `json:"trigger,omitempty"`
	At        time.Time      `json:"at"`
}

// NewCoverage builds the coverage record for reason.
func NewCoverage(reason CoverageReason, host, vendorRef string, trigger Trigger, at time.Time) (Coverage, error) {
	row, ok := reasonFor(reason)
	if !ok {
		return Coverage{}, fmt.Errorf("cloudsession: unknown coverage reason %q", reason)
	}
	return Coverage{State: row.state, Reason: reason, Host: host, VendorRef: vendorRef, Trigger: trigger, At: at.UTC()}, nil
}

// Message is the human sentence for the record.
func (c Coverage) Message() string {
	row, ok := reasonFor(c.Reason)
	if !ok {
		return string(c.State)
	}
	host := c.Host
	if host == "" {
		host = "the destination"
	}
	if row.reason == ReasonNotConfigured || row.reason == ReasonHookBlockChanged || row.reason == ReasonHookBlockUncommitted {
		return row.message
	}
	return fmt.Sprintf(row.message, host)
}

// SkipDelivery reports whether this flush should skip its delivery because
// the recorded coverage says the network level blocks the same host for the
// same vendor session, and the trigger is one that does not retry that.
// The scan still runs, so nothing is lost; the start and final triggers
// always try, so a changed environment is noticed at the next session.
func SkipDelivery(spec TriggerSpec, prev *Coverage, host, vendorRef string) bool {
	return spec.SkipWhenBlocked && prev != nil && prev.Reason == ReasonNetworkBlocked &&
		prev.Host == host && prev.VendorRef == vendorRef
}
