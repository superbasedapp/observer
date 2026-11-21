package cloudagents

// CoverageState is one state of the reference's coverage table ("Show
// coverage as part of the product"). The values are lowercase tokens, the
// shape internal/store accepts for cloud_connector_accounts.coverage_state.
type CoverageState string

// The closed coverage vocabulary, in the reference's order.
const (
	// CoverageVerified: a supported feed passed a representative
	// authenticated test for this account and runtime.
	CoverageVerified CoverageState = "verified"
	// CoverageAvailable: a documented path exists; enrolment or destination
	// configuration remains ("Available to configure").
	CoverageAvailable CoverageState = "available_to_configure"
	// CoveragePermissionRequired: a role, plan, tenant setting or vendor
	// feature flag blocks collection.
	CoveragePermissionRequired CoverageState = "permission_required"
	// CoveragePartialHistory: summary or some events were retrieved; a known
	// interval or content class is missing.
	CoveragePartialHistory CoverageState = "partial_history"
	// CoverageDelayed: data is expected on a provider-defined schedule.
	CoverageDelayed CoverageState = "delayed_reporting"
	// CoverageNotEstablished: current evidence does not establish support
	// for the signal or surface.
	CoverageNotEstablished CoverageState = "not_established"
	// CoverageDisconnected: credentials, transport or account authorization
	// no longer permit collection.
	CoverageDisconnected CoverageState = "disconnected"
)

var coverageStates = []CoverageState{
	CoverageVerified, CoverageAvailable, CoveragePermissionRequired, CoveragePartialHistory,
	CoverageDelayed, CoverageNotEstablished, CoverageDisconnected,
}

// coverageLabels are the user-facing names of the reference table.
var coverageLabels = map[CoverageState]string{
	CoverageVerified:           "Verified",
	CoverageAvailable:          "Available to configure",
	CoveragePermissionRequired: "Permission required",
	CoveragePartialHistory:     "Partial history",
	CoverageDelayed:            "Delayed reporting",
	CoverageNotEstablished:     "Not established",
	CoverageDisconnected:       "Disconnected",
}

// CoverageStates returns the vocabulary (a copy), in display order.
func CoverageStates() []CoverageState {
	return append([]CoverageState(nil), coverageStates...)
}

// KnownCoverageState reports whether s is in the vocabulary.
func KnownCoverageState(s CoverageState) bool {
	for _, k := range coverageStates {
		if k == s {
			return true
		}
	}
	return false
}

// Label is the user-facing name of a coverage state ("" for an unknown one).
func (s CoverageState) Label() string { return coverageLabels[s] }

// Signal is one separately reported capability of a connector (reference:
// "separate status indicators for discovery, identity, activity detail,
// usage, billing, and control").
type Signal string

// The closed signal vocabulary.
const (
	// SignalDiscovery: the connector finds the account's cloud sessions.
	SignalDiscovery Signal = "discovery"
	// SignalIdentity: who started the work, from a vendor record.
	SignalIdentity Signal = "identity"
	// SignalActivity: per-session activity detail (messages, tools, logs).
	SignalActivity Signal = "activity"
	// SignalTokens: real token counts.
	SignalTokens Signal = "tokens"
	// SignalUsage: native usage units (ACUs, credits, premium requests).
	SignalUsage Signal = "usage"
	// SignalBilling: money the vendor charged.
	SignalBilling Signal = "billing"
	// SignalControl: cancel, steer or approve from Observer.
	SignalControl Signal = "control"
)

var signals = []Signal{
	SignalDiscovery, SignalIdentity, SignalActivity, SignalTokens, SignalUsage, SignalBilling, SignalControl,
}

// Signals returns the signal vocabulary (a copy), in display order.
func Signals() []Signal { return append([]Signal(nil), signals...) }

// ErrorClass is the closed class of a failed collection call. Vendor error
// text is never kept; only this token is (it is what lands in
// cloud_connector_accounts.last_error_class).
type ErrorClass string

// The closed error-class vocabulary.
const (
	// ErrNone is the empty class (success).
	ErrNone ErrorClass = ""
	// ErrNotInstalled: the vendor CLI is not on PATH.
	ErrNotInstalled ErrorClass = "not_installed"
	// ErrNotSignedIn: the vendor CLI has no usable login.
	ErrNotSignedIn ErrorClass = "not_signed_in"
	// ErrPermissionDenied: the account lacks the plan, role or feature flag.
	ErrPermissionDenied ErrorClass = "permission_denied"
	// ErrRateLimited: the vendor asked us to slow down.
	ErrRateLimited ErrorClass = "rate_limited"
	// ErrUnreachable: the vendor could not be reached (a network failure:
	// DNS, connect, TLS, a dropped connection).
	ErrUnreachable ErrorClass = "unreachable"
	// ErrServerError: the vendor answered with a server error (HTTP 5xx).
	// The network is fine and the request was well formed; the vendor's side
	// failed, and the call is retried on the next pass. Distinct from
	// ErrUnreachable so a transient vendor fault never reads as "the network
	// is down" (live check 2026-11-01: one Cursor 500 on a usage read).
	ErrServerError ErrorClass = "server_error"
	// ErrTimeout: the call ran past its time cap.
	ErrTimeout ErrorClass = "timeout"
	// ErrWrongShape: the output did not parse as the recorded schema.
	ErrWrongShape ErrorClass = "wrong_shape"
	// ErrOverCap: the output exceeded the size cap.
	ErrOverCap ErrorClass = "over_cap"
	// ErrHostNotAllowed: a URL outside the exact-host table was refused.
	ErrHostNotAllowed ErrorClass = "host_not_allowed"
	// ErrInvalid: a request this package refused to build (bad id, cursor).
	ErrInvalid ErrorClass = "invalid"
	// ErrStreamExpired: an event stream can no longer be replayed (Cursor
	// 410 stream_expired: the retention window passed). The uncovered
	// interval becomes a gap; it is not an account failure.
	ErrStreamExpired ErrorClass = "stream_expired"
	// ErrStreamResumeRefused: the vendor refused a Last-Event-ID (Cursor
	// 400 invalid_last_event_id); the stream is re-read from its start.
	ErrStreamResumeRefused ErrorClass = "stream_resume_refused"
	// ErrFailed: the call failed for a reason none of the above names.
	ErrFailed ErrorClass = "failed"
)

var errorClasses = []ErrorClass{
	ErrNotInstalled, ErrNotSignedIn, ErrPermissionDenied, ErrRateLimited, ErrUnreachable,
	ErrServerError, ErrTimeout, ErrWrongShape, ErrOverCap, ErrHostNotAllowed, ErrInvalid,
	ErrStreamExpired, ErrStreamResumeRefused, ErrFailed,
}

// KnownErrorClass reports whether c is a non-empty member of the vocabulary.
func KnownErrorClass(c ErrorClass) bool {
	for _, k := range errorClasses {
		if k == c {
			return true
		}
	}
	return false
}

// coverageRule maps an error class to the account's discovery coverage. The
// table is walked top-down; Keep means the failure is transient and the
// previous state stands (a rate limit does not make a working account
// "Disconnected").
type coverageRule struct {
	class ErrorClass
	state CoverageState
	keep  bool
}

var coverageRules = []coverageRule{
	{ErrNone, CoverageVerified, false},
	{ErrNotInstalled, CoverageAvailable, false},
	{ErrNotSignedIn, CoverageDisconnected, false},
	{ErrPermissionDenied, CoveragePermissionRequired, false},
	{ErrRateLimited, "", true},
	{ErrUnreachable, "", true},
	{ErrServerError, "", true},
	{ErrTimeout, "", true},
	{ErrWrongShape, CoveragePartialHistory, false},
	{ErrOverCap, CoveragePartialHistory, false},
	// A stream-level outcome is recorded on that stream's checkpoint as a
	// gap; the account's discovery coverage stands.
	{ErrStreamExpired, "", true},
	{ErrStreamResumeRefused, "", true},
}

// CoverageAfter returns the discovery coverage an account has after a call
// that ended with class, given its previous state. An unlisted class keeps
// the previous state, or "not_established" when there is none.
func CoverageAfter(prev CoverageState, class ErrorClass) CoverageState {
	for _, r := range coverageRules {
		if r.class != class {
			continue
		}
		if r.keep {
			break
		}
		return r.state
	}
	if prev == "" {
		return CoverageNotEstablished
	}
	return prev
}
