package hostapi

import (
	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// AnswerKind says how far one attempt got.
type AnswerKind int

// Answer kinds.
const (
	// AnswerNotSent: nothing left the process (placement, resolving the
	// create extras, building or signing the request failed).
	AnswerNotSent AnswerKind = iota + 1
	// AnswerTransport: the request may have left but no answer came back
	// (dial, TLS, timeout, read).
	AnswerTransport
	// AnswerUnverified: an answer came back but did not verify against the
	// host's pinned response key (no envelope, unknown key id, nonce not
	// echoed, stale, digest or signature mismatch, oversized). Its body and
	// status are untrusted; it is never a success.
	AnswerUnverified
	// AnswerVerified: the answer's response envelope verified; Body is
	// exactly the signed body.
	AnswerVerified
)

// Answer is the outcome of one attempt as the transport reports it.
type Answer struct {
	// Kind is how far the attempt got.
	Kind AnswerKind
	// Reason is a short fixed word for NotSent, Transport and Unverified
	// answers (e.g. "dial", "signature"); it lands in the outbox error class.
	Reason string
	// Permanent marks a NotSent answer whose intent can never become a valid
	// request (ErrBadIntent): retrying cannot help.
	Permanent bool
	// Body is the signed body of a verified answer.
	Body []byte
	// HTTPStatus is the status line's code, for logs only. It is not covered
	// by the response signature and decides nothing.
	HTTPStatus int
}

// Action is what the dispatcher does with an outbox row after an attempt.
type Action string

// Actions.
const (
	// ActionAck: the host acted (or already had); the row is done.
	ActionAck Action = "ack"
	// ActionRetry: nothing is known to be wrong with the intent; send it
	// again after the backoff.
	ActionRetry Action = "retry"
	// ActionRetryNewRequest: the 409 class (replayed, idempotency in
	// progress): send it again as a new request, with a new nonce and the
	// same idempotency key, after a short delay.
	ActionRetryNewRequest Action = "retry_new_request"
	// ActionPark: the host refused the intent itself; it is never resent
	// blind. The row is marked failed for an operator.
	ActionPark Action = "park"
	// ActionWaitlist: the host put a create on its capacity waitlist
	// (capacity_waitlist, W14-D4). Nothing is wrong with the intent and
	// nothing was created; it is sent again after at least WaitlistMinDelay,
	// and the row's error class says it is waitlisted. Never parked.
	ActionWaitlist Action = "waitlist"
)

// Decision is the outcome of judging one answer.
type Decision struct {
	// Rule is the name of the answerRules row that matched.
	Rule string
	// Action is what to do with the row.
	Action Action
	// Class is the enum-only error class recorded on the row ("" on ack).
	Class string
	// Observed is the tenant state a verified success reported.
	Observed Observed
}

// answerFacts is one answer read once, before the rules are walked.
type answerFacts struct {
	a       Answer
	refusal *pc.ErrorResponse
	bodyErr error
	verdict verdict
}

// answerRule is one row of answerRules.
type answerRule struct {
	name   string
	match  func(f answerFacts) bool
	decide func(f answerFacts) Decision
}

// answerRules decides what an attempt's answer means, walked top-down, first
// match wins; the last row matches everything. Success is decided by the
// signed body alone (every row from bad_body on reads only a verified body);
// the HTTP status is never consulted. One test case per row (judge_test.go).
var answerRules = []answerRule{
	{
		name:   "not_sent_invalid",
		match:  func(f answerFacts) bool { return f.a.Kind == AnswerNotSent && f.a.Permanent },
		decide: fixed(ActionPark, "bad_intent"),
	},
	{
		name:   "not_sent",
		match:  func(f answerFacts) bool { return f.a.Kind == AnswerNotSent },
		decide: withReason(ActionRetry, "not_sent:"),
	},
	{
		name:   "transport",
		match:  func(f answerFacts) bool { return f.a.Kind == AnswerTransport },
		decide: withReason(ActionRetry, "transport:"),
	},
	// An answer that did not verify may be a refusal the host sent before
	// authenticating us (unsigned by design), a forgery, or a key-rotation
	// gap. Its content is untrusted either way, so it neither parks (a
	// forged refusal must not stop delivery) nor succeeds; it retries with
	// backoff and the class tells the operator why.
	{
		name:   "unverified",
		match:  func(f answerFacts) bool { return f.a.Kind != AnswerVerified },
		decide: withReason(ActionRetry, "unverified:"),
	},
	{
		name:   "bad_body",
		match:  func(f answerFacts) bool { return f.refusal == nil && f.bodyErr != nil },
		decide: fixed(ActionRetry, "bad_response"),
	},
	{
		name:   "replayed",
		match:  refusalIs(pc.CodeReplayed),
		decide: fixed(ActionRetryNewRequest, "refused:"+string(pc.CodeReplayed)),
	},
	{
		name:   "idempotency_in_progress",
		match:  refusalIs(pc.CodeIdempotencyInProgress),
		decide: fixed(ActionRetryNewRequest, "refused:"+string(pc.CodeIdempotencyInProgress)),
	},
	// A waitlisted create (W14-D4, answered with 503 by the host): the host
	// is at its capacity ceiling. The row stays open with this class, which
	// is what an operator or the console reads as "waitlisted"; it is
	// retried slowly. Matched before unknown_code, so it is honoured whether
	// or not this build's contract lists the code yet.
	{
		name:   "capacity_waitlist",
		match:  refusalIs(pc.CodeCapacityWaitlist),
		decide: fixed(ActionWaitlist, "refused:"+string(pc.CodeCapacityWaitlist)),
	},
	{
		name:   "unavailable",
		match:  refusalIs(pc.CodeUnavailable),
		decide: fixed(ActionRetry, "refused:"+string(pc.CodeUnavailable)),
	},
	{
		name:   "internal",
		match:  refusalIs(pc.CodeInternal),
		decide: fixed(ActionRetry, "refused:"+string(pc.CodeInternal)),
	},
	{
		name:   "unknown_code",
		match:  func(f answerFacts) bool { return f.refusal != nil && !f.refusal.Code.Valid() },
		decide: fixed(ActionPark, "refused:unknown_code"),
	},
	{
		name:  "refused",
		match: func(f answerFacts) bool { return f.refusal != nil },
		decide: func(f answerFacts) Decision {
			return Decision{Action: ActionPark, Class: "refused:" + string(f.refusal.Code)}
		},
	},
	// The host releases a failed create's idempotency key, so the retry acts
	// again (internal/orgserver/hostapi verbs.go "keep").
	{
		name:   "create_failed",
		match:  func(f answerFacts) bool { return f.verdict.createFailed },
		decide: fixed(ActionRetry, "create_failed"),
	},
	{
		name:   "ok",
		match:  func(answerFacts) bool { return true },
		decide: func(f answerFacts) Decision { return Decision{Action: ActionAck, Observed: f.verdict.observed} },
	},
}

// fixed is a decide func with a constant outcome.
func fixed(a Action, class string) func(answerFacts) Decision {
	return func(answerFacts) Decision { return Decision{Action: a, Class: class} }
}

// withReason is a decide func whose class is prefix plus the answer's reason.
func withReason(a Action, prefix string) func(answerFacts) Decision {
	return func(f answerFacts) Decision { return Decision{Action: a, Class: prefix + reason(f.a)} }
}

func refusalIs(code pc.ErrorCode) func(f answerFacts) bool {
	return func(f answerFacts) bool { return f.refusal != nil && f.refusal.Code == code }
}

func reason(a Answer) string {
	if a.Reason == "" {
		return "unknown"
	}
	return a.Reason
}

// Judge decides what to do with queued row q after answer a. It never
// returns ActionAck for an answer that is not AnswerVerified.
func Judge(q Queued, a Answer) Decision {
	return judgeWith(a, func(body []byte) (verdict, error) {
		if s, ok := specFor(q.Verb); ok {
			return s.judge(q, body)
		}
		return verdict{}, errBadResponse
	})
}

// judgeWith reads a once (a verified success body through read) and walks
// answerRules. Judge reads an outbox verb's answer; JudgeAvailability reads
// the host-level availability verb's (availability.go).
func judgeWith(a Answer, read func(body []byte) (verdict, error)) Decision {
	f := answerFacts{a: a}
	if a.Kind == AnswerVerified {
		f.refusal, f.bodyErr = splitBody(a.Body)
		if f.refusal == nil && f.bodyErr == nil {
			f.verdict, f.bodyErr = read(a.Body)
		}
	}
	for _, r := range answerRules {
		if r.match(f) {
			d := r.decide(f)
			d.Rule = r.name
			return d
		}
	}
	// Unreachable: the last row matches everything.
	return Decision{Rule: "none", Action: ActionRetry, Class: "unjudged"}
}
