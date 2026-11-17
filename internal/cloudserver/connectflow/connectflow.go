package connectflow

import (
	"time"
)

// Lifetimes and limits of a connect request (the contract's section 8).
const (
	// RequestTTL is how long a request stays pending.
	RequestTTL = 15 * time.Minute
	// PollInterval is the interval the create answer tells the machine to
	// poll at.
	PollInterval = 3 * time.Second
	// MaxDeliveries bounds how many polls may receive the sign-in of one
	// approved request (a lost response can be retried).
	MaxDeliveries = 3
	// DeliveryWindow bounds how long after approval the sign-in may still be
	// delivered.
	DeliveryWindow = 10 * time.Minute
	// EndedRetention is how long a declined or expired request, or an
	// approved one's machine facts beyond the account home, is kept after it
	// ends.
	EndedRetention = 24 * time.Hour
	// ApprovedRetention is how long an approved request is kept for the
	// account home's "recently connected" list.
	ApprovedRetention = 30 * 24 * time.Hour
	// RecentLimit bounds the account home's recent list.
	RecentLimit = 20
)

// Status is a connect request's state on the wire. Expired is never stored:
// a pending request past its expiry reads as expired (EffectiveStatus).
type Status string

// Statuses.
const (
	StatusPending  Status = "pending"
	StatusApproved Status = "approved"
	StatusDeclined Status = "declined"
	StatusExpired  Status = "expired"
)

// Event is what a signed-in browser does to a request.
type Event string

// Events.
const (
	// EventConnect approves the request with a chosen dashboard.
	EventConnect Event = "connect"
	// EventNotNow approves the sign-in only: no dashboard, nothing sent.
	EventNotNow Event = "not_now"
	// EventDecline refuses the request ("This is not my machine").
	EventDecline Event = "decline"
)

// transition is one row of the status machine.
type transition struct {
	from Status
	ev   Event
	to   Status
	// target is true when the row carries a chosen dashboard.
	target bool
}

// transitions is the status machine (the contract's section 4). Anything not
// listed is refused; in particular every terminal status stays put.
var transitions = []transition{
	{from: StatusPending, ev: EventConnect, to: StatusApproved, target: true},
	{from: StatusPending, ev: EventNotNow, to: StatusApproved, target: false},
	{from: StatusPending, ev: EventDecline, to: StatusDeclined, target: false},
}

// Transition reports the status ev moves a request in status from to, and
// whether that move carries a dashboard. ok is false when the move is not
// allowed (the caller answers 409 not_pending). from must already be the
// effective status (EffectiveStatus), so an expired request cannot move.
func Transition(from Status, ev Event) (to Status, withTarget, ok bool) {
	for _, t := range transitions {
		if t.from == from && t.ev == ev {
			return t.to, t.target, true
		}
	}
	return from, false, false
}

// EffectiveStatus is the status a stored request reads as at now: a pending
// request at or past its expiry is expired.
func EffectiveStatus(stored Status, expiresAt, now time.Time) Status {
	if stored == StatusPending && !now.Before(expiresAt) {
		return StatusExpired
	}
	return stored
}

// Delivery is the decision about one poll of an approved request.
type Delivery string

// Delivery outcomes.
const (
	// DeliverNone: the request is not approved; nothing to hand over.
	DeliverNone Delivery = "none"
	// DeliverSignIn: mint (or re-mint) the sign-in and hand it over.
	DeliverSignIn Delivery = "sign_in"
	// DeliverExhausted: the sign-in was already handed over as often, or as
	// late, as allowed (409 sign_in_already_delivered).
	DeliverExhausted Delivery = "exhausted"
)

// DeliveryFacts are the inputs of DeliveryDecision.
type DeliveryFacts struct {
	Status     Status
	Deliveries int
	ApprovedAt time.Time
	Now        time.Time
}

// deliveryRule is one row: the first whose when holds decides.
type deliveryRule struct {
	id      string
	when    func(DeliveryFacts) bool
	outcome Delivery
}

// deliveryRules decide whether a poll receives the sign-in, top down.
var deliveryRules = []deliveryRule{
	{id: "not-approved", when: func(f DeliveryFacts) bool { return f.Status != StatusApproved }, outcome: DeliverNone},
	{id: "too-many", when: func(f DeliveryFacts) bool { return f.Deliveries >= MaxDeliveries }, outcome: DeliverExhausted},
	{id: "too-late", when: func(f DeliveryFacts) bool { return f.Now.Sub(f.ApprovedAt) > DeliveryWindow }, outcome: DeliverExhausted},
	{id: "deliver", when: func(DeliveryFacts) bool { return true }, outcome: DeliverSignIn},
}

// DeliveryDecision decides what one poll of a request receives.
func DeliveryDecision(f DeliveryFacts) Delivery {
	for _, r := range deliveryRules {
		if r.when(f) {
			return r.outcome
		}
	}
	return DeliverNone
}
