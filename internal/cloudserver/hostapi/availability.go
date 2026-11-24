package hostapi

import (
	"encoding/json"
	"fmt"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// availability.go is the host-level availability verb (PUT
// /platform/v1/availability, platformcontract.SetAvailabilityRequest): the
// platform availability envelope pushed to a pooled host. Unlike the outbox
// verbs it is not about one tenant, so it has no outbox row: the worker's
// availability deliverer (internal/cloudserver/availwork) sends the newest
// envelope to every host until the host answers that it holds it, and keeps
// each host's state in availability_deliveries (cloud 0154). Answers are
// judged by the same answerRules as every outbox verb.

// AvailabilityPush is the request that pushes doc to a host.
func AvailabilityPush(doc pc.AvailabilityDocument) (Request, error) {
	r := pc.SetAvailabilityRequest{Document: doc}
	if err := r.Validate(); err != nil {
		return Request{}, fmt.Errorf("hostapi.AvailabilityPush: %w: %w", ErrBadIntent, err)
	}
	body, err := json.Marshal(r)
	if err != nil {
		return Request{}, fmt.Errorf("hostapi.AvailabilityPush: %w", err)
	}
	return Request{Method: methodPut, Path: pc.PathAvailability, Body: body}, nil
}

// DeliveryOutcome is what one availability push did.
type DeliveryOutcome string

// Delivery outcomes.
const (
	// DeliveryInForce: the host answered (verified) with the version it
	// holds, the pushed one or a newer one.
	DeliveryInForce DeliveryOutcome = "delivered"
	// DeliveryRetry: nothing is known to be wrong with the envelope; send
	// it again on a later pass.
	DeliveryRetry DeliveryOutcome = "retry"
	// DeliveryRefused: the host refused this envelope (a verified refusal:
	// its key is not pinned there, or its body breaks the host's rules).
	DeliveryRefused DeliveryOutcome = "refused"
)

// AvailabilityVerdict is JudgeAvailability's reading of one answer.
type AvailabilityVerdict struct {
	// Outcome is delivered, retry or refused.
	Outcome DeliveryOutcome
	// InForce is the version the host holds (delivered only).
	InForce int64
	// Class is the enum-only error class ("" when delivered).
	Class string
	// Rule is the answerRules row that matched.
	Rule string
}

// deliveryOutcomes maps the answer table's action to the delivery outcome.
var deliveryOutcomes = map[Action]DeliveryOutcome{
	ActionAck:             DeliveryInForce,
	ActionRetry:           DeliveryRetry,
	ActionRetryNewRequest: DeliveryRetry,
	ActionWaitlist:        DeliveryRetry,
	ActionPark:            DeliveryRefused,
}

// readAvailability reads a verified success body: the version in force must
// be positive (a host that just accepted an envelope holds one).
func readAvailability(body []byte) (verdict, error) {
	var r pc.SetAvailabilityResponse
	if err := json.Unmarshal(body, &r); err != nil || r.Version <= 0 {
		return verdict{}, errBadResponse
	}
	return verdict{}, nil
}

// JudgeAvailability decides what an availability push's answer means, with
// the outbox verbs' answer table (an unverified answer never counts as
// delivered nor as refused).
func JudgeAvailability(a Answer) AvailabilityVerdict {
	d := judgeWith(a, readAvailability)
	out := AvailabilityVerdict{Outcome: deliveryOutcomes[d.Action], Class: d.Class, Rule: d.Rule}
	if out.Outcome == "" {
		out.Outcome = DeliveryRetry
	}
	if out.Outcome == DeliveryInForce {
		var r pc.SetAvailabilityResponse
		if err := json.Unmarshal(a.Body, &r); err != nil {
			return AvailabilityVerdict{Outcome: DeliveryRetry, Class: "bad_response", Rule: "bad_body"}
		}
		out.InForce = r.Version
	}
	return out
}
