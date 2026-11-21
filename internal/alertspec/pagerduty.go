package alertspec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// pagerduty.go is the PagerDuty Events API v2 channel (Plane A W5-5, lane
// C9), beside Slack: the routing key check, the dedup key and the event body.
// Both evaluators post it at their own boundary (the org's guarded client,
// the machine's alert loop) to PagerDutyEventsURL.

// PagerDutyEventsURL is the Events API v2 enqueue endpoint, the one host the
// PagerDuty channel reaches (declared in both egress lane tables).
const PagerDutyEventsURL = "https://events.pagerduty.com/v2/enqueue"

// PagerDuty event actions.
const (
	PagerDutyTrigger = "trigger"
	PagerDutyResolve = "resolve"
)

// PagerDutyRoutingKeyLen is the length of an Events API v2 integration
// (routing) key.
const PagerDutyRoutingKeyLen = 32

// ErrPagerDutyKey is returned for a routing key that is not one. Its text
// never carries the key (the key is a secret).
var ErrPagerDutyKey = errors.New("pagerduty routing key must be the 32-character Events API v2 integration key")

// ValidPagerDutyRoutingKey checks an Events API v2 routing key: exactly 32
// ASCII letters or digits. The empty string is valid (it clears the setting).
func ValidPagerDutyRoutingKey(key string) error {
	if key == "" {
		return nil
	}
	if len(key) != PagerDutyRoutingKeyLen {
		return ErrPagerDutyKey
	}
	for i := 0; i < len(key); i++ {
		c := key[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') {
			return ErrPagerDutyKey
		}
	}
	return nil
}

// PagerDutyDedupKey is the incident key of one rule's alert: the scope (the
// organization id, or "machine"), the rule's stable id (the org rule id, or
// the machine rule name) and its dimensions, hashed. A trigger and the later
// resolve of the same rule and dimensions carry the same key, so PagerDuty
// folds repeated triggers into one incident and the resolve closes it. The
// key is a hash so the end user a rule names never reaches PagerDuty in it.
func PagerDutyDedupKey(scope, ruleID string, d Dimensions) string {
	var b strings.Builder
	b.WriteString("sbo-alert-v1\x00")
	b.WriteString(scope)
	b.WriteString("\x00")
	b.WriteString(ruleID)
	for _, row := range d.fields() {
		b.WriteString("\x00")
		b.WriteString(row.name)
		b.WriteString("=")
		b.WriteString(*row.val)
	}
	sum := sha256.Sum256([]byte(b.String()))
	return "sbo-" + hex.EncodeToString(sum[:20])
}

// PagerDutyHiddenUser is HiddenUser, the name the PagerDuty channel used
// first (review finding R-C19).
const PagerDutyHiddenUser = HiddenUser

// maxPagerDutySummary is the Events API v2 bound on payload.summary.
const maxPagerDutySummary = 1024

// pagerDutyBody is the Events API v2 enqueue body.
type pagerDutyBody struct {
	RoutingKey  string            `json:"routing_key"`
	EventAction string            `json:"event_action"`
	DedupKey    string            `json:"dedup_key"`
	Payload     *pagerDutyPayload `json:"payload,omitempty"`
}

type pagerDutyPayload struct {
	Summary       string         `json:"summary"`
	Source        string         `json:"source"`
	Severity      string         `json:"severity"`
	Timestamp     string         `json:"timestamp,omitempty"`
	Component     string         `json:"component,omitempty"`
	Class         string         `json:"class,omitempty"`
	CustomDetails map[string]any `json:"custom_details,omitempty"`
}

// PagerDutyEvent renders a into an Events API v2 body: a "fired" or "test"
// alert is a trigger (with a payload), a "resolved" one a resolve (no
// payload, which the API ignores on a resolve). The payload carries the
// rule's name, metric, value, threshold, window and its model, tag and
// service dimensions; a user dimension shows only as PagerDutyHiddenUser. dedupKey is
// PagerDutyDedupKey for a rule's alert.
func PagerDutyEvent(routingKey, dedupKey string, a SlackAlert) ([]byte, error) {
	if err := ValidPagerDutyRoutingKey(routingKey); err != nil || routingKey == "" {
		return nil, ErrPagerDutyKey
	}
	if dedupKey == "" {
		return nil, fmt.Errorf("alertspec.PagerDutyEvent: empty dedup key")
	}
	body := pagerDutyBody{RoutingKey: routingKey, EventAction: PagerDutyTrigger, DedupKey: dedupKey}
	if a.Event == "resolved" {
		body.EventAction = PagerDutyResolve
	} else {
		body.Payload = pagerDutyPayloadOf(a)
	}
	b, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("alertspec.PagerDutyEvent: %w", err)
	}
	return b, nil
}

func pagerDutyPayloadOf(a SlackAlert) *pagerDutyPayload {
	severity := "error"
	if a.Event == "test" {
		severity = "info"
	}
	source := a.Source
	if source == "" {
		source = "superbased"
	}
	summary := "superbased alert: " + a.RuleName
	if a.Event == "test" {
		summary = "superbased test event: " + a.RuleName
	} else {
		cmp := ">"
		if a.Comparator == "gte" {
			cmp = ">="
		}
		summary += fmt.Sprintf(" (%s %s %s %s)", a.Metric, formatNum(a.Value), cmp, formatNum(a.Threshold))
	}
	if len(summary) > maxPagerDutySummary {
		summary = summary[:maxPagerDutySummary]
	}
	details := map[string]any{"rule": a.RuleName}
	if a.Event != "test" {
		details["metric"] = a.Metric
		details["value"] = a.Value
		details["threshold"] = a.Threshold
		details["comparator"] = a.Comparator
		if a.Window != "" {
			details["window"] = a.Window
		}
	}
	// The end user a rule names is the hosted app's customer (PII); it
	// never leaves for PagerDuty, in the dedup key or the payload (review
	// finding R-C19). The rule in SuperBased names them.
	for _, p := range a.Dimensions.Outbound().Pairs() {
		details["dimension_"+p[0]] = p[1]
	}
	return &pagerDutyPayload{
		Summary: summary, Source: source, Severity: severity, Timestamp: a.FiredAt,
		Component: a.Metric, Class: "superbased.alert", CustomDetails: details,
	}
}
