package notify

import (
	"reflect"
	"strings"
	"time"
)

// What the guard cloud features send (guard spec section 15, plan
// docs/plans/dashboard-cli-parity-plan-2026-11-06.md decision P-2): the
// facts the dashboard's consent card discloses before a person turns a
// feature on. They live beside the builders so the disclosure cannot drift
// from the bytes: the field lists are read from the structs the builders
// marshal, so a field added to JudgeContext or WebhookAlert is disclosed
// without anyone editing a sentence.

// FieldLimit is the rune bound the free-text fields (a verdict's reason, its
// target excerpt, a judge's rationale) are cut to before a cloud call.
const FieldLimit = maxField

// JudgeApprovalTTL bounds the session approval a high-confidence judge allow
// writes on an ask-class verdict (section 15.2): short by design, so a human
// grant stays the durable path. The daemon's dispatcher uses this value, and
// the consent card states it.
const JudgeApprovalTTL = time.Hour

// JudgeFields lists, in order, the event fields one LLM-judge review sends:
// the JSON names of JudgeContext, which BuildJudgeRequest marshals as the
// user message.
func JudgeFields() []string { return jsonFieldNames(reflect.TypeOf(JudgeContext{})) }

// WebhookFields lists, in order, the alert fields a generic webhook body
// carries: the JSON names of WebhookAlert, which BuildWebhook marshals for
// the generic kind (Slack and Discord get one summary line built from the
// same fields; PagerDuty gets that line plus a subset, see BuildWebhook).
func WebhookFields() []string { return jsonFieldNames(reflect.TypeOf(WebhookAlert{})) }

// jsonFieldNames returns the JSON names of a struct type's exported fields,
// in declaration order, skipping fields tagged "-".
func jsonFieldNames(t reflect.Type) []string {
	out := make([]string, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name := f.Name
		if tag, ok := f.Tag.Lookup("json"); ok {
			head, _, _ := strings.Cut(tag, ",")
			if head == "-" {
				continue
			}
			if head != "" {
				name = head
			}
		}
		out = append(out, name)
	}
	return out
}
