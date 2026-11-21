package proxy

import (
	"context"
	"net/http"
)

// PromptAdmitter is the optional Plane-B coding-agent prompt admission seam
// (P-228, docs/guard.md "Org prompt admission judge"). It is DISTINCT from
// [Admitter], which is Plane A's hosted-app input admission and runs only on
// /up/<id> lanes: this one runs only on the default provider lanes, where the
// developer's coding agents are.
//
// The proxy hands over the provider lane, the plain-JSON request body (before
// conversation compression, after the deterministic prompt guard) and the
// turn's identity; the gate classifies the body itself, because what it
// judges depends on the org policy's scope (the newest user prompt only, or
// every request's new trailing segment). Block refuses the request with a
// provider-shaped 403 carrying Reason; anything else forwards.
//
// Bound in cmd/observer so internal/proxy never imports the admission engine,
// the org client or the store (the [Admitter] precedent). nil ⇒ disabled,
// zero overhead. The gate owns its own fail posture (the policy's strict
// flag) and must never panic.
type PromptAdmitter interface {
	// PromptAdmissionActive reports, cheaply, whether a policy is installed
	// that could judge anything. The proxy asks it first and skips resolving
	// the session id and client tool when it is false (fix round 1, F4).
	PromptAdmissionActive() bool
	AdmitPrompt(ctx context.Context, in PromptAdmitInput) PromptAdmitResult
}

// PromptAdmitInput is the plain request the proxy hands the prompt gate.
type PromptAdmitInput struct {
	// Provider is the resolved provider lane (anthropic | openai | google).
	Provider string
	// Body is the plain-JSON request body (still gzip-encoded when the
	// client gzipped it, which the gate cannot classify and skips).
	Body []byte
	// SessionID is the real API session id ("" when the client sent none).
	SessionID string
	// Tool is the client tool the boundary resolved ("" when unknown).
	Tool string
	// RequestID is the proxy's per-request correlation id.
	RequestID string
	// Model is the pre-mutation top-level request model.
	Model string
}

// PromptAdmitResult is the gate's answer.
type PromptAdmitResult struct {
	// Block refuses the request.
	Block bool
	// Reason is shown to the developer on a refusal.
	Reason string
	// Criterion is the policy criterion (or decision basis) that decided.
	Criterion string
}

// servePromptAdmissionDeny writes the prompt admitter's refusal: the same
// provider-shaped 403 the hosted-app admitter returns, recorded as an error
// api_turn exactly like a guard prompt refusal so the turn is visible.
func (p *Proxy) servePromptAdmissionDeny(w http.ResponseWriter, r *http.Request, provider string, res PromptAdmitResult, reqShapeBody []byte, sessionID string) {
	reason := res.Reason
	if reason == "" {
		reason = "Prompt refused by your organization's coding-agent admission policy."
	} else {
		reason = "Prompt refused by your organization's coding-agent admission policy: " + reason
	}
	body := admissionRefusalBody(provider, reason)
	p.logger.Info("proxy: org prompt admission refused request",
		"provider", provider, "criterion", res.Criterion, "session_id", sessionID)
	p.writeGuardErrorTurn(w, r, provider, body, http.StatusForbidden, reqShapeBody, sessionID,
		"proxy: write prompt-admission refusal", "proxy: insert prompt-admission-refused api_turn")
}
