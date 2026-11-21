package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudmetrics"
)

// metrics.go is the api package's metrics seam (FR-4 follow-up;
// docs/saas-monitoring.md "Cloud metrics"). The counters are fed from two
// places only: audit() (middleware.go) counts every audit event, and
// observePaddleWebhook below counts every Paddle webhook delivery from the
// answer the handler wrote (status, then its JSON code or outcome), so
// paddle.go carries no counter calls of its own beyond the one
// BindingRefused line in logBindingRefusal. The registry is
// Options.Metrics; nil (tests, an unwired caller) counts nothing.

// webhookBodyCap bounds how much of the webhook's answer the recorder keeps
// to read its code or outcome (every answer is a small JSON object).
const webhookBodyCap = 1024

// webhookRecorder records the status and the first bytes of the answer. It
// passes Flush through and implements Unwrap for http.ResponseController.
type webhookRecorder struct {
	http.ResponseWriter
	status int
	body   []byte
}

func (r *webhookRecorder) WriteHeader(code int) {
	if r.status == 0 {
		r.status = code
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *webhookRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	if room := webhookBodyCap - len(r.body); room > 0 {
		r.body = append(r.body, b[:min(room, len(b))]...)
	}
	return r.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *webhookRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

// Flush passes a flush through when the underlying writer supports it.
func (r *webhookRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Hijack passes a hijack through when the underlying writer supports it.
func (r *webhookRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := r.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, errors.New("cloudserver/api: response writer does not support hijacking")
}

// observePaddleWebhook wraps the Paddle webhook route: it puts the request's
// audit source (the trusted client IP, edgeClientIP) in the context for the
// audit-row limit (auditlimit.go), and counts the delivery from the answer.
// It is the OUTERMOST layer of the route so a rate-limited delivery is
// counted too. It changes nothing the handler writes.
func (s *Server) observePaddleWebhook(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if src, err := edgeClientIP(r); err == nil {
			r = r.WithContext(withAuditSource(r.Context(), src))
		}
		rec := &webhookRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		s.metrics.WebhookDelivery(webhookOutcome(rec.status, rec.body))
	})
}

// webhookStatusRules maps the webhook's non-200 answers to a (result,
// reason), walked top-down; the first matching row wins. The reasons are the
// closed values of cloudmetrics; the codes are the webhook's own error codes
// (paddle.go, rateLimitWebhook).
var webhookStatusRules = []struct {
	status         int
	code           string // "" matches any code
	result, reason string
}{
	{http.StatusUnauthorized, "", cloudmetrics.WebhookRefused, "signature_invalid"},
	{http.StatusNotImplemented, "", cloudmetrics.WebhookRefused, "not_configured"},
	{http.StatusRequestEntityTooLarge, "", cloudmetrics.WebhookRefused, "body_too_large"},
	{http.StatusBadRequest, "", cloudmetrics.WebhookRefused, "bad_envelope"},
	{http.StatusTooManyRequests, "", cloudmetrics.WebhookRefused, "rate_limited"},
	{http.StatusServiceUnavailable, "rate_limit_unavailable", cloudmetrics.WebhookRefused, "rate_limited"},
	{http.StatusInternalServerError, "event_processing_failed", cloudmetrics.WebhookFailed, "processing_failed"},
}

// webhookOutcome classifies one answer: a 200 is accepted with the body's
// outcome; anything else by webhookStatusRules; a 5xx no row names is a
// failed/other, the rest refused/other. The cloudmetrics labels close every
// value again.
func webhookOutcome(status int, body []byte) (result, reason string) {
	var ans struct {
		Code    string `json:"code"`
		Outcome string `json:"outcome"`
	}
	_ = json.Unmarshal(body, &ans)
	if status == http.StatusOK {
		return cloudmetrics.WebhookAccepted, ans.Outcome
	}
	for _, rule := range webhookStatusRules {
		if rule.status == status && (rule.code == "" || rule.code == ans.Code) {
			return rule.result, rule.reason
		}
	}
	if status >= 500 {
		return cloudmetrics.WebhookFailed, cloudmetrics.Other
	}
	return cloudmetrics.WebhookRefused, cloudmetrics.Other
}
