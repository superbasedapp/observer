package proxy

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

type networkCaptureInput struct {
	Provider     string
	SessionID    string
	RequestID    string
	APITurnID    int64
	Method       string
	URL          string
	Host         string
	StatusCode   int
	Duration     time.Duration
	RequestBody  []byte
	ResponseBody []byte
	RequestHead  http.Header
	ResponseHead http.Header
	RequestType  string
	ContentType  string
	Stream       bool
	Error        string
	Unavailable  string
}

// captureProcessNetwork records a proxied upstream call as a process-network
// event when [observer.process.network] capture is enabled. It is deliberately
// detached from the client request context, mirroring api_turn insertion: the
// client may close immediately after receiving the final byte, but diagnostics
// should still land best-effort.
func (p *Proxy) captureProcessNetwork(ctx context.Context, in networkCaptureInput) {
	if p.networkSink == nil || !p.networkCapture.Enabled {
		return
	}
	reqID := in.RequestID
	if reqID == "" {
		reqID = newRequestID()
	}
	// SR27-D3: a direct-provider Gemini call carries the developer's API key
	// in ?key=, and both the upstream URL and a transport error's text (a
	// *url.Error embeds the full URL) would otherwise land verbatim in
	// process_events / process_network_bodies - and ship to the org on a
	// full-content node. Redact at this one capture seam.
	in.URL = redactCredentialQueryText(in.URL)
	in.Error = redactCredentialQueryText(in.Error)
	bodyMode := p.networkCapture.CaptureBodies
	captureBodies := bodyMode == "proxied" || bodyMode == "available"

	details := map[string]any{
		"capture_source": "proxy",
		"provider":       in.Provider,
		"method":         in.Method,
		"url":            in.URL,
		"host":           in.Host,
		"status_code":    in.StatusCode,
		"duration_ms":    in.Duration.Milliseconds(),
		"stream":         in.Stream,
	}
	if in.Error != "" {
		details["error"] = truncateError(in.Error)
	}
	if !captureBodies {
		details["body_unavailable_reason"] = "body_capture_disabled"
	} else if in.Unavailable != "" {
		details["body_unavailable_reason"] = in.Unavailable
	}

	ev := processobs.ProcessEvent{
		ProcessKey: "proxy:" + shortHash(reqID),
		Timestamp:  p.now().UTC(),
		Type:       processobs.EventNetworkConnect,
		Attribution: processobs.Attribution{
			SessionID:  in.SessionID,
			Source:     processobs.AttrHeuristic,
			Confidence: processobs.ConfMedium,
		},
		TargetKind: "url",
		Target:     in.URL,
		Severity:   "info",
		Details:    details,
	}
	if captureBodies {
		reqCap := capBody(in.RequestBody, p.networkCapture.MaxRequestBytes, in.RequestType, p.networkCapture.ScrubBodies, p.networkCapture.StoreBinary)
		respCap := capBody(in.ResponseBody, p.networkCapture.MaxResponseBytes, in.ContentType, p.networkCapture.ScrubBodies, p.networkCapture.StoreBinary)
		body := &processobs.NetworkBodyCapture{
			CaptureSource:         "proxy",
			APITurnID:             in.APITurnID,
			RequestID:             reqID,
			Method:                in.Method,
			URL:                   in.URL,
			Host:                  in.Host,
			StatusCode:            in.StatusCode,
			DurationMs:            in.Duration.Milliseconds(),
			RequestBody:           reqCap.Text,
			RequestBodySHA256:     reqCap.SHA256,
			RequestBodyBytes:      reqCap.Bytes,
			RequestBodyTruncated:  reqCap.Truncated,
			ResponseBody:          respCap.Text,
			ResponseBodySHA256:    respCap.SHA256,
			ResponseBodyBytes:     respCap.Bytes,
			ResponseBodyTruncated: respCap.Truncated,
			ResponseContentType:   in.ContentType,
			BodyUnavailableReason: firstNonEmpty(in.Unavailable, reqCap.UnavailableReason, respCap.UnavailableReason),
		}
		if p.networkCapture.CaptureHeaders {
			body.RequestHeadersJSON = headersJSON(in.RequestHead, []string{
				"accept", "anthropic-version", "content-type", "openai-beta", "user-agent", "x-stainless-lang", "x-stainless-package-version",
			})
			body.ResponseHeadersJSON = headersJSON(in.ResponseHead, []string{
				"anthropic-ratelimit-requests-limit", "anthropic-ratelimit-requests-remaining", "content-type", "openai-organization", "request-id", "x-request-id",
			})
		}
		ev.NetworkBody = body
	}

	insertCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := p.networkSink.PersistProcessEvents(insertCtx, []processobs.ProcessEvent{ev}); err != nil {
		p.logger.Warn("proxy: persist process network event", "err", err)
		_ = ctx
	}
}

type capturedBody struct {
	Text              string
	SHA256            string
	Bytes             int
	Truncated         bool
	UnavailableReason string
}

func capBody(raw []byte, maxBytes int, contentType string, scrubBody, storeBinary bool) capturedBody {
	if maxBytes <= 0 {
		maxBytes = 64 * 1024
	}
	body := raw
	if scrubBody && len(body) > 0 {
		body = scrub.New().ScrubForward(body)
	}
	sum := sha256.Sum256(body)
	out := capturedBody{
		SHA256: hex.EncodeToString(sum[:]),
		Bytes:  len(body),
	}
	if len(body) == 0 {
		return out
	}
	if !looksTextual(contentType, body) && !storeBinary {
		out.UnavailableReason = "binary_content_type"
		return out
	}
	if len(body) > maxBytes {
		body = body[:maxBytes]
		out.Truncated = true
	}
	if !utf8.Valid(body) {
		out.UnavailableReason = "non_utf8_body"
		if !storeBinary {
			return out
		}
	}
	out.Text = string(body)
	return out
}

func looksTextual(contentType string, body []byte) bool {
	ct := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if strings.HasPrefix(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "x-www-form-urlencoded") ||
		strings.Contains(ct, "event-stream") {
		return true
	}
	if ct != "" {
		return false
	}
	return looksLikeText(body)
}

func looksLikeText(body []byte) bool {
	if !utf8.Valid(body) {
		return false
	}
	for _, b := range body {
		if b == 0 {
			return false
		}
		if b < 0x20 && b != '\n' && b != '\r' && b != '\t' {
			return false
		}
	}
	return true
}

func headersJSON(h http.Header, allowed []string) string {
	if len(h) == 0 {
		return ""
	}
	allow := map[string]struct{}{}
	for _, k := range allowed {
		allow[strings.ToLower(k)] = struct{}{}
	}
	out := map[string][]string{}
	for k, vals := range h {
		lk := strings.ToLower(k)
		if _, ok := allow[lk]; !ok {
			continue
		}
		out[lk] = vals
	}
	if len(out) == 0 {
		return ""
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

func contentTypeFrom(h http.Header) string {
	if h == nil {
		return ""
	}
	return h.Get("Content-Type")
}

func targetHost(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Host
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// credentialQueryRe matches a gatewayCredentialQueryParams query parameter
// (Gemini's ?key=) anywhere in a URL or in error text that embeds one, up to
// the next parameter / whitespace / quote.
var credentialQueryRe = func() *regexp.Regexp {
	names := make([]string, 0, len(gatewayCredentialQueryParams))
	for _, n := range gatewayCredentialQueryParams {
		names = append(names, regexp.QuoteMeta(n))
	}
	return regexp.MustCompile(`([?&](?:` + strings.Join(names, "|") + `)=)[^&#\s"']+`)
}()

// redactCredentialQueryText replaces the value of every provider-credential
// query parameter in s with REDACTED (security review 2026-09-27, SR27-D3).
// Used for text that is persisted or logged, never for the forwarded URL.
func redactCredentialQueryText(s string) string {
	if s == "" || !strings.Contains(s, "=") {
		return s
	}
	return credentialQueryRe.ReplaceAllString(s, "${1}REDACTED")
}
