package gwhttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/aigateway"
	"github.com/marmutapp/superbased-observer/internal/aigateway/providerext"
)

// ForwardRequest is one upstream dial. The credential is the PLAINTEXT provider
// key, resolved from the sealed store just before the call and never persisted
// or logged; Body has already been capped and pseudonym-stamped.
type ForwardRequest struct {
	Upstream    aigateway.Upstream
	Parser      aigateway.Parser
	Credential  string
	Body        []byte
	PathSuffix  string
	Stream      bool
	Guard       aigateway.GuardScanner
	MaxDuration time.Duration
	// MaxResponseBytes caps a BUFFERED response read (forwardProviderExt) so a
	// hostile/huge upstream body cannot force an unbounded io.ReadAll into
	// memory (§2.7 OOM guard, m4). Zero ⇒ aigateway.DefaultMaxBodyBytes.
	MaxResponseBytes int64

	// AbortCheck, when non-nil, is consulted before each response chunk is
	// relayed. A true result aborts the stream with the returned marker —
	// the strict-revocation in-flight abort (HG8): bytes already delivered
	// cannot be unsent, but nothing further reaches a revoked key's holder.
	// The check is expected to throttle its own cost (AuthCache.
	// StrictRevocationCheck does); a nil check is today's behavior.
	AbortCheck func() (abort bool, marker string)

	// Model is consumed only by forwardProviderExt's adapter-driven
	// URL mapping (providerext.ProviderAdapter.BuildURL needs a model
	// name); HTTPUpstreamer.Forward ignores it and derives the request
	// path from PathSuffix/kindDefaultPath instead.
	Model string
}

// ForwardResult is the observed outcome of the dial.
type ForwardResult struct {
	StatusCode   int
	Usage        aigateway.Usage
	Aborted      bool
	AbortMarker  string
	GuardFlagged bool
	BytesOut     int64
}

// Upstreamer dials a provider upstream and streams the response into w. It is
// an interface so the handler can be tested with a fake and so the real dialer
// can be swapped without touching the pipeline.
type Upstreamer interface {
	Forward(ctx context.Context, w http.ResponseWriter, req ForwardRequest) (ForwardResult, error)
}

// HTTPUpstreamer is the production net/http dialer. It builds a FRESH outbound
// request — the inbound virtual key is never copied onto it (custody) — and
// attaches the org's provider credential in the kind's own auth header.
type HTTPUpstreamer struct {
	Client *http.Client
}

// NewHTTPUpstreamer builds a dialer. A nil client uses a default with no
// timeout (the per-stream deadline is applied via context instead, so a
// long-but-healthy stream is not cut at a fixed wall clock).
func NewHTTPUpstreamer(client *http.Client) *HTTPUpstreamer {
	if client == nil {
		client = &http.Client{}
	}
	return &HTTPUpstreamer{Client: client}
}

// defaultAnthropicVersion is used when an anthropic upstream omits api_version.
const defaultAnthropicVersion = "2023-06-01"

// kindDefaultPath is the provider path used when the inbound request carried no
// path suffix (a bare gateway call). A real tool call carries its own path.
func kindDefaultPath(p aigateway.Parser) string {
	if p == aigateway.ParserAnthropic {
		return "/v1/messages"
	}
	return "/v1/chat/completions"
}

// Forward implements Upstreamer.
func (h *HTTPUpstreamer) Forward(ctx context.Context, w http.ResponseWriter, req ForwardRequest) (ForwardResult, error) {
	ctx, cancel := context.WithTimeout(ctx, req.MaxDuration)
	defer cancel()

	suffix := req.PathSuffix
	if suffix == "" {
		suffix = kindDefaultPath(req.Parser)
	}
	url := strings.TrimRight(req.Upstream.BaseURL, "/") + suffix
	if req.Upstream.Kind == aigateway.KindAzureOpenAI && req.Upstream.APIVersion != "" {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		url += sep + "api-version=" + req.Upstream.APIVersion
	}

	outReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req.Body))
	if err != nil {
		return ForwardResult{}, fmt.Errorf("gwhttp.Forward: build request: %w", err)
	}
	outReq.Header.Set("Content-Type", "application/json")
	if req.Stream {
		outReq.Header.Set("Accept", "text/event-stream")
	}
	attachAuth(outReq, req.Upstream, req.Credential)

	resp, err := h.Client.Do(outReq)
	if err != nil {
		return ForwardResult{}, fmt.Errorf("gwhttp.Forward: upstream dial: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Relay status + a minimal, SAFE set of response headers (content-type so
	// the client parses the stream; never any upstream credential echo).
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	w.WriteHeader(resp.StatusCode)

	res := ForwardResult{StatusCode: resp.StatusCode}
	cap := newUsageCapture()
	flusher, _ := w.(http.Flusher)
	buf := make([]byte, 16<<10)
	for {
		n, rerr := resp.Body.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			// Strict revocation mid-stream (HG8): stop BEFORE relaying this
			// chunk when the key was strict-revoked since the last check.
			if req.AbortCheck != nil {
				if abort, marker := req.AbortCheck(); abort {
					res.Aborted = true
					res.AbortMarker = marker
					break
				}
			}
			// Response-side inspection: abort on a critical hit, flag on a
			// non-critical one (design §2.7). Bytes already delivered cannot be
			// unsent (HG7); the abort stops FURTHER leakage.
			class := req.Guard.ScanChunk(chunk)
			if class == aigateway.ScanNonCritical {
				res.GuardFlagged = true
			}
			if aigateway.AbortOnScan(class) {
				res.Aborted = true
				res.AbortMarker = aigateway.MarkerAborted
				break
			}
			if _, werr := w.Write(chunk); werr != nil {
				res.Aborted = true
				res.AbortMarker = aigateway.MarkerStreamError
				break
			}
			cap.Write(chunk)
			res.BytesOut += int64(n)
			if flusher != nil {
				flusher.Flush()
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			// A deadline or connection drop finalizes with what was observed.
			res.Aborted = true
			if res.AbortMarker == "" {
				res.AbortMarker = aigateway.MarkerStreamError
			}
			break
		}
	}

	res.Usage = aigateway.ExtractUsage(req.Upstream.Kind, cap.Bytes())
	return res, nil
}

// forwardProviderExt dials a pluggable native-protocol upstream (Bedrock,
// Vertex — anything registered in a providerext.Registry) using the
// adapter's own URL mapping, auth attachment, and usage extraction, rather
// than the OpenAI/Anthropic wire conventions HTTPUpstreamer.Forward speaks.
//
// It reads the upstream response fully buffered rather than relaying chunks
// incrementally: a providerext.ProviderAdapter's ExtractUsage contract is a
// single JSON body, and Bedrock's unary invoke / Vertex's generateContent
// are both single-response calls for this wiring — the InvokeModelWithResponseStream
// / streamGenerateContent variants are a documented follow-up, not this
// change's scope. Buffering also lets a critical guard hit suppress the
// ENTIRE body (no bytes have reached the client yet), which is strictly
// safer than the streaming path's already-sent-bytes limitation.
func forwardProviderExt(ctx context.Context, client *http.Client, w http.ResponseWriter, req ForwardRequest, adapter providerext.ProviderAdapter, signer providerext.Signer) (ForwardResult, error) {
	ctx, cancel := context.WithTimeout(ctx, req.MaxDuration)
	defer cancel()

	url := adapter.BuildURL(req.Upstream.BaseURL, req.Model, req.Stream)
	outReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(req.Body))
	if err != nil {
		return ForwardResult{}, fmt.Errorf("gwhttp.forwardProviderExt: build request: %w", err)
	}
	outReq.Header.Set("Content-Type", "application/json")
	if err := adapter.AttachAuth(outReq, req.Credential, signer); err != nil {
		return ForwardResult{}, fmt.Errorf("gwhttp.forwardProviderExt: attach auth: %w", err)
	}

	resp, err := client.Do(outReq)
	if err != nil {
		return ForwardResult{}, fmt.Errorf("gwhttp.forwardProviderExt: upstream dial: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap the buffered read: an unbounded io.ReadAll of a hostile/huge upstream
	// response is an OOM vector (§2.7, m4). LimitReader at cap+1 lets us detect
	// overflow deterministically.
	maxBytes := req.MaxResponseBytes
	if maxBytes <= 0 {
		maxBytes = aigateway.DefaultMaxBodyBytes
	}
	respBody, rerr := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if rerr != nil {
		return ForwardResult{}, fmt.Errorf("gwhttp.forwardProviderExt: read response: %w", rerr)
	}
	if int64(len(respBody)) > maxBytes {
		// Over the cap: refuse rather than hold an unbounded body in memory. The
		// caller settles with MarkerStreamError (returned on the result), never
		// leaving the reservation open to be reconciled at worst-case.
		writeJSONError(w, http.StatusBadGateway, "response_too_large", "upstream response exceeded the gateway buffer cap")
		return ForwardResult{StatusCode: http.StatusBadGateway, Aborted: true, AbortMarker: aigateway.MarkerStreamError}, nil
	}

	res := ForwardResult{StatusCode: resp.StatusCode}
	class := req.Guard.ScanChunk(respBody)
	if class == aigateway.ScanNonCritical {
		res.GuardFlagged = true
	}
	if ct := resp.Header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	if aigateway.AbortOnScan(class) {
		res.Aborted = true
		res.AbortMarker = aigateway.MarkerAborted
		w.WriteHeader(resp.StatusCode)
		return res, nil
	}

	w.WriteHeader(resp.StatusCode)
	if _, werr := w.Write(respBody); werr != nil {
		res.Aborted = true
		res.AbortMarker = aigateway.MarkerStreamError
		return res, nil
	}
	res.BytesOut = int64(len(respBody))

	if u, ok := adapter.ExtractUsage(respBody); ok {
		res.Usage = aigateway.Usage{
			InputTokens:      int(u.InputTokens),
			OutputTokens:     int(u.OutputTokens),
			CacheReadTokens:  int(u.CacheReadTokens),
			CacheWriteTokens: int(u.CacheWriteTokens),
		}
	}
	return res, nil
}

// attachAuth sets the provider credential in the kind's own auth header on a
// FRESH request. This is the custody seam: the inbound virtual key is never
// present here, and the provider key never leaves this function's request.
func attachAuth(r *http.Request, u aigateway.Upstream, cred string) {
	switch u.Kind {
	case aigateway.KindAnthropic:
		r.Header.Set("x-api-key", cred)
		v := u.APIVersion
		if v == "" {
			v = defaultAnthropicVersion
		}
		r.Header.Set("anthropic-version", v)
	case aigateway.KindAzureOpenAI:
		r.Header.Set("api-key", cred)
	default: // openai_compatible / openrouter / local / custom
		r.Header.Set("Authorization", "Bearer "+cred)
	}
}
