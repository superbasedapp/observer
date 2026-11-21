package superbased

import (
	"context"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

// The AI gateway's headers (contract cost-source.md section 4, budgets).
const (
	HeaderRequestID = "X-SBO-Request-Id"
	HeaderUser      = "X-Superbased-User"
	HeaderService   = "X-Superbased-Service"
	maxRequestIDLen = 256
	maxAppIDLen     = 512
)

// StampGatewayRequestID sets request_id on sp from the AI gateway's
// X-SBO-Request-Id response header (default span: the one in ctx), so the org
// joins the gateway's exact cost to the span. It returns true when it stamped;
// a missing header, a span that already has request_id or a non-recording span
// stamps nothing.
func StampGatewayRequestID(ctx context.Context, h http.Header, sp trace.Span) bool {
	if h == nil {
		return false
	}
	rid := strings.TrimSpace(h.Get(HeaderRequestID))
	if rid == "" {
		return false
	}
	if sp == nil {
		sp = trace.SpanFromContext(ctx)
	}
	if !sp.IsRecording() || spanHas(sp, keyRequestID) {
		return false
	}
	if len(rid) > maxRequestIDLen {
		rid = rid[:maxRequestIDLen]
	}
	sp.SetAttributes(attribute.String(keyRequestID, rid))
	return true
}

// appValue is a header-safe identity value: printable ASCII, at most 512
// bytes; "" otherwise.
func appValue(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > maxAppIDLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x20 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}

// GatewayHeaders are the headers a request to the AI gateway should carry
// now: X-Superbased-User (the request scope's end user, else Init's),
// X-Superbased-Service (the service the app's spans carry, which app budget
// caps bind on) and a client-minted X-SBO-Request-Id. A value that is empty or
// not header-safe is left out.
func GatewayHeaders(ctx context.Context) map[string]string {
	out := map[string]string{HeaderRequestID: "sdk-" + randomHex(16)}
	user, _ := CurrentAttributes(ctx)["user"].(string)
	if user == "" {
		if s := CurrentSettings(); s != nil {
			user = s.User
		}
	}
	if v := appValue(user); v != "" {
		out[HeaderUser] = v
	}
	if v := appValue(admitServiceName()); v != "" {
		out[HeaderService] = v
	}
	return out
}

// gatewayTransport is GatewayTransport's RoundTripper.
type gatewayTransport struct{ base http.RoundTripper }

// GatewayTransport wraps base (nil: http.DefaultTransport) for model calls
// that go through the organization's AI gateway: it adds GatewayHeaders that
// the request does not already carry, and stamps the answer's X-SBO-Request-Id
// as request_id on the span in the request's context. Use it as the
// Transport of the http.Client your model SDK takes (for example the OpenAI
// Go SDK's option.WithHTTPClient).
func GatewayTransport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &gatewayTransport{base}
}

func (g *gatewayTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()
	r := req.Clone(ctx)
	for k, v := range GatewayHeaders(ctx) {
		if r.Header.Get(k) == "" {
			r.Header.Set(k, v)
		}
	}
	resp, err := g.base.RoundTrip(r)
	if err == nil && resp != nil {
		StampGatewayRequestID(ctx, resp.Header, nil)
	}
	return resp, err
}
