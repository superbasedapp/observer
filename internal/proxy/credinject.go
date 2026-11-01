package proxy

import (
	"context"
	"net/http"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// credinject.go is the proxy side of credential injection for sandboxed
// runs (sandbox plan v2 section 7.3, gap G24, lane GATES-SBX): a relayed
// model request of a run whose box holds only a sentinel gets the user's
// own key on the way out, when the injector says every match row holds
// (internal/sandboxcred, which this package does not import). The injector is process-wide and nil unless the
// terminals.sandbox.credentials component set it (cmd/observer), so with
// it unset the request path is exactly as before. The real key is set on
// the outbound request only: never logged, never put in api_turns (which
// record no request headers), never echoed back, and never sent to any
// host but the provider's own (the injector checks the upstream host; a
// same-target retry or fallback rebuilds the request for the same URL).

// SandboxCredTokenHeader carries a run's relay token from the home side of
// the run's relay to the proxy; it never goes upstream. The same spelling is
// internal/sandboxcred's TokenHeader (a test in cmd/observer pins them
// equal; the proxy does not import the sandbox module).
const SandboxCredTokenHeader = "X-Observer-Sandbox-Cred" //nolint:gosec // G101: a header name

// CredentialRequest is what the proxy hands the injector: the run headers
// the home side of a run's relay set, the upstream host, and the request's
// credential headers as they would go upstream.
type CredentialRequest struct {
	RunID, Token, Host              string
	XAPIKey, Authorization, GoogKey string
}

// CredentialInjector decides one request: the header to set and its value,
// or ok false to leave the request untouched.
type CredentialInjector interface {
	Inject(ctx context.Context, in CredentialRequest) (header, value string, ok bool)
}

type credInjectorBox struct{ i CredentialInjector }

// credInjector is the process-wide injector (nil: none).
var credInjector atomic.Pointer[credInjectorBox]

// SetCredentialInjector installs the process-wide injector; nil clears it.
func SetCredentialInjector(i CredentialInjector) {
	if i == nil {
		credInjector.Store(nil)
		return
	}
	credInjector.Store(&credInjectorBox{i: i})
}

// injectSandboxCredential applies the injector to out, the upstream request
// built from in. The relay token header never goes upstream, injector or
// not (copyRequestHeaders and the passthrough Rewrite drop it too; audit
// F6); with no injector nothing else changes, and only an injected request
// has its credential headers replaced.
func (p *Proxy) injectSandboxCredential(out, in *http.Request) {
	out.Header.Del(SandboxCredTokenHeader)
	b := credInjector.Load()
	if b == nil {
		return
	}
	run := in.Header.Get(sandboxvocab.RelayRunHeader)
	if run == "" {
		return
	}
	header, value, ok := b.i.Inject(in.Context(), CredentialRequest{
		RunID: run, Token: in.Header.Get(SandboxCredTokenHeader), Host: out.URL.Hostname(),
		XAPIKey: out.Header.Get("X-Api-Key"), Authorization: out.Header.Get("Authorization"), GoogKey: out.Header.Get("X-Goog-Api-Key"),
	})
	if !ok || header == "" || value == "" {
		return
	}
	for _, h := range []string{"X-Api-Key", "Authorization", "X-Goog-Api-Key"} {
		out.Header.Del(h)
	}
	out.Header.Set(header, value)
}
