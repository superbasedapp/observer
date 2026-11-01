package proxy

import (
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/proxyauth"
)

// clientauth.go is the proxy side of client authentication (OSH-R-009,
// docs/plans/proxy-client-auth-2026-10-30.md). A routed client carries the
// node's client token as the first path segment of its base URL
// (http://127.0.0.1:<port>/t/<token>/...). serve calls applyClientAuth right
// after the liveness probe: the decision is internal/proxyauth.Decide, and an
// accepted token is stripped from the path, the raw path and the request URI
// before the browser rule, lanes, routing, logging or capture read any of
// them, so the token never reaches an upstream, a log line or api_turns.
//
// With no token configured (the default) every plain request is untouched;
// only a path starting with a well-formed /t/<token> is refused locally, so a
// token never reaches a provider.

// clientAuthCode is the machine-readable code of a refusal body.
const clientAuthCode = "observer_client_auth_required"

// clientAuthLogEvery bounds the refusal log line: a misconfigured client
// retries in a loop, and one line per minute says the same thing.
const clientAuthLogEvery = time.Minute

// clientAuthState is the proxy's client token state. The token is fixed for
// the proxy's life; the requirement can be lowered or raised at run time.
type clientAuthState struct {
	token    string
	required atomic.Bool
	// refused counts refused requests; lastLog is the unix-nano time of the
	// last refusal log line.
	refused atomic.Uint64
	lastLog atomic.Int64
}

func (c *clientAuthState) init(token string, required bool) {
	c.token = token
	c.required.Store(required)
}

// SetRequireClientAuth turns enforcement on or off at run time. It is inert
// on a proxy built without a client token.
func (p *Proxy) SetRequireClientAuth(on bool) { p.clientAuth.required.Store(on) }

// ClientAuthEnforced reports whether a request without the client token is
// refused right now.
func (p *Proxy) ClientAuthEnforced() bool {
	return p.clientAuth.token != "" && p.clientAuth.required.Load()
}

// ClientAuthRefused is how many requests client authentication refused.
func (p *Proxy) ClientAuthRefused() uint64 { return p.clientAuth.refused.Load() }

// applyClientAuth checks one request. It returns false when it answered the
// request (a refusal) and true when serve goes on, with the token prefix
// stripped when there was one.
func (p *Proxy) applyClientAuth(w http.ResponseWriter, r *http.Request) bool {
	c := &p.clientAuth
	if c.token == "" && !strings.HasPrefix(r.URL.Path, proxyauth.PathPrefix) {
		// The common default: a plain request on a node with no token.
		return true
	}
	d := proxyauth.Decide(proxyauth.Request{Configured: c.token, Required: c.required.Load(), Path: r.URL.Path})
	switch d.Verdict {
	case proxyauth.Accept:
		stripClientToken(r)
		return true
	case proxyauth.Refuse:
		c.refused.Add(1)
		_, rest, _ := proxyauth.SplitPath(r.URL.Path)
		provider := providerForPath(rest)
		if now := time.Now().UnixNano(); now-c.lastLog.Load() >= int64(clientAuthLogEvery) {
			c.lastLog.Store(now)
			// Never the path: a refused path may carry a wrong token.
			p.logger.Warn("proxy: refused a request without a valid client token", "provider", provider, "method", r.Method, "refused_total", c.refused.Load())
		}
		writeLaneRefusal(w, provider, d.Status, clientAuthCode, "observer: "+d.Reason+"; the request was not forwarded")
		return false
	default:
		return true
	}
}

// stripClientToken removes the /t/<token> prefix from every place the
// request keeps its target.
func stripClientToken(r *http.Request) {
	_, rest, _ := proxyauth.SplitPath(r.URL.Path)
	r.URL.Path = rest
	if r.URL.RawPath != "" {
		_, rawRest, found := proxyauth.SplitPath(r.URL.RawPath)
		if found && strings.HasPrefix(rawRest, "/") {
			r.URL.RawPath = rawRest
		} else {
			r.URL.RawPath = ""
		}
	}
	r.RequestURI = r.URL.RequestURI()
}
