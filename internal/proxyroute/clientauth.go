package proxyroute

import "github.com/marmutapp/superbased-observer/internal/proxyauth"

// clientauth.go: the route writers' side of the proxy client token
// (OSH-R-009, docs/plans/proxy-client-auth-2026-10-30.md). The token form
// of a route is the plain URL with /t/<token> as its first path segment; a
// writer whose inspection row declares clientAuth writes it when the
// registrar holds a token (RegisterOptions.ClientToken).

// clientAuthURL is plain in the form this registrar writes: with the client
// token when it holds one, else plain.
func (r *Registrar) clientAuthURL(plain string) string {
	return proxyauth.WithToken(plain, r.opts.ClientToken)
}

// redactResult marks whether res's route carries a client token and masks
// the token, so no caller prints, logs or returns it. It runs after the
// provenance record (note), which compares the unmasked value.
func redactResult(res RegistrationResult) RegistrationResult {
	if proxyauth.HasToken(res.BaseURL) {
		res.ClientAuth = true
		res.BaseURL = proxyauth.Redact(res.BaseURL)
	}
	return res
}
