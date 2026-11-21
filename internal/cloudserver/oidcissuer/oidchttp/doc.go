// Package oidchttp is the HTTP face of the platform OIDC issuer (managed-SaaS
// M6.2): the four handlers internal/cloudserver/api mounts under
// oidcissuer.IssuerPath on the portal origin.
//
//	GET  /oauth2/.well-known/openid-configuration   discovery (public metadata)
//	GET  /oauth2/jwks.json                          published keys (max-age 300)
//	GET  /oauth2/authorize                          browser; the caller's portal
//	                                                session decides who signs in
//	POST /oauth2/token                              machine call from the tenant
//
// It translates requests to oidcissuer calls and results back to HTTP, and
// nothing else: every decision is the pure core's. The api package resolves
// the portal session (the host-only __Host-sbci cookie, which is why the
// issuer lives on the portal origin) and passes the account id in; this
// package never reads a cookie or the database. An authorize request
// without a session is sent to the WorkOS sign-in start with a return_to of
// the same authorize request (the one return_to exception, api
// portalauth.go).
//
// No CORS on any route: the tenant fetches discovery, JWKS and token
// server-side. The token endpoint takes a form body only (no query, no HTTP
// Basic credentials: these are public clients) and answers no-store.
package oidchttp
