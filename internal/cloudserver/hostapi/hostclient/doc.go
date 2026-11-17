// Package hostclient is the I/O half of the control plane's host-API client
// (managed-SaaS plan 07 row M6.4; design
// docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md 4.6). The
// decisions (verbs, answer rules, backoff, reconciliation rules) are the pure
// parent package internal/cloudserver/hostapi; this package composes them
// with the transport and the store seam (internal/cloudserver/store
// orgoutbox.go).
//
//   - Sender signs every request with the injected RequestSigner (the key's
//     custody is the document signer's, design 3.3), sends it over mTLS (the
//     TLS configuration with the platform CA and the client certificate is
//     injected), refuses to dial any address that is not private, follows no
//     redirect and uses no environment proxy, and verifies every answer
//     against the host's pinned response keys with
//     platformcontract.VerifyResponse (the nonce echoed, fresh, the body
//     digest, the signature). Only a verified body is ever judged.
//
//   - Dispatcher claims due outbox rows under a lease (two dispatchers never
//     hold one row), places a new tenant on a host, builds, sends, judges the
//     answer with hostapi.Judge and records the outcome fenced by the lease
//     token, with backoff. After an acked create it runs the injected
//     AfterCreate hook (the worker issues the org's launch entitlements
//     document there, lead decision W14-D1a).
//
//   - Reconciler compares every org with its host's verified route-check and
//     health answers (hostapi.Reconcile), records findings and enqueues the
//     corrections through the same outbox; with a UsageStore it then pulls
//     each placed host's signed daily usage report (usage.go, M6.0 Q11) and
//     stores the entries the hostapi usage rules accept.
//
//   - Client.Run drives both on injected tickers until the context ends.
//
//   - EnvelopeRequestSigner is the RequestSigner over the document signer's
//     sign_request (the worker holds no request key); ClientTLSConfig and
//     ParseHostsFile turn the worker's PEM and hosts files into the TLS
//     configuration and the Directory; a CreateResolver's *ResolveError names
//     why a create waits ("not_sent:resolve:<reason>").
//
// cmd/observer-cloud's worker composes these (hostapiworker.go, behind
// SBCI_HOSTAPI_HOSTS_FILE): the store bound to RoleWorker, the Sender, the
// entitlementwork create resolver and issuer, then Run.
package hostclient
