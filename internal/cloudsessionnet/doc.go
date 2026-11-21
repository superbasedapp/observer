// Package cloudsessionnet is the ONLY egress of the cloud-session feature
// (Rail S, docs/cloud-sessions.md): `observer cloud-session flush` hands it
// one encoded org push envelope and a resolved destination, and it delivers
// the bytes. tests/invariant/cloudsession_egress_test.go pins that no other
// package of the feature imports net or net/http, that the always-on daemon
// paths (watcher, proxy, store, hook, adapters) never link it, and that only
// the observer command imports it.
//
// The rules it enforces, before the ship token is attached:
//
//   - HTTPS only, except plain http to a loopback host; no user info in the
//     URL (internal/cloudsession.ResolveDestination decides, this package
//     re-checks);
//   - redirects are never followed (a redirect would carry the token to
//     another host);
//   - the request body and the read of the response are capped, and every
//     call has a timeout;
//   - the ship token is sent only as an Authorization bearer header and is
//     never logged or returned in an error.
//
// It also holds the file destination (tests, and a look at exactly what
// would ship), so every delivery of the feature goes through one package.
package cloudsessionnet
