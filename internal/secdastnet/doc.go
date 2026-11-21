// Package secdastnet is the security.dast egress lane, kind local
// (tests/invariant/egress_lanes_test.go; OS and CI vulnerability scanning
// plan sections 14.9 and 14.13): the only package that dials for the local
// passive DAST checker, whose pure core is internal/secdast.
//
// It reaches ONE development server on the developer's own machine, and
// enforces that in code at every layer:
//
//   - the target must be "localhost" or a loopback IP literal with a port
//     (secdast.ParseTarget, checked again here);
//   - the host is resolved once, when the client is made, and every address
//     it resolves to must be loopback (secdast.IsLoopbackAddr: 127.0.0.0/8 or
//     ::1, stricter than internal/netpolicy, which this component may not
//     import and which reads a NAT64 or 6to4 form embedding 127/8 as
//     loopback); one that is not refuses the run;
//   - every connection dials that pinned address and the target's port, and
//     the dialer's Control hook refuses any address that is not loopback
//     (after DNS, per connection), and anything but TCP;
//   - no proxy from the environment, no cookie jar, no credential, no
//     request body, a fixed User-Agent, and only the canary Origin header;
//   - a redirect is followed only on the same origin, at most
//     secdast.MaxRedirects times; one off the origin is never followed;
//   - each body is read to at most secdast.MaxBodyBytes, headers to
//     secdast.MaxHeaderBytes, each request within secdast.RequestTimeout,
//     and a client makes at most MaxRoundTrips round trips (the caller holds
//     the run to secdast.RunTimeout).
//
// Only cmd/observer links it (tests/invariant/security_dast_egress_test.go):
// never the watcher, the proxy, the store, the hook, the dashboard or the
// daemon loops. A run starts only from the developer (the CLI; R-165 denies
// an agent the verb) after the one accept (internal/secdast/dastconsent).
package secdastnet
