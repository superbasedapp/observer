// Package secdast is the pure core of Observer's local passive DAST checker
// (component security.dast; OS and CI vulnerability scanning plan section
// 14.9, item 7, phase M3L-5; operator go 2026-11-04: "native passive
// checker, loopback only, own consent and isolation; ZAP no-go; nuclei only
// as 14.9 allows").
//
// "Passive" means: a small fixed set of plain GET requests to ONE dev server
// the developer names on their own machine, and checks on what comes back.
// Nothing is fuzzed, no payload is injected, no form is submitted, no
// credential is sent, and no request ever leaves the origin the developer
// typed. The probes are the page itself (sent with a canary Origin header,
// an unregistered name that is never contacted, to read the CORS answer),
// /.git/HEAD, /.env, one random path that should be a 404 (framework debug
// pages show up on errors) and, for up to MaxScripts same-origin scripts
// the page references, the script and the source map it names.
//
// The check table (Checks) is the whole decision: security headers, cookie
// flags, CORS reflection, exposed .git and .env, directory listings,
// exposed source maps, framework debug pages and server banners, exactly
// the set section 14.9 lists, one row per check, one test case per row.
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1): no network,
// file, database, process or fsnotify import (imports_test.go). It decides
// the target (ParseTarget: loopback hosts only, with a port), the requests
// (Run, over an injected Fetch), the checks and the findings. The one
// package that dials is internal/secdastnet, the security.dast egress lane
// of kind local (tests/invariant/egress_lanes_test.go), which refuses any
// address that is not loopback (IsLoopbackAddr), follows no
// redirect off the origin and caps bodies, requests and time. The developer's
// one accept is internal/secdast/dastconsent.
//
// Findings use the shared secfinding shape, flag only: a finding's Message
// and FixHint come from the table, never from the server's text, and its
// evidence states facts (a status, a header name, a byte count), never a
// response body (an exposed .env is counted, not read into the finding).
package secdast
