// Package sandboxcred is the pure decision layer of credential injection
// for sandboxed runs (sandbox plan v2 sections 7.2 and 7.3, gap G24, lane
// GATES-SBX): the box holds a per-run sentinel in its tool's key variable,
// and the home proxy swaps the sentinel for the user's own key on the way
// out, only when every row of an ordered match table holds. It also holds
// the `provider_injected` custody decisions: the vendor broker table (with
// the documentation each row cites), the refusals and the disclosure text.
//
// It decides and does nothing: the provider table (providers.go), sentinel
// and relay-token minting over an injected random source and their hashes
// (sentinel.go), the match rules (match.go), and the custody rules
// (custody.go). The keystore, the run files, the proxy and the hosted
// helper are the caller's (cmd/observer/sandbox_cred*.go and
// internal/proxy/credinject.go).
//
// The package is pure: no database/sql, net, net/http, os, os/exec or
// fsnotify (imports_test.go pins it).
package sandboxcred
