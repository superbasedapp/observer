// Package sandboxkey holds the pure rules for how a sandboxed run's agent
// gets its model key, which every hosted sandbox row needs whether or not
// credential injection is built (audit
// docs/audits/sandbox-terminal-gaps-2026-11-18.md): the provider table
// (providers.go), the key custody table HomeKey and its per-launch auto
// resolution (homekey.go, auto.go), the set of providers a run binds
// (bind.go), the opt-in in-box key sources (toolkeys.go) and the custody
// disclosures and provider_injected broker rules (custody.go).
//
// internal/sandboxcred, the credential injection component's own pure
// layer (sentinels, the match table, the local fold), re-exports these and
// is linked only with that component, so a build without it
// (sbo_omit_terminals_sandbox_credentials) carries no injection code.
//
// The package is pure: standard library only, no database/sql, net,
// net/http, os, os/exec or fsnotify (imports_test.go pins it).
package sandboxkey
