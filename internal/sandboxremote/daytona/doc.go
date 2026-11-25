// Package daytona is the Daytona wire client of the hosted sandbox rows
// (sandbox plan v2 section 13 P7, a hosted vendor): Daytona's public
// REST API (app.daytona.io/api, the main API of
// https://www.daytona.io/docs/openapi.json) and the per-sandbox toolbox API
// (proxy.app.daytona.io/toolbox/{sandboxId}, the toolbox API of
// https://www.daytona.io/docs/toolbox-openapi.json), spoken from Go with
// net/http and golang.org/x/crypto/ssh
// (BSD-3-Clause), for the exec transport over Daytona's SSH access tokens
// (sandbox plan v2's Daytona row: REST plus its SSH access tokens through
// the pure-Go SSH transport). Daytona's own Go SDK is AGPL and is never
// imported, nor is any other Daytona module.
//
// It is one of the packages that talk to a vendor (an egress lane row in
// tests/invariant/egress_lanes_test.go) and is imported only by
// cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The call
// table is in docs/sandboxed-terminals.md ("Hosted sandboxes", Daytona) and
// in the vendor row's Docs (internal/sandboxremote/vendors.go). Every fact
// was read from Daytona's documentation on 2026-11-11; nothing was run with
// a key.
//
// It implements sandboxremote.Client and nothing more. A box is a Daytona
// sandbox whose NAME is derived from the run id, so a retried or lost create
// is found by name and by label (delete accepts the name too). Every box is
// created ephemeral (autoDeleteInterval 0: deleted as soon as it stops),
// with auto-stop off (Daytona's auto-stop fires even while processes run,
// sandboxes page "Auto-stop sandboxes"), a wall-clock TTL equal to the
// vendor timeout (ttlMinutes destroys the box in any state), no public
// preview, and networkBlockAll unless the tier is internet. The key never
// appears in an error.
//
// Processes run on SSH exec channels (ssh.go, process.go): stdout, stdin,
// stdin's close, stderr and the exit status are the SSH protocol's own. The
// PTY Daytona documents is reached over a WebSocket whose framing the docs
// do not describe (the PTY page, 2026-11-11), and its toolbox session
// commands stream logs over an undocumented WebSocket framing too, so the
// client uses neither: the guest helper owns the PTY over an exec channel,
// there is no vendor resize and no reattach (a cut transport ends the run,
// A7).
package daytona
