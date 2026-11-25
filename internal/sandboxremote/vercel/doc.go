// Package vercel is the Vercel Sandbox wire client of the hosted sandbox
// rows (sandbox plan v2 section 13 P7 R4, lane SBX-P7): Vercel's public REST
// API (api.vercel.com, the /v2 and /v3 sandbox paths of openapi.vercel.sh),
// spoken from Go with net/http (no SDK). It is one of the three packages
// that talk to a vendor (an egress lane row in
// tests/invariant/egress_lanes_test.go) and is imported only by
// cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The call
// table is in docs/sandboxed-terminals.md ("Hosted sandboxes", Vercel).
//
// It implements sandboxremote.Client and nothing more. A box is a Vercel
// sandbox NAME derived from the run id (so a retried or lost create is found
// by name and by tag), created with persistent=false (no snapshot on stop),
// no ports and a deny-all network policy unless the tier is internet; the
// client keeps each name's current session id, which every command and file
// call addresses. The token never appears in an error.
//
// The interactive PTY Vercel's CLI uses is an undocumented WebSocket
// protocol; the client does not speak it. The guest helper owns the PTY over
// the documented command stdin and log stream instead, so there is no
// vendor resize and no reattach (a cut transport ends the run, A7).
package vercel
