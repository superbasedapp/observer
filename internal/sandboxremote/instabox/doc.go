// Package instabox is the InstaBox wire client of the hosted sandbox rows:
// InstaBox's public REST API (api.instabox.sh, the /v1 machine, operation,
// exec, file and terminal routes of https://api.instabox.sh/v1/openapi.json
// and https://instabox.sh/docs/api.md), spoken from Go with net/http and the
// github.com/coder/websocket module the node already links (no SDK, no
// vendor CLI, no SSH). It is one of the packages that talk to a vendor (an
// egress lane row in tests/invariant/egress_lanes_test.go) and is imported
// only by cmd/observer (tests/invariant/sandbox_remote_egress_test.go). The
// call table is in docs/sandboxed-terminals.md ("Hosted sandboxes",
// InstaBox).
//
// It implements sandboxremote.Client and nothing more. A box is an InstaBox
// machine ("sandbox" in the vendor's prose) named from the run id and
// labelled with it in the machine's metadata, created with
// deleteAfterSeconds set to the run's timeout so the vendor deletes it even
// when this machine is gone. Changes are asynchronous: a create or a delete
// answers 202 with an operation the client long-polls to its end.
//
// Processes take two routes. A one-shot command (no streaming stdin) is
// POST /v1/machines/{id}/exec, which blocks until it exits and answers its
// output and exit code. A process with a streaming stdin (the capture relay
// and the guest helper that owns the agent's PTY) rides the documented
// terminal WebSocket: the client opens a fresh session, types one short line
// that runs an owner-only start script it uploaded first, and the script
// puts the PTY in raw mode (byte-transparent, no echo) before it prints a
// marker and execs the program. Everything before the marker is discarded.
// The vendor's own PTY is not offered to the agent: the guest helper owns
// the PTY, as on the Modal and Vercel rows.
//
// The key is held only in memory for the client's life, sent only in the
// X-API-Key header, and never appears in an error.
package instabox
