// Package dockersbx is the Docker Sandboxes wire client of the hosted
// sandbox rows (lane SBX-DOCKER): Docker's cloud sandboxes (the Docker
// Agentic Platform), driven through the Sandboxes API that Docker publishes
// as an OpenAPI 3.2 document (https://docs.docker.com/reference/api/sandboxes/api.yaml,
// API v1, labelled experimental), spoken from Go with net/http and the
// module's existing WebSocket library (no SDK: Docker's SDK is TypeScript
// only, and no CLI is wrapped). It is one of the packages that talk to a
// vendor (an egress lane row in tests/invariant/egress_lanes_test.go) and is
// imported only by cmd/observer (tests/invariant/sandbox_remote_egress_test.go).
// The call table is the vendor row's Docs in internal/sandboxremote and
// docs/sandboxed-terminals.md ("Hosted sandboxes", Docker Sandboxes).
//
// It implements sandboxremote.Client and nothing more. Three credentials,
// each sent to one place only:
//
//   - the Docker account's access token and Docker ID go only to Docker
//     Hub's exchange URL (https://hub.docker.com/v2/auth/token), which
//     answers a short-lived management token;
//   - the management token goes only to the bound API endpoint
//     (https://connect.docker.com/sandboxes) and is exchanged again once on
//     a 401;
//   - each box's file and process calls go to that box's own endpoint
//     (core.endpoint.uri, which must be https under docker.com) with a
//     scoped endpoint credential of at most five minutes, minted per box
//     and minted again before it expires.
//
// A box is created from an OCI image reference (the template, or
// DefaultImage), the small size (2 vCPU, 4 GiB), the run label, a
// sleep-infinity start command, a delete-on-timeout deadline and an inline
// denyAll network policy (every name and address below the internet tier;
// on it, only the private ranges, unless they are allowed: SBXD-7); Create
// waits until the box runs. A lost create answer is recovered by repeating
// the request under the same Idempotency-Key (the errors page's documented
// recovery); past the retries it reads create_unknown. The API has no label filter, so
// ListByLabel matches the run label in the client. Delete sends the box's
// etag as If-Match with force.
//
// Processes are interactive processes over the documented WebSocket
// (subprotocol sandboxes.v1): a PTY with resize for the agent, pipes for
// the relay and the setup commands. A stream that drops before the process
// exits is re-attached with a fresh endpoint credential from the last
// stream sequence received, so no output repeats and none is skipped that
// the service retained; stdin is never replayed. No value of any
// credential appears in an error.
package dockersbx
