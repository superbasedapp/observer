// Package winrelaysvc runs the fail-open Windows route relay whose decisions
// live in the pure internal/winrelay (finding CC-9, decision D12): a
// listener bound to 127.0.0.1 only that forwards each request to Observer's
// proxy when a connection to it opens, and otherwise appends a metadata-only
// bypass record (internal/winrelay Entry) and forwards straight to the lane's
// provider. A request whose bypass record cannot be written is refused, so a
// fail-open forward is never silent.
//
// What it handles: the request is passed through unchanged except for the
// hop-by-hop headers and the route prefix; headers, credentials included,
// are never read, logged or recorded, and no X-Forwarded header is added.
// What it logs: one line per fail-open forward or refusal, carrying the
// tool, the provider host, the method, the sanitized path and a fixed
// reason class, never a header, query, body or error text from upstream.
//
// It is reachable only from `observer relay serve` (cmd/observer), which
// refuses to start while the relay's live-check gate waits (DEC-12); the
// always-on daemon paths never link it (tests/invariant/winrelay_test.go).
package winrelaysvc
