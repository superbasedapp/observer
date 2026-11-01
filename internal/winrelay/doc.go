// Package winrelay is the pure core of the fail-open Windows route relay
// (surface-gap arc, finding CC-9, decision D12): a loopback listener on the
// Windows host that a Windows-side tool's settings route points at, which
// forwards each request to Observer's proxy when that proxy answers and,
// when it does not (WSL or the daemon is down), straight to the provider, so
// the session keeps working instead of failing with ConnectionRefused.
//
// A forward that skips the proxy is a BYPASS and is never silent: it is
// recorded in a metadata-only journal before the request leaves (Entry), and
// a forward whose record cannot be written is refused. The bypassed session
// has no api_turns row, so the Gateway-Mode gate (decision D11) and every
// other route-attestation reader judge it as unproxied traffic; the node's
// managed-integrity report also reads the journal and never reports a clean
// route observation while a recorded bypass is inside the observed window.
//
// This package holds only data and decisions: the lane table (Lanes), the
// route URL a writer points a tool at (RouteURL), the ordered decision table
// (Decide), the port rules (ValidatePorts), the journal entry format and its
// summary (Encode, ParseJournal, Summarize) and the live-check gate (Gate).
// It imports no net, net/http, os, database/sql or fsnotify (imports_test.go);
// the listener, the forwarding and the journal file live in
// internal/winrelaysvc, the command in cmd/observer (`observer relay`).
//
// The relay and the route change are built and switched off behind live
// checks LC6 (tracker WSL-2: do the wsl.exe bridge hooks block with the
// daemon down) and LC14 (cold-start wrap), per DEC-12: Gate reports the
// wait, `observer relay serve` refuses to start, and the Windows route
// writer keeps its WSL proxy target until the gate is cleared.
package winrelay
