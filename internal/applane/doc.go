// Package applane is the pure core of the machine's LOCAL APP LANE (hosted
// AI gateway plan L7, ruling L-172): the daemon proxy's `/up/<id>` lanes an
// app built on this machine points its model client at
// (http://127.0.0.1:<port>/up/<id>).
//
// It holds the decisions the proxy and the obs wiring point make about an
// app lane call, as data and rule tables, with no I/O:
//
//   - the model allow-list ([proxy.app_lanes] models): which patterns apply
//     to a lane and whether a model matches one;
//   - which upstream hosts take the stream_options.include_usage injection
//     (APPLANE-2: only hosts known to accept it, never the Responses API);
//   - the app identity the SDK sends (X-SBO-Request-Id, X-Superbased-Service)
//     and the bounds a value must meet before the lane honours it;
//   - the lane kind of an upstream URL and the client base URL a lane is
//     advertised at (`observer apps lane add`, GET /api/sdk/destination);
//   - the in-memory reservation ledger: a hold per call over the recorded
//     app spend plus every call in flight, decided by the shared
//     reserve-and-settle core (internal/reserve). The daemon is one process,
//     so the ledger is in memory and adds no table (plan section 8.2, L7).
//
// The package imports no database/sql, net/http, fsnotify or os/exec
// (imports_test.go pins it). The proxy reads the request and calls in
// through plain values; the obs wiring point supplies the caps and the
// recorded spend.
package applane
