// Package gwhttp is the AI Gateway's HTTP layer: the listener handler that
// runs the design §2.4 ordered request pipeline (authn → model policy →
// concurrency → budget → egress guard → forward) and the §2.7 streaming rules
// (all blocking decisions pre-first-byte, pass-through SSE, abort-on-detect),
// then settles the reservation and writes the metadata-only audit row.
//
// It legitimately imports net/http — it is the I/O layer the pure core
// (internal/aigateway) drives through injected interfaces. The core stays pure;
// this handler wires concrete stores, a rate card, a model policy, a guard
// scanner, and an upstream dialer onto it. The reverse-import boundary
// (internal/proxy never imports this or orgserver) is unaffected: this package
// is server-side only.
package gwhttp
