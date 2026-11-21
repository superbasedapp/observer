// Package spanprice is the pure pricing rule of one Plane A span: which cost
// a span records and with what provenance (plan
// docs/plans/plane-a-sdk-buildout/02-plan-of-record-2026-11-19.md principle 7
// and operator ruling D24).
//
// D24, as an ordered rule table (Rules): when the span's model is priced by
// the price book the caller hands in, the COMPUTED cost wins and any reported
// cost is kept beside it; when the model is not priced, a reported cost is
// used; otherwise the span is unpriced (nil, never a fabricated $0). Both
// costs are always kept in Detail, and Source says which one won.
//
// The package owns no price book and no engine: the caller passes a Lookup
// (on the org server, orgreprice's engine over the org price book; the
// node's obs rail can delegate the same way). It also owns the gross/net
// input rule (NetInput), so a cached prompt token is never billed at both the
// input and the cache-read rate. No SQL, HTTP or I/O (imports_test.go).
package spanprice
