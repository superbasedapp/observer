// Package vendorapi is the pure contract every vendor driver satisfies
// (enterprise vendor API plan, section 6.3): a driver builds a request,
// parses one response body into a Page of typed landings and reports drift.
// A driver never touches SQL, logs or HTTP; the runner (lane F7) owns egress,
// the sanitizer owns the field allowlists and the vendorconn store facade
// (internal/orgserver/vendorconn/connstore) owns every write.
//
// Lane F5 adds the graph outputs: a Page may carry a SnapshotManifest and the
// ResourceObservation and EdgeObservation rows tied to it (plan 4.5 R-E-03 and
// R-E-05). Validate is the one structural gate a page passes before the store
// will land it: namespaced external ids, parseable namespaced resource types,
// typed edges, observations inside the manifest's declared scope, and no
// secret-shaped attribute on any resource (a credential carries metadata
// only, never a value).
//
// Per-vendor drivers live in subpackages (internal/vendorapi/<vendor>, lane
// F8 onward). They share this package's small parse helpers (helpers.go:
// Drift, DecodeNumbers, Str, TrimStr) rather than re-declaring them. This
// package imports only the pure catalog types and the standard library;
// imports_test.go pins it.
package vendorapi
