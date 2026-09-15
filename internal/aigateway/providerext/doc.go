// Package providerext — see providerext.go for the package overview.
//
// # Integration (wiring, not yet performed — the STOP-AND-REPORT point)
//
// The gateway consumes this package at WIRING time through the EXISTING
// injection seams, without any change to this package:
//
//  1. Build the registry: reg := providerext.DefaultRegistry().
//  2. Provide a native dialer that, for a registry kind, uses the adapter's
//     BuildURL/AttachAuth/ExtractUsage, and otherwise delegates to the core's
//     default HTTPUpstreamer. Set it on the gateway handler's Dialer field
//     (gwhttp.Handler.Dialer, the existing Upstreamer injection seam).
//
// One coordination change in the P4/P6a-owned core remains and is DELIBERATELY
// NOT made here (per the P6b lane's "STOP-AND-REPORT before editing existing
// aigateway files" rule): the core refuses an unknown kind BEFORE the dialer
// runs —
//
//	parser, ok := aigateway.ParserForKind(upstream.Kind)
//	if !ok { writeJSONError(w, 502, "unsupported_kind", …); return }
//
// (internal/aigateway/gwhttp/handler.go). So a bedrock/vertex upstream is
// rejected at admission and never reaches the injected dialer. Wiring these
// adapters end-to-end therefore needs exactly ONE P4-side edit: ParserForKind
// (or that pre-dial refusal) must consult an injected external-adapter registry
// — this package's Registry.Has(kind) is precisely what it would consult, and
// registering KindBedrock/KindVertex there lets the request through to the
// native dialer. That edit is left to the P6a lane / a follow-up; the contract
// and both instances are complete and tested here.
package providerext
