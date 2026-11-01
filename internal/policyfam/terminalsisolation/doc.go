// Package terminalsisolation is the PURE compiler of the sandbox module's
// policy family `terminals.isolation` (sandbox plan v2 sections 8.1 and 8.2,
// D-752 Q41, ledger SBX-GOV-1): the org's raise-only isolation floors for
// sandboxed terminals (every section 8.1 floor except the shipped
// `sandbox_required`, which stays in node.features).
//
// The body decodes strictly (DisallowUnknownFields, no trailing bytes), so a
// key this build does not know is refused rather than ignored; every floor
// key present in a body also requires its own capability token, so a node
// that cannot enforce a floor NACKs (capability_mismatch) instead of
// silently dropping it. A floor only ever tightens: values that would widen
// a node (allow_remote = true, min_egress = none, an empty allow-list) are
// refused at compile.
//
// It is linked into a build by the pair file
// internal/policyfam/family_terminalsisolation.go (omit tag
// sbo_omit_terminals_sandbox); the node applies a compiled spec through
// cmd/observer/sandbox_posture_wire.go into sandboxselect.Floors.
package terminalsisolation
