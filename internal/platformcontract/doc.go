// Package platformcontract is the pure wire contract of the private host API
// (/platform/v1) that the SaaS control plane (observer-cloud) speaks to each
// pooled tenant host (observer-org). Both sides import this one package so
// neither waits for the other (plan 06 section 5.8.2; plan 07 row M5.0).
//
// The package holds types, closed enums, request validation and the pure
// signed-body envelope helpers (digest, signing input, freshness, ed25519
// sign and verify over caller-supplied keys). It holds no transport, no mTLS,
// no key storage and no I/O; those belong to the seams in M5.2 (server) and
// M6.4 (client). Imports are pinned by imports_test.go.
//
// # Versioning rule
//
// Version is "v1" and every route lives under BasePath. Within v1 only
// ADDITIVE changes are allowed: a new optional field, a new verb, a new enum
// value that readers treat as unknown-but-tolerated. Readers MUST ignore
// unknown JSON fields (the types here are decoded with plain encoding/json,
// never DisallowUnknownFields). A removed field, a changed meaning, a changed
// type or a removed enum value is a v2 and a new BasePath.
//
// # Scope
//
// The API carries lifecycle and entitlement intents only. Export, enrolment
// tokens and role grants are NOT part of this API and must never be added to
// it: the control plane holds no standing credential to tenant data.
package platformcontract
