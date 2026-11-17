// Package entitlements is the pure core of signed entitlements (plan 06
// 5.8.4, ADR-9; plan 07 M7b.1): the body schema of an sbo-entitlements-v1
// document, its verification over an injected key set, the floor document
// of every org kind, the effective entitlement (Has / Cap / Term), the
// mapping of every server catalog row to an entitlement gate, the plan
// catalog the cloud plans rows are generated from, and the plan-name
// vocabulary the plan-name lint reads.
//
// # What it answers
//
// Entitlement answers "has this org paid for it?" (plan 06 18.3.1). It is
// layer 3 of the one component resolver: Effective.ComponentInput is the
// Governance.Entitled input of components.Resolve, so a refusal is the
// resolver's not_entitled decision and the one component_not_installed
// body, never a second refusal shape. Availability (is it cleared to run
// here?) and org policy (does the org want it?) are other layers; nothing
// here narrows or widens them.
//
// # The document
//
// The envelope (domain tag, signing input, version rule, key id) is
// internal/platformcontract's (M6.3); this package owns the body inside it.
// Verify checks the envelope through platformcontract.VerifyEntitlements,
// then decodes the body, validates it and binds it to the org and kind the
// caller expects. The same document is the self-hosted licence: a licence
// is an entitlements document of kind self_hosted.
//
// # Floors
//
// Every kind has a floor document compiled into the binary. Evaluate
// composes the floor with the document in force: capabilities are the
// union, a cap is the larger of the two (Unlimited above every number), a
// term is the document's when it sets one. A missing, expired, not yet
// valid or mismatched document therefore leaves exactly the floor (plan 06
// 6.1 row L7: "fall back to the floor tier"), and no document can grant
// less than the floor of its kind.
//
// # Keys
//
// The verification key is compiled in (plan 06 5.3.8, "vendor entitlement
// verify key"); keys.go holds the two rotation slots. Until the operator's
// key custody plan (operator item C12) produces the key, both slots are
// empty, CompiledKeys returns an empty set, every document is refused and
// every org resolves to its floor. Tests and callers inject their own
// platformcontract.KeySet.
//
// # Purity
//
// No SQL, no HTTP, no fsnotify, no os/exec, no clock: the caller passes now.
// Pinned by imports_test.go. The store seams that persist documents and the
// generated cloud plans rows live with their owners (internal/cloudserver/
// store for the cloud).
package entitlements
