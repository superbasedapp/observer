// Package pricewire is the ONE projection of a signed price document's wire
// rows (orgcontract.PricingPolicyRow) onto the cost engine's input type
// (cost.OrgPrice).
//
// It exists because two places need the SAME answer to "what does this org
// price book mean to the cost engine": the node, which composes the org's
// document it fetched over GET /api/agent/pricing into its one process cost
// engine (cmd/observer/costengine_wire.go), and the org server, which prices
// its own stored spend rows at the rate the org's book held at each row's
// timestamp when an admin re-prices them (internal/orgserver/reprice). Two
// copies of this projection would be two answers to the presence rule
// (server migration 135: a nil rate is "not quoted", a set 0 is "negotiated
// free") and to the structural threshold / peak dimensions, and the first
// divergence would re-price an org's history at a rate no node ever applied.
//
// It is PURE: a field copy between two vocabularies, no I/O, no database, no
// HTTP (imports_test.go pins it). It moved here from cmd/observer behind
// one-line shims at the old names (the repo's "move + one-line shim" pattern),
// so every existing node caller compiles unchanged.
package pricewire
