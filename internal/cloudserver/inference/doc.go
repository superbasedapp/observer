// Package inference is the provider seam the Cloud Intelligence worker's
// executors call (the Luna session-enrichment executor, the project-digest
// executor, and the operator-only proving lane). It owns the provider-neutral
// request/response shapes, the sentinel errors the executors classify on, the
// dialect capability table, and a Router that dispatches one bounded call to
// the provider client that speaks the route's dialect.
//
// It is pure: no SQL, no HTTP, no file system. The concrete clients live in
// their own packages (internal/cloudserver/foundry for Azure AI Foundry,
// internal/cloudserver/anthropic for the Anthropic Messages API) and are
// composed by cmd/observer-cloud. Every caller branches on a dialect's
// capability row (DialectSpec), never on a provider name.
package inference
