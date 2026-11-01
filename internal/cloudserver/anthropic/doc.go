// Package anthropic is the Anthropic Messages API implementation of the Cloud
// Intelligence provider seam (internal/cloudserver/inference). It serves the
// anthropic_messages dialect: one bounded, stateless, non-agentic call to
// POST /v1/messages through the official Go SDK, with strict structured output
// (output_config.format json_schema), effort "low", adaptive thinking left at
// the model default, and the stable system prompt marked for prompt caching.
//
// Discipline it shares with the Foundry client:
//
//   - The credential is an EXPLICIT request field. The SDK's environment
//     autoload (ANTHROPIC_API_KEY, ANTHROPIC_BASE_URL, profiles, federation) is
//     switched off, so an ambient key can never reach a call the worker's
//     credential-absence gate did not authorize.
//   - No internal retries: the SDK's retry loop is disabled because the worker
//     owns the attempt loop and re-runs the full execution-lease revalidation
//     before every provider call. A second call without that revalidation would
//     break the lease contract.
//   - No tools, no sampling parameters, no Batch, no stateful endpoints.
//
// Every failure maps onto the inference sentinels (quota, timeout, provider
// status) so the worker's classification never depends on the provider.
package anthropic
