// Package openhands holds the pure drivers of the OpenHands Cloud V1 app
// gateway (lane CA-A4, cloud agents arc; plan
// docs/plans/cloud-agents/cloud-agents-implementation-plan-2026-10-31.md
// section 5.1, connector openhands-cloud).
//
// Two surfaces are built, both written from the reviewed cloud-agent
// integration reference (sources OH01, OH04, OH08), never from a live
// response, so both are "synthetic, awaiting live validation":
//
//   - openhands.cloud.app_conversations_search: GET
//     /api/v1/app-conversations/search, the account's conversations with
//     their accumulated token and cost metrics.
//   - openhands.cloud.events_search: GET
//     /api/v1/conversation/{conversation_id}/events/search, one
//     conversation's event history (messages, tool actions and
//     observations, errors).
//
// Both authenticate with the OpenHands Cloud API key as Bearer on
// app.all-hands.dev. The key is not the OpenHands LLM key, and the
// conversation's session_api_key (a runtime credential the search schema
// returns) is never decoded.
//
// The drivers are consumed by the node cloud-agents connector (lane CA-B2)
// through the node's own egress package; they have no entry in the org
// driver table. A driver here never touches SQL, logs or HTTP: Build returns
// a path and a query, ParseResponse turns one response into a vendorapi.Page.
// imports_test.go pins the package pure.
package openhands
