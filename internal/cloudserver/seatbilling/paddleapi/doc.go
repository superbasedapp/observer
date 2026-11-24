// Package paddleapi is the outbound Paddle Billing API client of the
// control plane (plan 07 M7b.2, E1.6): GET and PATCH /subscriptions/{id}
// for the seat sync (it implements seatbilling.API), POST
// /customers/{id}/portal-sessions for the portal's billing link, and POST
// /subscriptions/{id}/cancel (effective immediately) for an org deletion's
// cancel_billing step (FR-1) and an account deletion's cancellation of the
// account's live subscriptions (ORGDEL-7). Nothing else.
//
// The base URL table (client.go baseRules) names Paddle's sandbox API, its
// live API and a loopback test server. A key must belong to the base URL's
// environment by its prefix (pdl_sdbx_ for sandbox, pdl_live_ for live;
// KeyEnvironment), so a sandbox key never reaches the live API and a live
// key never reaches the sandbox. The live row arrived with wave 17
// (paddle-live); before it the package was sandbox only.
//
// No lane has had network or a key, so the tests run against httptest
// servers that replay the fixtures under testdata/, which follow Paddle's
// documented response and error shapes (they are not recordings of a live
// or sandbox call; see the w11 and w17 handbacks).
//
// The API key is held in the Client only: it is never logged and never put
// in an error. Responses are read through a size limit. Portal session
// links carry a token and are never stored or logged by the caller.
package paddleapi
