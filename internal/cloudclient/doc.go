// Package cloudclient is the node-side client for the SuperBased personal
// cloud-intelligence service (arc 2, CI-P2 — docs/plans/cloud-intelligence-
// azure-foundry-plan-of-record-2026-08-30.md §6 "CI-P2"; amendment §3.3). It:
//
//   - creates/loads the device Ed25519 key via internal/cloudcred;
//   - exchanges a WorkOS access token + the device public key + a server nonce
//     (signed by the device key) for a short-lived, device-bound SuperBased API
//     token (POST /v1/auth/exchange), WorkOS remaining the sole refresh
//     authority (obtained through the CloudIdentityBroker seam);
//   - attaches a fresh internal/cloudpop proof-of-possession header to EVERY
//     API request, with a body digest on writes, so a stolen API token alone is
//     useless;
//   - uploads an evidence envelope as the EXACT bytes handed to it by
//     internal/cloudevidence.Serialize (the client never re-serializes), keyed
//     by a client idempotency key that binds device + cloud session + feature +
//     schema + upload digest (Sol SC10 — the server owns the canonical job key);
//   - pulls results with a monotonic cursor (GET /v1/results?after=<cursor>);
//   - retries transport errors only, with bounded jittered backoff, never 4xx.
//
// # WorkOS broker
//
// CloudIdentityBroker is the WorkOS seam, with two implementations: the
// production WorkOSBroker (workosbroker.go — WorkOS AuthKit PKCE loopback
// sign-in, refresh-token rotation; the CLI orchestrates the loopback + browser,
// the broker refreshes) and the dev/test StubBroker. The node uses only the
// PUBLIC WORKOS_CLIENT_ID; the WorkOS API key is server-side only, and the
// server validates access tokens via the WorkOS JWKS
// (internal/cloudserver/identity.WorkOSVerifier). The remaining gate is the
// operator's WorkOS dashboard config (a 127.0.0.1 loopback redirect URI) +
// AuthKit environment, not code.
//
// # Wire contract this client assumes (the server lane implements)
//
//	GET  /v1/auth/nonce     -> {"nonce":"<opaque>","expires_at":"<rfc3339>"}
//	                           short-lived, single-use, hashed server-side.
//	POST /v1/auth/exchange  <- {"workos_access_token","device_public_key",
//	                            "nonce","signature","device_label"}
//	                        -> {"api_token","expires_at","device_id"}
//	    signature = base64url(Ed25519(devkey, ExchangeSigningInput(nonce,pub))).
//	POST /v1/jobs           body = the exact serialized envelope bytes.
//	                        headers: Authorization: Bearer <api_token>,
//	                                 SBO-PoP: <proof>, Idempotency-Key,
//	                                 SBO-Feature, Content-Type: application/json.
//	                        -> {"job_id","status","cloud_session_id"}
//	GET  /v1/results?after=<cursor>
//	                        headers: Authorization + SBO-PoP.
//	                        -> {"results":[...],"next_cursor":"<opaque>"}
//	                           cursors are monotonic (non-decreasing) opaque
//	                           strings; a page returning rows advances the cursor.
//
// # Purity
//
// stdlib plus internal/cloudpop, internal/cloudcred, internal/cloudcontract,
// and internal/cloudevidence only (pinned by imports_test.go). No internal/
// store, internal/config, database/sql, or fsnotify. New performs no network
// I/O; every method takes a context; no method spawns a goroutine that
// outlives the call.
package cloudclient
