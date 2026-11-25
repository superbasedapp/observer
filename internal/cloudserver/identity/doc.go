// Package identity is the server-side identity-broker seam (plan §6 CI-P3):
// validating a broker (WorkOS) access token into a stable subject + claims,
// behind an interface with a dev-auth stub. WorkOS remains the SOLE refresh
// authority (plan §4) — this package never mints or refreshes anything; it only
// validates an access token the client already holds.
//
// The PRODUCTION WorkOS verifier (JWKS signature + issuer + client_id + expiry,
// with kid-selected key rotation) is implemented in workos.go (WorkOSVerifier);
// chooseVerifier activates it when WORKOS_CLIENT_ID is set. The dev-auth stub
// (SBCI_DEV_AUTH=1) and the fail-closed placeholder remain for local/unset use.
package identity
