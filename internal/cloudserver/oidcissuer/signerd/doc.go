// Package signerd is the I/O of the control plane's two key-holding signer
// processes (design docs/plans/managed-saas/m6.0-control-plane-design-2026-11-13.md
// 3.3):
//
//   - the OIDC signer (managed-SaaS M6.2): a unix-socket server that holds the
//     RSA private key(s) and signs id_tokens for `observer-cloud serve`, the
//     matching client (an oidcissuer.Signer), and the RSA key-file loader.
//     `observer-cloud signer oidc serve` runs it on both app VMs.
//   - the DOCUMENT signer (M6.3, document.go): the same process model with
//     different keys, run as `observer-cloud signer document serve` on the
//     worker VM for the worker. It holds the Ed25519 keys that sign
//     entitlements documents (sbo-entitlements-v1), the availability envelope
//     (sbo-availability-v1) and host-API request envelopes, keeps a durable
//     record of the last version it signed per (kind, scope) (versions.go),
//     and enforces the rules of internal/platformcontract before it signs.
//
// Why one package and two processes: plan 06 (5.4, 18.3.5) and the design
// note put the two signers on different VMs under different users with
// different keys, so they are separate commands and units, never one process
// with two key sets; but they share everything that is not a key - the
// peer-uid check, the socket listener, the line framing - so the document
// signer lives beside the OIDC one rather than in a copy of this code. The
// pure document rules (domain tags, signing input, version rule, body
// sections) are in internal/platformcontract, which the tenant imports to
// verify.
//
// Each signer runs as its own Linux user, so the web process and the worker
// never hold a private key.
//
// The rest of this comment describes the OIDC signer; document.go's header
// gives the document signer's protocol.
//
// # Protocol (version 1)
//
// One request per connection, one JSON object per line, at most 64 KiB:
//
//	-> {"v":1,"op":"keys"}
//	<- {"v":1,"keys":[{"kid":"...","jwk":{"kty":"RSA",...}}]}
//
//	-> {"v":1,"op":"sign","kid":"<kid>","claims":{"iss":...,"aud":...,...}}
//	<- {"v":1,"jwt":"<compact RS256 JWS>"}
//
//	<- {"v":1,"error":"claims_refused"|"bad_request"|"peer_refused"|"internal"}
//
// The request is decoded with unknown fields refused (in the claims too), so
// a claim outside oidcissuer.Claims cannot be signed. The signer applies
// oidcissuer.ValidateClaims (fixed iss, aud = "org:" + org, exp at most five
// minutes after iat, iat within a minute of its own clock, jti present) and
// writes the JWS header itself: the caller names a kid it holds, never an
// algorithm or a header field.
//
// # Who may connect
//
// The peer's uid is read with SO_PEERCRED on every connection and must equal
// the configured uid (the serve process's user); anything else is answered
// peer_refused. SO_PEERCRED is Linux-only, so ListenUnix refuses to start on
// any other OS; tests on other systems drive Server.Serve over a loopback
// listener with an injected peer check, and use oidcissuer.LocalSigner
// in-process behind the same Signer interface.
//
// # Keys at rest
//
// The document signer's keys are PKCS#8 Ed25519 PEM files under the same
// rules (edkey.go), one systemd credential per purpose. The OIDC key is a PEM
// file (PKCS#8 or PKCS#1, RSA of at least 3072 bits),
// readable by the signer's user only (a group- or world-readable file is
// refused). The repository has no age dependency, so this package does not
// decrypt age files; production decrypts at start with a systemd credential
// (LoadCredentialEncrypted=oidc-signing-key:..., read from
// $CREDENTIALS_DIRECTORY/oidc-signing-key, see CredentialKeyPath) or a
// cloud-init-restored file readable only by the signer user (design A16).
package signerd
