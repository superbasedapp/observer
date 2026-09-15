// Package sealbox is the PURE per-machine sealing primitive behind break-glass
// credential leases (Plane B dual-mode gateway design 2026-08-29 §4.2 rung 3;
// gap register 2026-09-02 G1-BREAKGLASS). The org server SEALS a provider
// credential to one target node's public seal key; only that node can OPEN it.
// The signature on the lease (orgcontract.BreakGlassLease) gives authenticity;
// this box gives confidentiality — so a lease can ride an org-wide-readable
// rail and still never expose the plaintext credential to anyone but the
// machine it was minted for.
//
// Scheme (SchemeV1): X25519 ECDH with an ephemeral sender key → HKDF-SHA256
// (info = the scheme tag + both public keys) → AES-256-GCM with a random
// nonce, the caller's additional data bound as AEAD AAD. The wire blob is
// ephemeral_public(32) || nonce(12) || ciphertext, base64 (std). Every
// primitive is Go standard library; no third-party crypto.
//
// The node's seal key pair is DERIVED from its existing enrolment Ed25519
// signing key seed (DeriveKeyPair), so a node holds ONE long-lived secret and
// publishes the derived X25519 public half on the push rail
// (orgcontract.SealKeyAdvertisement). No new keychain slot is needed for the
// private half; the opened credential lands in its own slot node-side.
//
// Pure package: no SQL, no HTTP, no fsnotify, no logging — pinned by
// imports_test.go. Both sides (internal/orgserver/breakglass sealer and
// internal/orgclient redemption) call it through Seal / Open only.
package sealbox
