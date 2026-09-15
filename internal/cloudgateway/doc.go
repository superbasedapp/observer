// Package cloudgateway is the CONSENT-GATED EGRESS SEAM for the personal
// cloud-intelligence plane. It is the one place in the node that composes the
// network lane (internal/cloudclient + internal/cloudpop + internal/cloudcred),
// and it exists to make one invariant structural rather than aspirational:
//
//	NO FEATURE EGRESS WITHOUT A LIVE CONSENT GRANT.
//
// # Why a package and not a check
//
// The plane's original posture was "only typed CLI commands may touch the
// network", pinned by an import-graph test that allow-listed cmd/observer.
// Operator ruling R2 (divergence-remediation plan rev 4.1 §2) replaced that
// principle with "no egress without prior explicit consent; after consent,
// egress for the consented purposes is unrestricted in mechanism" — background
// sync, dashboard buttons and page-load reads all become legitimate callers.
//
// An import-graph pin cannot check consent at runtime, and allow-listing a whole
// command binary would let a future background path skip the check entirely. So
// the R2 disposition (F11) names the mechanism this package implements: a single
// gateway that resolves live grant state from the store, FAIL-CLOSED, before any
// network attempt, with a distinguished bootstrap lane for sign-in itself.
// tests/invariant/cloud_egress_test.go now allow-lists THIS package — and no
// longer cmd/observer — as the importer of the network lane.
//
// # The two lanes
//
// BOOTSTRAP lane (methods prefixed Bootstrap*). The `account_device_operations`
// purpose: the device-token exchange, logout/revocation, and account deletion.
// These pass WITHOUT a grant check, and that is not a hole — per the R2
// disposition (F10), "explicit consent" begins at the user's own sign-in ACTION
// (a typed `observer cloud login`, a clicked portal sign-in). That action
// authorizes authentication and account-device bootstrap egress, and nothing
// else. Naming them Bootstrap* in the API is deliberate: an ungated call is
// visible as such at every call site.
//
// FEATURE lane (FeatureSend / StandingSend / FeatureFetch). Everything derived
// from a session or a window. Each resolves the live grant for a typed purpose
// from the store before touching the network, re-checks it immediately before
// handing over the client, and refuses with ErrNoLiveGrant otherwise. The
// network handle can only be obtained from inside an authorized callback —
// there is no way to get one without passing the check — and it is NARROWED to
// the operation class the check authorized: FeatureFetch yields a ReadSession
// (Results only), FeatureSend an UploadSession (session evidence only),
// StandingSend a StructuralSession (snapshots only). Go cannot stop a callback
// from storing the handle it was given, so the enforcement is that a stored
// handle can do nothing outside its own class. Both write handles additionally
// REQUIRE a per-item PreAttempt re-check and run the gateway's own grant
// re-resolve in front of it before every physical attempt.
//
// # What this package does NOT own
//
// It is a BELT, not a replacement for the per-item authorization the store
// already enforces. Each individual upload still gets its own digest, its own
// outbox row, its own endpoint binding (FD1), and its own atomic pre-dispatch
// re-verification (store.PrepareCloudOutboxSend / PrepareStructuralSend /
// VerifyCloudSendAuthorization). In particular the gateway deliberately does
// NOT filter grants by endpoint: endpoint binding is a per-item rule the store
// owns, and duplicating it here would turn a precise per-item refusal into a
// coarse "no grant" one.
//
// # Purity and dependencies
//
// This package is a COMPOSITION seam, not a pure package: it holds the HTTP
// client and the credential store. It reads consent through a narrow local
// interface (GrantStore) rather than the whole store, so it is trivially fakeable
// and so the dependency direction stays one-way — internal/store never imports
// this package, which is what keeps the always-on daemon paths free of the
// network lane.
package cloudgateway
