package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedEnrolledNode writes an Enrolment row plus the org policy key pin that
// AcceptGrantReplacement requires (it never TOFU-pins), returning the signing
// key so callers can mint fixture-signed GrantReplacement messages.
func seedEnrolledNode(t *testing.T, s *store.Store, orgURL, orgID string) (pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()
	ctx := context.Background()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	enr := store.Enrolment{
		OrgID:        orgID,
		OrgName:      "Acme",
		OrgServerURL: orgURL,
		UserID:       "scim-42",
		UserEmail:    "dev@acme.example",
		EnrolledAt:   "2026-08-15T10:00:00Z",
		BearerKeyID:  "bearer-1",
	}
	if err := s.WriteEnrolment(ctx, enr); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	if _, err := s.RecordGuardPolicyState(ctx, store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        PolicyKeyPinPath(orgURL),
		ContentHash: orgcontract.PublicKeyPinHash(pub),
	}); err != nil {
		t.Fatalf("RecordGuardPolicyState (key pin): %v", err)
	}
	return pub, priv
}

// validReplacement returns a well-formed, signed GrantReplacement for the
// given (orgURL, orgID) pair at the given replacement generation.
func validReplacement(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, orgURL, orgID string, generation int64) orgcontract.GrantReplacement {
	t.Helper()
	return validReplacementWithAuthority(t, priv, pub, orgURL, orgID, generation, []string{"dashboard.visibility"})
}

// validReplacementWithAuthority is validReplacement with a caller-chosen
// authority set, signed AFTER the authority is set — a replacement's
// Authority must never be mutated post-construction, or its signature no
// longer covers what the message actually claims.
func validReplacementWithAuthority(t *testing.T, priv ed25519.PrivateKey, pub ed25519.PublicKey, orgURL, orgID string, generation int64, authority []string) orgcontract.GrantReplacement {
	t.Helper()
	r := orgcontract.GrantReplacement{
		OrgID:        orgID,
		OrgServerURL: orgURL,
		KeyPinSHA256: orgcontract.PublicKeyPinHash(pub),
		Generation:   generation,
		PublicKey:    base64.RawURLEncoding.EncodeToString(pub),
		Authority:    authority,
		GrantedAt:    time.Now().UTC().Format(time.RFC3339),
		ExpiresAt:    time.Now().UTC().Add(30 * 24 * time.Hour).Format(time.RFC3339),
	}
	r.Signature = orgcontract.SignGrantReplacement(priv, r)
	return r
}

func TestAcceptGrantReplacement_Success(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})

	const orgURL = "https://org.example.com"
	const orgID = "org-1"
	pub, priv := seedEnrolledNode(t, s, orgURL, orgID)
	r := validReplacement(t, priv, pub, orgURL, orgID, 1)

	accepted, err := c.AcceptGrantReplacement(ctx, r)
	if err != nil {
		t.Fatalf("AcceptGrantReplacement: %v", err)
	}
	if !accepted {
		t.Fatal("a valid, freshly-signed replacement was refused")
	}

	orgKey := OrgKey(orgURL, orgID)
	got, ok, err := s.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGrant after accept: ok=%v err=%v", ok, err)
	}
	if got.ReplacementGeneration != 1 {
		t.Fatalf("ReplacementGeneration = %d, want 1", got.ReplacementGeneration)
	}
	if len(got.Authority) != 1 || got.Authority[0] != "dashboard.visibility" {
		t.Fatalf("Authority = %v, want [dashboard.visibility]", got.Authority)
	}
	// No pre-existing grant row and no P0-5 EnrolmentGeneration row either —
	// the fallback resolves to the zero value, and the fresh-row INSERT path
	// carries it through untouched.
	if got.Generation != 0 {
		t.Fatalf("Generation = %d, want 0 (no P0-5 fence row existed to fall back to)", got.Generation)
	}
}

// TestAcceptGrantReplacement_GenerationFallsBackToFence proves the P0-5
// enrolment-identity generation is used when no EnrolmentGrant row already
// exists for this org_key — the case of a node that enrolled ungoverned and
// is now receiving its first authority grant via replacement rather than at
// Enroll time.
func TestAcceptGrantReplacement_GenerationFallsBackToFence(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})

	const orgURL = "https://org.example.com"
	const orgID = "org-1"
	pub, priv := seedEnrolledNode(t, s, orgURL, orgID)
	orgKey := OrgKey(orgURL, orgID)

	if _, err := s.BumpEnrolmentGeneration(ctx, orgKey, false); err != nil {
		t.Fatalf("BumpEnrolmentGeneration: %v", err)
	}
	fence, ok, err := s.LoadEnrolmentGeneration(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGeneration: ok=%v err=%v", ok, err)
	}
	if fence.Generation == 0 {
		t.Fatal("expected a bumped fence generation > 0")
	}

	r := validReplacement(t, priv, pub, orgURL, orgID, 1)
	accepted, err := c.AcceptGrantReplacement(ctx, r)
	if err != nil {
		t.Fatalf("AcceptGrantReplacement: %v", err)
	}
	if !accepted {
		t.Fatal("valid replacement was refused")
	}
	got, ok, err := s.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGrant: ok=%v err=%v", ok, err)
	}
	if got.Generation != fence.Generation {
		t.Fatalf("Generation = %d, want the P0-5 fence value %d", got.Generation, fence.Generation)
	}
}

// TestAcceptGrantReplacement_GenerationPreservedFromExistingRow proves that
// once an EnrolmentGrant row already exists, its stored Generation (the
// enrolment epoch) is carried forward untouched by a replacement — never
// overwritten by the replacement's own (unrelated) Generation field.
func TestAcceptGrantReplacement_GenerationPreservedFromExistingRow(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})

	const orgURL = "https://org.example.com"
	const orgID = "org-1"
	pub, priv := seedEnrolledNode(t, s, orgURL, orgID)
	orgKey := OrgKey(orgURL, orgID)

	seeded := store.EnrolmentGrant{
		OrgKey:       orgKey,
		Generation:   7,
		OrgID:        orgID,
		OrgName:      "Acme",
		OrgServerURL: orgURL,
		KeyPinSHA256: orgcontract.PublicKeyPinHash(pub),
		Authority:    []string{"settings.pin"},
		GrantedAt:    time.Now().UTC(),
		ExpiresAt:    time.Now().UTC().Add(24 * time.Hour),
		Signature:    "sig",
		ReceiptHash:  "rh",
	}
	if err := s.WriteEnrolmentGrant(ctx, seeded); err != nil {
		t.Fatalf("seed WriteEnrolmentGrant: %v", err)
	}

	r := validReplacement(t, priv, pub, orgURL, orgID, 1)
	accepted, err := c.AcceptGrantReplacement(ctx, r)
	if err != nil {
		t.Fatalf("AcceptGrantReplacement: %v", err)
	}
	if !accepted {
		t.Fatal("valid replacement was refused")
	}
	got, ok, err := s.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGrant: ok=%v err=%v", ok, err)
	}
	if got.Generation != 7 {
		t.Fatalf("Generation = %d, want 7 (preserved from the existing row, not replacement's own Generation field)", got.Generation)
	}
}

// TestAcceptGrantReplacement_Monotonic proves a second, strictly-greater
// replacement supersedes the first, and a stale/replayed one is refused
// while leaving the last-good grant untouched.
func TestAcceptGrantReplacement_Monotonic(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})

	const orgURL = "https://org.example.com"
	const orgID = "org-1"
	pub, priv := seedEnrolledNode(t, s, orgURL, orgID)
	orgKey := OrgKey(orgURL, orgID)

	first := validReplacement(t, priv, pub, orgURL, orgID, 1)
	if accepted, err := c.AcceptGrantReplacement(ctx, first); err != nil || !accepted {
		t.Fatalf("first replacement: accepted=%v err=%v", accepted, err)
	}

	second := validReplacementWithAuthority(t, priv, pub, orgURL, orgID, 2, []string{"settings.pin", "capture.raise"})
	if accepted, err := c.AcceptGrantReplacement(ctx, second); err != nil || !accepted {
		t.Fatalf("second replacement: accepted=%v err=%v", accepted, err)
	}

	stale := validReplacement(t, priv, pub, orgURL, orgID, 2) // equal, not greater
	accepted, err := c.AcceptGrantReplacement(ctx, stale)
	if err != nil {
		t.Fatalf("stale replacement (equal generation): %v", err)
	}
	if accepted {
		t.Fatal("a replayed replacement with an equal generation was accepted")
	}

	older := validReplacement(t, priv, pub, orgURL, orgID, 1) // strictly less
	accepted, err = c.AcceptGrantReplacement(ctx, older)
	if err != nil {
		t.Fatalf("older replacement: %v", err)
	}
	if accepted {
		t.Fatal("a replacement with a lower generation than already-applied was accepted")
	}

	got, ok, err := s.LoadEnrolmentGrant(ctx, orgKey)
	if err != nil || !ok {
		t.Fatalf("LoadEnrolmentGrant: ok=%v err=%v", ok, err)
	}
	if got.ReplacementGeneration != 2 {
		t.Fatalf("ReplacementGeneration = %d, want 2 (unaffected by the refused stale/older replacements)", got.ReplacementGeneration)
	}
	if len(got.Authority) != 2 {
		t.Fatalf("Authority = %v, want the second replacement's authority, untouched by the refusals", got.Authority)
	}
}

// TestAcceptGrantReplacement_Refusals is the table-driven refusal sweep,
// mirroring TestEnrollRefusesUngroundedGrants's idiom in grant_test.go: every
// case must refuse (accepted=false, err=nil) and must never corrupt the
// stored state.
func TestAcceptGrantReplacement_Refusals(t *testing.T) {
	const orgURL = "https://org.example.com"
	const orgID = "org-1"

	cases := []struct {
		name string
		// setup optionally customizes the store/client before the call
		// (e.g. skip enrolment entirely). Returns the store+client to use.
		setup func(t *testing.T) (*store.Store, *Client, ed25519.PublicKey, ed25519.PrivateKey)
		mut   func(r *orgcontract.GrantReplacement)
	}{
		{
			name: "node is not enrolled at all",
			setup: func(t *testing.T) (*store.Store, *Client, ed25519.PublicKey, ed25519.PrivateKey) {
				s := newAgentStore(t)
				c := newTestClient(t, s, &memBearerStore{})
				pub, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatalf("keygen: %v", err)
				}
				return s, c, pub, priv
			},
		},
		{
			name: "different org id than the current enrolment",
			mut:  func(r *orgcontract.GrantReplacement) { r.OrgID = "org-2" },
		},
		{
			name: "different org server than the current enrolment",
			mut:  func(r *orgcontract.GrantReplacement) { r.OrgServerURL = "https://evil.example" },
		},
		{
			name: "signature does not verify (message tampered post-signing)",
			mut:  func(r *orgcontract.GrantReplacement) { r.Authority = append(r.Authority, "capture.raise") },
		},
		{
			// Handled entirely by the special-case block below the mut
			// loop: it needs KeyPinSHA256 set AND the message re-signed
			// so the signature itself still verifies — this exercises the
			// DECLARED-pin cross-check, distinct from the signing-key pin
			// check that "wrong key never matches pin" (a separate test)
			// covers.
			name: "declared key pin does not match the recorded pin",
		},
		{
			name: "already expired",
			mut:  func(r *orgcontract.GrantReplacement) { r.ExpiresAt = "2020-01-01T00:00:00Z" },
		},
		{
			name: "expires_at is not RFC3339",
			mut:  func(r *orgcontract.GrantReplacement) { r.ExpiresAt = "not-a-timestamp" },
		},
		{
			name: "generation is zero (never applies)",
			mut:  func(r *orgcontract.GrantReplacement) { r.Generation = 0 },
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			var s *store.Store
			var c *Client
			var pub ed25519.PublicKey
			var priv ed25519.PrivateKey
			if tc.setup != nil {
				s, c, pub, priv = tc.setup(t)
			} else {
				s = newAgentStore(t)
				c = newTestClient(t, s, &memBearerStore{})
				pub, priv = seedEnrolledNode(t, s, orgURL, orgID)
			}

			r := validReplacement(t, priv, pub, orgURL, orgID, 1)
			if tc.mut != nil {
				tc.mut(&r)
				if tc.name != "signature does not verify (message tampered post-signing)" &&
					tc.name != "declared key pin does not match the recorded pin" {
					// Re-sign so we're testing the specific gate named by
					// the case, not an incidental signature failure — EXCEPT
					// the "tampered" case, which deliberately mutates
					// AFTER signing, and the "declared pin" case, which
					// needs a mismatched-but-still-verifying signature.
					r.Signature = orgcontract.SignGrantReplacement(priv, r)
				}
			}
			if tc.name == "declared key pin does not match the recorded pin" {
				r.KeyPinSHA256 = "0000000000000000000000000000000000000000000000000000000000000"
				r.Signature = orgcontract.SignGrantReplacement(priv, r)
			}

			accepted, err := c.AcceptGrantReplacement(ctx, r)
			if err != nil {
				t.Fatalf("AcceptGrantReplacement returned an error (want a clean refusal): %v", err)
			}
			if accepted {
				t.Fatalf("case %q was accepted, want refused", tc.name)
			}

			orgKey := OrgKey(orgURL, orgID)
			if _, ok, lerr := s.LoadEnrolmentGrant(ctx, orgKey); lerr != nil {
				t.Fatalf("LoadEnrolmentGrant after refusal: %v", lerr)
			} else if ok {
				t.Fatalf("case %q: a refused replacement still wrote a grant row", tc.name)
			}
		})
	}
}

// TestAcceptGrantReplacement_UnpinnedKeyNeverTOFU proves the accept path
// refuses when no key pin exists yet — unlike a first policy-bundle fetch,
// a replacement must never trust-on-first-use.
func TestAcceptGrantReplacement_UnpinnedKeyNeverTOFU(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})

	const orgURL = "https://org.example.com"
	const orgID = "org-1"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	// Enrolled, but NO key pin recorded — a pre-governance enrolment.
	if err := s.WriteEnrolment(ctx, store.Enrolment{
		OrgID: orgID, OrgName: "Acme", OrgServerURL: orgURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: "2026-08-15T10:00:00Z", BearerKeyID: "bearer-1",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}

	r := validReplacement(t, priv, pub, orgURL, orgID, 1)
	accepted, err := c.AcceptGrantReplacement(ctx, r)
	if err != nil {
		t.Fatalf("AcceptGrantReplacement: %v", err)
	}
	if accepted {
		t.Fatal("a replacement was accepted with no key pin recorded — must never TOFU-pin")
	}
}

// TestAcceptGrantReplacement_WrongKeyNeverMatchesPin proves a replacement
// signed under a DIFFERENT key than the one pinned at enrolment is refused,
// even though its own self-contained signature verifies fine.
func TestAcceptGrantReplacement_WrongKeyNeverMatchesPin(t *testing.T) {
	ctx := context.Background()
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})

	const orgURL = "https://org.example.com"
	const orgID = "org-1"
	_, _ = seedEnrolledNode(t, s, orgURL, orgID) // pins THIS key

	otherPub, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	r := validReplacement(t, otherPriv, otherPub, orgURL, orgID, 1)

	accepted, err := c.AcceptGrantReplacement(ctx, r)
	if err != nil {
		t.Fatalf("AcceptGrantReplacement: %v", err)
	}
	if accepted {
		t.Fatal("a replacement signed under an unpinned key was accepted")
	}
	orgKey := OrgKey(orgURL, orgID)
	if _, ok, lerr := s.LoadEnrolmentGrant(ctx, orgKey); lerr != nil {
		t.Fatalf("LoadEnrolmentGrant: %v", lerr)
	} else if ok {
		t.Fatal("a refused wrong-key replacement still wrote a grant row")
	}
}
