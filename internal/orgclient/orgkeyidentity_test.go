package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ONE ORG DISTRIBUTION IDENTITY, node half (fundamentals fix plan
// 2026-09-13, ruling R1).
//
// The defect these tests pin, proven on the live estate: the org server signed
// routing policy and announcements with its DATABASE key and budget, pricing
// and policy bundles with the CONFIGURED FILE key — the key it delivers at
// enrolment. The node resolved the budget/pricing verification key from the
// FETCH-RAIL caches only, so any node that had ever fetched a routing policy
// verified budget documents against the wrong key and refused them forever
// ("budget policy signature does not verify", every 30 seconds).
//
// The fix makes the enrolment-delivered key the node's trust root and lets the
// fetch rails re-pin to it without a re-enrol.

// seedEnrolmentKey writes the enrolment key-material row the way Enroll does,
// for a client whose enrolment points at orgURL.
func seedEnrolmentKey(t *testing.T, c *Client, orgURL string, pub ed25519.PublicKey) {
	t.Helper()
	if _, err := c.recordEnrolmentKeyMaterial(context.Background(), orgURL,
		base64.RawURLEncoding.EncodeToString(pub)); err != nil {
		t.Fatalf("recordEnrolmentKeyMaterial: %v", err)
	}
}

// seedStaleEnrolmentPin writes ONLY the hash pin a pre-R1 enrolment left
// behind — no key material. The rails must fall back to their own pins
// instead of panicking or refusing.
func seedStaleEnrolmentPin(t *testing.T, s *store.Store, orgURL string, pub ed25519.PublicKey) {
	t.Helper()
	seedKeyPinWithProvenance(t, s, orgURL, pub, "")
}

// seedKeyPinWithProvenance writes a `#policy-key` HASH row (no material) with
// the given version-column stamp: "" for a pre-2026-09-13 Enroll,
// railPinProvenance for a fetch rail's TOFU, enrolmentPinProvenance for a
// current Enroll.
func seedKeyPinWithProvenance(t *testing.T, s *store.Store, orgURL string, pub ed25519.PublicKey, provenance string) {
	t.Helper()
	if _, err := s.RecordGuardPolicyState(context.Background(), store.GuardPolicyStateRow{
		Layer:       "org",
		Path:        PolicyKeyPinPath(orgURL),
		Version:     provenance,
		ContentHash: orgcontract.PublicKeyPinHash(pub),
	}); err != nil {
		t.Fatalf("RecordGuardPolicyState: %v", err)
	}
}

// TestBudgetAndPricingVerifyAgainstTheEnrolmentPin is the live defect,
// reproduced: the routing rail holds an OLD key (the server's database key,
// TOFU-pinned months ago) while the org signs budget and pricing with the key
// it handed this node at enrolment.
func TestBudgetAndPricingVerifyAgainstTheEnrolmentPin(t *testing.T) {
	filePub, filePriv, _ := ed25519.GenerateKey(rand.Reader)
	dbPub, dbPriv, _ := ed25519.GenerateKey(rand.Reader)
	thirdPub, thirdPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		// enrolKey is the key stored as enrolment material ("" = a stale
		// pre-R1 enrolment that stored only the pin hash).
		enrolKey ed25519.PublicKey
		// railKey is what the routing rail has cached.
		railKey ed25519.PublicKey
		// signer signs the served document.
		signer     ed25519.PrivateKey
		wantAccept bool
	}{
		{
			name:     "enrolment key wins over a stale routing-rail pin",
			enrolKey: filePub, railKey: dbPub, signer: filePriv, wantAccept: true,
		},
		{
			name:     "a document signed with the stale rail key is refused",
			enrolKey: filePub, railKey: dbPub, signer: dbPriv, wantAccept: false,
		},
		{
			name:     "a third, unrelated key is refused",
			enrolKey: filePub, railKey: dbPub, signer: thirdPriv, wantAccept: false,
		},
		{
			name:     "no enrolment material: the rail pin still answers",
			enrolKey: nil, railKey: dbPub, signer: dbPriv, wantAccept: true,
		},
		{
			name:     "no enrolment material: a foreign key is still refused",
			enrolKey: nil, railKey: dbPub, signer: thirdPriv, wantAccept: false,
		},
	}

	for _, tc := range cases {
		t.Run("budget/"+tc.name, func(t *testing.T) {
			bs := newBudgetServer(t)
			c, s, _ := enrolledClient(t, bs.srv.URL)
			pinRoutingKey(t, s, encodeStdKey(tc.railKey))
			if tc.enrolKey != nil {
				seedEnrolmentKey(t, c, bs.srv.URL, tc.enrolKey)
			} else {
				seedStaleEnrolmentPin(t, s, bs.srv.URL, thirdPub)
			}

			doc, err := orgcontract.SignBudgetPolicy(tc.signer, "org-1", "scim-42", budgetBody(9, 1_000_000))
			if err != nil {
				t.Fatalf("SignBudgetPolicy: %v", err)
			}
			bs.doc.Store(&doc)

			out, err := c.FetchBudgetPolicy(context.Background())
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("FetchBudgetPolicy: %v", err)
				}
				if out.State != orgcontract.BudgetFetchOK || !out.HaveBody {
					t.Fatalf("outcome = %+v, want ok + a body", out)
				}
				return
			}
			if err == nil {
				t.Fatal("a document the org identity did not sign was accepted")
			}
			if out.State != orgcontract.BudgetFetchUnverified || out.HaveBody {
				t.Fatalf("outcome = %+v, want unverified with no body", out)
			}
		})

		t.Run("pricing/"+tc.name, func(t *testing.T) {
			ps := newPricingServer(t)
			c, s, _ := enrolledClient(t, ps.srv.URL)
			enabledPricing(c)
			pinRoutingKey(t, s, encodeStdKey(tc.railKey))
			if tc.enrolKey != nil {
				seedEnrolmentKey(t, c, ps.srv.URL, tc.enrolKey)
			} else {
				seedStaleEnrolmentPin(t, s, ps.srv.URL, thirdPub)
			}

			doc, err := orgcontract.SignPricingPolicy(tc.signer, "org-1", pricingBody(9, "claude-opus-4-8", 4, 20))
			if err != nil {
				t.Fatalf("SignPricingPolicy: %v", err)
			}
			ps.doc.Store(&doc)

			out, err := c.FetchPricingPolicy(context.Background())
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("FetchPricingPolicy: %v", err)
				}
				if out.State != orgcontract.PricingFetchVerified || !out.HaveBody {
					t.Fatalf("outcome = %+v, want ok + a body", out)
				}
				return
			}
			if err == nil {
				t.Fatal("a document the org identity did not sign was accepted")
			}
			if out.State != orgcontract.PricingFetchUnverified || out.HaveBody {
				t.Fatalf("outcome = %+v, want unverified with no body", out)
			}
		})
	}
	_ = thirdPub
}

// TestRoutingRailRepinsToTheEnrolmentKey is R1(c): the migration path. A node
// that TOFU-pinned the database key on the routing rail must accept the
// server's move to the enrolment key WITHOUT a re-enrol — and must still
// refuse any other key change, which is the property that makes the pin worth
// having.
func TestRoutingRailRepinsToTheEnrolmentKey(t *testing.T) {
	filePub, filePriv, _ := ed25519.GenerateKey(rand.Reader)
	dbPub, _, _ := ed25519.GenerateKey(rand.Reader)
	thirdPub, thirdPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name        string
		servedPub   ed25519.PublicKey
		servedPriv  ed25519.PrivateKey
		version     int64
		wantAccept  bool
		wantPinnedT ed25519.PublicKey
	}{
		{
			name:      "the enrolment key at a NEW version is adopted",
			servedPub: filePub, servedPriv: filePriv, version: 2,
			wantAccept: true, wantPinnedT: filePub,
		},
		{
			name:      "the enrolment key at the SAME version still re-pins",
			servedPub: filePub, servedPriv: filePriv, version: 1,
			wantAccept: true, wantPinnedT: filePub,
		},
		{
			name:      "a third, unrelated key is refused and the pin is kept",
			servedPub: thirdPub, servedPriv: thirdPriv, version: 2,
			wantAccept: false, wantPinnedT: dbPub,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			doc := signedRoutingDoc(tc.servedPriv, tc.servedPub, tc.version, "[routing]\n# v"+string(rune('0'+tc.version))+"\n")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/agent/routing-policy" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeTestJSON(w, http.StatusOK, doc)
			}))
			t.Cleanup(srv.Close)

			c, s, _ := enrolledClient(t, srv.URL)
			pinRoutingKey(t, s, encodeStdKey(dbPub)) // the old TOFU pin, version 1
			seedEnrolmentKey(t, c, srv.URL, filePub)

			_, outcome, err := c.FetchRoutingPolicy(context.Background())
			if tc.wantAccept && err != nil {
				t.Fatalf("FetchRoutingPolicy: %v", err)
			}
			if !tc.wantAccept {
				if err == nil {
					t.Fatal("a key change with no enrolment backing was accepted")
				}
				if outcome == nil || outcome.RejectCode != RejectKeyPinMismatch {
					t.Fatalf("outcome = %+v, want a key-pin-mismatch reject", outcome)
				}
			}
			row, ok, rerr := s.GetOrgRoutingPolicy(context.Background())
			if rerr != nil || !ok {
				t.Fatalf("GetOrgRoutingPolicy: ok=%v err=%v", ok, rerr)
			}
			if want := encodeStdKey(tc.wantPinnedT); row.ServerPubkey != want {
				t.Fatalf("cached pubkey = %s…, want %s…", prefix8(row.ServerPubkey), prefix8(want))
			}
		})
	}
}

// TestAnnouncementRailRepinsToTheEnrolmentKey is the announcement rail's half
// of R1(c) — the same rule, because the two rails are the same mechanism and a
// node that accepted the cut-over on one and refused it on the other would
// report a permanent cross-rail disagreement.
func TestAnnouncementRailRepinsToTheEnrolmentKey(t *testing.T) {
	filePub, filePriv, _ := ed25519.GenerateKey(rand.Reader)
	dbPub, _, _ := ed25519.GenerateKey(rand.Reader)
	thirdPub, thirdPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name       string
		servedPub  ed25519.PublicKey
		servedPriv ed25519.PrivateKey
		wantAccept bool
		wantPinned ed25519.PublicKey
	}{
		{"the enrolment key is adopted", filePub, filePriv, true, filePub},
		{"a third, unrelated key is refused", thirdPub, thirdPriv, false, dbPub},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			as := newAnnouncementServer(t)
			c, s, _ := enrolledClient(t, as.srv.URL)
			pinAnnouncementKey(t, s, encodeStdKey(dbPub))
			seedEnrolmentKey(t, c, as.srv.URL, filePub)

			doc := signAnnouncementDoc(2, testAnnBody, tc.servedPriv, tc.servedPub)
			as.doc = &doc

			_, err := c.FetchOrgAnnouncement(context.Background())
			if tc.wantAccept && err != nil {
				t.Fatalf("FetchOrgAnnouncement: %v", err)
			}
			if !tc.wantAccept && err == nil {
				t.Fatal("a key change with no enrolment backing was accepted")
			}
			row, ok, rerr := s.GetOrgAnnouncement(context.Background())
			if rerr != nil || !ok {
				t.Fatalf("GetOrgAnnouncement: ok=%v err=%v", ok, rerr)
			}
			if want := encodeStdKey(tc.wantPinned); row.ServerPubkey != want {
				t.Fatalf("cached pubkey = %s…, want %s…", prefix8(row.ServerPubkey), prefix8(want))
			}
		})
	}
}

// TestEnrollPersistsTheOrgKeyMaterial pins R1(b)/(d): enrolment stores the
// KEY, not only its hash, because a hash cannot verify a signature — and a
// re-enrol against a rotated key overwrites it.
func TestEnrollPersistsTheOrgKeyMaterial(t *testing.T) {
	pub1, _, _ := ed25519.GenerateKey(rand.Reader)
	pub2, _, _ := ed25519.GenerateKey(rand.Reader)

	served := base64.RawURLEncoding.EncodeToString(pub1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
			OrgPolicyPublicKey: served,
		})
	}))
	defer srv.Close()

	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	if _, _, err := c.Enroll(context.Background(), srv.URL, "tok_id.secret"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	got, err := c.enrolmentKeyPin(context.Background())
	if err != nil {
		t.Fatalf("enrolmentKeyPin: %v", err)
	}
	if want := encodeStdKey(pub1); got != want {
		t.Fatalf("stored key = %q, want %q", got, want)
	}
	// The hash pin the policy-bundle gate reads is untouched by the sibling row.
	if row := orgStateRow(t, s, PolicyKeyPinPath(srv.URL)); row == nil ||
		row.ContentHash != orgcontract.PublicKeyPinHash(pub1) {
		t.Fatalf("policy key-pin row = %+v, want the sha256 of the delivered key", row)
	}

	// A rotated key delivered on a re-enrol replaces the material.
	served = base64.RawURLEncoding.EncodeToString(pub2)
	if _, _, err := c.Enroll(context.Background(), srv.URL, "tok_id.secret"); err != nil {
		t.Fatalf("re-Enroll: %v", err)
	}
	got, err = c.enrolmentKeyPin(context.Background())
	if err != nil {
		t.Fatalf("enrolmentKeyPin after re-enrol: %v", err)
	}
	if want := encodeStdKey(pub2); got != want {
		t.Fatalf("stored key after re-enrol = %q, want the rotated key %q", got, want)
	}
}

// TestHashOnlyEnrolmentHealsWithoutReEnrol is the LIVE devbox case: the node
// enrolled before the key material was ever stored, so all it has is the
// `#policy-key` pin HASH — and its routing rail holds the server's old
// database key. The server now offers the configured file key.
//
// Post-C1 the hash alone is not enough to promote a key (an unstamped
// `#policy-key` row could have been written by a fetch rail's TOFU rather than
// by enrolment), so promotion needs CORROBORATION: another rail holding a key
// that hashes to the pin — a pin that exists only because a real signature
// verified under it. With corroboration the node heals in place; without it,
// the key change is refused and the remedy is a re-enrol.
func TestHashOnlyEnrolmentHealsWithoutReEnrol(t *testing.T) {
	filePub, filePriv, _ := ed25519.GenerateKey(rand.Reader)
	dbPub, _, _ := ed25519.GenerateKey(rand.Reader)
	thirdPub, thirdPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		// offeredPub/offeredPriv is what the routing rail is served.
		offeredPub  ed25519.PublicKey
		offeredPriv ed25519.PrivateKey
		// hashPin is the key whose sha256 the `#policy-key` row holds.
		hashPin ed25519.PublicKey
		// provenance is the row's version-column stamp: "" is a
		// pre-2026-09-13 Enroll (the live devbox), railPinProvenance a
		// fetch rail's TOFU.
		provenance string
		// corroborate pins the file key on the announcement rail.
		corroborate bool
		wantAccept  bool
	}{
		{
			name:       "corroborated pre-stamp enrolment hash: the offered key is adopted and the material written",
			offeredPub: filePub, offeredPriv: filePriv, hashPin: filePub,
			corroborate: true, wantAccept: true,
		},
		{
			// THE LIVE DEVBOX SHAPE (W7, 2026-09-13): routing rail holds the
			// database key, no rail holds the file key, `#policy-key` is the
			// unstamped enrolment hash of the file key. Must heal.
			name:       "uncorroborated pre-stamp enrolment hash: the offered key is adopted (the devbox shape)",
			offeredPub: filePub, offeredPriv: filePriv, hashPin: filePub,
			corroborate: false, wantAccept: true,
		},
		{
			name:       "a rail-stamped TOFU hash never promotes, even uncorroborated (C1)",
			offeredPub: filePub, offeredPriv: filePriv, hashPin: filePub, provenance: railPinProvenance,
			corroborate: false, wantAccept: false,
		},
		{
			name:       "a rail-stamped TOFU hash never promotes, even corroborated (C1)",
			offeredPub: filePub, offeredPriv: filePriv, hashPin: filePub, provenance: railPinProvenance,
			corroborate: true, wantAccept: false,
		},
		{
			name:       "a third key that hashes to nothing we pinned: refused",
			offeredPub: thirdPub, offeredPriv: thirdPriv, hashPin: filePub,
			corroborate: true, wantAccept: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			doc := signedRoutingDoc(tc.offeredPriv, tc.offeredPub, 2, "[routing]\n# v2\n")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/agent/routing-policy" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeTestJSON(w, http.StatusOK, doc)
			}))
			t.Cleanup(srv.Close)

			c, s, _ := enrolledClient(t, srv.URL)
			pinRoutingKey(t, s, encodeStdKey(dbPub)) // the old TOFU pin
			if tc.corroborate {
				pinAnnouncementKey(t, s, encodeStdKey(filePub))
			}
			seedKeyPinWithProvenance(t, s, srv.URL, tc.hashPin, tc.provenance) // hash ONLY, no material

			if pin, err := c.enrolmentKeyPin(ctx); err != nil || pin != "" {
				t.Fatalf("precondition: material pin = %q err=%v, want empty", pin, err)
			}

			_, outcome, err := c.FetchRoutingPolicy(ctx)
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("FetchRoutingPolicy: %v", err)
				}
				// The material row was written — AFTER the signature verified
				// and the cache was upserted (M3).
				pin, perr := c.enrolmentKeyPin(ctx)
				if perr != nil || pin != encodeStdKey(tc.offeredPub) {
					t.Fatalf("material after accept = %q err=%v, want the offered key", pin, perr)
				}
				row, ok, rerr := s.GetOrgRoutingPolicy(ctx)
				if rerr != nil || !ok || row.ServerPubkey != encodeStdKey(tc.offeredPub) {
					t.Fatalf("cached pubkey = %q (ok=%v err=%v), want the offered key", row.ServerPubkey, ok, rerr)
				}
				return
			}
			if err == nil {
				t.Fatal("a key the enrolment trust root does not vouch for was adopted")
			}
			if outcome == nil || outcome.RejectCode != RejectKeyPinMismatch {
				t.Fatalf("outcome = %+v, want a key-pin-mismatch reject", outcome)
			}
			if pin, perr := c.enrolmentKeyPin(ctx); perr != nil || pin != "" {
				t.Fatalf("material = %q after a refusal, want none written", pin)
			}
			row, ok, rerr := s.GetOrgRoutingPolicy(ctx)
			if rerr != nil || !ok || row.ServerPubkey != encodeStdKey(dbPub) {
				t.Fatalf("cached pubkey = %q, want the refusal to leave the old pin", row.ServerPubkey)
			}
		})
	}
}

// TestBudgetVerifiesAfterHashOnlyAdoption is the end of that same story: once
// a rail pin has been recognised against the enrolment hash, the budget rail —
// which carries no key of its own — resolves THAT key and the document the org
// actually signed verifies. This is the exact devbox failure
// ("budget policy signature does not verify") going away without a re-enrol.
func TestBudgetVerifiesAfterHashOnlyAdoption(t *testing.T) {
	filePub, filePriv, _ := ed25519.GenerateKey(rand.Reader)
	dbPub, dbPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name string
		// railPins are the fetch-rail caches: routing holds the old key, and
		// the announcement rail may or may not already hold the file key.
		announcementHoldsFileKey bool
		signer                   ed25519.PrivateKey
		wantAccept               bool
	}{
		{"the file key is recognised from an announcement-rail pin", true, filePriv, true},
		{"the old database key is refused once the file key is adopted", true, dbPriv, false},
		{"no rail holds the enrolment key yet: the routing pin still answers", false, dbPriv, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bs := newBudgetServer(t)
			c, s, _ := enrolledClient(t, bs.srv.URL)
			pinRoutingKey(t, s, encodeStdKey(dbPub))
			if tc.announcementHoldsFileKey {
				pinAnnouncementKey(t, s, encodeStdKey(filePub))
			}
			seedStaleEnrolmentPin(t, s, bs.srv.URL, filePub) // hash ONLY

			doc, err := orgcontract.SignBudgetPolicy(tc.signer, "org-1", "scim-42", budgetBody(3, 7_000_000))
			if err != nil {
				t.Fatalf("SignBudgetPolicy: %v", err)
			}
			bs.doc.Store(&doc)

			out, err := c.FetchBudgetPolicy(context.Background())
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("FetchBudgetPolicy: %v", err)
				}
				if out.State != orgcontract.BudgetFetchOK || !out.HaveBody {
					t.Fatalf("outcome = %+v, want ok + a body", out)
				}
				return
			}
			if err == nil {
				t.Fatal("a body signed by the superseded key was accepted")
			}
			if out.State != orgcontract.BudgetFetchUnverified || out.HaveBody {
				t.Fatalf("outcome = %+v, want unverified with no body", out)
			}
		})
	}
}

// TestBundleTOFUPinCannotBecomeTheEnrolmentTrustRoot is finding C1.
//
// THREE rails write the shared `#policy-key` row: Enroll, and the
// policy-bundle / policy-resource rails by trust-on-first-fetch. If a hash
// written by a FETCH rail counted as the enrolment pin, an attacker who
// reaches a node holding no pin could plant his key through the bundle rail
// and then have the routing rail promote it into the enrolment material —
// becoming the node's trust root and locking the real org out.
//
// Two properties are pinned here: a TOFU-written row does not promote, and a
// TOFU write is itself refused when any existing pin disagrees.
func TestBundleTOFUPinCannotBecomeTheEnrolmentTrustRoot(t *testing.T) {
	attackerPub, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	orgPub, orgPriv, _ := ed25519.GenerateKey(rand.Reader)

	t.Run("a TOFU-written pin never promotes to the trust root", func(t *testing.T) {
		ctx := context.Background()
		ps := newPolicyBundleServer(t)
		c, s, cachePath := enrolledClient(t, ps.srv.URL)
		b := signedTestBundle(t, attackerPriv, attackerPub, 1, escalatingTOML)
		ps.bundle = &b

		// The node has nothing pinned anywhere: the bundle rail TOFUs.
		if _, err := c.FetchPolicyBundle(ctx, cachePath); err != nil {
			t.Fatalf("FetchPolicyBundle: %v", err)
		}
		pin := orgStateRow(t, s, PolicyKeyPinPath(ps.srv.URL))
		if pin == nil || pin.ContentHash != orgcontract.PublicKeyPinHash(attackerPub) {
			t.Fatalf("precondition: the bundle rail must have TOFU-pinned; row = %+v", pin)
		}
		if pin.Version != railPinProvenance {
			t.Fatalf("a fetch rail's TOFU pin must carry railPinProvenance, got %q", pin.Version)
		}
		// It must NOT be the trust root: nothing may be promoted from it, and
		// no material may be written from it.
		if ok, err := c.offeredIsEnrolmentKey(ctx, encodeStdKey(attackerPub)); err != nil || ok {
			t.Fatalf("offeredIsEnrolmentKey(TOFU key) = %v err=%v, want false", ok, err)
		}
		c.adoptEnrolmentKeyMaterial(ctx, encodeStdKey(attackerPub))
		if material, err := c.enrolmentKeyPin(ctx); err != nil || material != "" {
			t.Fatalf("material = %q err=%v, want nothing promoted from a TOFU pin", material, err)
		}
	})

	t.Run("a TOFU write is refused when an existing pin disagrees", func(t *testing.T) {
		ctx := context.Background()
		ps := newPolicyBundleServer(t)
		c, s, cachePath := enrolledClient(t, ps.srv.URL)
		// The node already trusts the org key on the routing rail.
		pinRoutingKey(t, s, encodeStdKey(orgPub))

		b := signedTestBundle(t, attackerPriv, attackerPub, 1, escalatingTOML)
		ps.bundle = &b
		res, err := c.FetchPolicyBundle(ctx, cachePath)
		if err != nil {
			t.Fatalf("FetchPolicyBundle: %v", err)
		}
		if res.Status != PolicyRejected || res.RejectCode != RejectKeyPinMismatch {
			t.Fatalf("result = %+v, want a key-pin-mismatch rejection", res)
		}
		if row := orgStateRow(t, s, PolicyKeyPinPath(ps.srv.URL)); row != nil {
			t.Fatalf("a refused bundle still established a key pin: %+v", row)
		}

		// The genuine key, on the other hand, is accepted and pins.
		good := signedTestBundle(t, orgPriv, orgPub, 1, escalatingTOML)
		ps.bundle = &good
		if res, err := c.FetchPolicyBundle(ctx, cachePath); err != nil || res.Status == PolicyRejected {
			t.Fatalf("the org's own bundle was rejected: res=%+v err=%v", res, err)
		}
	})
}

// TestFirstFetchRefusesAKeyThatDoesNotHashToTheEnrolmentPin is finding H1: on
// a TRUE first fetch (no rail pins, no material) the node used to TOFU-accept
// any key even though its `#policy-key` row already named the org's. A hash
// cannot verify a signature, but it can REFUSE one, and refusing is the whole
// value of having been told the key at enrolment.
func TestFirstFetchRefusesAKeyThatDoesNotHashToTheEnrolmentPin(t *testing.T) {
	orgPub, orgPriv, _ := ed25519.GenerateKey(rand.Reader)
	foreignPub, foreignPriv, _ := ed25519.GenerateKey(rand.Reader)

	cases := []struct {
		name       string
		servedPub  ed25519.PublicKey
		servedPriv ed25519.PrivateKey
		wantAccept bool
	}{
		{"the key the enrolment pin names", orgPub, orgPriv, true},
		{"a foreign key on an unpinned rail", foreignPub, foreignPriv, false},
	}

	for _, tc := range cases {
		t.Run("routing/"+tc.name, func(t *testing.T) {
			ctx := context.Background()
			doc := signedRoutingDoc(tc.servedPriv, tc.servedPub, 1, "[routing]\n")
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/agent/routing-policy" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				writeTestJSON(w, http.StatusOK, doc)
			}))
			t.Cleanup(srv.Close)

			c, s, _ := enrolledClient(t, srv.URL)
			seedStaleEnrolmentPin(t, s, srv.URL, orgPub) // hash only, no rail pins

			_, outcome, err := c.FetchRoutingPolicy(ctx)
			if tc.wantAccept {
				if err != nil {
					t.Fatalf("FetchRoutingPolicy: %v", err)
				}
				if row, ok, _ := s.GetOrgRoutingPolicy(ctx); !ok || row.ServerPubkey != encodeStdKey(tc.servedPub) {
					t.Fatalf("cached pubkey = %+v, want the offered (pinned) key", row)
				}
				return
			}
			if err == nil {
				t.Fatal("a first fetch TOFU-accepted a key the enrolment pin refuses")
			}
			if outcome == nil || outcome.RejectCode != RejectKeyPinMismatch {
				t.Fatalf("outcome = %+v, want a key-pin-mismatch reject", outcome)
			}
			if _, ok, _ := s.GetOrgRoutingPolicy(ctx); ok {
				t.Fatal("a refused first fetch still cached a policy")
			}
		})

		t.Run("announcement/"+tc.name, func(t *testing.T) {
			ctx := context.Background()
			as := newAnnouncementServer(t)
			c, s, _ := enrolledClient(t, as.srv.URL)
			seedStaleEnrolmentPin(t, s, as.srv.URL, orgPub)
			doc := signAnnouncementDoc(1, testAnnBody, tc.servedPriv, tc.servedPub)
			as.doc = &doc

			_, err := c.FetchOrgAnnouncement(ctx)
			if tc.wantAccept != (err == nil) {
				t.Fatalf("FetchOrgAnnouncement err = %v, wantAccept = %v", err, tc.wantAccept)
			}
			_, cached, _ := s.GetOrgAnnouncement(ctx)
			if cached != tc.wantAccept {
				t.Fatalf("cached = %v, want %v", cached, tc.wantAccept)
			}
		})
	}
}
