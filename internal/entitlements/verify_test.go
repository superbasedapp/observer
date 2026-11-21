package entitlements

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// testKey is a deterministic test signing key (never a real key).
func testKey(seed byte) ed25519.PrivateKey {
	s := sha256.Sum256([]byte{'e', 'n', 't', 'l', seed})
	return ed25519.NewKeyFromSeed(s[:])
}

func keysOf(privs ...ed25519.PrivateKey) platformcontract.KeySet {
	var ks platformcontract.KeySet
	for _, p := range privs {
		ks = append(ks, platformcontract.NewDocumentKey(p.Public().(ed25519.PublicKey)))
	}
	return ks
}

// mustDoc turns a template into a Document for org (no signature: the
// effective-layer tests start after verification).
func mustDoc(t *testing.T, b Body, org string) Document {
	t.Helper()
	b = b.Normalized()
	b.Org = org
	b.IssuedAt = 1
	return Document{Version: 1, KeyID: "test", Body: b}
}

// sign composes a catalog plan for org and signs it at version.
func sign(t *testing.T, priv ed25519.PrivateKey, plan string, org string, version int64, mutate func(*Body)) platformcontract.EntitlementDocument {
	t.Helper()
	b, err := Compose(plan, 0, org, 1_700_000_000, 0, 0)
	if err != nil {
		t.Fatalf("Compose: %v", err)
	}
	if mutate != nil {
		mutate(&b)
	}
	raw, err := b.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	doc, err := platformcontract.SignEntitlements(priv, org, version, raw)
	if err != nil {
		t.Fatalf("SignEntitlements: %v", err)
	}
	return doc
}

// TestVerifyTable: one row per refusal and the accept path.
func TestVerifyTable(t *testing.T) {
	t.Parallel()
	k1, k2, stranger := testKey(1), testKey(2), testKey(9)
	keys := keysOf(k1, k2) // a rollover: two pinned keys
	bind := Binding{Org: "org-a", Kind: KindTeam}
	tampered := sign(t, k1, "team", "org-a", 3, nil)
	tampered.Body = append([]byte(nil), tampered.Body...)
	tampered.Body[len(tampered.Body)-2] ^= 1
	availability, err := platformcontract.SignAvailability(k1, 3, sign(t, k1, "team", "org-a", 3, nil).Body)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		doc     platformcontract.EntitlementDocument
		bind    Binding
		last    int64
		wantErr error
	}{
		{name: "accepted under the current key", doc: sign(t, k1, "team", "org-a", 3, nil), bind: bind, last: 2},
		{name: "accepted under the second pinned key", doc: sign(t, k2, "business", "org-a", 3, nil), bind: bind, last: 2},
		{name: "an unpinned key", doc: sign(t, stranger, "team", "org-a", 3, nil), bind: bind, last: 2, wantErr: platformcontract.ErrUnknownDocumentKey},
		{name: "a tampered body", doc: tampered, bind: bind, last: 2, wantErr: platformcontract.ErrBadSignature},
		{name: "an equal version", doc: sign(t, k1, "team", "org-a", 3, nil), bind: bind, last: 3, wantErr: platformcontract.ErrVersionNotNewer},
		{name: "an older version", doc: sign(t, k1, "team", "org-a", 2, nil), bind: bind, last: 3, wantErr: platformcontract.ErrVersionNotNewer},
		{name: "signed for another org", doc: sign(t, k1, "team", "org-b", 3, nil), bind: bind, last: 2, wantErr: platformcontract.ErrBadSignature},
		{name: "body names another org", doc: sign(t, k1, "team", "org-a", 3, func(b *Body) { b.Org = "org-b" }), bind: bind, last: 2, wantErr: ErrBinding},
		{name: "a personal document on a team org", doc: sign(t, k1, "personal_pro", "org-a", 3, nil), bind: bind, last: 2, wantErr: ErrBinding},
		{name: "a self-hosted licence on a pooled org", doc: sign(t, k1, "self_hosted", "org-a", 3, nil), bind: bind, last: 2, wantErr: ErrBinding},
		{name: "an availability signature is not an entitlements one", doc: platformcontract.EntitlementDocument{
			Version: availability.Version, Body: availability.Body, Signature: availability.Signature, KeyID: availability.KeyID,
		}, bind: bind, last: 2, wantErr: platformcontract.ErrBadSignature},
		{name: "a body that is not a body", doc: func() platformcontract.EntitlementDocument {
			d, err := platformcontract.SignEntitlements(k1, "org-a", 3, []byte(`{"schema":"other"}`))
			if err != nil {
				t.Fatal(err)
			}
			return d
		}(), bind: bind, last: 2, wantErr: ErrBody},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			d, err := Verify(tc.doc, tc.bind, keys, tc.last)
			if tc.wantErr == nil {
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
				if d.Version != tc.doc.Version || d.Body.Org != tc.bind.Org || d.KeyID != tc.doc.KeyID {
					t.Fatalf("Verify = %+v", d)
				}
				return
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Verify err = %v, want %v", err, tc.wantErr)
			}
		})
	}
}

// TestReverifyTheStoredDocument: a host re-reads the version it accepted,
// and a key it no longer pins refuses it.
func TestReverifyTheStoredDocument(t *testing.T) {
	t.Parallel()
	k1 := testKey(1)
	bind := Binding{Org: "org-a", Kind: KindTeam}
	doc := sign(t, k1, "team", "org-a", 7, nil)
	if _, err := Reverify(doc, bind, keysOf(k1)); err != nil {
		t.Fatalf("Reverify: %v", err)
	}
	if _, err := Reverify(doc, bind, keysOf(testKey(2))); !errors.Is(err, platformcontract.ErrUnknownDocumentKey) {
		t.Fatalf("Reverify after the key left: %v", err)
	}
	doc.Version = 0
	if _, err := Reverify(doc, bind, keysOf(k1)); !errors.Is(err, platformcontract.ErrDocumentVersion) {
		t.Fatalf("Reverify of version 0: %v", err)
	}
}

// TestCompiledKeysAreEmptyUntilCustody: with no compiled key (operator C12)
// every document is refused, so every org is on its floor.
func TestCompiledKeysAreEmptyUntilCustody(t *testing.T) {
	t.Parallel()
	ks, err := CompiledKeys()
	if err != nil {
		t.Fatalf("CompiledKeys: %v", err)
	}
	if EntitlementsPublicKeyV1 == "" && len(ks) != 0 {
		t.Fatalf("empty slots produced %d keys", len(ks))
	}
	doc := sign(t, testKey(1), "team", "org-a", 1, nil)
	if EntitlementsPublicKeyV1 == "" {
		if _, err := Verify(doc, Binding{Org: "org-a", Kind: KindTeam}, ks, 0); !errors.Is(err, platformcontract.ErrUnknownDocumentKey) {
			t.Fatalf("Verify with no compiled key: %v", err)
		}
	}
}

// TestKeySetFromSlots: an empty slot adds nothing, a good slot pins under
// its derived id, a bad slot fails.
func TestKeySetFromSlots(t *testing.T) {
	t.Parallel()
	pub := testKey(3).Public().(ed25519.PublicKey)
	good := base64.StdEncoding.EncodeToString(pub)
	ks, err := keySetFrom(good, "")
	if err != nil || len(ks) != 1 || ks[0].KeyID != platformcontract.DocumentKeyID(pub) {
		t.Fatalf("keySetFrom(good) = %+v, %v", ks, err)
	}
	if _, err := keySetFrom("not base64!"); err == nil {
		t.Fatal("a bad slot decoded")
	}
	if _, err := keySetFrom(base64.StdEncoding.EncodeToString([]byte("short"))); err == nil {
		t.Fatal("a short key decoded")
	}
}

// TestPreferCompiled: a compiled key always wins (never a union); with none
// compiled the pinned set stands in; the answer is a copy. HostKeys today,
// with both compiled slots empty (ENTL-1), is the pinned set (W14-D1(b)).
func TestPreferCompiled(t *testing.T) {
	t.Parallel()
	compiled := platformcontract.KeySet{platformcontract.NewDocumentKey(testKey(4).Public().(ed25519.PublicKey))}
	pinned := platformcontract.KeySet{platformcontract.NewDocumentKey(testKey(5).Public().(ed25519.PublicKey))}
	for _, c := range []struct {
		name             string
		compiled, pinned platformcontract.KeySet
		want             platformcontract.KeySet
	}{
		{"compiled wins over pinned", compiled, pinned, compiled},
		{"compiled alone", compiled, nil, compiled},
		{"pinned stands in", nil, pinned, pinned},
		{"neither", nil, nil, nil},
	} {
		got := PreferCompiled(c.compiled, c.pinned)
		if len(got) != len(c.want) || (len(got) == 1 && got[0].KeyID != c.want[0].KeyID) {
			t.Errorf("%s: %+v, want %+v", c.name, got, c.want)
		}
	}
	got := PreferCompiled(nil, pinned)
	got[0] = compiled[0]
	if pinned[0].KeyID == compiled[0].KeyID {
		t.Fatal("PreferCompiled returned the caller's slice")
	}
	host, err := HostKeys(pinned)
	if err != nil || len(host) != 1 || host[0].KeyID != pinned[0].KeyID {
		t.Fatalf("HostKeys with no compiled key = %+v, %v; want the pinned key", host, err)
	}
	if ks, err := ParsePublicKeys(base64.StdEncoding.EncodeToString(testKey(5).Public().(ed25519.PublicKey)), ""); err != nil || len(ks) != 1 || ks[0].KeyID != pinned[0].KeyID {
		t.Fatalf("ParsePublicKeys = %+v, %v", ks, err)
	}
	if _, err := ParsePublicKeys("short"); err == nil {
		t.Fatal("ParsePublicKeys decoded a bad key")
	}
}
