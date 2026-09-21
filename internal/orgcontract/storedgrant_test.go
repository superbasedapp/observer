package orgcontract

import (
	"crypto/ed25519"
	"testing"
	"time"
)

// storedGrantFixture builds a signed enrolment grant and the stored document
// that corresponds to it byte-for-byte, the way
// cmd/observer/nodegov_wire.go::verifyStoredGrantIntegrity reconstructs one
// from the SQLite row.
func storedGrantFixture(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, EnrolmentGrant, StoredGrantDocument) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 9, 21, 10, 0, 0, 0, time.UTC)
	g := EnrolmentGrant{
		OrgID:        "org-1",
		OrgServerURL: "https://org.example",
		KeyPinSHA256: PublicKeyPinHash(pub),
		Authority:    CanonicalAuthority([]string{"dashboard.visibility", "settings.pin"}),
		GrantedAt:    now.Format(time.RFC3339),
		ExpiresAt:    now.AddDate(0, 0, 30).Format(time.RFC3339),
	}
	g.Signature = SignEnrolmentGrant(priv, g)
	doc := StoredGrantDocument{
		OrgID:        g.OrgID,
		OrgServerURL: g.OrgServerURL,
		KeyPinSHA256: g.KeyPinSHA256,
		Authority:    g.Authority,
		GrantedAt:    g.GrantedAt,
		ExpiresAt:    g.ExpiresAt,
		Signature:    g.Signature,
	}
	return pub, priv, g, doc
}

// TestVerifyStoredGrant is the Track C item 1 table: one row per way a
// stored grant can be read back, including the tamper the feature exists to
// catch (an authority list rewritten in the node-local SQLite file).
func TestVerifyStoredGrant(t *testing.T) {
	pub, priv, _, clean := storedGrantFixture(t)

	authorityRewritten := clean
	authorityRewritten.Authority = CanonicalAuthority(
		append(append([]string{}, clean.Authority...), "enforce.budget", "extract.managed"))

	authorityRemoved := clean
	authorityRemoved.Authority = []string{"dashboard.visibility"}

	expiryExtended := clean
	expiryExtended.ExpiresAt = "2099-01-01T00:00:00Z"

	serverSwapped := clean
	serverSwapped.OrgServerURL = "https://attacker.example"

	signatureStripped := clean
	signatureStripped.Signature = ""

	// A grant that was RENEWED: the working expires_at moved forward but the
	// signed window (what the document carries) did not. The reconstruction
	// uses signed_expires_at, so this must still verify.
	renewed := clean

	// A REPLACEMENT document: signed over a different domain with the
	// replacement generation bound in. It must verify through the same
	// entry point, selected by the row's own ReplacementGeneration.
	repl := GrantReplacement{
		OrgID:        clean.OrgID,
		OrgServerURL: clean.OrgServerURL,
		KeyPinSHA256: clean.KeyPinSHA256,
		Generation:   7,
		Authority:    clean.Authority,
		GrantedAt:    clean.GrantedAt,
		ExpiresAt:    clean.ExpiresAt,
	}
	repl.Signature = SignGrantReplacement(priv, repl)
	replDoc := StoredGrantDocument{
		OrgID: repl.OrgID, OrgServerURL: repl.OrgServerURL, KeyPinSHA256: repl.KeyPinSHA256,
		Authority: repl.Authority, GrantedAt: repl.GrantedAt, ExpiresAt: repl.ExpiresAt,
		Signature: repl.Signature, ReplacementGeneration: repl.Generation,
	}
	// Flipping the generation on a replacement row cannot dodge the check:
	// it just selects the other signing message, which also fails.
	replGenBumped := replDoc
	replGenBumped.ReplacementGeneration = 8
	replAsEnrolment := replDoc
	replAsEnrolment.ReplacementGeneration = 0

	cases := []struct {
		name    string
		doc     StoredGrantDocument
		key     ed25519.PublicKey
		wantErr bool
		// wantUncheckable asserts the honest "could not check" sentinel
		// rather than a tamper verdict.
		wantUncheckable bool
	}{
		{name: "untouched grant verifies", doc: clean, key: pub},
		{name: "renewed grant still verifies against the signed window", doc: renewed, key: pub},
		{name: "replacement document verifies", doc: replDoc, key: pub},
		{name: "authority list widened", doc: authorityRewritten, key: pub, wantErr: true},
		{name: "authority list narrowed", doc: authorityRemoved, key: pub, wantErr: true},
		{name: "signed expiry extended", doc: expiryExtended, key: pub, wantErr: true},
		{name: "org server swapped", doc: serverSwapped, key: pub, wantErr: true},
		{name: "signature stripped", doc: signatureStripped, key: pub, wantErr: true},
		{name: "replacement generation bumped", doc: replGenBumped, key: pub, wantErr: true},
		{name: "replacement relabelled as an enrolment grant", doc: replAsEnrolment, key: pub, wantErr: true},
		{name: "no key material is unchecked, not invalid", doc: clean, key: nil, wantErr: true, wantUncheckable: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := VerifyStoredGrant(tc.doc, tc.key)
			if tc.wantErr && err == nil {
				t.Fatalf("VerifyStoredGrant accepted a document it must refuse")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("VerifyStoredGrant refused a good document: %v", err)
			}
			if tc.wantUncheckable && err != ErrStoredGrantUncheckable { //nolint:errorlint // sentinel identity is the assertion
				t.Fatalf("err = %v, want ErrStoredGrantUncheckable", err)
			}
			if tc.wantErr && !tc.wantUncheckable && err == ErrStoredGrantUncheckable { //nolint:errorlint // sentinel identity is the assertion
				t.Fatalf("a tampered document must never report as uncheckable")
			}
		})
	}
}

// TestStoredGrantSigningMessageMatchesTheSigner pins that the runtime check
// rebuilds EXACTLY the bytes the signer signed, for both document shapes —
// the property that makes a false tamper report impossible when nothing was
// tampered with.
func TestStoredGrantSigningMessageMatchesTheSigner(t *testing.T) {
	_, _, g, doc := storedGrantFixture(t)
	if string(StoredGrantSigningMessage(doc)) != string(EnrolmentGrantSigningMessage(g)) {
		t.Fatal("stored-document signing message diverged from EnrolmentGrantSigningMessage")
	}
	repl := GrantReplacement{
		OrgID: g.OrgID, OrgServerURL: g.OrgServerURL, KeyPinSHA256: g.KeyPinSHA256,
		Generation: 4, Authority: g.Authority, GrantedAt: g.GrantedAt, ExpiresAt: g.ExpiresAt,
	}
	replDoc := StoredGrantDocument{
		OrgID: repl.OrgID, OrgServerURL: repl.OrgServerURL, KeyPinSHA256: repl.KeyPinSHA256,
		Authority: repl.Authority, GrantedAt: repl.GrantedAt, ExpiresAt: repl.ExpiresAt,
		ReplacementGeneration: repl.Generation,
	}
	if string(StoredGrantSigningMessage(replDoc)) != string(GrantReplacementSigningMessage(repl)) {
		t.Fatal("stored-document signing message diverged from GrantReplacementSigningMessage")
	}
}
