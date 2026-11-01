package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestGrantReportDoesNotPresentAnUnsignedActorAsSigned (Sol A3-03): a
// token-rail grant is signed with NO consent fields, so its stored
// consent_actor is a local annotation the signature never covered. Rewriting
// that actor in the database must not let the grant report present the new
// name as the consent the organization signed. The grant itself stays valid
// (the GRANT-INTEG-2 tolerance is needed for every managed token enrolment);
// what changes is that the report labels the actor as unsigned.
func TestGrantReportDoesNotPresentAnUnsignedActorAsSigned(t *testing.T) {
	ctx := context.Background()
	st, database, orgKey := grantIntegrityFixture(t)
	if _, err := database.ExecContext(ctx,
		`UPDATE org_enrolment_grant SET consent_mode = ?, consent_actor = ? WHERE org_key = ?`,
		govern.ConsentManaged, "ceo@acme.example", orgKey); err != nil {
		t.Fatalf("tamper actor: %v", err)
	}
	grant, live, err := governanceIdentityLoader(st)(ctx)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if grant == nil || grant.Integrity != govern.GrantIntegrityValid {
		t.Fatalf("grant = %+v, want a valid grant (the actor is outside the signature)", grant)
	}

	var out bytes.Buffer
	printGrantShow(&out, grantShowReport{Live: live, Grant: grant}, config.Config{}, "")
	var line string
	for _, ln := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(ln, "Consent:") {
			line = ln
		}
	}
	if line == "" {
		t.Fatalf("no Consent line in:\n%s", out.String())
	}
	if !strings.Contains(line, "not signed by the organization") {
		t.Fatalf("Consent line presents an unsigned actor as signed attribution: %q", line)
	}
}

// TestStoredGrantConsentEvidence pins which consent fields the verifying
// signature actually covered, per rail, and the report wording each yields.
func TestStoredGrantConsentEvidence(t *testing.T) {
	cases := []struct {
		name     string
		mode     string
		actor    string
		signMode string
		signAct  string
		tenancy  string
		want     govern.ConsentEvidence
		wantLine string
	}{
		{"idp rail: mode and actor signed verbatim", govern.ConsentIdP, "a@acme", govern.ConsentIdP, "a@acme", "managed", govern.ConsentEvidenceModeAndActor, "idp (a@acme)"},
		{"enterprise posture: mode signed, actor local", govern.ConsentManaged, "dev", govern.ConsentManaged, "", "managed", govern.ConsentEvidenceMode, "managed; actor dev recorded on this machine, not signed by the organization"},
		{"token rail: nothing signed", govern.ConsentManaged, "dev", "", "", "managed", govern.ConsentEvidenceNone, "managed (from the enrolment type); actor dev recorded on this machine, not signed by the organization"},
		{"token rail: actor rewritten is still only a local annotation", govern.ConsentManaged, "ceo@acme", "", "", "managed", govern.ConsentEvidenceNone, "managed (from the enrolment type); actor ceo@acme recorded on this machine, not signed by the organization"},
		{"idp rail: actor rewritten is tampering", govern.ConsentIdP, "mallory", govern.ConsentIdP, "a@acme", "managed", govern.ConsentEvidenceUnverified, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, pub := signedGrantRow(t, tc.mode, tc.actor, tc.signMode, tc.signAct)
			integrity, ev := storedGrantIntegrity(r, tc.tenancy, pub)
			if ev != tc.want {
				t.Fatalf("evidence = %q (integrity %q), want %q", ev, integrity, tc.want)
			}
			if tc.wantLine == "" {
				return
			}
			g := grantFromStore(r, nil)
			g.Integrity, g.ConsentEvidence = integrity, ev
			if got := grantConsentLine(g); got != tc.wantLine {
				t.Fatalf("consent line = %q, want %q", got, tc.wantLine)
			}
		})
	}
}

// TestGrantConsentLineUnverified: a grant this node could not check labels
// its consent as unverified rather than as the organization's statement.
func TestGrantConsentLineUnverified(t *testing.T) {
	g := &govern.Grant{ConsentMode: govern.ConsentManaged, ConsentActor: "dev"}
	if got, want := grantConsentLine(g), "managed (dev), not verified against the organization signature"; got != want {
		t.Fatalf("consent line = %q, want %q", got, want)
	}
}

// signedGrantRow is a stored grant recording (mode, actor) whose signature
// covers (signMode, signActor), the gap the rails can leave between them.
func signedGrantRow(t *testing.T, mode, actor, signMode, signActor string) (store.EnrolmentGrant, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	granted := time.Date(2026, 10, 3, 4, 0, 0, 0, time.UTC)
	expires := granted.Add(30 * 24 * time.Hour)
	sig := orgcontract.SignEnrolmentGrant(priv, orgcontract.EnrolmentGrant{
		OrgID: "org", OrgServerURL: "http://org", KeyPinSHA256: "pin",
		Authority: []string{"settings.pin"},
		GrantedAt: granted.Format(time.RFC3339), ExpiresAt: expires.Format(time.RFC3339),
		ConsentMode: signMode, ConsentActor: signActor,
	})
	return store.EnrolmentGrant{
		OrgID: "org", OrgServerURL: "http://org", KeyPinSHA256: "pin",
		Authority: []string{"settings.pin"},
		GrantedAt: granted, SignedExpiresAt: expires,
		ConsentMode: mode, ConsentActor: actor, Signature: sig,
	}, pub
}
