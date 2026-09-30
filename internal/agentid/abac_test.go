package agentid

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

const abacHash = "0123456789abcdef"

func TestValidProjectHash(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want bool
	}{
		{abacHash, true},
		{strings.Repeat("a", 64), true},
		{strings.Repeat("a", 15), false},
		{strings.Repeat("a", 65), false},
		{"0123456789ABCDEF", false}, // upper case: never a canonical hash
		{"0123456789abcdeg", false},
		{"", false},
		{"../../etc/passwd", false},
	} {
		if got := ValidProjectHash(tc.in); got != tc.want {
			t.Errorf("ValidProjectHash(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
	h := ProjectHashOfRoot("/home/dev/src/app")
	if len(h) != 16 || !ValidProjectHash(h) || h != ProjectHashOfRoot("/home/dev/src/app") || h == ProjectHashOfRoot("/home/dev/src/other") {
		t.Fatalf("ProjectHashOfRoot = %q: must be a stable, root-distinct 16-hex hash", h)
	}
	if ProjectHashOfRoot("") != "" {
		t.Fatal("an empty root has no project hash")
	}
}

// TestABACClaimsWire pins the P11(e) claim encoding: sbo_team_ids keeps
// PRESENT-empty ([]) distinct from ABSENT (omitted), both through Mint and
// through a JSON round-trip, and sbo_project_hash rides only when set.
func TestABACClaimsWire(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	jwks, _ := ring.JWKS()
	jkt := strings.Repeat("A", 43)
	for _, tc := range []struct {
		name        string
		teams       []string
		project     string
		wantTeamsIn bool
	}{
		{"roster", []string{"team-a", "team-b"}, abacHash, true},
		{"known empty roster", []string{}, "", true},
		{"absent roster", nil, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := principal()
			p.TeamIDs, p.ProjectHash = tc.teams, tc.project
			o := mintOpts()
			o.Cnf = &Confirmation{JKT: jkt}
			tok, c, err := Mint(ring, p, testAud, 0, nil, o)
			if err != nil {
				t.Fatal(err)
			}
			j, _ := jose.Parse(tok, 0)
			var m map[string]json.RawMessage
			_ = json.Unmarshal(j.Payload, &m)
			raw, present := m["sbo_team_ids"]
			if present != tc.wantTeamsIn {
				t.Fatalf("sbo_team_ids present=%v, want %v (payload %s)", present, tc.wantTeamsIn, j.Payload)
			}
			if tc.teams != nil && len(tc.teams) == 0 && string(raw) != "[]" {
				t.Fatalf("known empty roster must be the empty array, got %s", raw)
			}
			if _, has := m["sbo_project_hash"]; has != (tc.project != "") {
				t.Fatalf("sbo_project_hash present=%v, want %v", has, tc.project != "")
			}
			got, err := VerifyFull(VerifyOptions{}, jwks, tok, testAud, testIss, t0.Add(time.Minute))
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if (got.SboTeamIDs == nil) != (tc.teams == nil) || !reflect.DeepEqual(append([]string{}, got.SboTeamIDs...), append([]string{}, tc.teams...)) {
				t.Fatalf("round-trip roster = %#v, want %#v", got.SboTeamIDs, tc.teams)
			}
			if got.SboProjectHash != tc.project || c.SboProjectHash != tc.project {
				t.Fatalf("round-trip project = %q/%q, want %q", got.SboProjectHash, c.SboProjectHash, tc.project)
			}
		})
	}
}

// TestABACProfileRefusals: VerifyProfile refuses a project label on a token
// that is not relay-originated (the spoof), a malformed hash and an
// over-bound roster; Mint refuses to sign a project for a non-node principal
// or a malformed one, and an over-bound roster.
func TestABACProfileRefusals(t *testing.T) {
	relay := func() Claims {
		return Claims{
			Sub: "usr_1", ClientID: "agent:x", Jti: "j", SboOrg: "acme", Iat: t0.Unix(), Exp: t0.Unix() + 60,
			Act:            &ActClaim{Sub: "agent:x", SboCredAssurance: CredNodeEnrolled, SboClientAttestation: AttestConfigured, Act: &ActClaim{Sub: "node:m1"}},
			Cnf:            &Confirmation{JKT: strings.Repeat("A", 43)},
			SboProjectHash: abacHash, SboTeamIDs: []string{"t1"},
		}
	}
	if err := VerifyProfile(relay(), t0); err != nil {
		t.Fatalf("relay-originated token refused: %v", err)
	}
	for _, tc := range []struct {
		name string
		mut  func(*Claims)
	}{
		{"project on a bearer token (no cnf.jkt)", func(c *Claims) { c.Cnf = nil }},
		{"project on an mTLS-bound token", func(c *Claims) { c.Cnf = &Confirmation{X5TS256: strings.Repeat("B", 43)} }},
		{"project on a token with no node actor (F5 / OBO shape)", func(c *Claims) { c.Act.Act = nil }},
		{"project on a token whose nested actor is not a node", func(c *Claims) { c.Act.Act = &ActClaim{Sub: "agent:other"} }},
		{"malformed project hash", func(c *Claims) { c.SboProjectHash = "Project-X" }},
		{"roster over the bound", func(c *Claims) { c.SboTeamIDs = make([]string, MaxTeamIDs+1); fillTeams(c.SboTeamIDs) }},
		{"empty roster entry", func(c *Claims) { c.SboTeamIDs = []string{""} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := relay()
			tc.mut(&c)
			if err := VerifyProfile(c, t0); CodeOf(err) != TokErrClaims {
				t.Fatalf("VerifyProfile = %v, want %s", err, TokErrClaims)
			}
		})
	}
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	for _, tc := range []struct {
		name string
		mut  func(*Principal)
	}{
		{"project for a non-node principal", func(p *Principal) { p.Node = NodeRef{}; p.ProjectHash = abacHash }},
		{"malformed project", func(p *Principal) { p.ProjectHash = "nope" }},
		{"over-bound roster", func(p *Principal) { p.TeamIDs = make([]string, MaxTeamIDs+1); fillTeams(p.TeamIDs) }},
	} {
		t.Run("mint refuses "+tc.name, func(t *testing.T) {
			p := principal()
			tc.mut(&p)
			if _, _, err := Mint(ring, p, testAud, 0, nil, mintOpts()); err == nil {
				t.Fatal("Mint signed it")
			}
		})
	}
}

func fillTeams(ts []string) {
	for i := range ts {
		ts[i] = "t" + strings.Repeat("x", i%5)
	}
}

// TestActorAssertionProjectHash: the relay signs sbo_project_hash inside its
// actor assertion; a well-formed value round-trips through the STS verifier,
// a malformed one is refused (bad_claims), and absence is legal.
func TestActorAssertionProjectHash(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "")
	for _, tc := range []struct {
		name, hash string
		want       ActorErrorCode
	}{
		{"attested project round-trips", abacHash, ""},
		{"no project context", "", ""},
		{"malformed project refused", "not-a-hash", ActErrClaims},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := actorClaims("j-" + tc.name)
			c.SboProjectHash = tc.hash
			a, err := CreateActorAssertion(s, c)
			if err != nil {
				t.Fatal(err)
			}
			got, err := VerifyActorAssertion(a, expectFor(s), (&fakeReplay{}).fn)
			if ActorCodeOf(err) != tc.want {
				t.Fatalf("verify = %v, want %q", err, tc.want)
			}
			if tc.want == "" && got.SboProjectHash != tc.hash {
				t.Fatalf("attested project = %q, want %q", got.SboProjectHash, tc.hash)
			}
		})
	}
}
