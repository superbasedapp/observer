package agentid

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// TestTeamOverflowClaim (P11 fold PF2, IE Q-IE-3): a member whose roster is
// over MaxTeamIDs is minted WITHOUT sbo_team_ids and WITH sbo_team_overflow
// (never a failed mint); the marker round-trips through Mint + VerifyFull;
// the mint refuses a principal carrying both, and VerifyProfile refuses a
// token carrying both. The claim is presence-typed: any value decodes as an
// overflow (the fail-closed reading agentgateway's has() also takes).
func TestTeamOverflowClaim(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	jwks, _ := ring.JWKS()

	p := principal()
	p.TeamIDs, p.TeamsOverflow = nil, true
	tok, c, err := Mint(ring, p, testAud, 0, nil, mintOpts())
	if err != nil {
		t.Fatalf("an overflowed roster failed the mint: %v", err)
	}
	if !c.SboTeamOverflow || c.SboTeamIDs != nil {
		t.Fatalf("minted claims overflow=%v teams=%#v, want overflow and no roster", c.SboTeamOverflow, c.SboTeamIDs)
	}
	j, _ := jose.Parse(tok, 0)
	var m map[string]json.RawMessage
	_ = json.Unmarshal(j.Payload, &m)
	if string(m["sbo_team_overflow"]) != "true" {
		t.Fatalf("sbo_team_overflow on the wire = %s, want true (payload %s)", m["sbo_team_overflow"], j.Payload)
	}
	if _, has := m["sbo_team_ids"]; has {
		t.Fatalf("an overflowed token carries sbo_team_ids: %s", j.Payload)
	}
	got, err := VerifyFull(VerifyOptions{}, jwks, tok, testAud, testIss, t0.Add(time.Minute))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !got.SboTeamOverflow || got.SboTeamIDs != nil {
		t.Fatalf("verified overflow=%v teams=%#v", got.SboTeamOverflow, got.SboTeamIDs)
	}

	// A normal roster never carries the marker.
	p2 := principal()
	p2.TeamIDs = []string{"t1"}
	tok2, _, err := Mint(ring, p2, testAud, 0, nil, mintOpts())
	if err != nil {
		t.Fatal(err)
	}
	j2, _ := jose.Parse(tok2, 0)
	if strings.Contains(string(j2.Payload), "sbo_team_overflow") {
		t.Fatalf("a bounded roster carries the overflow marker: %s", j2.Payload)
	}

	// Mint refuses both together (a token with both would read as trusted).
	both := principal()
	both.TeamIDs, both.TeamsOverflow = []string{"t1"}, true
	if _, _, err := Mint(ring, both, testAud, 0, nil, mintOpts()); err == nil {
		t.Fatal("Mint signed a roster beside the overflow marker")
	}
	empty := principal()
	empty.TeamIDs, empty.TeamsOverflow = []string{}, true
	if _, _, err := Mint(ring, empty, testAud, 0, nil, mintOpts()); err == nil {
		t.Fatal("Mint signed a known-empty roster beside the overflow marker")
	}

	// VerifyProfile refuses a token carrying both.
	c2 := got
	c2.SboTeamIDs = []string{}
	if err := VerifyProfile(c2, t0); CodeOf(err) != TokErrClaims {
		t.Fatalf("VerifyProfile(overflow + roster) = %v, want %s", err, TokErrClaims)
	}

	// Presence-typed decode: an explicit false still reads as overflow.
	var dec Claims
	if err := json.Unmarshal([]byte(`{"iss":"i","sub":"s","aud":"a","client_id":"c","sbo_org":"o","sbo_member_gen":0,"sbo_cred_gen":0,"sbo_policy_gen":0,"sbo_issuer_epoch":0,"jti":"j","iat":1,"exp":2,"sbo_team_overflow":false}`), &dec); err != nil {
		t.Fatal(err)
	}
	if !dec.SboTeamOverflow {
		t.Fatal("a present sbo_team_overflow (even false) must decode as overflow")
	}
	if err := json.Unmarshal([]byte(`{"iss":"i","sub":"s","aud":"a","client_id":"c","sbo_org":"o","sbo_member_gen":0,"sbo_cred_gen":0,"sbo_policy_gen":0,"sbo_issuer_epoch":0,"jti":"j","iat":1,"exp":2}`), &dec); err != nil {
		t.Fatal(err)
	}
	if dec.SboTeamOverflow {
		t.Fatal("an absent sbo_team_overflow decoded as overflow")
	}
}
