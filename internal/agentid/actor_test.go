package agentid

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

const stsURL = "https://auth.acme.superbased.app/oauth2/token"

type fakeReplay struct {
	mu   sync.Mutex
	seen map[string]bool
	err  error
}

func (f *fakeReplay) fn(jti string, _ int64) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return false, f.err
	}
	if f.seen == nil {
		f.seen = map[string]bool{}
	}
	dup := f.seen[jti]
	f.seen[jti] = true
	return dup, nil
}

func actorClaims(jti string) ActorClaims {
	return ActorClaims{
		Iss: "node_m_9b21", Sub: "cred_1", Aud: stsURL, Jti: jti, Iat: t0.Unix(), Exp: t0.Unix() + 60,
		SboMember: "usr_7f3a", SboMachineFP: "fp1", SboCredGen: 2, SboAgent: "agent:claude-code", SboClientAttestation: "process_attested",
	}
}

func expectFor(s Signer) ActorExpect {
	_, pub := s.PublicJWK()
	// CredentialID is set the way the STS sets it (§4.3): the happy path
	// below mints only because sub == the verified credential's id.
	return ActorExpect{Key: pub, Audience: stsURL, Now: t0, Member: "usr_7f3a", MachineFP: "fp1", CredentialID: "cred_1"}
}

func TestActorAssertionRoundTripPerAlg(t *testing.T) {
	for _, alg := range []string{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256} {
		t.Run(alg, func(t *testing.T) {
			s := newSigner(t, alg, "")
			a, err := CreateActorAssertion(s, actorClaims("j1"))
			if err != nil {
				t.Fatal(err)
			}
			kid, err := ActorKeyID(a)
			if err != nil {
				t.Fatal(err)
			}
			_, pub := s.PublicJWK()
			if tp, _ := pub.Thumbprint(); kid != tp {
				t.Fatal("kid must be the agent-access key thumbprint")
			}
			rp := &fakeReplay{}
			c, err := VerifyActorAssertion(a, expectFor(s), rp.fn)
			if err != nil {
				t.Fatal(err)
			}
			if c.KeyThumbprint != kid || c.SboCredGen != 2 || c.SboAgent != "agent:claude-code" {
				t.Fatalf("claims = %+v", c)
			}
		})
	}
}

// TestActorAssertionAdversarial covers doc3 §4.3's named attacks.
func TestActorAssertionAdversarial(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "")
	other := newSigner(t, jose.AlgEdDSA, "")
	ring := ringOf(t, activeEntry(newSigner(t, jose.AlgEdDSA, "k"), "k"))
	accessTok, _, _ := Mint(ring, principal(), testAud, 0, nil, mintOpts())
	mk := func(mut func(*ActorClaims)) string {
		c := actorClaims("j")
		if mut != nil {
			mut(&c)
		}
		a, err := CreateActorAssertion(s, c)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	cases := []struct {
		name   string
		a      string
		expect func(ActorExpect) ActorExpect
		store  *fakeReplay
		want   ActorErrorCode
	}{
		{"wrong-type substitution: an at+jwt as actor", accessTok, nil, nil, ActErrType},
		{"signed by another key (foreign device)", func() string { a, _ := CreateActorAssertion(other, actorClaims("j")); return a }(), nil, nil, ActErrKey},
		{"expired", mk(nil), func(e ActorExpect) ActorExpect { e.Now = t0.Add(2 * time.Minute); return e }, nil, ActErrExpired},
		{"not yet valid", mk(nil), func(e ActorExpect) ActorExpect { e.Now = t0.Add(-time.Minute); return e }, nil, ActErrNotYetValid},
		{"foreign machine", mk(func(c *ActorClaims) { c.SboMachineFP = "fp-other" }), nil, nil, ActErrBinding},
		{"other member", mk(func(c *ActorClaims) { c.SboMember = "usr_x" }), nil, nil, ActErrBinding},
		{"wrong audience", mk(func(c *ActorClaims) { c.Aud = "https://evil/oauth2/token" }), nil, nil, ActErrAudience},
		{"unknown attestation value", mk(func(c *ActorClaims) { c.SboClientAttestation = "trusted" }), nil, nil, ActErrClaims},
		{"node issuer mismatch", mk(nil), func(e ActorExpect) ActorExpect { e.Issuer = "node_other"; return e }, nil, ActErrBinding},
		// Cross-credential subject substitution (§4.3, Sol finding 6): a
		// correctly signed assertion from credential A whose sub names
		// credential B, or arbitrary text, is refused with the closed code.
		{"sub names another credential", mk(func(c *ActorClaims) { c.Sub = "cred_2" }), nil, nil, ActErrSubject},
		{"sub is arbitrary text", mk(func(c *ActorClaims) { c.Sub = "not a credential id" }), nil, nil, ActErrSubject},
		{"sub names the credential in another case", mk(func(c *ActorClaims) { c.Sub = "CRED_1" }), nil, nil, ActErrSubject},
		{"off proof allowlist", mk(nil), func(e ActorExpect) ActorExpect { e.Algs, _ = jose.NewAlgSet(jose.AlgES256); return e }, nil, ActErrAlg},
		{"replay store down fails closed", mk(nil), nil, &fakeReplay{err: errors.New("down")}, ActErrReplayUnavailable},
		{"no registered binding", mk(nil), func(e ActorExpect) ActorExpect { e.MachineFP = ""; return e }, nil, ActErrBinding},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := expectFor(s)
			if tc.expect != nil {
				e = tc.expect(e)
			}
			st := tc.store
			if st == nil {
				st = &fakeReplay{}
			}
			_, err := VerifyActorAssertion(tc.a, e, st.fn)
			if ActorCodeOf(err) != tc.want || !errors.Is(err, ErrInvalidActor) {
				t.Fatalf("err = %v, want %s", err, tc.want)
			}
			if tc.want != ActErrReplayUnavailable && len(st.seen) != 0 {
				t.Fatal("a rejected assertion burned its jti")
			}
		})
	}
	// Lifetime > 60 s can't even be created; a hand-signed one is refused.
	if _, err := CreateActorAssertion(s, func() ActorClaims { c := actorClaims("j"); c.Exp = c.Iat + 120; return c }()); err == nil {
		t.Fatal("120 s assertion created")
	}
	_, pub := s.PublicJWK()
	tp, _ := pub.Thumbprint()
	long, _ := jose.Sign(s, jose.Header{Typ: TypActorAssertion, Alg: jose.AlgEdDSA, Kid: tp},
		[]byte(`{"iss":"n","sub":"c","aud":"`+stsURL+`","jti":"j","iat":1790000000,"exp":1790000120,"sbo_member":"usr_7f3a","sbo_machine_fp":"fp1","sbo_cred_gen":2}`))
	if _, err := VerifyActorAssertion(long, expectFor(s), (&fakeReplay{}).fn); ActorCodeOf(err) != ActErrLifetime {
		t.Fatalf("long lifetime err = %v", err)
	}
	// Missing binding claim.
	nobind, _ := jose.Sign(s, jose.Header{Typ: TypActorAssertion, Alg: jose.AlgEdDSA, Kid: tp},
		[]byte(`{"iss":"n","sub":"c","aud":"`+stsURL+`","jti":"j","iat":1790000000,"exp":1790000060,"sbo_member":"usr_7f3a","sbo_cred_gen":2}`))
	if _, err := VerifyActorAssertion(nobind, expectFor(s), (&fakeReplay{}).fn); ActorCodeOf(err) != ActErrClaims {
		t.Fatalf("missing machine claim err = %v", err)
	}
	// An actor assertion is never accepted as an access token.
	if _, err := VerifyFull(VerifyOptions{}, []JWK{pub}, mk(nil), testAud, testIss, t0); CodeOf(err) != TokErrType {
		t.Fatalf("actor-as-access-token err = %v", err)
	}
}

// TestActorSubjectBinding pins the sub <-> credential binding on its own:
// the same signed assertion is accepted exactly when the expected credential
// id equals its sub, and an expectation with no credential id (a caller with
// no credential table) keeps the pre-existing key-only behaviour.
func TestActorSubjectBinding(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "")
	cases := []struct {
		name   string
		sub    string
		expect string
		want   ActorErrorCode // "" = accepted
	}{
		{"sub equals the verified credential", "cred_1", "cred_1", ""},
		{"sub names another credential", "cred_1", "cred_2", ActErrSubject},
		{"sub names another credential (reversed)", "cred_2", "cred_1", ActErrSubject},
		{"no credential expectation: any sub", "anything", "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := actorClaims("j-" + tc.name)
			c.Sub = tc.sub
			a, err := CreateActorAssertion(s, c)
			if err != nil {
				t.Fatal(err)
			}
			e := expectFor(s)
			e.CredentialID = tc.expect
			st := &fakeReplay{}
			got, err := VerifyActorAssertion(a, e, st.fn)
			if ActorCodeOf(err) != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.want == "" {
				if got.Sub != tc.sub || len(st.seen) != 1 {
					t.Fatalf("accepted assertion: sub=%q seen=%d", got.Sub, len(st.seen))
				}
				return
			}
			if !errors.Is(err, ErrInvalidActor) || len(st.seen) != 0 {
				t.Fatal("a refused substitution must match ErrInvalidActor and never burn its jti")
			}
		})
	}
}

func TestActorReplaySingleUse(t *testing.T) {
	s := newSigner(t, jose.AlgES256, "")
	a, _ := CreateActorAssertion(s, actorClaims("once"))
	shared := &fakeReplay{}
	if _, err := VerifyActorAssertion(a, expectFor(s), shared.fn); err != nil {
		t.Fatal(err)
	}
	// A second STS replica sharing the store refuses the replay.
	if _, err := VerifyActorAssertion(a, expectFor(s), shared.fn); ActorCodeOf(err) != ActErrReplay {
		t.Fatalf("replay err = %v", err)
	}
	if _, err := VerifyActorAssertion(a, expectFor(s), nil); ActorCodeOf(err) != ActErrReplayUnavailable {
		t.Fatalf("nil store err = %v", err)
	}
}

func FuzzVerifyActorAssertion(f *testing.F) {
	s := newSigner(f, jose.AlgEdDSA, "")
	a, _ := CreateActorAssertion(s, actorClaims("j"))
	f.Add(a)
	f.Add("")
	f.Add("x.y.z")
	e := expectFor(s)
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = ActorKeyID(in)
		_, _ = VerifyActorAssertion(in, e, (&fakeReplay{}).fn)
	})
}
