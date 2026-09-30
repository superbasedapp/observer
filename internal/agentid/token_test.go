package agentid

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

const (
	testIss = "https://auth.acme.superbased.app"
	testAud = "https://mcp-gw.acme.superbased.app/mcp/gh"
)

var t0 = time.Unix(1790000000, 0)

func newSigner(t testing.TB, alg, kid string) Signer {
	t.Helper()
	var (
		k   crypto.Signer
		err error
	)
	if alg == jose.AlgRS256 {
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		k, err = jose.GenerateKey(rand.Reader, alg)
	}
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewKeySigner(k, kid)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func ringOf(t testing.TB, entries ...RingEntry) *StaticRing {
	t.Helper()
	r, err := NewStaticRing(entries)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func activeEntry(s Signer, kid string) RingEntry {
	_, pub := s.PublicJWK()
	return RingEntry{Kid: kid, State: KeyActive, Public: pub, Signer: s}
}

func publicEntry(s Signer, kid string, st KeyState) RingEntry {
	_, pub := s.PublicJWK()
	return RingEntry{Kid: kid, State: st, Public: pub}
}

func principal() Principal {
	return Principal{
		User:              UserRef{ID: "usr_7f3a"},
		Agent:             AgentRef{ID: "ad_1", ClientID: "agent:claude-code", Kind: "coding_agent", Product: "claude-code"},
		Node:              NodeRef{ID: "m_9b21", MachineFP: "fp1"},
		Org:               "acme",
		Posture:           "enterprise",
		Groups:            []string{"eng"},
		CredAssurance:     CredNodeEnrolled,
		ClientAttestation: AttestProcessAttested,
	}
}

func mintOpts() MintOptions {
	return MintOptions{Issuer: testIss, Now: t0, Gens: Generations{Member: 7, Cred: 2, Policy: 41, IssuerEpoch: 3}, Session: "sess_4d"}
}

// TestMintVerifyPerAlgorithm is the R8.23.m/B9 roundtrip for every
// allowlisted algorithm, plus the header/claim shape of doc3 §6.3.
func TestMintVerifyPerAlgorithm(t *testing.T) {
	for _, alg := range []string{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256} {
		t.Run(alg, func(t *testing.T) {
			s := newSigner(t, alg, "ask_a")
			ring := ringOf(t, activeEntry(s, "ask_a"))
			o := mintOpts()
			o.Cnf = &Confirmation{JKT: strings.Repeat("A", 43)}
			tok, c, err := Mint(ring, principal(), testAud, 0, nil, o)
			if err != nil {
				t.Fatal(err)
			}
			j, _ := jose.Parse(tok, 0)
			if j.Header.Typ != "at+jwt" || j.Header.Alg != alg || j.Header.Kid != "ask_a" {
				t.Fatalf("header = %+v", j.Header)
			}
			if c.Exp-c.Iat != 300 || c.SboSender != SenderDPoP || c.Act.SboCredAssurance != CredNodeEnrolled ||
				c.Act.Act == nil || c.Act.Act.Sub != "node:m_9b21" || c.ClientID != "agent:claude-code" {
				t.Fatalf("claims = %+v", c)
			}
			jwks, _ := ring.JWKS()
			got, err := VerifyFull(VerifyOptions{}, jwks, tok, testAud, testIss, t0.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if got.Sub != "usr_7f3a" || got.SboIssuerEpoch != 3 || got.Cnf.JKT != o.Cnf.JKT {
				t.Fatalf("verified = %+v", got)
			}
			// No MFA claims ever inferred (R6).
			var m map[string]any
			_ = json.Unmarshal(j.Payload, &m)
			for _, k := range []string{"amr", "acr", "auth_time"} {
				if _, ok := m[k]; ok {
					t.Fatalf("%s present without a fresh assertion", k)
				}
			}
		})
	}
}

func TestBearerIsDefault(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	tok, c, err := Mint(ring, principal(), testAud, 0, nil, mintOpts())
	if err != nil {
		t.Fatal(err)
	}
	if c.Cnf != nil || c.SboSender != SenderBearer {
		t.Fatalf("default token must be bearer: %+v", c)
	}
	if strings.Contains(tok, "cnf") {
		t.Fatal("unexpected cnf")
	}
}

func TestTTLBounds(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	for _, tc := range []struct {
		ttl, max time.Duration
		want     int64
	}{
		{0, 0, 300},
		{10 * time.Minute, 0, 600},
		{2 * time.Hour, 0, 3600},
		{30 * time.Minute, 15 * time.Minute, 900},
		{30 * time.Minute, 5 * time.Hour, 1800},
	} {
		o := mintOpts()
		o.MaxTTL = tc.max
		_, c, err := Mint(ring, principal(), testAud, tc.ttl, nil, o)
		if err != nil || c.Exp-c.Iat != tc.want {
			t.Errorf("ttl %s max %s -> %d (%v), want %d", tc.ttl, tc.max, c.Exp-c.Iat, err, tc.want)
		}
	}
}

func TestM2MSubIsAgent(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	p := principal()
	p.User = UserRef{}
	p.Node = NodeRef{}
	p.CredAssurance = CredWorkloadBound
	_, c, err := Mint(ring, p, testAud, 0, nil, mintOpts())
	if err != nil || c.Sub != "ad_1" || c.Act.Act != nil {
		t.Fatalf("m2m claims = %+v %v", c, err)
	}
}

func TestVerifyRejects(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k1")
	ring := ringOf(t, activeEntry(s, "k1"))
	jwks, _ := ring.JWKS()
	tok, _, err := Mint(ring, principal(), testAud, 0, nil, mintOpts())
	if err != nil {
		t.Fatal(err)
	}
	signRaw := func(h jose.Header, payload string) string {
		out, err := jose.Sign(s, h, []byte(payload))
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	_, c, _ := Mint(ring, principal(), testAud, 0, nil, mintOpts())
	claimsWith := func(mut func(map[string]any)) string {
		raw, _ := json.Marshal(c)
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		mut(m)
		out, _ := json.Marshal(m)
		return string(out)
	}
	esOnly, _ := jose.NewAlgSet(jose.AlgES256)
	cases := []struct {
		name string
		tok  string
		aud  string
		opts VerifyOptions
		now  time.Time
		want TokenErrorCode
	}{
		{"wrong aud", tok, "https://mcp-gw.acme.superbased.app/mcp/other", VerifyOptions{}, t0, TokErrAudience},
		{"expired", tok, testAud, VerifyOptions{}, t0.Add(301 * time.Second), TokErrExpired},
		{"expired exactly at exp (no 60s leeway)", tok, testAud, VerifyOptions{}, t0.Add(300 * time.Second), TokErrExpired},
		{"off-allowlist alg", tok, testAud, VerifyOptions{Algs: esOnly}, t0, TokErrAlg},
		{"typ sbo-actor+jwt", signRaw(jose.Header{Typ: TypActorAssertion, Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(map[string]any) {})), testAud, VerifyOptions{}, t0, TokErrType},
		{"typ sbo-internal+jwt (hop token)", signRaw(jose.Header{Typ: "sbo-internal+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(map[string]any) {})), testAud, VerifyOptions{}, t0, TokErrType},
		{"typ JWT", signRaw(jose.Header{Typ: "JWT", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(map[string]any) {})), testAud, VerifyOptions{}, t0, TokErrType},
		{"no typ", signRaw(jose.Header{Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(map[string]any) {})), testAud, VerifyOptions{}, t0, TokErrType},
		{"unknown kid", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "nope"}, claimsWith(func(map[string]any) {})), testAud, VerifyOptions{}, t0, TokErrUnknownKID},
		{"multi audience", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { m["aud"] = []string{testAud, "https://x"} })), testAud, VerifyOptions{}, t0, TokErrClaims},
		{"single-element aud array accepted", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { m["aud"] = []string{testAud} })), testAud, VerifyOptions{}, t0, ""},
		{"missing generation claim", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { delete(m, "sbo_issuer_epoch") })), testAud, VerifyOptions{}, t0, TokErrClaims},
		{"missing client_id", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { delete(m, "client_id") })), testAud, VerifyOptions{}, t0, TokErrClaims},
		{"unknown assurance enum", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) {
			m["act"].(map[string]any)["sbo_cred_assurance"] = "attested_node"
		})), testAud, VerifyOptions{}, t0, TokErrClaims},
		{"sbo_sender dpop without cnf", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { m["sbo_sender"] = "dpop" })), testAud, VerifyOptions{}, t0, TokErrClaims},
		{"lifetime over 60 min", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { m["exp"] = c.Iat + 7200 })), testAud, VerifyOptions{}, t0, TokErrClaims},
		{"iat in the future", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { m["iat"] = c.Iat + 60; m["exp"] = c.Iat + 300 })), testAud, VerifyOptions{}, t0, TokErrNotYetValid},
		{"wrong issuer", signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, claimsWith(func(m map[string]any) { m["iss"] = "https://auth.acme.superbased.app/o/acme" })), testAud, VerifyOptions{}, t0, TokErrIssuer},
		{"duplicate claim", func() string {
			raw := strings.Replace(claimsWith(func(map[string]any) {}), `"aud":`, `"aud":"x","aud":`, 1)
			return signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1"}, raw)
		}(), testAud, VerifyOptions{}, t0, TokErrMalformed},
		{"embedded jwk refused", func() string {
			_, pub := s.PublicJWK()
			pub = pub.PublicOnly()
			return signRaw(jose.Header{Typ: "at+jwt", Alg: jose.AlgEdDSA, Kid: "k1", JWK: &pub}, claimsWith(func(map[string]any) {}))
		}(), testAud, VerifyOptions{}, t0, TokErrMalformed},
		{"alg none", func() string {
			h, _ := json.Marshal(map[string]string{"typ": "at+jwt", "alg": "none", "kid": "k1"})
			return b64(h) + "." + b64([]byte(claimsWith(func(map[string]any) {}))) + "." + b64([]byte("x"))
		}(), testAud, VerifyOptions{}, t0, TokErrAlg},
		{"HS256 with the public key as secret", func() string {
			h, _ := json.Marshal(map[string]string{"typ": "at+jwt", "alg": "HS256", "kid": "k1"})
			return b64(h) + "." + b64([]byte(claimsWith(func(map[string]any) {}))) + "." + b64([]byte("forged-mac"))
		}(), testAud, VerifyOptions{}, t0, TokErrAlg},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyFull(tc.opts, jwks, tc.tok, tc.aud, testIss, tc.now)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if CodeOf(err) != tc.want || !errors.Is(err, ErrInvalidToken) {
				t.Fatalf("err = %v, want %s", err, tc.want)
			}
		})
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// TestKidRotationOverlap: a token minted by the old key keeps verifying while
// that key is RETIRING (published), and stops once RETIRED.
func TestKidRotationOverlap(t *testing.T) {
	k1 := newSigner(t, jose.AlgEdDSA, "k1")
	k2 := newSigner(t, jose.AlgES256, "k2")
	before := ringOf(t, activeEntry(k1, "k1"), publicEntry(k2, "k2", KeyPending))
	jwksBefore, _ := before.JWKS()
	if len(jwksBefore) != 2 {
		t.Fatalf("pending key must be published: %d", len(jwksBefore))
	}
	old, _, err := Mint(before, principal(), testAud, 0, nil, mintOpts())
	if err != nil {
		t.Fatal(err)
	}
	during := ringOf(t, publicEntry(k1, "k1", KeyRetiring), activeEntry(k2, "k2"))
	jwksDuring, _ := during.JWKS()
	fresh, _, err := Mint(during, principal(), testAud, 0, nil, mintOpts())
	if err != nil {
		t.Fatal(err)
	}
	for _, tok := range []string{old, fresh} {
		if _, err := VerifyFull(VerifyOptions{}, jwksDuring, tok, testAud, testIss, t0); err != nil {
			t.Fatalf("overlap verify: %v", err)
		}
	}
	after := ringOf(t, publicEntry(k1, "k1", KeyRetired), activeEntry(k2, "k2"))
	jwksAfter, _ := after.JWKS()
	if _, err := VerifyFull(VerifyOptions{}, jwksAfter, old, testAud, testIss, t0); CodeOf(err) != TokErrUnknownKID {
		t.Fatalf("retired key err = %v", err)
	}
}

func TestStaticRingInvariants(t *testing.T) {
	a := newSigner(t, jose.AlgEdDSA, "a")
	b := newSigner(t, jose.AlgEdDSA, "b")
	if _, err := NewStaticRing([]RingEntry{activeEntry(a, "a"), activeEntry(b, "b")}); err == nil {
		t.Error("two active keys accepted")
	}
	e := activeEntry(a, "a")
	e.Signer = nil
	if _, err := NewStaticRing([]RingEntry{e}); err == nil {
		t.Error("active without signer accepted")
	}
	e = activeEntry(a, "a")
	_, e.Public = b.PublicJWK()
	if _, err := NewStaticRing([]RingEntry{e}); err == nil {
		t.Error("active signer/public mismatch accepted")
	}
	if _, err := NewStaticRing([]RingEntry{publicEntry(a, "x", KeyPending), publicEntry(b, "x", KeyRetiring)}); err == nil {
		t.Error("duplicate kid accepted")
	}
	empty := ringOf(t)
	if _, _, err := empty.Active(); !errors.Is(err, ErrNoActiveKey) {
		t.Error("empty ring must have no active key")
	}
	if _, _, err := Mint(empty, principal(), testAud, 0, nil, mintOpts()); err == nil {
		t.Error("mint on an empty ring must fail")
	}
}

// TestUnknownKidSingleRefetch: a miss refetches exactly once; a second miss
// inside the interval does not refetch; after the interval it may again.
func TestUnknownKidSingleRefetch(t *testing.T) {
	k1 := newSigner(t, jose.AlgEdDSA, "k1")
	k2 := newSigner(t, jose.AlgEdDSA, "k2")
	served := ringOf(t, activeEntry(k1, "k1"))
	now := t0
	cache := &JWKSCache{
		Fetch:              func(context.Context) ([]JWK, error) { return served.JWKS() },
		MinRefetchInterval: 30 * time.Second,
		Now:                func() time.Time { return now },
	}
	ctx := context.Background()
	if _, err := cache.KeyForKID(ctx, "k1"); err != nil || cache.Fetches() != 1 {
		t.Fatalf("initial: %v fetches=%d", err, cache.Fetches())
	}
	// Rotation happens server-side; a token under k2 arrives.
	served = ringOf(t, publicEntry(k1, "k1", KeyRetiring), activeEntry(k2, "k2"))
	now = now.Add(time.Minute)
	if _, err := cache.KeyForKID(ctx, "k2"); err != nil || cache.Fetches() != 2 {
		t.Fatalf("refetch on miss: %v fetches=%d", err, cache.Fetches())
	}
	if _, err := cache.KeyForKID(ctx, "bogus"); CodeOf(err) != TokErrUnknownKID || cache.Fetches() != 2 {
		t.Fatalf("rate-limited miss: %v fetches=%d", err, cache.Fetches())
	}
	now = now.Add(31 * time.Second)
	if _, err := cache.KeyForKID(ctx, "bogus"); CodeOf(err) != TokErrUnknownKID || cache.Fetches() != 3 {
		t.Fatalf("second miss after interval: %v fetches=%d", err, cache.Fetches())
	}
	tok, _, _ := Mint(served, principal(), testAud, 0, nil, mintOpts())
	if _, err := cache.VerifyToken(ctx, VerifyOptions{}, tok, testAud, testIss, t0); err != nil {
		t.Fatal(err)
	}
}

func TestGenerationFloor(t *testing.T) {
	c := Claims{SboMemberGen: 7, SboCredGen: 2, SboPolicyGen: 41, SboIssuerEpoch: 3}
	for _, tc := range []struct {
		name  string
		floor GenerationFloor
		ok    bool
	}{
		{"at floor", GenerationFloor{7, 2, 41, 3}, true},
		{"below member", GenerationFloor{Member: 8}, false},
		{"below cred", GenerationFloor{Cred: 3}, false},
		{"below policy", GenerationFloor{Policy: 42}, false},
		{"below issuer epoch", GenerationFloor{IssuerEpoch: 4}, false},
		{"zero floor", GenerationFloor{}, true},
	} {
		err := CheckGenerations(c, tc.floor)
		if (err == nil) != tc.ok || (!tc.ok && CodeOf(err) != TokErrGenerationStale) {
			t.Errorf("%s: err = %v", tc.name, err)
		}
	}
}

func TestSizeBudgetReferenceGrant(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	var grants []GrantDetail
	for i := 0; i < 200; i++ {
		grants = append(grants, GrantDetail{Type: "sbo_mcp_tool", Identifier: strings.Repeat("t", 30), Locations: []string{testAud}, Actions: []string{"call"}})
	}
	tok, c, err := Mint(ring, principal(), testAud, 0, grants, mintOpts())
	if err != nil {
		t.Fatal(err)
	}
	if len(tok) > AccessTokenTargetBytes {
		t.Fatalf("token %d bytes over target", len(tok))
	}
	want, _ := GrantSetDigest(grants)
	if len(c.AuthorizationDetails) != 1 || c.AuthorizationDetails[0].Type != GrantDetailTypeReference || c.AuthorizationDetails[0].Identifier != want {
		t.Fatalf("details = %+v", c.AuthorizationDetails)
	}
	// Small grant sets stay inline.
	_, c2, _ := Mint(ring, principal(), testAud, 0, grants[:1], mintOpts())
	if c2.AuthorizationDetails[0].Type != "sbo_mcp_tool" {
		t.Fatal("small grant set should stay inline")
	}
	// Groups are bounded.
	p := principal()
	p.Groups = make([]string, MaxGroups+1)
	if _, _, err := Mint(ring, p, testAud, 0, nil, mintOpts()); err == nil {
		t.Fatal("unbounded groups accepted")
	}
	if err := CheckHeaderBudget("DPoP "+tok, strings.Repeat("p", 4000)); err != nil {
		t.Fatalf("worst-case header budget: %v", err)
	}
	if err := CheckHeaderBudget(strings.Repeat("a", 5000), strings.Repeat("p", 4000)); err == nil {
		t.Fatal("8 KiB ceiling not enforced")
	}
}

func TestMintRequiresInputs(t *testing.T) {
	s := newSigner(t, jose.AlgEdDSA, "k")
	ring := ringOf(t, activeEntry(s, "k"))
	mut := []func(*Principal, *MintOptions, *string){
		func(_ *Principal, o *MintOptions, _ *string) { o.Issuer = "" },
		func(_ *Principal, _ *MintOptions, aud *string) { *aud = "" },
		func(p *Principal, _ *MintOptions, _ *string) { p.Agent.ClientID = "" },
		func(p *Principal, _ *MintOptions, _ *string) { p.Org = "" },
		func(p *Principal, _ *MintOptions, _ *string) { p.CredAssurance = CredUnknown },
		func(_ *Principal, o *MintOptions, _ *string) { o.Cnf = &Confirmation{} },
		func(_ *Principal, o *MintOptions, _ *string) { o.Cnf = &Confirmation{JKT: "a", X5TS256: "b"} },
	}
	for i, m := range mut {
		p, o, aud := principal(), mintOpts(), testAud
		m(&p, &o, &aud)
		if _, _, err := Mint(ring, p, aud, 0, nil, o); err == nil {
			t.Errorf("mutation %d accepted", i)
		}
	}
}

func TestEnumsRankAndExpand(t *testing.T) {
	if got := AcceptedCredAssurances(CredSharedSecret); strings.Join(got, ",") != "hardware_bound,node_enrolled,workload_bound,shared_secret" {
		t.Fatalf("cred expansion = %v", got)
	}
	if got := AcceptedClientAttestations(AttestIPCBound); strings.Join(got, ",") != "process_attested,ipc_bound" {
		t.Fatalf("attest expansion = %v", got)
	}
	if AttestConfigured.ProductScoped() || !AttestIPCBound.ProductScoped() || AttestClaimed.ProductScoped() {
		t.Fatal("product-scoped threshold wrong")
	}
	if _, err := ParseCredentialAssurance("attested_node"); err == nil {
		t.Fatal("attested_node is not a v1 assurance (finding-10)")
	}
	for c := CredClaimed; c <= CredHardwareBound; c++ {
		back, err := ParseCredentialAssurance(c.String())
		if err != nil || back != c {
			t.Fatalf("roundtrip %v", c)
		}
	}
	if _, err := CredUnknown.MarshalText(); err == nil {
		t.Fatal("zero enum marshalled")
	}
}

func FuzzVerifyAccessToken(f *testing.F) {
	s, _ := NewKeySigner(func() crypto.Signer { k, _ := jose.GenerateKey(rand.Reader, jose.AlgEdDSA); return k }(), "k")
	ring, _ := NewStaticRing([]RingEntry{{Kid: "k", State: KeyActive, Public: func() JWK { _, p := s.PublicJWK(); return p }(), Signer: s}})
	tok, _, _ := Mint(ring, principal(), testAud, 0, nil, mintOpts())
	jwks, _ := ring.JWKS()
	f.Add(tok)
	f.Add("")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, in string) {
		c, err := VerifyFull(VerifyOptions{}, jwks, in, testAud, testIss, t0)
		if err == nil && c.Aud != testAud {
			t.Fatalf("accepted a token for aud %q", c.Aud)
		}
		_, _ = TokenKID(in)
	})
}
