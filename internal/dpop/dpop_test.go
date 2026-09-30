package dpop

import (
	"context"
	"crypto"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
)

// sharedReplay is a fake of the SHARED dpop_replay store (one instance used
// by several verifier "replicas").
type sharedReplay struct {
	mu   sync.Mutex
	seen map[string]int64
	err  error
}

func newShared() *sharedReplay { return &sharedReplay{seen: map[string]int64{}} }

func (s *sharedReplay) InsertIfAbsent(_ context.Context, org, jti string, exp int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	k := org + "\x00" + jti
	if _, ok := s.seen[k]; ok {
		return false, nil
	}
	s.seen[k] = exp
	return true, nil
}

// replica is one verifier process: it owns nothing but a handle to the
// shared store (no per-process cache).
type replica struct{ rs ReplayStore }

func (r replica) verify(proof string, e Expect, now time.Time) (string, error) {
	return Verify(context.Background(), proof, e, r.rs, now)
}

var t0 = time.Unix(1790000000, 0)

const (
	tokURL = "https://auth.acme.superbased.app/oauth2/token"
	resURL = "https://mcp-gw.acme.superbased.app/mcp/gh"
	accTok = "header.payload.sig"
)

func key(t testing.TB, alg string) crypto.Signer {
	t.Helper()
	s, err := jose.GenerateKey(rand.Reader, alg)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func jktOf(t testing.TB, s crypto.Signer, alg string) string {
	t.Helper()
	k, _ := jose.PublicJWK(s.Public(), alg, "")
	tp, _ := k.Thumbprint()
	return tp
}

func TestRoundTripBothProfilesPerAlg(t *testing.T) {
	for _, alg := range []string{jose.AlgEdDSA, jose.AlgES256, jose.AlgRS256} {
		t.Run(alg, func(t *testing.T) {
			s := key(t, alg)
			rs := newShared()
			p, err := Create(s, alg, "POST", tokURL, "", "", t0)
			if err != nil {
				t.Fatal(err)
			}
			jkt, err := Verify(context.Background(), p, Expect{HTM: "POST", HTU: tokURL, Profile: ProfileTokenEndpoint, Org: "o"}, rs, t0)
			if err != nil {
				t.Fatalf("token-endpoint: %v", err)
			}
			if jkt != jktOf(t, s, alg) {
				t.Fatal("jkt mismatch")
			}
			p2, err := Create(s, alg, "POST", resURL, ATH(accTok), "", t0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := Verify(context.Background(), p2, Expect{HTM: "POST", HTU: resURL, ATH: ATH(accTok), JKT: jkt, Org: "o"}, rs, t0); err != nil {
				t.Fatalf("resource: %v", err)
			}
		})
	}
}

// TestReplayAcrossReplicas: the same proof presented to two replicas sharing
// the store is accepted exactly once (finding-8).
func TestReplayAcrossReplicas(t *testing.T) {
	s := key(t, jose.AlgEdDSA)
	shared := newShared()
	a, b := replica{shared}, replica{shared}
	p, _ := Create(s, jose.AlgEdDSA, "POST", tokURL, "", "", t0)
	e := Expect{HTM: "POST", HTU: tokURL, Profile: ProfileTokenEndpoint, Org: "o"}
	if _, err := a.verify(p, e, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := b.verify(p, e, t0.Add(time.Second)); CodeOf(err) != ErrCodeReplay {
		t.Fatalf("second replica err = %v, want replay", err)
	}
	// The same jti under ANOTHER org is a different key space.
	e2 := e
	e2.Org = "other"
	if _, err := b.verify(p, e2, t0); err != nil {
		t.Fatalf("other org: %v", err)
	}
}

func TestReplayStoreFailClosed(t *testing.T) {
	s := key(t, jose.AlgEdDSA)
	p, _ := Create(s, jose.AlgEdDSA, "POST", tokURL, "", "", t0)
	e := Expect{HTM: "POST", HTU: tokURL, Profile: ProfileTokenEndpoint, Org: "o"}
	if _, err := Verify(context.Background(), p, e, nil, t0); CodeOf(err) != ErrCodeReplayUnavailable {
		t.Fatalf("nil store err = %v", err)
	}
	broken := newShared()
	broken.err = errors.New("pg down")
	if _, err := Verify(context.Background(), p, e, broken, t0); CodeOf(err) != ErrCodeReplayUnavailable {
		t.Fatalf("erroring store err = %v", err)
	}
}

// TestInvalidProofDoesNotBurnJTI: a proof that fails a check never reaches
// the replay store.
func TestInvalidProofDoesNotBurnJTI(t *testing.T) {
	s := key(t, jose.AlgEdDSA)
	rs := newShared()
	p, _ := Create(s, jose.AlgEdDSA, "POST", tokURL, "", "", t0)
	if _, err := Verify(context.Background(), p, Expect{HTM: "GET", HTU: tokURL, Profile: ProfileTokenEndpoint, Org: "o"}, rs, t0); err == nil {
		t.Fatal("expected htm failure")
	}
	if len(rs.seen) != 0 {
		t.Fatal("a rejected proof burned its jti")
	}
}

func TestVerifyRejectsTable(t *testing.T) {
	s := key(t, jose.AlgES256)
	other := key(t, jose.AlgES256)
	good := func() string { p, _ := Create(s, jose.AlgES256, "POST", resURL, ATH(accTok), "", t0); return p }
	base := Expect{HTM: "POST", HTU: resURL, ATH: ATH(accTok), Org: "o"}
	edOnly, _ := jose.NewAlgSet(jose.AlgEdDSA)
	cases := []struct {
		name  string
		proof func() string
		e     func(Expect) Expect
		now   time.Time
		want  ErrorCode
	}{
		{"htm mismatch", good, func(e Expect) Expect { e.HTM = "GET"; return e }, t0, ErrCodeHTM},
		{"htu mismatch", good, func(e Expect) Expect { e.HTU = "https://mcp-gw.acme.superbased.app/mcp/other"; return e }, t0, ErrCodeHTU},
		{"ath missing (resource profile)", func() string { p, _ := Create(s, jose.AlgES256, "POST", resURL, "", "", t0); return p }, nil, t0, ErrCodeATH},
		{"ath mismatch", good, func(e Expect) Expect { e.ATH = ATH("other"); return e }, t0, ErrCodeATH},
		{"thumbprint mismatch", good, func(e Expect) Expect { e.JKT = jktOf(t, other, jose.AlgES256); return e }, t0, ErrCodeJKT},
		{"stale iat", good, nil, t0.Add(2 * time.Minute), ErrCodeIATStale},
		{"future iat", good, nil, t0.Add(-time.Minute), ErrCodeIATFuture},
		{"off-allowlist alg", good, func(e Expect) Expect { e.Algs = edOnly; return e }, t0, ErrCodeAlg},
		{"wrong typ", func() string {
			jwk, _ := jose.PublicJWK(s.Public(), jose.AlgES256, "")
			jwk = jwk.PublicOnly()
			p, _ := jose.Sign(s, jose.Header{Typ: "at+jwt", Alg: jose.AlgES256, JWK: &jwk}, []byte(`{"jti":"j","htm":"POST","htu":"`+resURL+`","iat":1790000000}`))
			return p
		}, nil, t0, ErrCodeType},
		{"no embedded jwk", func() string {
			p, _ := jose.Sign(s, jose.Header{Typ: Typ, Alg: jose.AlgES256}, []byte(`{"jti":"j","htm":"POST","htu":"`+resURL+`","iat":1790000000}`))
			return p
		}, nil, t0, ErrCodeMalformed},
		{"jwk is not the signing key", func() string {
			jwk, _ := jose.PublicJWK(other.Public(), jose.AlgES256, "")
			jwk = jwk.PublicOnly()
			p, _ := jose.Sign(s, jose.Header{Typ: Typ, Alg: jose.AlgES256, JWK: &jwk}, []byte(`{"jti":"j","htm":"POST","htu":"`+resURL+`","iat":1790000000,"ath":"`+ATH(accTok)+`"}`))
			return p
		}, nil, t0, ErrCodeSignature},
		{"missing jti", func() string {
			jwk, _ := jose.PublicJWK(s.Public(), jose.AlgES256, "")
			jwk = jwk.PublicOnly()
			p, _ := jose.Sign(s, jose.Header{Typ: Typ, Alg: jose.AlgES256, JWK: &jwk}, []byte(`{"htm":"POST","htu":"`+resURL+`","iat":1790000000,"ath":"`+ATH(accTok)+`"}`))
			return p
		}, nil, t0, ErrCodeClaims},
		{"garbage", func() string { return "not.a.proof" }, nil, t0, ErrCodeMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := base
			if tc.e != nil {
				e = tc.e(base)
			}
			_, err := Verify(context.Background(), tc.proof(), e, newShared(), tc.now)
			if CodeOf(err) != tc.want {
				t.Fatalf("err = %v, want %s", err, tc.want)
			}
			if !errors.Is(err, ErrInvalidProof) || OAuthError(err) != "invalid_dpop_proof" {
				t.Fatalf("external mapping wrong for %v", err)
			}
		})
	}
}

// TestProfileATHTable pins R8.23.j for BOTH profiles (Sol finding 7): the
// token-endpoint profile has NO ath - a proof carrying one (resource-shaped
// or arbitrary) is refused, whatever the caller put in Expect.ATH - while
// the resource profile requires an exact ath match. A refused proof never
// burns its jti and maps to invalid_dpop_proof externally.
func TestProfileATHTable(t *testing.T) {
	s := key(t, jose.AlgEdDSA)
	cases := []struct {
		name      string
		profile   Profile
		proofATH  string // ath claim signed into the proof ("" = absent)
		expectATH string // Expect.ATH
		want      ErrorCode
	}{
		// token endpoint: ath absent -> ok; present -> refused.
		{"token-endpoint: ath absent", ProfileTokenEndpoint, "", "", ""},
		{"token-endpoint: ath present (resource-shaped proof)", ProfileTokenEndpoint, ATH(accTok), "", ErrCodeATH},
		{"token-endpoint: ath present (arbitrary)", ProfileTokenEndpoint, "not-a-hash", "", ErrCodeATH},
		{"token-endpoint: ath present and Expect.ATH matches (expectation never widens the profile)", ProfileTokenEndpoint, ATH(accTok), ATH(accTok), ErrCodeATH},
		{"token-endpoint: ath absent with a stray Expect.ATH", ProfileTokenEndpoint, "", ATH(accTok), ""},
		// resource: ath present + exact -> ok; absent or mismatched -> refused.
		{"resource: ath present, exact match", ProfileResource, ATH(accTok), ATH(accTok), ""},
		{"resource (zero profile): ath present, exact match", 0, ATH(accTok), ATH(accTok), ""},
		{"resource: ath absent", ProfileResource, "", ATH(accTok), ErrCodeATH},
		{"resource: ath mismatch", ProfileResource, ATH("other"), ATH(accTok), ErrCodeATH},
		{"resource: ath present but nothing expected", ProfileResource, ATH(accTok), "", ErrCodeATH},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			htu := tokURL
			if tc.profile == ProfileResource || tc.profile == 0 {
				htu = resURL
			}
			p, err := Create(s, jose.AlgEdDSA, "POST", htu, tc.proofATH, "", t0)
			if err != nil {
				t.Fatal(err)
			}
			rs := newShared()
			e := Expect{HTM: "POST", HTU: htu, Profile: tc.profile, ATH: tc.expectATH, Org: "o"}
			jkt, err := Verify(context.Background(), p, e, rs, t0)
			if CodeOf(err) != tc.want {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if tc.want == "" {
				if jkt != jktOf(t, s, jose.AlgEdDSA) || len(rs.seen) != 1 {
					t.Fatalf("accepted proof: jkt=%s seen=%d", jkt, len(rs.seen))
				}
				return
			}
			if !errors.Is(err, ErrInvalidProof) || OAuthError(err) != "invalid_dpop_proof" {
				t.Fatalf("external mapping wrong for %v", err)
			}
			if len(rs.seen) != 0 {
				t.Fatal("a rejected proof burned its jti")
			}
		})
	}
}

// TestUnknownProfileFailsClosed: the profile vocabulary is closed; a value
// outside it is never treated as the lenient profile.
func TestUnknownProfileFailsClosed(t *testing.T) {
	s := key(t, jose.AlgEdDSA)
	p, _ := Create(s, jose.AlgEdDSA, "POST", tokURL, "", "", t0)
	rs := newShared()
	if _, err := Verify(context.Background(), p, Expect{HTM: "POST", HTU: tokURL, Profile: Profile(99), Org: "o"}, rs, t0); CodeOf(err) != ErrCodeClaims || len(rs.seen) != 0 {
		t.Fatalf("unknown profile err = %v seen=%d", err, len(rs.seen))
	}
}

func TestNonce(t *testing.T) {
	ni := NonceIssuer{Key: []byte(strings.Repeat("k", 32))}
	s := key(t, jose.AlgEdDSA)
	e := Expect{
		HTM: "POST", HTU: tokURL, Profile: ProfileTokenEndpoint, Org: "o", RequireNonce: true,
		NonceCheck: func(n string) bool { return ni.Check(n, t0) },
	}
	p, _ := Create(s, jose.AlgEdDSA, "POST", tokURL, "", "", t0)
	_, err := Verify(context.Background(), p, e, newShared(), t0)
	if CodeOf(err) != ErrCodeUseNonce || OAuthError(err) != "use_dpop_nonce" {
		t.Fatalf("no-nonce err = %v", err)
	}
	p, _ = Create(s, jose.AlgEdDSA, "POST", tokURL, "", ni.Issue(t0), t0)
	if _, err := Verify(context.Background(), p, e, newShared(), t0); err != nil {
		t.Fatalf("with nonce: %v", err)
	}
	p, _ = Create(s, jose.AlgEdDSA, "POST", tokURL, "", "bogus", t0)
	if _, err := Verify(context.Background(), p, e, newShared(), t0); CodeOf(err) != ErrCodeUseNonce {
		t.Fatalf("bogus nonce err = %v", err)
	}
	// Bucket semantics: current + previous accepted, older and other-key refused.
	n := ni.Issue(t0)
	if !ni.Check(n, t0.Add(DefaultNonceWindow)) || ni.Check(n, t0.Add(3*DefaultNonceWindow)) {
		t.Fatal("nonce window wrong")
	}
	if (NonceIssuer{Key: []byte(strings.Repeat("x", 32))}).Check(n, t0) {
		t.Fatal("nonce from another key accepted")
	}
	if (NonceIssuer{Key: []byte("short")}).Check(n, t0) {
		t.Fatal("short key must fail closed")
	}
}

func TestCanonicalHTU(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://Auth.Example.COM/oauth2/token", "https://auth.example.com/oauth2/token"},
		{"https://auth.example.com:443/oauth2/token?x=1#f", "https://auth.example.com/oauth2/token"},
		{"http://h:80", "http://h/"},
		{"https://h:8850/t", "https://h:8850/t"},
		{"HTTPS://h/a%2Fb", "https://h/a%2Fb"},
		{"https://[::1]:8443/t", "https://[::1]:8443/t"},
	}
	for _, c := range cases {
		got, err := CanonicalHTU(c.in)
		if err != nil || got != c.want {
			t.Errorf("CanonicalHTU(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "ftp://h/x", "https://u:p@h/x", "/relative", "https://", "mailto:x@y"} {
		if _, err := CanonicalHTU(bad); err == nil {
			t.Errorf("CanonicalHTU(%q) accepted", bad)
		}
	}
}

func TestCanonicalRequestHTUTrustedProxy(t *testing.T) {
	trusted := []string{"10.0.0.0/8", "fd00::/8"}
	cases := []struct {
		name string
		ri   RequestInfo
		want string
	}{
		{"direct TLS", RequestInfo{TLS: true, Host: "auth.acme.test", Path: "/oauth2/token", RemoteAddr: "203.0.113.9:4000"}, "https://auth.acme.test/oauth2/token"},
		{"untrusted peer forwarded headers ignored", RequestInfo{Host: "10.1.1.1:8850", Path: "/oauth2/token", RemoteAddr: "203.0.113.9:4000", ForwardedProto: "https", ForwardedHost: "evil.test"}, "http://10.1.1.1:8850/oauth2/token"},
		{"trusted terminator honoured", RequestInfo{Host: "10.1.1.1:8850", Path: "/oauth2/token", RemoteAddr: "10.2.3.4:5555", ForwardedProto: "https", ForwardedHost: "auth.acme.test"}, "https://auth.acme.test/oauth2/token"},
		{"trusted terminator: last list element wins", RequestInfo{Host: "x", Path: "/t", RemoteAddr: "10.2.3.4:1", ForwardedProto: "http, https", ForwardedHost: "evil.test, auth.acme.test"}, "https://auth.acme.test/t"},
		{"ipv6 trusted", RequestInfo{Host: "x", Path: "/t", RemoteAddr: "[fd00::5]:1", ForwardedProto: "https", ForwardedHost: "auth.acme.test"}, "https://auth.acme.test/t"},
		{"ipv4-mapped ipv6 peer", RequestInfo{Host: "x", Path: "/t", RemoteAddr: "[::ffff:10.0.0.7]:1", ForwardedProto: "https", ForwardedHost: "auth.acme.test"}, "https://auth.acme.test/t"},
	}
	for _, c := range cases {
		got, err := CanonicalRequestHTU(c.ri, trusted)
		if err != nil || got != c.want {
			t.Errorf("%s: got %q, %v; want %q", c.name, got, err, c.want)
		}
	}
	if _, err := CanonicalRequestHTU(RequestInfo{Host: "h", Path: "/"}, []string{"not-a-cidr"}); err != nil {
		t.Log("no peer -> never trusted, CIDR not parsed:", err)
	}
	if _, err := CanonicalRequestHTU(RequestInfo{Host: "h", Path: "/", RemoteAddr: "10.0.0.1:1"}, []string{"not-a-cidr"}); err == nil {
		t.Error("bad CIDR accepted")
	}
	// End to end: a proof for the public URL verifies behind a trusted terminator.
	s := key(t, jose.AlgEdDSA)
	p, _ := Create(s, jose.AlgEdDSA, "POST", "https://auth.acme.test/oauth2/token", "", "", t0)
	e := Expect{
		HTM: "POST", Profile: ProfileTokenEndpoint, Org: "o", TrustedProxyCIDRs: trusted,
		Request: &RequestInfo{Host: "10.1.1.1:8850", Path: "/oauth2/token", RemoteAddr: "10.2.3.4:5555", ForwardedProto: "https", ForwardedHost: "auth.acme.test"},
	}
	if _, err := Verify(context.Background(), p, e, newShared(), t0); err != nil {
		t.Fatal(err)
	}
	e.Request.RemoteAddr = "203.0.113.9:1" // same headers, untrusted peer
	if _, err := Verify(context.Background(), p, e, newShared(), t0); CodeOf(err) != ErrCodeHTU {
		t.Fatalf("spoofed forwarded headers err = %v", err)
	}
}

func TestCorrelationClaim(t *testing.T) {
	s := key(t, jose.AlgEdDSA)
	corr := &Correlation{CodingSessionID: "s", TurnRef: "t", ActionRef: "a", CallID: "c"}
	p, err := CreateWith(s, jose.AlgEdDSA, Claims{HTM: "POST", HTU: resURL, ATH: ATH(accTok), Corr: corr}, t0, nil)
	if err != nil {
		t.Fatal(err)
	}
	r, err := VerifyDetailed(context.Background(), p, Expect{HTM: "POST", HTU: resURL, ATH: ATH(accTok), Org: "o"}, newShared(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if r.Claims.Corr == nil || *r.Claims.Corr != *corr {
		t.Fatalf("corr = %+v", r.Claims.Corr)
	}
	// Two calls under one access token each carry their own proof + corr; a
	// replayed proof (same jti) across turns is refused.
	rs := newShared()
	e := Expect{HTM: "POST", HTU: resURL, ATH: ATH(accTok), Org: "o"}
	if _, err := Verify(context.Background(), p, e, rs, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(context.Background(), p, e, rs, t0.Add(10*time.Second)); CodeOf(err) != ErrCodeReplay {
		t.Fatalf("replay across turns err = %v", err)
	}
}

func TestParseAuthorization(t *testing.T) {
	cases := []struct{ in, scheme, tok string }{
		{"DPoP abc.def.ghi", SchemeDPoP, "abc.def.ghi"},
		{"dpop abc", SchemeDPoP, "abc"},
		{"Bearer abc", SchemeBearer, "abc"},
		{"BEARER   abc", SchemeBearer, "abc"},
	}
	for _, c := range cases {
		s, tok, err := ParseAuthorization(c.in)
		if err != nil || s != c.scheme || tok != c.tok {
			t.Errorf("%q -> %q %q %v", c.in, s, tok, err)
		}
	}
	for _, bad := range []string{"", "Basic abc", "DPoP", "DPoP a b", "Bearer a,b", "Bearer ab\"c"} {
		if _, _, err := ParseAuthorization(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

type vector struct {
	Name      string `json:"name"`
	Profile   string `json:"profile"`
	Proof     string `json:"proof"`
	HTM       string `json:"htm"`
	HTU       string `json:"htu"`
	Now       int64  `json:"verify_at_unix"`
	AccessTok string `json:"access_token"`
	WantJKT   string `json:"want_jkt"`
	WantError string `json:"want_error"`
}

// TestInteropVectors verifies the published vectors in testdata/: the RFC
// 9449 §4.1 example proof (whose jkt is RFC 9449 §6.1's) and SuperBased's
// own EdDSA/ES256/RS256 token-endpoint and resource vectors (incl. sbo_corr)
// plus negative vectors.
func TestInteropVectors(t *testing.T) {
	raw, err := os.ReadFile("testdata/interop_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vs []vector
	if err := json.Unmarshal(raw, &vs); err != nil {
		t.Fatal(err)
	}
	if len(vs) < 16 {
		t.Fatalf("only %d vectors", len(vs))
	}
	for _, v := range vs {
		t.Run(v.Name, func(t *testing.T) {
			e := Expect{HTM: v.HTM, HTU: v.HTU, Org: "vec", Profile: ProfileTokenEndpoint}
			if v.Profile == "resource" {
				e.Profile, e.ATH = ProfileResource, ATH(v.AccessTok)
			}
			jkt, err := Verify(context.Background(), v.Proof, e, newShared(), time.Unix(v.Now, 0))
			if v.WantError != "" {
				if string(CodeOf(err)) != v.WantError {
					t.Fatalf("err = %v, want %s", err, v.WantError)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if jkt != v.WantJKT {
				t.Fatalf("jkt = %s, want %s", jkt, v.WantJKT)
			}
		})
	}
}

func FuzzVerify(f *testing.F) {
	s, _ := jose.GenerateKey(rand.Reader, jose.AlgEdDSA)
	p, _ := Create(s, jose.AlgEdDSA, "POST", tokURL, "", "", t0)
	f.Add(p)
	f.Add("")
	f.Add("a.b.c")
	f.Fuzz(func(t *testing.T, in string) {
		_, _ = Verify(context.Background(), in, Expect{HTM: "POST", HTU: tokURL, Profile: ProfileTokenEndpoint, Org: "o"}, newShared(), t0)
		_, _ = CanonicalHTU(in)
		_, _, _ = ParseAuthorization(in)
	})
}
