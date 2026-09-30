package orgclient

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"

	keyring "github.com/zalando/go-keyring"

	"github.com/marmutapp/superbased-observer/internal/dpop/jose"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// memAgentAccessKeys is an in-memory AgentAccessKeyStore.
type memAgentAccessKeys struct {
	mu    sync.Mutex
	key   *AgentAccessKey
	saves int
}

func (m *memAgentAccessKeys) LoadAgentAccessKey() (AgentAccessKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.key == nil {
		return AgentAccessKey{}, ErrNoSecret
	}
	return *m.key, nil
}

func (m *memAgentAccessKeys) SaveAgentAccessKey(k AgentAccessKey) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.key = &k
	m.saves++
	return nil
}
func (m *memAgentAccessKeys) ClearAgentAccessKey() error { m.key = nil; return nil }

func TestAgentAccessKeychainStoreRoundTripPerAlg(t *testing.T) {
	keyring.MockInit()
	st, err := OpenAgentAccessKeyStoreIn("sbo-aa-test", t.TempDir(), quietLogger())
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if _, err := st.LoadAgentAccessKey(); !errors.Is(err, ErrNoSecret) {
		t.Fatalf("load before save err = %v", err)
	}
	for _, alg := range []string{"EdDSA", "ES256", "RS256"} {
		t.Run(alg, func(t *testing.T) {
			signer, err := jose.GenerateKey(rand.Reader, alg)
			if err != nil {
				t.Fatal(err)
			}
			if err := st.SaveAgentAccessKey(AgentAccessKey{Alg: alg, Signer: signer}); err != nil {
				t.Fatal(err)
			}
			got, err := st.LoadAgentAccessKey()
			if err != nil || got.Alg != alg {
				t.Fatalf("load = %+v %v", got, err)
			}
			want, _ := jose.PublicJWK(signer.Public(), alg, "")
			have, _ := jose.PublicJWK(got.Signer.Public(), alg, "")
			if want != have {
				t.Fatal("round-tripped key differs")
			}
		})
	}
	// A key whose alg tag disagrees with its type is refused on save.
	ed, _ := jose.GenerateKey(rand.Reader, "EdDSA")
	if err := st.SaveAgentAccessKey(AgentAccessKey{Alg: "ES256", Signer: ed}); err == nil {
		t.Fatal("saved a key under the wrong alg")
	}
	// A corrupted record is refused, not guessed at.
	for _, bad := range []string{"plain", "sbo-aak-v1:EdDSA:!!!", "sbo-aak-v1:ES256:" + mustEnvelopeBody(t, ed)} {
		if err := keyring.Set("sbo-aa-test", recAgentAccessKey, bad); err != nil {
			t.Fatal(err)
		}
		if _, err := st.LoadAgentAccessKey(); err == nil {
			t.Fatalf("loaded a corrupted record %q", bad)
		}
	}
	if err := st.ClearAgentAccessKey(); err != nil {
		t.Fatal(err)
	}
	if err := st.ClearAgentAccessKey(); err != nil {
		t.Fatalf("clear of an absent key: %v", err)
	}
}

func mustEnvelopeBody(t *testing.T, k crypto.Signer) string {
	t.Helper()
	s, err := encodeAgentAccessKey(AgentAccessKey{Alg: "EdDSA", Signer: k})
	if err != nil {
		t.Fatal(err)
	}
	return s[len("sbo-aak-v1:EdDSA:"):]
}

// TestAgentAccessKeyStoreFailsClosed: with no keychain AND no usable file
// fallback there is no key store (ErrAgentAccessKeychainUnavailable); the
// file-fallback cases live in agentaccess_keystore_test.go.
func TestAgentAccessKeyStoreFailsClosed(t *testing.T) {
	keyring.MockInitWithError(errors.New("no secret service"))
	defer keyring.MockInit()
	st, err := OpenAgentAccessKeyStoreIn("sbo-aa-test", "", quietLogger())
	if !errors.Is(err, ErrAgentAccessKeychainUnavailable) || st != nil {
		t.Fatalf("open = %v, %v; want ErrAgentAccessKeychainUnavailable", st, err)
	}
	if _, _, err := EnsureAgentAccessKey(nil); !errors.Is(err, ErrAgentAccessKeychainUnavailable) {
		t.Fatalf("ensure(nil) err = %v", err)
	}
}

func TestEnsureAgentAccessKeyGeneratesOnce(t *testing.T) {
	keys := &memAgentAccessKeys{}
	k1, created, err := EnsureAgentAccessKey(keys)
	if err != nil || !created || k1.Alg != DefaultAgentAccessKeyAlg {
		t.Fatalf("first = %+v %t %v", k1, created, err)
	}
	k2, created, err := EnsureAgentAccessKey(keys)
	if err != nil || created || keys.saves != 1 {
		t.Fatalf("second created=%t saves=%d err=%v", created, keys.saves, err)
	}
	p1, _ := jose.PublicJWK(k1.Signer.Public(), k1.Alg, "")
	p2, _ := jose.PublicJWK(k2.Signer.Public(), k2.Alg, "")
	if p1 != p2 {
		t.Fatal("EnsureAgentAccessKey replaced an existing key")
	}
}

// registerServer is a minimal org-server double: it verifies the enrolment
// signature and the key proof exactly as the real rail does, then answers
// from script.
type registerServer struct {
	t       *testing.T
	pushPub ed25519.PublicKey
	mu      sync.Mutex
	seen    []string // thumbprints, in arrival order
	script  func(n int, jkt string) (int, string)
}

func (s *registerServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	t := s.t
	if r.URL.Path != "/api/agent/agent-access/register" || r.Header.Get("Authorization") != "Bearer bearer-xyz" {
		t.Errorf("unexpected request %s auth=%q", r.URL.Path, r.Header.Get("Authorization"))
	}
	raw, _ := io.ReadAll(r.Body)
	ts, _ := strconv.ParseInt(r.Header.Get(orgcontract.HeaderTimestamp), 10, 64)
	sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get(orgcontract.HeaderAgentSignature))
	if !ed25519.Verify(s.pushPub, orgcontract.PushSigningMessage(ts, raw), sig) {
		t.Error("enrolment-key signature does not verify")
	}
	var body struct {
		MachineFP string          `json:"machine_fp"`
		Alg       string          `json:"alg"`
		PublicJWK json.RawMessage `json:"public_jwk"`
		KeyProof  string          `json:"key_proof"`
	}
	// t.Errorf, never t.Fatalf: this runs on the server's goroutine.
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Errorf("body: %v", err)
		return
	}
	jwk, err := jose.DecodeJWK(body.PublicJWK)
	if err != nil {
		t.Errorf("public_jwk: %v", err)
		return
	}
	jkt, _ := jwk.Thumbprint()
	proof, err := jose.Parse(body.KeyProof, 0)
	if err != nil || proof.Header.Typ != AgentAccessKeyProofTyp || proof.Verify(jose.DefaultAlgs(), jwk) != nil {
		t.Errorf("key_proof does not verify: %v", err)
		return
	}
	var c agentAccessKeyProofClaims
	_ = json.Unmarshal(proof.Payload, &c)
	if c.Aud != "org-1" || c.Sub != "scim-42" || c.MachineFP != body.MachineFP || c.JKT != jkt || c.MachineFP != "mfp-test" {
		t.Errorf("proof claims = %+v", c)
	}
	s.mu.Lock()
	s.seen = append(s.seen, jkt)
	n := len(s.seen)
	s.mu.Unlock()
	status, code := s.script(n, jkt)
	if status >= 300 {
		writeTestJSON(w, status, map[string]string{"error": code, "message": "scripted"})
		return
	}
	writeTestJSON(w, status, AgentAccessRegistration{
		CredentialID: "acn_" + strconv.Itoa(n), MachineFP: body.MachineFP,
		KeyThumbprint: jkt, Alg: body.Alg, CredentialAssurance: "node_enrolled", CredGen: 1, Status: "active",
		CreatedAt: "2026-09-24T12:00:00Z", Created: status == http.StatusCreated,
	})
}

func registerClient(t *testing.T, srvURL string) (*Client, ed25519.PublicKey) {
	t.Helper()
	s := newAgentStore(t)
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example",
		EnrolledAt: time.Now().UTC().Format(time.RFC3339), BearerKeyID: "test",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	return newTestClient(t, s, &memBearerStore{bearer: "bearer-xyz", key: priv}), pub
}

func withMachineFP(t *testing.T, fp string) {
	t.Helper()
	prev := agentAccessMachineFP
	agentAccessMachineFP = func(string) (string, error) { return fp, nil }
	t.Cleanup(func() { agentAccessMachineFP = prev })
}

func TestRegisterAgentAccessKeyHappyPathAndIdempotence(t *testing.T) {
	withMachineFP(t, "mfp-test")
	srv := &registerServer{t: t, script: func(n int, _ string) (int, string) {
		if n == 1 {
			return http.StatusCreated, ""
		}
		return http.StatusOK, ""
	}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c, pub := registerClient(t, ts.URL)
	srv.pushPub = pub
	keys := &memAgentAccessKeys{}

	reg, err := c.RegisterAgentAccessKey(context.Background(), keys)
	if err != nil || !reg.Created || reg.CredentialAssurance != "node_enrolled" || reg.MachineFP != "mfp-test" {
		t.Fatalf("first = %+v %v", reg, err)
	}
	again, err := c.RegisterAgentAccessKey(context.Background(), keys)
	if err != nil || again.Created || keys.saves != 1 || srv.seen[0] != srv.seen[1] {
		t.Fatalf("second = %+v saves=%d err=%v seen=%v", again, keys.saves, err, srv.seen)
	}
}

func TestRegisterAgentAccessKeyStatusMapping(t *testing.T) {
	withMachineFP(t, "mfp-test")
	cases := []struct {
		status int
		code   string
		want   error
	}{
		{http.StatusNotFound, "not_supported", ErrAgentAccessUnsupported},
		{http.StatusMethodNotAllowed, "", ErrAgentAccessUnsupported},
		{http.StatusForbidden, "device_revoked", ErrAgentAccessDeviceRevoked},
		{http.StatusForbidden, "member_not_active", ErrAuthFailed},
		{http.StatusUnauthorized, "unauthorized", ErrAuthFailed},
		{http.StatusConflict, "device_limit", ErrAgentAccessDeviceLimit},
		{http.StatusBadRequest, "bad_request", ErrAgentAccessRejected},
		{http.StatusRequestEntityTooLarge, "too_large", ErrAgentAccessRejected},
	}
	for _, tc := range cases {
		t.Run(strconv.Itoa(tc.status)+"_"+tc.code, func(t *testing.T) {
			srv := &registerServer{t: t, script: func(int, string) (int, string) { return tc.status, tc.code }}
			ts := httptest.NewServer(srv)
			defer ts.Close()
			c, pub := registerClient(t, ts.URL)
			srv.pushPub = pub
			if _, err := c.RegisterAgentAccessKey(context.Background(), &memAgentAccessKeys{}); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	// A 5xx is retryable: none of the terminal sentinels.
	srv := &registerServer{t: t, script: func(int, string) (int, string) { return http.StatusServiceUnavailable, "x" }}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c, pub := registerClient(t, ts.URL)
	srv.pushPub = pub
	_, err := c.RegisterAgentAccessKey(context.Background(), &memAgentAccessKeys{})
	for _, terminal := range []error{ErrAgentAccessUnsupported, ErrAgentAccessDeviceRevoked, ErrAgentAccessRejected, ErrAuthFailed} {
		if err == nil || errors.Is(err, terminal) {
			t.Fatalf("503 err = %v", err)
		}
	}
}

// TestRegisterAgentAccessKeyRotatesAnExpiredKeyOnce: a 409
// credential_expired makes the node generate a fresh key and register THAT,
// once; a second expired answer is a contract error, not a loop.
func TestRegisterAgentAccessKeyRotatesAnExpiredKeyOnce(t *testing.T) {
	withMachineFP(t, "mfp-test")
	srv := &registerServer{t: t, script: func(n int, _ string) (int, string) {
		if n == 1 {
			return http.StatusConflict, "credential_expired"
		}
		return http.StatusCreated, ""
	}}
	ts := httptest.NewServer(srv)
	defer ts.Close()
	c, pub := registerClient(t, ts.URL)
	srv.pushPub = pub
	keys := &memAgentAccessKeys{}
	reg, err := c.RegisterAgentAccessKey(context.Background(), keys)
	if err != nil || !reg.Created || len(srv.seen) != 2 || srv.seen[0] == srv.seen[1] || keys.saves != 2 {
		t.Fatalf("reg=%+v err=%v seen=%v saves=%d", reg, err, srv.seen, keys.saves)
	}
	stored, _ := keys.LoadAgentAccessKey()
	jwk, _ := jose.PublicJWK(stored.Signer.Public(), stored.Alg, "")
	if tp, _ := jwk.Thumbprint(); tp != srv.seen[1] {
		t.Fatal("the stored key is not the one that registered")
	}

	always := &registerServer{t: t, script: func(int, string) (int, string) { return http.StatusConflict, "credential_expired" }}
	ts2 := httptest.NewServer(always)
	defer ts2.Close()
	c2, pub2 := registerClient(t, ts2.URL)
	always.pushPub = pub2
	if _, err := c2.RegisterAgentAccessKey(context.Background(), &memAgentAccessKeys{}); !errors.Is(err, ErrAgentAccessRejected) || len(always.seen) != 2 {
		t.Fatalf("looping expiry err = %v attempts=%d", err, len(always.seen))
	}
}

func TestRegisterAgentAccessKeyNotEnrolled(t *testing.T) {
	c := newTestClient(t, newAgentStore(t), &memBearerStore{})
	if _, err := c.RegisterAgentAccessKey(context.Background(), &memAgentAccessKeys{}); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("err = %v, want ErrNotEnrolled", err)
	}
}
