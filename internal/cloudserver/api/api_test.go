package api_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/deletionjournal"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/dataauthority"
)

type harness struct {
	srv   *httptest.Server
	store *store.Store
}

// exchangeSigningInput mirrors internal/cloudclient/device.go's
// exchangeSigningContext / ExchangeSigningInput (and the server's own
// unexported api.exchangeSigningInput in auth.go — this test package can't
// import either, so the byte-for-byte construction is reproduced a third
// time here) so these hand-rolled exchange requests sign what the fixed
// handleExchange actually verifies: a domain-separated digest over the
// nonce AND the device public key, not the bare nonce bytes.
func exchangeSigningInput(nonce string, pub ed25519.PublicKey) []byte {
	return []byte("sbo-device-exchange.v1" + "\n" + nonce + "\n" + base64.RawURLEncoding.EncodeToString(pub))
}

// mustJournal builds a temp-file deletion journal for a harness store. W6d
// makes the journal a hard dependency of the deletion path (portal + structural
// deletion tests exercise it).
func mustJournal(t *testing.T) deletionjournal.Journal {
	t.Helper()
	j, err := deletionjournal.NewFileJournal(filepath.Join(t.TempDir(), "dj.jsonl"))
	if err != nil {
		t.Fatalf("deletion journal: %v", err)
	}
	return j
}

// mustAPIStore binds the SERVER's store to the least-privilege sbci_api role
// exactly as `observer-cloud serve` does (cmd/observer-cloud/main.go
// openStoreForRole(RoleAPI)), so a grant the front-door role lacks fails HERE
// instead of on the estate (2026-09-03: pop_replay's ON CONFLICT DO UPDATE
// needed UPDATE — every authenticated route 500'd after the first sbci_api-
// bound roll while this suite, bound as sbci_app, stayed green). Fixtures and
// assertions keep the sbci_app-bound `s`.
func mustAPIStore(t *testing.T, pool *pgxpool.Pool) *store.Store {
	t.Helper()
	s, err := store.NewForRole(pool, store.RoleAPI)
	if err != nil {
		t.Fatalf("store.NewForRole(RoleAPI): %v", err)
	}
	return s
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))

	// httptest.NewServer's URL is only known AFTER the server starts, but
	// api.New needs ExternalBaseURL up front — every PoP proof the test
	// client mints binds its htu to that base, and the server reconstructs
	// the same base to verify it, so the two must agree exactly. Pre-bind a
	// listener so the base URL is known before the handler (and therefore
	// the Server) is built, then hand that listener to httptest.Server
	// instead of letting it pick its own.
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()

	// Raise caps so allowance limits don't interfere with functional tests, and
	// DISABLE rate limiting (all-zero config) so unrelated functional tests are
	// deterministic — the rate-limit behaviour has its own harness below. Wire a
	// HEALTHY admission gate (verified attestation + present credential) so the
	// default harness represents a provider-enabled server and its post-admission
	// flow tests still submit successfully; the credential-absent / unhealthy
	// postures (fail-closed) have their own harnesses in admission_test.go.
	handler := api.New(api.Options{
		Store:           apiStore,
		Queue:           jobs.NewPGQueue(apiStore),
		Verifier:        identity.NewDevAuth(),
		ExternalBaseURL: base,
		RateLimit:       &api.RateLimitConfig{},
		Attestor:        admAttestor{verified: true},
		Credentials:     jobs.StaticCredentials{Key: "test-key"},
	}).Handler()

	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// newHarnessRL builds a harness with an explicit rate-limit policy so the
// per-IP/device/account caps can be exercised (dev-auth verifier).
func newHarnessRL(t *testing.T, cfg api.RateLimitConfig) *harness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	handler := api.New(api.Options{
		Store:           apiStore,
		Queue:           jobs.NewPGQueue(apiStore),
		Verifier:        identity.NewDevAuth(),
		ExternalBaseURL: base,
		RateLimit:       &cfg,
		Attestor:        admAttestor{verified: true},
		Credentials:     jobs.StaticCredentials{Key: "test-key"},
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// newHarnessPaddle builds a harness with the W9 Paddle webhook secret set (so
// POST /portal/webhooks/paddle verifies rather than 501s) and the price map
// wired on the store.
func newHarnessPaddle(t *testing.T, secret string) *harness {
	t.Helper()
	pool := cloudtestpg.NewDB(t)
	s := store.New(pool)
	apiStore := mustAPIStore(t, pool)
	s.SetDeletionJournal(mustJournal(t))
	apiStore.SetDeletionJournal(mustJournal(t))
	// The price map is per-Store state: the SERVER resolves prices through
	// apiStore, the fixtures (mintPaddleNonce) through s — both need it.
	priceMap := map[string]store.PaddlePlan{"pri_test_plus": {Name: "plus_beta", Version: 1}}
	s.SetPaddlePriceMap(priceMap)
	apiStore.SetPaddlePriceMap(priceMap)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	base := "http://" + lis.Addr().String()
	handler := api.New(api.Options{
		Store:               apiStore,
		Queue:               jobs.NewPGQueue(apiStore),
		Verifier:            identity.NewDevAuth(),
		ExternalBaseURL:     base,
		RateLimit:           &api.RateLimitConfig{},
		Attestor:            admAttestor{verified: true},
		Credentials:         jobs.StaticCredentials{Key: "test-key"},
		PaddleWebhookSecret: secret,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// testClient models a signed-in device.
type testClient struct {
	t          *testing.T
	base       string
	http       *http.Client
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	token      string
	thumbprint string
	accountID  string
}

func (h *harness) login(t *testing.T, subject string) *testClient {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := &testClient{t: t, base: h.srv.URL, http: h.srv.Client(), priv: priv, pub: pub}

	// GET nonce.
	resp, err := c.http.Get(c.base + "/v1/auth/nonce")
	if err != nil {
		t.Fatalf("nonce: %v", err)
	}
	var nb struct{ Nonce string }
	decode(t, resp, &nb)

	// Sign the nonce and exchange a dev-auth token.
	sig := ed25519.Sign(priv, exchangeSigningInput(nb.Nonce, pub))
	body, _ := json.Marshal(map[string]string{
		"workos_access_token": "dev:" + subject,
		"device_public_key":   base64.RawURLEncoding.EncodeToString(pub),
		"device_label":        "test",
		"nonce":               nb.Nonce,
		"signature":           base64.RawURLEncoding.EncodeToString(sig),
	})
	resp, err = c.http.Post(c.base+"/v1/auth/exchange", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("exchange status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var er struct {
		Token      string `json:"api_token"`
		AccountID  string `json:"account_id"`
		Thumbprint string `json:"thumbprint"`
	}
	decode(t, resp, &er)
	c.token, c.accountID, c.thumbprint = er.Token, er.AccountID, er.Thumbprint
	return c
}

// signedReq builds a request with a valid Bearer + PoP proof.
func (c *testClient) signedReq(method, path string, body []byte) *http.Request {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, bytes.NewReader(body))
	if err != nil {
		c.t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("SBO-PoP", c.proof(method, path, body, ""))
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

// proof builds the SBO-PoP header via the real cloudpop.Create — the same
// call internal/cloudclient makes. overrideJTI="" ⇒ cloudpop mints a fresh
// random one.
func (c *testClient) proof(method, path string, body []byte, jti string) string {
	c.t.Helper()
	p, err := cloudpop.Create(cloudpop.CreateParams{
		PrivateKey:  c.priv,
		Method:      method,
		URL:         c.base + path,
		AccessToken: c.token,
		JTI:         jti,
		Body:        body,
	})
	if err != nil {
		c.t.Fatalf("cloudpop.Create: %v", err)
	}
	return p
}

func (c *testClient) do(req *http.Request) *http.Response {
	c.t.Helper()
	resp, err := c.http.Do(req)
	if err != nil {
		c.t.Fatalf("do %s %s: %v", req.Method, req.URL.Path, err)
	}
	return resp
}

func decode(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatalf("decode: %v", err)
	}
}

func readAll(resp *http.Response) string {
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func TestExchangeAndAuthenticatedUsage(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "alice")

	resp := c.do(c.signedReq("GET", "/v1/usage", nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("usage status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var snap store.UsageSnapshot
	decode(t, resp, &snap)
	// free v2 (migration 0039): daily 20, monthly 100.
	if snap.DailyCap != 20 || snap.MonthlyCap != 100 {
		t.Fatalf("unexpected caps: %+v", snap)
	}
}

func TestStolenTokenWithoutValidPoP(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "bob")

	// Valid token but NO PoP header ⇒ 401.
	req, _ := http.NewRequest("GET", c.base+"/v1/usage", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	if resp := c.do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("missing PoP: status=%d, want 401", resp.StatusCode)
	}

	// Valid token but PoP signed by a DIFFERENT key (attacker lacks the device
	// private key) ⇒ 401. The forged proof embeds the ATTACKER's own JWK (a
	// real, self-consistent, well-signed cloudpop proof), so this fails on
	// thumbprint mismatch rather than a bad signature — still 401.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, err := cloudpop.Create(cloudpop.CreateParams{
		PrivateKey:  attackerPriv,
		Method:      "GET",
		URL:         c.base + "/v1/usage",
		AccessToken: c.token,
		JTI:         "x",
	})
	if err != nil {
		t.Fatalf("cloudpop.Create (attacker): %v", err)
	}
	req, _ = http.NewRequest("GET", c.base+"/v1/usage", nil)
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("SBO-PoP", forged)
	if resp := c.do(req); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged PoP sig: status=%d, want 401", resp.StatusCode)
	}
}

func TestPoPReplayRejected(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "carol")

	// A valid bounded base64url jti (FC3 requires 16–64 base64url bytes); the
	// point of the test is the REPLAY of the same jti, not its shape.
	proof := c.proof("GET", "/v1/usage", nil, "fixedjtithatis22charsok")
	mk := func() *http.Request {
		req, _ := http.NewRequest("GET", c.base+"/v1/usage", nil)
		req.Header.Set("Authorization", "Bearer "+c.token)
		req.Header.Set("SBO-PoP", proof)
		return req
	}
	if resp := c.do(mk()); resp.StatusCode != http.StatusOK {
		t.Fatalf("first request status=%d, want 200", resp.StatusCode)
	}
	if resp := c.do(mk()); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed jti status=%d, want 401", resp.StatusCode)
	}
}

func TestUnknownTokenRejected(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "dan")
	// A random opaque token (models an org/foreign token) fails closed.
	c.token = "not-a-real-token"
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unknown token status=%d, want 401", resp.StatusCode)
	}
}

func TestExchangeReplayedNonce(t *testing.T) {
	h := newHarness(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	client := h.srv.Client()

	resp, _ := client.Get(h.srv.URL + "/v1/auth/nonce")
	var nb struct{ Nonce string }
	decode(t, resp, &nb)
	sig := ed25519.Sign(priv, exchangeSigningInput(nb.Nonce, pub))
	mkBody := func() []byte {
		b, _ := json.Marshal(map[string]string{
			"workos_access_token": "dev:eve",
			"device_public_key":   base64.RawURLEncoding.EncodeToString(pub),
			"nonce":               nb.Nonce,
			"signature":           base64.RawURLEncoding.EncodeToString(sig),
		})
		return b
	}
	if r, _ := client.Post(h.srv.URL+"/v1/auth/exchange", "application/json", bytes.NewReader(mkBody())); r.StatusCode != http.StatusOK {
		t.Fatalf("first exchange status=%d", r.StatusCode)
	}
	if r, _ := client.Post(h.srv.URL+"/v1/auth/exchange", "application/json", bytes.NewReader(mkBody())); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replayed nonce exchange status=%d, want 401", r.StatusCode)
	}
}

// --- job admission ---

func makeEnvelope(t *testing.T, withContext bool) (raw []byte, uploadDigest, contentDigest string) {
	t.Helper()
	env := cloudcontract.Envelope{
		SchemaVersion:      cloudcontract.EnvelopeSchemaVersion,
		CloudSessionID:     "cs-123",
		CloudProjectID:     "cp-123",
		Tool:               "codex",
		ModelFamily:        "gpt-5.6",
		StartedAtBucket:    time.Now().UTC().Format(time.RFC3339),
		DurationSeconds:    120,
		Metrics:            cloudcontract.MetricsBlock{TokensIn: 10, TokensOut: 5, DeterministicScore: 80},
		Outcomes:           cloudcontract.Outcomes{TestsRun: 2, TestsPassed: 2, Build: "passed"},
		DisclosurePurposes: []cloudcontract.Purpose{cloudcontract.PurposeStructuralInsights},
		ScrubberVersion:    "scrub-v1",
		Authority:          dataauthority.Classification{Authority: dataauthority.AuthorityPersonal, Version: dataauthority.Version},
	}
	if withContext {
		env.Context = []cloudcontract.ContextExcerpt{{Source: "task_excerpt", Text: "fix the bug", LengthCapBytes: 4096}}
		env.DisclosurePurposes = append(env.DisclosurePurposes, cloudcontract.PurposeContextEnrichment)
	}
	cd, err := cloudcontract.EvidenceContentDigest(env)
	if err != nil {
		t.Fatalf("content digest: %v", err)
	}
	env.EvidenceContentDigest = cd
	raw, err = cloudcontract.UploadBytes(env)
	if err != nil {
		t.Fatalf("upload bytes: %v", err)
	}
	return raw, cloudcontract.UploadDigest(raw), cd
}

func (c *testClient) previewConfirm(t *testing.T, uploadDigest, contentDigest string, purposes []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"purposes":                purposes,
		"field_classes":           []string{"structural_metrics"},
		"evidence_schema":         cloudcontract.EnvelopeSchemaVersion,
		"scrubber_version":        "scrub-v1",
		"upload_digest":           uploadDigest,
		"evidence_content_digest": contentDigest,
	})
	resp := c.do(c.signedReq("POST", "/v1/consents/preview-confirmation", body))
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("preview-confirmation status=%d body=%s", resp.StatusCode, readAll(resp))
	}
}

func TestJobHappyPathAndIdempotency(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "frank")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	// First submit ⇒ 202 accepted, queued.
	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var j1 struct {
		JobID    string `json:"job_id"`
		State    string `json:"state"`
		Existing bool   `json:"existing"`
	}
	decode(t, resp, &j1)
	if j1.State != "queued" || j1.Existing {
		t.Fatalf("unexpected first submit: %+v", j1)
	}

	// Retry same bytes ⇒ 200, existing, same job (idempotent, no extra unit).
	resp = c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("retry status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var j2 struct {
		JobID    string `json:"job_id"`
		Existing bool   `json:"existing"`
	}
	decode(t, resp, &j2)
	if !j2.Existing || j2.JobID != j1.JobID {
		t.Fatalf("retry not idempotent: %+v vs %+v", j2, j1)
	}

	// GET the job.
	resp = c.do(c.signedReq("GET", "/v1/intelligence/jobs/"+j1.JobID, nil))
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get job status=%d", resp.StatusCode)
	}

	// Usage shows exactly one unit consumed.
	resp = c.do(c.signedReq("GET", "/v1/usage", nil))
	var snap store.UsageSnapshot
	decode(t, resp, &snap)
	if snap.DailyUsed != 1 {
		t.Fatalf("daily used=%d, want 1", snap.DailyUsed)
	}
}

func TestJobDigestTamperRejected(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "grace")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	// Tamper: flip a byte in the body so the embedded content digest no longer
	// matches the recompute.
	tampered := append([]byte{}, raw...)
	// Change a digit inside the JSON (duration) without breaking JSON validity.
	tampered = bytes.Replace(tampered, []byte(`"duration_seconds": 120`), []byte(`"duration_seconds": 121`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("failed to construct tampered body")
	}
	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", tampered))
	if resp.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("tampered submit status=%d body=%s, want 422", resp.StatusCode, readAll(resp))
	}
}

func TestJobOutOfPurposeRejected(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "heidi")
	// Envelope carries context excerpts (requires bounded_context_enrichment)
	// but the receipt grants only structural insights.
	raw, ud, cd := makeEnvelope(t, true)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-purpose status=%d body=%s, want 403", resp.StatusCode, readAll(resp))
	}
}

func TestJobWithoutReceiptReconfirmation(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "ivan")
	raw, _, _ := makeEnvelope(t, false)
	// No preview-confirmation ⇒ no receipt for these bytes ⇒ 409.
	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("no-receipt submit status=%d body=%s, want 409", resp.StatusCode, readAll(resp))
	}
}

func TestDeletionRequestSkeleton(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "judy")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})
	c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))

	resp := c.do(c.signedReq("POST", "/v1/deletion-requests", []byte("{}")))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("deletion status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	var dr struct {
		JobsCanceled   int `json:"jobs_canceled"`
		DevicesRevoked int `json:"devices_revoked"`
	}
	decode(t, resp, &dr)
	if dr.JobsCanceled != 1 || dr.DevicesRevoked != 1 {
		t.Fatalf("deletion skeleton: %+v (want 1 job canceled, 1 device revoked)", dr)
	}
	// After device revocation, the (now-revoked) token is rejected.
	if resp := c.do(c.signedReq("GET", "/v1/usage", nil)); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("post-deletion usage status=%d, want 401", resp.StatusCode)
	}
}

func TestDeviceListAndRevoke(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "ken")
	resp := c.do(c.signedReq("GET", "/v1/devices", nil))
	var body struct {
		Devices []struct {
			ID string `json:"id"`
		} `json:"devices"`
	}
	decode(t, resp, &body)
	if len(body.Devices) != 1 {
		t.Fatalf("want 1 device, got %d", len(body.Devices))
	}
	// A second account cannot see or revoke this device.
	c2 := h.login(t, "laura")
	if resp := c2.do(c2.signedReq("DELETE", "/v1/devices/"+body.Devices[0].ID, nil)); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("cross-account device revoke status=%d, want 404", resp.StatusCode)
	}
}
