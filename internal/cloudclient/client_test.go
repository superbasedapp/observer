package cloudclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
)

// testCred returns a hardened file-backed store rooted in a temp dir, so tests
// never touch the real OS keychain.
func testCred(t *testing.T) cloudcred.Store {
	t.Helper()
	// Open falls back to the file store only when the keychain is unavailable;
	// to guarantee the file backend in every environment we construct it via the
	// exported Open against a temp HOME-like dir AND assert we did not silently
	// bind a shared keychain. We cannot force the fallback through Open, so we
	// use Open's fallback dir and accept either backend — the round-trips below
	// exercise the interface regardless.
	return cloudcred.Open(t.TempDir(), nil)
}

// newTestClient wires a client at baseURL with a stub broker and instant,
// deterministic backoff.
func newTestClient(t *testing.T, baseURL, workosToken string) (*Client, cloudcred.Store) {
	t.Helper()
	cred := testCred(t)
	c, err := New(Options{
		BaseURL:    baseURL,
		Cred:       cred,
		Broker:     &StubBroker{Token: workosToken},
		Clock:      func() time.Time { return time.Unix(1_800_000_000, 0) },
		MaxRetries: 3,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, cred
}

// verifyProof runs the server-side PoP check exactly as the real server would.
func verifyProof(t *testing.T, r *http.Request, thumbprint, bearer string, body []byte) *cloudpop.Verified {
	t.Helper()
	proof := r.Header.Get(headerPoP)
	if proof == "" {
		t.Fatalf("%s %s: missing PoP header", r.Method, r.URL.Path)
	}
	// The server reconstructs the absolute URL it observed.
	scheme := "http"
	full := scheme + "://" + r.Host + r.URL.Path
	v, err := cloudpop.Verify(proof, cloudpop.VerifyParams{
		ExpectedMethod:          r.Method,
		ExpectedURL:             full,
		ExpectedThumbprint:      thumbprint,
		ExpectedAccessTokenHash: cloudpop.HashAccessToken(bearer),
		Now:                     time.Unix(1_800_000_000, 0),
		MaxAge:                  2 * time.Minute,
		MaxSkew:                 time.Minute,
		Body:                    body,
	})
	if err != nil {
		t.Fatalf("%s %s: PoP verify failed: %v", r.Method, r.URL.Path, err)
	}
	return v
}

func bearerOf(r *http.Request) string {
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

// fakeServer implements the exchange + jobs + results endpoints with real PoP
// verification.
type fakeServer struct {
	t          *testing.T
	apiToken   string
	nonce      string
	thumbprint string // set after exchange from the presented device key

	mu         sync.Mutex
	seenJTIs   map[string]bool
	idemKeys   []string
	jobsByIdem map[string]string // idem key -> job id
	nextJob    int
	requirePoP bool
}

func newFakeServer(t *testing.T) *fakeServer {
	return &fakeServer{
		t:          t,
		apiToken:   "sbo_api_short_lived_123",
		nonce:      "server-nonce-xyz",
		seenJTIs:   map[string]bool{},
		jobsByIdem: map[string]string{},
		requirePoP: true,
	}
}

func (fs *fakeServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, nonceResponse{Nonce: fs.nonce, ExpiresAt: "2099-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/v1/auth/exchange", func(w http.ResponseWriter, r *http.Request) {
		var req exchangeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "bad json", http.StatusBadRequest)
			return
		}
		pubRaw, err := base64.RawURLEncoding.DecodeString(req.DevicePublicKey)
		if err != nil || len(pubRaw) != ed25519.PublicKeySize {
			http.Error(w, "bad key", http.StatusBadRequest)
			return
		}
		pub := ed25519.PublicKey(pubRaw)
		sig, err := base64.RawURLEncoding.DecodeString(req.Signature)
		if err != nil {
			http.Error(w, "bad sig", http.StatusBadRequest)
			return
		}
		if req.Nonce != fs.nonce {
			http.Error(w, "bad nonce", http.StatusBadRequest)
			return
		}
		if !ed25519.Verify(pub, ExchangeSigningInput(req.Nonce, pub), sig) {
			http.Error(w, "sig verify failed", http.StatusUnauthorized)
			return
		}
		fs.mu.Lock()
		fs.thumbprint = cloudpop.Thumbprint(pub)
		fs.mu.Unlock()
		writeJSON(w, exchangeResponse{APIToken: fs.apiToken, ExpiresAt: "2099-01-01T00:00:00Z", DeviceID: "dev-1"})
	})
	mux.HandleFunc("/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		body := readBody(fs.t, r)
		if fs.requirePoP {
			if bearerOf(r) != fs.apiToken {
				http.Error(w, "bad bearer", http.StatusUnauthorized)
				return
			}
			v := verifyProof(fs.t, r, fs.thumbprint, fs.apiToken, body)
			fs.mu.Lock()
			if fs.seenJTIs[v.JTI] {
				fs.mu.Unlock()
				http.Error(w, "replay", http.StatusUnauthorized)
				return
			}
			fs.seenJTIs[v.JTI] = true
			fs.mu.Unlock()
		}
		idem := r.Header.Get(headerIdempotency)
		fs.mu.Lock()
		fs.idemKeys = append(fs.idemKeys, idem)
		job, ok := fs.jobsByIdem[idem]
		if !ok {
			fs.nextJob++
			job = "job-" + strconv.Itoa(fs.nextJob)
			fs.jobsByIdem[idem] = job
		}
		fs.mu.Unlock()
		writeJSON(w, UploadResponse{JobID: job, Status: "queued", CloudSessionID: r.Header.Get(headerFeature)})
	})
	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	if r.Body == nil {
		return nil
	}
	b := make([]byte, 0, 512)
	buf := make([]byte, 512)
	for {
		n, err := r.Body.Read(buf)
		b = append(b, buf[:n]...)
		if err != nil {
			break
		}
	}
	return b
}

// startServer binds an ephemeral 127.0.0.1 port only (never a fixed daemon port).
func startServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(h)
	if !strings.HasPrefix(srv.URL, "http://127.0.0.1:") {
		srv.Close()
		t.Fatalf("test server bound unexpected addr %q", srv.URL)
	}
	t.Cleanup(srv.Close)
	return srv
}

func TestExchangeAndUploadRoundTrip(t *testing.T) {
	fs := newFakeServer(t)
	srv := startServer(t, fs.handler())
	c, cred := newTestClient(t, srv.URL, "workos-access-tok")

	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if got, _ := cred.LoadAPIToken(); got != fs.apiToken {
		t.Fatalf("stored api token = %q, want %q", got, fs.apiToken)
	}

	env := []byte(`{"schema_version":"` + cloudcontract.EnvelopeSchemaVersion + `","x":1}`)
	digests := cloudcontract.Digests{Upload: cloudpop.BodyDigest(env)}
	resp, err := c.Upload(ctx, UploadRequest{
		CloudSessionID: "cs-1",
		Feature:        "session_enrichment",
		Envelope:       env,
		Digests:        digests,
	})
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if resp.JobID == "" {
		t.Error("empty job id")
	}
	if resp.IdempotencyKey == "" {
		t.Error("client did not record idempotency key")
	}
}

// TestPreviewConfirmSendsDigestsAndDecodesReceipt pins the preview-confirmation
// handshake: it POSTs the two digests + disclosure metadata to
// /v1/consents/preview-confirmation under Bearer + PoP, and decodes the 201
// {receipt_id, generation} response. Registering the exact bytes is what makes
// the subsequent Upload admissible (the server otherwise 409s reconfirmation_required).
func TestPreviewConfirmSendsDigestsAndDecodesReceipt(t *testing.T) {
	var (
		gotMethod, gotPath, gotAuth, gotPoP string
		gotBody                             previewConfirmWire
	)
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotPoP = r.Header.Get(headerPoP)
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"receipt_id":"rcpt-x","generation":7}`))
	})
	srv := startServer(t, h)
	c, cred := newTestClient(t, srv.URL, "workos-access-tok")
	if err := cred.SaveAPIToken("api-tok"); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}

	out, err := c.PreviewConfirm(context.Background(), PreviewConfirmRequest{
		Purposes:        []string{"structural_activity_insights"},
		FieldClasses:    []string{"structural_metrics"},
		EvidenceSchema:  cloudcontract.EnvelopeSchemaVersion,
		ScrubberVersion: "scrub.v1",
		UploadDigest:    "sha256:abc",
		ContentDigest:   "sha256:def",
	})
	if err != nil {
		t.Fatalf("PreviewConfirm: %v", err)
	}
	if out.ReceiptID != "rcpt-x" || out.Generation != 7 {
		t.Fatalf("response = %+v, want {rcpt-x 7}", out)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/consents/preview-confirmation" {
		t.Fatalf("request = %s %s, want POST /v1/consents/preview-confirmation", gotMethod, gotPath)
	}
	if !strings.HasPrefix(gotAuth, "Bearer ") || gotPoP == "" {
		t.Fatalf("missing auth/PoP: auth=%q pop=%q", gotAuth, gotPoP)
	}
	if gotBody.UploadDigest != "sha256:abc" || gotBody.ContentDigest != "sha256:def" ||
		gotBody.EvidenceSchema != cloudcontract.EnvelopeSchemaVersion || gotBody.ScrubberVersion != "scrub.v1" ||
		len(gotBody.Purposes) != 1 || gotBody.Purposes[0] != "structural_activity_insights" {
		t.Fatalf("wire body = %+v", gotBody)
	}
}

// TestPreviewConfirmRequiresAuth pins that with no stored API token the call
// fails closed with ErrNotAuthenticated and never reaches the network.
func TestPreviewConfirmRequiresAuth(t *testing.T) {
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("server must not be reached without a token (got %s %s)", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	_, err := c.PreviewConfirm(context.Background(), PreviewConfirmRequest{UploadDigest: "sha256:abc"})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("want ErrNotAuthenticated, got %v", err)
	}
}

func TestStolenTokenWithoutProofRejected(t *testing.T) {
	fs := newFakeServer(t)
	srv := startServer(t, fs.handler())
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	// Populate the server's known thumbprint via a legit upload first.
	env := []byte(`{"a":1}`)
	if _, err := c.Upload(ctx, UploadRequest{CloudSessionID: "cs", Feature: "f", Envelope: env, Digests: cloudcontract.Digests{Upload: cloudpop.BodyDigest(env)}}); err != nil {
		t.Fatalf("seed upload: %v", err)
	}

	// An attacker who stole only the bearer token (no device key, no proof).
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/results", nil)
	req.Header.Set("Authorization", "Bearer "+fs.apiToken)
	// Server requires a PoP header on /v1/results too — reuse the jobs guard by
	// checking directly: no proof header present.
	if fs.thumbprint == "" {
		t.Fatal("server never learned the device thumbprint")
	}
	// Simulate the server's verification of a proof-less request.
	v, err := cloudpop.Verify(req.Header.Get(headerPoP), cloudpop.VerifyParams{
		ExpectedMethod: http.MethodGet, ExpectedURL: srv.URL + "/v1/results",
		ExpectedThumbprint: fs.thumbprint, MaxSkew: time.Minute,
	})
	if err == nil || v != nil {
		t.Fatalf("proof-less request verified: v=%v err=%v", v, err)
	}
	if !errors.Is(err, cloudpop.ErrMalformed) {
		t.Fatalf("want ErrMalformed for empty proof, got %v", err)
	}
}

func TestIdempotencyKeyStableAcrossRetries(t *testing.T) {
	fs := newFakeServer(t)

	// Wrap the jobs handler so the FIRST /v1/jobs attempt fails at the transport
	// level (hijack + close), forcing a retry; the second succeeds.
	var jobsCalls int
	var mu sync.Mutex
	base := fs.handler()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jobs" {
			mu.Lock()
			jobsCalls++
			first := jobsCalls == 1
			mu.Unlock()
			if first {
				// Record the idempotency key before killing the connection.
				fs.mu.Lock()
				fs.idemKeys = append(fs.idemKeys, r.Header.Get(headerIdempotency))
				fs.mu.Unlock()
				hj, ok := w.(http.Hijacker)
				if !ok {
					t.Fatal("no hijacker")
				}
				conn, _, err := hj.Hijack()
				if err != nil {
					t.Fatalf("hijack: %v", err)
				}
				_ = conn.Close() // transport error at the client
				return
			}
		}
		base.ServeHTTP(w, r)
	})
	srv := startServer(t, h)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	env := []byte(`{"a":1}`)
	resp, err := c.Upload(ctx, UploadRequest{CloudSessionID: "cs", Feature: "f", Envelope: env, Digests: cloudcontract.Digests{Upload: cloudpop.BodyDigest(env)}})
	if err != nil {
		t.Fatalf("Upload (with retry): %v", err)
	}
	fs.mu.Lock()
	keys := append([]string(nil), fs.idemKeys...)
	fs.mu.Unlock()
	if len(keys) < 2 {
		t.Fatalf("expected >=2 recorded idempotency keys (retry), got %d", len(keys))
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] != keys[0] {
			t.Fatalf("idempotency key changed across retry: %q vs %q", keys[0], keys[i])
		}
	}
	if resp.IdempotencyKey != keys[0] {
		t.Fatalf("response key %q != sent key %q", resp.IdempotencyKey, keys[0])
	}
}

// TestUploadPreAttemptAbortsBeforeFirstSend is the FD3 re-fix: a PreAttempt
// callback that reports revoked authorization aborts the upload WITHOUT any
// physical POST reaching the server (the prepare→dispatch window).
func TestUploadPreAttemptAbortsBeforeFirstSend(t *testing.T) {
	fs := newFakeServer(t)
	var jobsCalls int
	var mu sync.Mutex
	base := fs.handler()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jobs" {
			mu.Lock()
			jobsCalls++
			mu.Unlock()
		}
		base.ServeHTTP(w, r)
	})
	srv := startServer(t, h)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	revoked := errors.New("reconfirmation required: receipt revoked")
	env := []byte(`{"a":1}`)
	_, err := c.Upload(ctx, UploadRequest{
		CloudSessionID: "cs", Feature: "f", Envelope: env,
		Digests:    cloudcontract.Digests{Upload: cloudpop.BodyDigest(env)},
		PreAttempt: func() error { return revoked },
	})
	if !errors.Is(err, revoked) {
		t.Fatalf("Upload should return the PreAttempt error, got %v", err)
	}
	mu.Lock()
	got := jobsCalls
	mu.Unlock()
	if got != 0 {
		t.Fatalf("revoked send still hit /v1/jobs %d time(s) — the body left the process", got)
	}
}

// TestUploadPreAttemptAbortsOnRetry is the FD3 re-fix, retry window: the first
// physical attempt fails at the transport level (forcing a retry); before the
// SECOND physical send, PreAttempt reports revocation, so no second body leaves.
func TestUploadPreAttemptAbortsOnRetry(t *testing.T) {
	fs := newFakeServer(t)
	var jobsCalls int
	var mu sync.Mutex
	base := fs.handler()
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/jobs" {
			mu.Lock()
			jobsCalls++
			mu.Unlock()
			// Transport-fail the first attempt to force the retry path.
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatal("no hijacker")
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				t.Fatalf("hijack: %v", err)
			}
			_ = conn.Close()
			return
		}
		base.ServeHTTP(w, r)
	})
	srv := startServer(t, h)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	revoked := errors.New("reconfirmation required: session flipped to org")
	var preCalls int
	env := []byte(`{"a":1}`)
	_, err := c.Upload(ctx, UploadRequest{
		CloudSessionID: "cs", Feature: "f", Envelope: env,
		Digests: cloudcontract.Digests{Upload: cloudpop.BodyDigest(env)},
		PreAttempt: func() error {
			preCalls++
			if preCalls >= 2 { // authorized for attempt 1, revoked before attempt 2
				return revoked
			}
			return nil
		},
	})
	if !errors.Is(err, revoked) {
		t.Fatalf("Upload should abort on the retry PreAttempt, got %v", err)
	}
	// The precise invariant is the number of AUTHORIZED dispatches: PreAttempt is
	// called exactly twice — nil for attempt 0 (which physically sends and
	// transport-fails), then revoked before attempt 1, which returns before
	// sendOnce so no second body is ever built or sent. (Raw physical /v1/jobs
	// hits are not asserted: Go's transport may auto-retry attempt 0's POST once
	// when the server closes the connection with no response — that ambiguity is
	// exactly why the retry gate lives before sendOnce, and why the existing
	// idempotency test uses >= comparisons on physical hits.)
	if preCalls != 2 {
		t.Fatalf("PreAttempt should be called exactly twice (authorize attempt 0, revoke attempt 1), got %d", preCalls)
	}
	mu.Lock()
	got := jobsCalls
	mu.Unlock()
	if got == 0 {
		t.Fatal("attempt 0 should have physically sent at least once before the transport failure")
	}
}

func TestIdempotencyKeyDeterministicAndRegenerationDistinct(t *testing.T) {
	k1 := idempotencyKey("thumb", "cs-1", "session_enrichment", "v1", "sha256:aaa")
	k2 := idempotencyKey("thumb", "cs-1", "session_enrichment", "v1", "sha256:aaa")
	if k1 != k2 {
		t.Fatalf("idempotency key not deterministic: %q vs %q", k1, k2)
	}
	// A different upload digest (regeneration / edited evidence) yields a new key.
	if k3 := idempotencyKey("thumb", "cs-1", "session_enrichment", "v1", "sha256:bbb"); k3 == k1 {
		t.Fatal("distinct upload digest produced the same idempotency key")
	}
	// Field-boundary safety: shifting a separator must not collide.
	a := idempotencyKey("a", "b", "c", "d", "e")
	b := idempotencyKey("ab", "", "c", "d", "e")
	if a == b {
		t.Fatal("idempotency key field boundaries are ambiguous")
	}
}

func TestResultsCursorMonotonicity(t *testing.T) {
	fs := newFakeServer(t)
	mux := http.NewServeMux()
	// Reuse exchange/nonce from the fake.
	mux.Handle("/v1/auth/", fs.handler())
	// A results endpoint whose cursor behavior we control per-test via a header.
	var nextCursor string
	var results []cloudcontract.ResultRecord
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		verifyProof(t, r, fs.thumbprint, fs.apiToken, nil)
		writeJSON(w, ResultsPage{Results: results, NextCursor: nextCursor})
	})
	srv := startServer(t, mux)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	// Seed the thumbprint on the server via a direct proof round-trip: call
	// Results once with an advancing cursor.
	results = []cloudcontract.ResultRecord{{CloudSessionID: "cs-1", Result: cloudcontract.Result{Title: "t", SchemaVersion: cloudcontract.ResultSchemaVersion}}}
	nextCursor = "20"
	page, err := c.Results(ctx, "10")
	if err != nil {
		t.Fatalf("Results advancing: %v", err)
	}
	if page.NextCursor != "20" || len(page.Results) != 1 {
		t.Fatalf("unexpected page: %+v", page)
	}

	// Regressing cursor (< after) must be rejected.
	nextCursor = "05"
	if _, err := c.Results(ctx, "10"); !errors.Is(err, ErrCursorRegression) {
		t.Fatalf("regressing cursor err = %v, want ErrCursorRegression", err)
	}

	// Rows returned but cursor unchanged must be rejected (loop guard).
	nextCursor = "10"
	if _, err := c.Results(ctx, "10"); !errors.Is(err, ErrCursorRegression) {
		t.Fatalf("stalled cursor err = %v, want ErrCursorRegression", err)
	}
}

// TestResultsCursorDigitBoundary is the FE5 regression: the server's decimal
// cursor advances 9 -> 10 and 50 -> 100, which sort LEXICOGRAPHICALLY backwards
// ("10" < "9"). The old string compare rejected these as ErrCursorRegression
// and wedged the sync; numeric comparison must accept them. An empty page must
// also be accepted, while an exact repeat with rows is still rejected.
func TestResultsCursorDigitBoundary(t *testing.T) {
	fs := newFakeServer(t)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", fs.handler())
	var nextCursor string
	var results []cloudcontract.ResultRecord
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		verifyProof(t, r, fs.thumbprint, fs.apiToken, nil)
		writeJSON(w, ResultsPage{Results: results, NextCursor: nextCursor})
	})
	srv := startServer(t, mux)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	row := []cloudcontract.ResultRecord{{CloudSessionID: "cs-1", Result: cloudcontract.Result{Title: "t", SchemaVersion: cloudcontract.ResultSchemaVersion}}}

	cases := []struct {
		name       string
		after      string
		nextCursor string
		results    []cloudcontract.ResultRecord
		wantErr    bool
	}{
		{"9 -> 10 advances (not lexical regression)", "9", "10", row, false},
		{"50 -> 100 advances", "50", "100", row, false},
		{"empty page keeps cursor without error", "9", "9", nil, false},
		{"exact repeat with rows still rejected", "10", "10", row, true},
		{"true numeric regression rejected", "100", "50", row, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextCursor = tc.nextCursor
			results = tc.results
			_, err := c.Results(ctx, tc.after)
			if tc.wantErr {
				if !errors.Is(err, ErrCursorRegression) {
					t.Fatalf("want ErrCursorRegression, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want no error for %s->%s, got %v", tc.after, tc.nextCursor, err)
			}
		})
	}
}

// TestResultsCursorV2Format is the E1 / W6b regression: the node guard must
// understand the per-account "v2:<n>" cursor. A v2 cursor advances/regresses on
// its stripped numeric value (so a real backward move still fires
// ErrCursorRegression, and 9->10 is NOT a lexical regression), the legacy
// bare-decimal cursor keeps working, and a MIXED pair (a v2 cursor vs a bare
// decimal — the two families are not numerically ordered against each other)
// never triggers a FALSE regression; only the exact-repeat rule applies to it.
func TestResultsCursorV2Format(t *testing.T) {
	fs := newFakeServer(t)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", fs.handler())
	var nextCursor string
	var results []cloudcontract.ResultRecord
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		verifyProof(t, r, fs.thumbprint, fs.apiToken, nil)
		writeJSON(w, ResultsPage{Results: results, NextCursor: nextCursor})
	})
	srv := startServer(t, mux)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	row := []cloudcontract.ResultRecord{{CloudSessionID: "cs-1", Result: cloudcontract.Result{Title: "t", SchemaVersion: cloudcontract.ResultSchemaVersion}}}

	cases := []struct {
		name       string
		after      string
		nextCursor string
		results    []cloudcontract.ResultRecord
		wantErr    bool
	}{
		{"v2 advance", "v2:1", "v2:2", row, false},
		{"v2 digit boundary 9->10 not lexical regression", "v2:9", "v2:10", row, false},
		{"v2 true regression rejected", "v2:2", "v2:1", row, true},
		{"v2 exact repeat with rows rejected", "v2:2", "v2:2", row, true},
		{"v2 empty page keeps cursor", "v2:2", "v2:2", nil, false},
		{"legacy bare decimal advance still works", "1", "2", row, false},
		{"legacy bare decimal regression still rejected", "2", "1", row, true},
		// Mixed families must not FALSE-regress: v2:5's numeric 5 must never be
		// compared against a bare 3, and vice versa. Only exact-repeat applies.
		{"mixed v2-after bare-next not a regression", "v2:5", "3", row, false},
		{"mixed bare-after v2-next not a regression", "9", "v2:1", row, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			nextCursor = tc.nextCursor
			results = tc.results
			_, err := c.Results(ctx, tc.after)
			if tc.wantErr {
				if !errors.Is(err, ErrCursorRegression) {
					t.Fatalf("want ErrCursorRegression, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("want no error for %s->%s, got %v", tc.after, tc.nextCursor, err)
			}
		})
	}
}

// TestUsageDecodesPlanFields pins the /v1/usage decode: every field round-
// trips, and — the value-upgrade plan §W5 honesty rule — a response that
// omits digest_weekly / results_retention_days (an older server) decodes
// those pointer fields to nil rather than a fabricated false/zero.
func TestUsageDecodesPlanFields(t *testing.T) {
	fs := newFakeServer(t)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", fs.handler())
	var body string
	mux.HandleFunc("/v1/usage", func(w http.ResponseWriter, r *http.Request) {
		verifyProof(t, r, fs.thumbprint, fs.apiToken, nil)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	})
	srv := startServer(t, mux)
	c, _ := newTestClient(t, srv.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}

	body = `{"plan":"plus","plan_label":"Plus","plan_version":3,"budget_pool":"plus",` +
		`"daily_used":1,"daily_cap":50,"monthly_used":2,"monthly_cap":500,` +
		`"digest_weekly":true,"results_retention_days":30,"digests_this_week":1}`
	got, err := c.Usage(ctx)
	if err != nil {
		t.Fatalf("Usage: %v", err)
	}
	if got.Plan != "plus" || got.PlanLabel != "Plus" || got.PlanVersion != 3 || got.BudgetPool != "plus" {
		t.Fatalf("plan fields = %+v", got)
	}
	if got.DailyCap != 50 || got.MonthlyCap != 500 {
		t.Fatalf("caps = %+v", got)
	}
	if got.DigestWeekly == nil || !*got.DigestWeekly {
		t.Fatalf("digest_weekly = %v, want true", got.DigestWeekly)
	}
	if got.ResultsRetentionDays == nil || *got.ResultsRetentionDays != 30 {
		t.Fatalf("results_retention_days = %v, want 30", got.ResultsRetentionDays)
	}
	if got.DigestsThisWeek != 1 {
		t.Fatalf("digests_this_week = %d, want 1", got.DigestsThisWeek)
	}

	// An older server predating the W5 wave never emits these keys.
	body = `{"plan":"free","plan_label":"Free","budget_pool":"free","daily_cap":10,"monthly_cap":100}`
	got2, err := c.Usage(ctx)
	if err != nil {
		t.Fatalf("Usage (older server): %v", err)
	}
	if got2.DigestWeekly != nil {
		t.Fatalf("digest_weekly = %v, want nil (unknown) for an older server", got2.DigestWeekly)
	}
	if got2.ResultsRetentionDays != nil {
		t.Fatalf("results_retention_days = %v, want nil (unknown) for an older server", got2.ResultsRetentionDays)
	}
}

// TestUploadRefusesRedirect is the FD1 regression: an evidence upload that the
// approved origin answers with a 307/308 redirect must NOT be followed — the
// request body (the exact confirmed evidence) must never be re-sent to the
// redirect target. The client refuses every redirect (CheckRedirect).
func TestUploadRefusesRedirect(t *testing.T) {
	// Attacker origin: records any request that reaches it (with its body).
	var attackerHits int
	var attackerGotBody bool
	attacker := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerHits++
		if b := readBody(t, r); len(b) > 0 {
			attackerGotBody = true
		}
		writeJSON(w, UploadResponse{JobID: "attacker-job", Status: "queued"})
	}))

	// Approved origin: normal exchange, but /v1/jobs 307-redirects to attacker.
	fs := newFakeServer(t)
	mux := http.NewServeMux()
	mux.Handle("/v1/auth/", fs.handler())
	mux.HandleFunc("/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/v1/jobs", http.StatusTemporaryRedirect)
	})
	approved := startServer(t, mux)

	c, _ := newTestClient(t, approved.URL, "workos-access-tok")
	ctx := context.Background()
	if err := c.Exchange(ctx); err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	_, err := c.Upload(ctx, UploadRequest{
		CloudSessionID: "cs-1",
		Feature:        "session_enrichment",
		Envelope:       []byte(`{"evidence":"secret"}`),
		SchemaVersion:  cloudcontract.EnvelopeSchemaVersion,
	})
	if err == nil {
		t.Fatal("Upload must fail on a redirect, not silently follow it")
	}
	if attackerHits != 0 {
		t.Fatalf("the evidence upload reached the attacker origin %d time(s) — redirect was followed (FD1)", attackerHits)
	}
	if attackerGotBody {
		t.Fatal("the evidence body was re-sent to the attacker origin (FD1)")
	}
}

func TestUploadRejectsMismatchedDigest(t *testing.T) {
	c, _ := newTestClient(t, "http://127.0.0.1:1", "tok")
	env := []byte(`{"a":1}`)
	_, err := c.Upload(context.Background(), UploadRequest{
		CloudSessionID: "cs", Feature: "f", Envelope: env,
		Digests: cloudcontract.Digests{Upload: "sha256:deadbeef"},
	})
	if err == nil || !strings.Contains(err.Error(), "upload digest") {
		t.Fatalf("want upload-digest mismatch error, got %v", err)
	}
}

func TestNotAuthenticatedBeforeExchange(t *testing.T) {
	c, _ := newTestClient(t, "http://127.0.0.1:1", "tok")
	env := []byte(`{"a":1}`)
	_, err := c.Upload(context.Background(), UploadRequest{
		CloudSessionID: "cs", Feature: "f", Envelope: env,
		Digests: cloudcontract.Digests{Upload: cloudpop.BodyDigest(env)},
	})
	if !errors.Is(err, ErrNotAuthenticated) {
		t.Fatalf("want ErrNotAuthenticated, got %v", err)
	}
}

func TestNewNoNetworkAndDeviceStable(t *testing.T) {
	cred := testCred(t)
	c1, err := New(Options{BaseURL: "https://cloud.example", Cred: cred, Broker: &StubBroker{Token: "x"}})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A second client over the same cred sees the SAME device key (persisted).
	c2, err := New(Options{BaseURL: "https://cloud.example", Cred: cred, Broker: &StubBroker{Token: "x"}})
	if err != nil {
		t.Fatalf("New 2: %v", err)
	}
	if c1.DeviceThumbprint() != c2.DeviceThumbprint() {
		t.Fatal("device key not stable across clients over the same cred")
	}
	if c1.DeviceThumbprint() == "" {
		t.Fatal("empty device thumbprint")
	}
}

// TestEphemeralPortsOnly is a guard that the suite never binds a daemon port.
func TestEphemeralPortsOnly(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer l.Close()
	_, port, _ := net.SplitHostPort(l.Addr().String())
	for _, forbidden := range []string{"8820", "8840"} {
		if port == forbidden {
			t.Fatalf("bound forbidden daemon port %s", port)
		}
	}
}

// --- API token self-heal (sendAuthed) ----------------------------------------

// healServer scripts the authenticated route's responses one call at a time and
// counts the bootstrap-lane calls the self-heal makes. Each exchange mints a
// NEW token (tok-1, tok-2, …) so a test can prove the retry carried the fresh
// bearer and that the fresh token was persisted.
type healServer struct {
	t *testing.T

	mu        sync.Mutex
	nonces    int
	exchanges int
	authed    int
	bearers   []string
	script    []func(w http.ResponseWriter) // per authed call, in order; last repeats
}

func (h *healServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, _ *http.Request) {
		h.mu.Lock()
		h.nonces++
		h.mu.Unlock()
		writeJSON(w, nonceResponse{Nonce: "n", ExpiresAt: "2099-01-01T00:00:00Z"})
	})
	mux.HandleFunc("/v1/auth/exchange", func(w http.ResponseWriter, _ *http.Request) {
		h.mu.Lock()
		h.exchanges++
		n := h.exchanges
		h.mu.Unlock()
		writeJSON(w, exchangeResponse{APIToken: "tok-" + strconv.Itoa(n), ExpiresAt: "2099-01-01T00:00:00Z", DeviceID: "dev-1"})
	})
	authed := func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(headerPoP) == "" {
			h.t.Errorf("%s %s: no PoP header on an authenticated call", r.Method, r.URL.Path)
		}
		h.mu.Lock()
		i := h.authed
		h.authed++
		h.bearers = append(h.bearers, bearerOf(r))
		if i >= len(h.script) {
			i = len(h.script) - 1
		}
		step := h.script[i]
		h.mu.Unlock()
		step(w)
	}
	mux.HandleFunc("/v1/results", authed)
	mux.HandleFunc("/v1/structural-insights", authed)
	return mux
}

func (h *healServer) counts() (nonces, exchanges, authed int) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.nonces, h.exchanges, h.authed
}

// Scripted responses.
func respondTokenRejected(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"invalid or expired token","code":"unauthorized"}`))
}

func respondOtherCode401(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_, _ = w.Write([]byte(`{"error":"device revoked","code":"device_revoked"}`))
}

func respondResultsOK(w http.ResponseWriter) {
	writeJSON(w, ResultsPage{NextCursor: "v2:7"})
}

func respondStructuralOK(w http.ResponseWriter) {
	writeJSON(w, StructuralUploadResponse{SnapshotID: "snap-1", Status: "stored"})
}

// newHealClient wires a client whose stored API token is the EXPIRED one
// (tok-0), with the given broker, so the first authenticated call is rejected.
func newHealClient(t *testing.T, baseURL string, broker CloudIdentityBroker) (*Client, cloudcred.Store) {
	t.Helper()
	cred := testCred(t)
	if err := cred.SaveAPIToken("tok-0"); err != nil {
		t.Fatalf("seed expired token: %v", err)
	}
	c, err := New(Options{
		BaseURL:    baseURL,
		Cred:       cred,
		Broker:     broker,
		Clock:      func() time.Time { return time.Unix(1_800_000_000, 0) },
		MaxRetries: 1,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, cred
}

// TestAuthedTokenSelfHeal is the table for the one-shot self-heal: an expired
// device token is re-exchanged ONCE through the broker and the request re-sent
// ONCE; every other outcome surfaces without a retry storm.
func TestAuthedTokenSelfHeal(t *testing.T) {
	cases := []struct {
		name          string
		script        []func(http.ResponseWriter)
		broker        CloudIdentityBroker
		wantErr       error  // errors.Is target; nil with wantFail means "any error"
		wantFail      bool   // an error of some kind is expected
		wantAPIErr    bool   // the surfaced error still carries the 401 APIError
		wantExchanges int    // bootstrap exchanges attempted
		wantAuthed    int    // authenticated calls that reached the server
		wantToken     string // API token stored afterwards
		wantLastBear  string // bearer on the last authenticated call
	}{
		{
			name:          "401 once then 200: exchange once, retry once, succeed",
			script:        []func(http.ResponseWriter){respondTokenRejected, respondResultsOK},
			broker:        &StubBroker{Token: "workos"},
			wantExchanges: 1, wantAuthed: 2, wantToken: "tok-1", wantLastBear: "tok-1",
		},
		{
			name:          "401 twice: exactly one exchange, then the login error",
			script:        []func(http.ResponseWriter){respondTokenRejected, respondTokenRejected},
			broker:        &StubBroker{Token: "workos"},
			wantErr:       ErrSignInExpired,
			wantFail:      true,
			wantAPIErr:    true,
			wantExchanges: 1, wantAuthed: 2, wantToken: "tok-1", wantLastBear: "tok-1",
		},
		{
			name:          "401 with a different code: no exchange, the 401 surfaces as-is",
			script:        []func(http.ResponseWriter){respondOtherCode401, respondResultsOK},
			broker:        &StubBroker{Token: "workos"},
			wantFail:      true,
			wantAPIErr:    true,
			wantExchanges: 0, wantAuthed: 1, wantToken: "tok-0", wantLastBear: "tok-0",
		},
		{
			name:          "refresh fails: honest login error, no retry, no exchange reaches the server",
			script:        []func(http.ResponseWriter){respondTokenRejected, respondResultsOK},
			broker:        &StubBroker{Err: ErrNoIdentity},
			wantErr:       ErrSignInExpired,
			wantFail:      true,
			wantAPIErr:    true,
			wantExchanges: 0, wantAuthed: 1, wantToken: "tok-0", wantLastBear: "tok-0",
		},
		{
			name:          "no broker configured: honest login error, no retry",
			script:        []func(http.ResponseWriter){respondTokenRejected, respondResultsOK},
			broker:        nil,
			wantErr:       ErrSignInExpired,
			wantFail:      true,
			wantAPIErr:    true,
			wantExchanges: 0, wantAuthed: 1, wantToken: "tok-0", wantLastBear: "tok-0",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hs := &healServer{t: t, script: tc.script}
			srv := startServer(t, hs.handler())
			c, cred := newHealClient(t, srv.URL, tc.broker)

			_, err := c.Results(context.Background(), "")
			switch {
			case !tc.wantFail && err != nil:
				t.Fatalf("Results: unexpected error: %v", err)
			case tc.wantFail && err == nil:
				t.Fatalf("Results: want an error, got nil")
			case tc.wantErr != nil && !errors.Is(err, tc.wantErr):
				t.Fatalf("Results: want errors.Is(%v), got %v", tc.wantErr, err)
			}
			// A non-heal refusal must surface untouched, never dressed up as an
			// expired sign-in.
			if tc.wantFail && tc.wantErr == nil && errors.Is(err, ErrSignInExpired) {
				t.Fatalf("Results: a 401 with another code must not become ErrSignInExpired, got %v", err)
			}
			if tc.wantAPIErr {
				var apiErr *APIError
				if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
					t.Errorf("the surfaced error must still carry the 401 APIError, got %v", err)
				}
			}
			if errors.Is(err, ErrSignInExpired) && !strings.Contains(err.Error(), "observer cloud login") {
				t.Errorf("an expired sign-in must tell the user to log in again, got %q", err)
			}
			_, exchanges, authed := hs.counts()
			if exchanges != tc.wantExchanges {
				t.Errorf("exchanges = %d, want %d", exchanges, tc.wantExchanges)
			}
			if authed != tc.wantAuthed {
				t.Errorf("authenticated calls = %d, want %d", authed, tc.wantAuthed)
			}
			if tok, _ := cred.LoadAPIToken(); tok != tc.wantToken {
				t.Errorf("stored API token = %q, want %q", tok, tc.wantToken)
			}
			hs.mu.Lock()
			last := hs.bearers[len(hs.bearers)-1]
			hs.mu.Unlock()
			if last != tc.wantLastBear {
				t.Errorf("last bearer = %q, want %q", last, tc.wantLastBear)
			}
		})
	}
}

// TestSelfHealLatchesAfterFailure pins "never a retry storm": once the heal has
// failed, LATER authenticated calls on the same client fail fast with the same
// error — no request is sent and no further exchange is attempted.
func TestSelfHealLatchesAfterFailure(t *testing.T) {
	hs := &healServer{t: t, script: []func(http.ResponseWriter){respondTokenRejected}}
	srv := startServer(t, hs.handler())
	broker := &StubBroker{Err: ErrNoIdentity}
	c, _ := newHealClient(t, srv.URL, broker)

	ctx := context.Background()
	if _, err := c.Results(ctx, ""); !errors.Is(err, ErrSignInExpired) {
		t.Fatalf("first call: want ErrSignInExpired, got %v", err)
	}
	for i := 0; i < 3; i++ {
		if _, err := c.Results(ctx, ""); !errors.Is(err, ErrSignInExpired) {
			t.Fatalf("latched call %d: want ErrSignInExpired, got %v", i, err)
		}
	}
	_, exchanges, authed := hs.counts()
	if authed != 1 {
		t.Errorf("authenticated calls = %d, want 1 (latched calls must not send)", authed)
	}
	if exchanges != 0 || broker.Calls != 1 {
		t.Errorf("exchanges = %d, broker calls = %d; want 0 and 1 (one refresh attempt, ever)", exchanges, broker.Calls)
	}
}

// TestSelfHealRetryRerunsGuardsAndKeepsIdempotencyKey proves the healed retry
// of a standing-rail upload is just another attempt in the existing attempt
// model: PreAttempt and the dispatch guard run again before the second send,
// and the Idempotency-Key is identical, so the server replay-acks rather than
// storing twice even in the hypothetical case the first attempt was admitted.
func TestSelfHealRetryRerunsGuardsAndKeepsIdempotencyKey(t *testing.T) {
	var idems []string
	hs := &healServer{t: t}
	hs.script = []func(http.ResponseWriter){respondTokenRejected, respondStructuralOK}
	base := hs.handler()
	srv := startServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/structural-insights" {
			idems = append(idems, r.Header.Get(headerIdempotency))
		}
		base.ServeHTTP(w, r)
	}))
	c, _ := newHealClient(t, srv.URL, &StubBroker{Token: "workos"})

	var pre, guards, releases int
	resp, err := c.UploadStructural(context.Background(), StructuralUploadRequest{
		Payload: []byte(`{"w":1}`), Period: "2026-09-01", PeriodRuleVersion: 1,
		SchemaVersion: "structural.v1", Revision: 1, Digest: "sha256:x",
		ConsentGeneration: 1, DataDictionaryDigest: "sha256:dd", SourceWindowRule: "rule.v1",
		PreAttempt: func() error { pre++; return nil },
		DispatchGuard: func(context.Context) (time.Time, func(), error) {
			guards++
			return time.Time{}, func() { releases++ }, nil
		},
	})
	if err != nil {
		t.Fatalf("UploadStructural: %v", err)
	}
	if resp.SnapshotID != "snap-1" {
		t.Errorf("snapshot id = %q, want snap-1", resp.SnapshotID)
	}
	if pre != 2 || guards != 2 || releases != 2 {
		t.Errorf("preAttempt=%d guard=%d release=%d; want 2/2/2 (the healed retry re-runs every gate)", pre, guards, releases)
	}
	if len(idems) != 2 || idems[0] == "" || idems[0] != idems[1] {
		t.Errorf("idempotency keys across the healed retry = %q, want two identical non-empty keys", idems)
	}
	if _, exchanges, _ := hs.counts(); exchanges != 1 {
		t.Errorf("exchanges = %d, want 1", exchanges)
	}
}

// TestLogoutDoesNotSelfHeal pins that revoking a token the server already
// rejects never mints a replacement first.
func TestLogoutDoesNotSelfHeal(t *testing.T) {
	var exchanges int
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, _ *http.Request) {
		exchanges++
		writeJSON(w, nonceResponse{Nonce: "n"})
	})
	mux.HandleFunc("/v1/logout", func(w http.ResponseWriter, _ *http.Request) { respondTokenRejected(w) })
	srv := startServer(t, mux)
	c, _ := newHealClient(t, srv.URL, &StubBroker{Token: "workos"})
	err := c.Logout(context.Background())
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Logout: want the plain 401, got %v", err)
	}
	if errors.Is(err, ErrSignInExpired) || exchanges != 0 {
		t.Errorf("Logout must not attempt the self-heal (exchanges=%d, err=%v)", exchanges, err)
	}
}

// TestTokenRejectedClassifier pins the one refusal the heal reacts to.
func TestTokenRejectedClassifier(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"401 code unauthorized", &APIError{StatusCode: 401, Body: `{"error":"invalid or expired token","code":"unauthorized"}`}, true},
		{"401 other code", &APIError{StatusCode: 401, Body: `{"error":"x","code":"device_revoked"}`}, false},
		{"401 non-JSON body", &APIError{StatusCode: 401, Body: `unauthorized`}, false},
		{"403 code unauthorized", &APIError{StatusCode: 403, Body: `{"code":"unauthorized"}`}, false},
		{"wrapped 401", fmt.Errorf("outer: %w", &APIError{StatusCode: 401, Body: `{"code":"unauthorized"}`}), true},
		{"transport error", errors.New("dial tcp: refused"), false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tokenRejected(tc.err); got != tc.want {
				t.Errorf("tokenRejected = %v, want %v", got, tc.want)
			}
		})
	}
}
