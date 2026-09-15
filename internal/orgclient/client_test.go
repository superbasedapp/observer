package orgclient

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// --- test doubles -----------------------------------------------------------

// memBearerStore is an in-memory BearerStore for tests.
type memBearerStore struct {
	bearer  string
	key     ed25519.PrivateKey
	vkey    string
	vkeyGen uint64
	vkeySet bool
}

func (m *memBearerStore) SaveBearer(b string) error { m.bearer = b; return nil }
func (m *memBearerStore) LoadBearer() (string, error) {
	if m.bearer == "" {
		return "", ErrNoSecret
	}
	return m.bearer, nil
}
func (m *memBearerStore) SaveAgentKey(k ed25519.PrivateKey) error { m.key = k; return nil }
func (m *memBearerStore) LoadAgentKey() (ed25519.PrivateKey, error) {
	if m.key == nil {
		return nil, ErrNoSecret
	}
	return m.key, nil
}

func (m *memBearerStore) SaveVirtualKey(key string, generation uint64) error {
	m.vkey, m.vkeyGen, m.vkeySet = key, generation, true
	return nil
}

func (m *memBearerStore) LoadVirtualKey() (string, uint64, error) {
	if !m.vkeySet {
		return "", 0, ErrNoSecret
	}
	return m.vkey, m.vkeyGen, nil
}

func (m *memBearerStore) Clear() error {
	m.bearer, m.key, m.vkey, m.vkeyGen, m.vkeySet = "", nil, "", 0, false
	return nil
}
func (m *memBearerStore) Backend() string { return "mem" }

// --- helpers ----------------------------------------------------------------

func newAgentStore(t *testing.T) *store.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.db")
	database, err := db.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database)
}

// seedActivity inserts a project + session + n actions so a push batch is
// non-empty above a zero cursor.
func seedActivity(t *testing.T, s *store.Store, n int) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "git@example.com:acme/app.git")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	acts := make([]models.Action, n)
	for i := range acts {
		acts[i] = models.Action{
			SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionReadFile, Target: "a.go", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e" + strconv.Itoa(i),
		}
	}
	if _, err := s.InsertActions(ctx, acts); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}
}

func newTestClient(t *testing.T, s *store.Store, bs BearerStore) *Client {
	t.Helper()
	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
	}
	return New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
}

// --- Enroll -----------------------------------------------------------------

func TestEnroll_Success(t *testing.T) {
	s := newAgentStore(t)
	seedActivity(t, s, 3) // pre-enrolment activity that must NOT be shared

	var gotReq orgcontract.EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotReq)
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
		})
	}))
	defer srv.Close()

	bs := &memBearerStore{}
	c := newTestClient(t, s, bs)
	enr, _, err := c.Enroll(context.Background(), srv.URL, "tok_id.secret")
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}

	// The request carried a valid base64url public key and the token.
	if gotReq.OneTimeToken != "tok_id.secret" {
		t.Errorf("token = %q", gotReq.OneTimeToken)
	}
	if pk, derr := base64.RawURLEncoding.DecodeString(gotReq.AgentPublicKey); derr != nil || len(pk) != ed25519.PublicKeySize {
		t.Errorf("agent_public_key not a valid base64url Ed25519 key: %v", derr)
	}

	// Secrets persisted; bearer matches; signing key is the private half whose
	// public key was sent.
	if bs.bearer != "bearer-xyz" || bs.key == nil {
		t.Fatalf("secrets not stored: bearer=%q keyNil=%v", bs.bearer, bs.key == nil)
	}
	wantPub, _ := base64.RawURLEncoding.DecodeString(gotReq.AgentPublicKey)
	if !ed25519.PublicKey(wantPub).Equal(bs.key.Public()) {
		t.Errorf("stored signing key does not match the enrolled public key")
	}

	// Enrolment row written with the resolved identity + server URL.
	if enr.OrgID != "org-1" || enr.UserID != "scim-42" || enr.UserEmail != "dev@acme.example" || enr.OrgServerURL != srv.URL {
		t.Errorf("enrolment row = %+v", enr)
	}

	// Cursor seeded at the current high-water ids: pre-enrolment rows are NOT
	// shareable.
	cur, _ := s.LoadPushCursor(context.Background())
	if cur.Actions == 0 || cur.Sessions == 0 {
		t.Errorf("cursor not seeded from current max ids: %+v", cur)
	}
	batch, _ := s.SelectUnpushedSince(context.Background(), cur, 1<<20, "org-1", "dev@acme.example", store.ShareOptions{}, store.ScopeOptions{})
	if !batch.Empty() {
		t.Errorf("pre-enrolment activity is shareable after enrol (cursor not seeded): %d rows", batch.RowCount())
	}
}

func TestEnroll_AuthFailure(t *testing.T) {
	s := newAgentStore(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}))
	defer srv.Close()

	bs := &memBearerStore{}
	c := newTestClient(t, s, bs)
	_, _, err := c.Enroll(context.Background(), srv.URL, "bad")
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("Enroll error = %v, want ErrAuthFailed", err)
	}
	// Nothing persisted on a failed enrol.
	if bs.bearer != "" || bs.key != nil {
		t.Errorf("secrets stored despite failed enrol")
	}
	if enr, _ := s.LoadEnrolment(context.Background()); enr != nil {
		t.Errorf("enrolment row written despite failed enrol")
	}
}

// --- PushOnce ---------------------------------------------------------------

// enrolFixture writes an enrolment row + bearer/key for an agent enrolled
// against srvURL, returning the bound public key the server verifies against.
func enrolFixture(t *testing.T, s *store.Store, bs *memBearerStore, srvURL string) ed25519.PublicKey {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	bs.bearer = "bearer-xyz"
	bs.key = priv
	if err := s.WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "org-1", OrgName: "Acme", OrgServerURL: srvURL,
		UserID: "scim-42", UserEmail: "dev@acme.example", BearerKeyID: "k",
	}); err != nil {
		t.Fatalf("WriteEnrolment: %v", err)
	}
	return pub
}

func TestPushOnce_SuccessSignsAndAdvancesCursor(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}

	var rows int
	var serverReceived []byte // the decompressed JSON the server actually got
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer bearer-xyz" {
			t.Errorf("Authorization = %q", got)
		}
		if got := r.Header.Get("Content-Encoding"); got != "gzip" {
			t.Errorf("Content-Encoding = %q, want gzip", got)
		}
		ts, _ := strconv.ParseInt(r.Header.Get("X-SBO-Timestamp"), 10, 64)
		sig, _ := base64.RawURLEncoding.DecodeString(r.Header.Get("X-SBO-Agent-Signature"))
		wire, _ := io.ReadAll(r.Body) // the gzip bytes, exactly as signed
		pub := pubFromCtx(r)
		if !ed25519.Verify(pub, orgcontract.PushSigningMessage(ts, wire), sig) {
			t.Errorf("per-push signature did not verify")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		serverReceived = gunzip(t, wire)
		env := decodeEnvelope(t, wire)
		rows = len(env.Sessions) + len(env.Actions) + len(env.APITurns) + len(env.TokenUsage)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{
			AcceptedRows: int64(rows), DedupedRows: 0, NextCursor: env.CursorTo,
		})
	}))
	defer srv.Close()

	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	seedActivity(t, s, 4) // 1 session + 4 actions, all above the (zero) cursor

	c := newTestClient(t, s, bs)
	res, err := c.PushOnce(context.Background())
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if res.Empty || res.RowCount != 5 || res.AcceptedRows != 5 {
		t.Fatalf("unexpected result: %+v (server saw %d rows)", res, rows)
	}

	// Cursor advanced past the pushed rows.
	cur, _ := s.LoadPushCursor(context.Background())
	if cur.Actions == 0 || cur.Sessions == 0 {
		t.Errorf("cursor not advanced: %+v", cur)
	}
	// A second push has nothing left.
	res2, err := c.PushOnce(context.Background())
	if err != nil || !res2.Empty {
		t.Errorf("second PushOnce = %+v, %v; want empty", res2, err)
	}
	// org_push_log recorded an "ok" row with the gzip byte count.
	last, _ := s.LastPushLog(context.Background())
	if last == nil || last.Status != "ok" || last.RowCount != 5 || last.Bytes == 0 {
		t.Errorf("push log = %+v, want ok/5/non-zero bytes", last)
	}

	// The stored last-payload is byte-for-byte what the server received
	// (the dashboard serves these bytes verbatim for the transparency view).
	stored, err := c.LastPayload(context.Background())
	if err != nil {
		t.Fatalf("LastPayload: %v", err)
	}
	if !bytes.Equal(stored, serverReceived) {
		t.Errorf("LastPayload is not byte-for-byte the pushed payload\n stored=%s\n server=%s", stored, serverReceived)
	}
}

func TestPushOnce_EmptyMakesNoCall(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Errorf("server hit for an empty batch")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	enrolFixture(t, s, bs, srv.URL) // enrolled, but no activity seeded → empty

	c := newTestClient(t, s, bs)
	res, err := c.PushOnce(context.Background())
	if err != nil || !res.Empty {
		t.Fatalf("PushOnce empty = %+v, %v", res, err)
	}
	if last, _ := s.LastPushLog(context.Background()); last != nil {
		t.Errorf("empty push wrote a log row: %+v", last)
	}
}

// stubObsProviders returns canned obs-tier rows so a push can be driven
// without a real obs DB — the goal is to prove the composed obs slices
// survive the PushEnvelope construction and reach the server.
func stubObsProviders() store.ObsOrgProviders {
	return store.ObsOrgProviders{
		Summaries: func(context.Context, int) ([]orgcontract.ObsSummaryRow, error) {
			return []orgcontract.ObsSummaryRow{{Day: "2026-05-26", Model: "claude", Traces: 3, CostUSD: 0.5}}, nil
		},
		Spans: func(context.Context, orgcontract.ObsCursor, int) (orgcontract.ObsSpanBatch, error) {
			return orgcontract.ObsSpanBatch{
				Traces: []orgcontract.ObsTraceRow{{TraceID: "t1", StartedAt: "2026-05-26T10:00:00Z", Status: "ok"}},
				Spans:  []orgcontract.ObsSpanRow{{TraceID: "t1", SpanID: "sp1", Kind: "llm"}},
				Events: []orgcontract.ObsSpanEventRow{{TraceID: "t1", SpanID: "sp1", Name: "first_token", Time: "2026-05-26T10:00:01Z"}},
			}, nil
		},
		Content: func(context.Context, orgcontract.ObsCursor, int) ([]orgcontract.ObsContentRow, error) {
			return []orgcontract.ObsContentRow{{TraceID: "t1", SpanID: "sp1", Kind: "prompt", ContentHash: "h1", Content: "hello"}}, nil
		},
		EvalRuns: func(context.Context, int) ([]orgcontract.ObsEvalRow, error) {
			return []orgcontract.ObsEvalRow{{Day: "2026-05-26", DatasetName: "d", RunName: "r", ScorerName: "s", Total: 5, Passed: 4}}, nil
		},
	}
}

// newObsSharingClient builds a client opted into every obs tier (and full
// content so the T3 body rides), mirroring newTestClient otherwise.
func newObsSharingClient(t *testing.T, s *store.Store, bs BearerStore) *Client {
	t.Helper()
	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
		Share: config.OrgClientShareConfig{
			FullContent: true,
			Obs: config.OrgClientShareObsConfig{
				Summary: true, Traces: true, Content: true, EvalSummary: true,
			},
		},
	}
	return New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
}

// TestPushOnce_ShipsObsTiers guards the obs push leg: with the obs provider
// seam wired and every [org_client.share] obs flag opted in, all six obs
// slices must survive the PushEnvelope construction and reach the server.
// This is the direct regression guard for the client.go envelope mapping
// (the obs slices were composed but never mapped into the envelope).
func TestPushOnce_ShipsObsTiers(t *testing.T) {
	s := newAgentStore(t)
	s.SetObsOrgProviders(stubObsProviders())
	bs := &memBearerStore{}

	var env orgcontract.PushEnvelope
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		env = decodeEnvelope(t, wire)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{
			AcceptedRows: int64(len(env.Sessions) + len(env.Actions)), NextCursor: env.CursorTo,
		})
	}))
	defer srv.Close()

	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	seedActivity(t, s, 2) // row data so the batch also carries non-obs rows

	c := newObsSharingClient(t, s, bs)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatalf("PushOnce: %v", err)
	}

	if len(env.ObsSummaries) != 1 {
		t.Errorf("ObsSummaries not shipped: %+v", env.ObsSummaries)
	}
	if len(env.ObsTraces) != 1 || len(env.ObsSpans) != 1 || len(env.ObsSpanEvents) != 1 {
		t.Errorf("ObsTraces/Spans/SpanEvents not shipped: traces=%d spans=%d events=%d",
			len(env.ObsTraces), len(env.ObsSpans), len(env.ObsSpanEvents))
	}
	if len(env.ObsContent) != 1 || env.ObsContent[0].Content != "hello" {
		t.Errorf("ObsContent not shipped with raw body under full content: %+v", env.ObsContent)
	}
	if len(env.ObsEvalRuns) != 1 {
		t.Errorf("ObsEvalRuns not shipped: %+v", env.ObsEvalRuns)
	}
}

// TestPushOnce_AggregateOnlyStillShips guards the batch.Empty() nuance: a node
// opted into ONLY an aggregate tier (obs_summary) with no row activity has
// RowCount()==0, but the aggregate must still ship — Empty() consults
// hasAggregates() so PushOnce does not early-return.
func TestPushOnce_AggregateOnlyStillShips(t *testing.T) {
	s := newAgentStore(t)
	s.SetObsOrgProviders(store.ObsOrgProviders{
		Summaries: func(context.Context, int) ([]orgcontract.ObsSummaryRow, error) {
			return []orgcontract.ObsSummaryRow{{Day: "2026-05-26", Model: "claude", Traces: 1, CostUSD: 0.1}}, nil
		},
	})
	bs := &memBearerStore{}

	var env orgcontract.PushEnvelope
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		wire, _ := io.ReadAll(r.Body)
		env = decodeEnvelope(t, wire)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{NextCursor: env.CursorTo})
	}))
	defer srv.Close()

	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)
	// NO seedActivity — the only thing to push is the aggregate summary.

	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
		Share: config.OrgClientShareConfig{Obs: config.OrgClientShareObsConfig{Summary: true}},
	}
	c := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
	res, err := c.PushOnce(context.Background())
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if res.Empty {
		t.Fatalf("aggregate-only push reported Empty; the summary was dropped")
	}
	if !hit {
		t.Fatalf("server was never hit for an aggregate-only batch")
	}
	if len(env.ObsSummaries) != 1 {
		t.Errorf("ObsSummaries not shipped in aggregate-only push: %+v", env.ObsSummaries)
	}
	if n := len(env.Sessions) + len(env.Actions); n != 0 {
		t.Errorf("aggregate-only push unexpectedly carried %d rows", n)
	}
}

func TestPushOnce_NotEnrolled(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	_, err := c.PushOnce(context.Background())
	if !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("PushOnce (not enrolled) = %v, want ErrNotEnrolled", err)
	}
}

func TestPushOnce_AuthFailureRecordsFailedAndKeepsCursor(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusUnauthorized, map[string]string{"error": "bad signature"})
	}))
	defer srv.Close()
	enrolFixture(t, s, bs, srv.URL)
	seedActivity(t, s, 2)

	c := newTestClient(t, s, bs)
	_, err := c.PushOnce(context.Background())
	if !errors.Is(err, ErrAuthFailed) {
		t.Fatalf("PushOnce = %v, want ErrAuthFailed", err)
	}
	if cur, _ := s.LoadPushCursor(context.Background()); cur.Actions != 0 {
		t.Errorf("cursor advanced on auth failure: %+v", cur)
	}
	if last, _ := s.LastPushLog(context.Background()); last == nil || last.Status != "failed" {
		t.Errorf("push log = %+v, want failed", last)
	}
}

func TestPushOnce_ServerErrorIsRetryable(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusInternalServerError, map[string]string{"error": "boom"})
	}))
	defer srv.Close()
	enrolFixture(t, s, bs, srv.URL)
	seedActivity(t, s, 2)

	c := newTestClient(t, s, bs)
	_, err := c.PushOnce(context.Background())
	if err == nil || errors.Is(err, ErrAuthFailed) {
		t.Fatalf("PushOnce = %v, want a non-auth retryable error", err)
	}
	if cur, _ := s.LoadPushCursor(context.Background()); cur.Actions != 0 {
		t.Errorf("cursor advanced on 5xx: %+v", cur)
	}
	if last, _ := s.LastPushLog(context.Background()); last == nil || last.Status != "retry" {
		t.Errorf("push log = %+v, want retry", last)
	}
}

// --- Status / Unenroll ------------------------------------------------------

func TestStatusAndUnenroll(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	c := newTestClient(t, s, bs)
	ctx := context.Background()

	st, err := c.Status(ctx)
	if err != nil || st.Enrolled {
		t.Fatalf("Status (fresh) = %+v, %v; want not enrolled", st, err)
	}

	enrolFixture(t, s, bs, "https://org.acme.example")
	st, err = c.Status(ctx)
	if err != nil || !st.Enrolled || st.OrgID != "org-1" || st.UserEmail != "dev@acme.example" {
		t.Fatalf("Status (enrolled) = %+v, %v", st, err)
	}

	if err := c.Unenroll(ctx); err != nil {
		t.Fatalf("Unenroll: %v", err)
	}
	if bs.bearer != "" || bs.key != nil {
		t.Errorf("secrets not cleared on unenrol")
	}
	if st, _ := c.Status(ctx); st.Enrolled {
		t.Errorf("still enrolled after unenrol")
	}
}

// --- runLoop timing (synctest) ----------------------------------------------

// The loop waits one interval before the first cycle, backs off exponentially
// (jittered) on retryable errors, resets the backoff after a success, and —
// crucially — RETRIES an auth failure on a separate track (initialBackoff-then-
// climb) rather than stopping, so a re-enrol recovers without a restart.
func TestRunLoop_BackoffResetAndAuthRetry(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(config.OrgClientConfig{}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
		const interval = 900 * time.Second

		ctx, cancel := context.WithCancel(context.Background())
		// boom, boom (backoff climbs) → nil (reset) → three ErrAuthFailed (auth
		// track: retry at 250ms then 500ms, proving it does NOT stop); cancel
		// after the last scripted step ends the loop.
		script := []error{errors.New("boom"), errors.New("boom"), nil, ErrAuthFailed, ErrAuthFailed, ErrAuthFailed}
		var gaps []time.Duration
		last := time.Now()
		i := 0
		action := func(context.Context) error {
			now := time.Now()
			gaps = append(gaps, now.Sub(last))
			last = now
			err := script[i]
			i++
			if i == len(script) {
				cancel()
			}
			return err
		}

		if err := c.runLoop(ctx, interval, action); !errors.Is(err, context.Canceled) {
			t.Fatalf("runLoop returned %v, want context.Canceled (auth is retryable, not terminal)", err)
		}
		if len(gaps) != 6 {
			t.Fatalf("ran %d cycles, want 6 (auth failures retried, not stopped)", len(gaps))
		}
		// First cycle: exactly one interval.
		if gaps[0] != interval {
			t.Errorf("gap[0] = %v, want %v", gaps[0], interval)
		}
		// After boom #1/#2: 250ms then doubled to 500ms.
		assertWithin(t, "gap[1]", gaps[1], 250*time.Millisecond)
		assertWithin(t, "gap[2]", gaps[2], 500*time.Millisecond)
		// After the success: backoff reset → back to the full interval.
		if gaps[3] != interval {
			t.Errorf("gap[3] = %v, want %v (backoff reset after success)", gaps[3], interval)
		}
		// After ErrAuthFailed #1/#2: the auth track retries at 250ms then 500ms
		// — proof the loop keeps going instead of terminating.
		assertWithin(t, "gap[4]", gaps[4], 250*time.Millisecond)
		assertWithin(t, "gap[5]", gaps[5], 500*time.Millisecond)
	})
}

// An idle cycle (not enrolled) keeps the interval cadence and never backs off,
// so an enrol on a running daemon is picked up within one interval.
func TestRunLoop_IdleKeepsIntervalCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(config.OrgClientConfig{}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
		const interval = 900 * time.Second

		ctx, cancel := context.WithCancel(context.Background())
		script := []error{errIdle, errIdle}
		var gaps []time.Duration
		last := time.Now()
		i := 0
		action := func(context.Context) error {
			now := time.Now()
			gaps = append(gaps, now.Sub(last))
			last = now
			err := script[i]
			i++
			if i == len(script) {
				cancel()
			}
			return err
		}
		_ = c.runLoop(ctx, interval, action)
		for j, g := range gaps {
			if g != interval {
				t.Errorf("idle gap[%d] = %v, want %v", j, g, interval)
			}
		}
	})
}

func TestValidatePushBodySize(t *testing.T) {
	if err := validatePushBodySize([]byte("1234"), 4); err != nil {
		t.Fatalf("exact-limit body rejected: %v", err)
	}
	if err := validatePushBodySize([]byte("12345"), 4); !errors.Is(err, ErrBatchTooLarge) {
		t.Fatalf("oversized body = %v, want ErrBatchTooLarge", err)
	}
}

func TestRunLoop_OversizedBatchUsesCircuitBreakerCadence(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(config.OrgClientConfig{}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
		ctx, cancel := context.WithCancel(context.Background())
		var gaps []time.Duration
		last := time.Now()
		calls := 0
		action := func(context.Context) error {
			now := time.Now()
			gaps = append(gaps, now.Sub(last))
			last = now
			calls++
			if calls == 2 {
				cancel()
			}
			return ErrBatchTooLarge
		}
		_ = c.runLoop(ctx, time.Minute, action)
		if len(gaps) != 2 {
			t.Fatalf("ran %d cycles, want 2", len(gaps))
		}
		if gaps[0] != time.Minute || gaps[1] != oversizedBatchBackoff {
			t.Fatalf("gaps = %v, want [%v %v]", gaps, time.Minute, oversizedBatchBackoff)
		}
	})
}

// ctx cancellation makes the loop return ctx.Err() promptly.
func TestRunLoop_ContextCancel(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		c := New(config.OrgClientConfig{}, nil, &memBearerStore{}, "v", http.DefaultClient, quietLogger())
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- c.runLoop(ctx, time.Hour, func(context.Context) error { return nil }) }()
		synctest.Wait()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Fatalf("runLoop returned %v, want context.Canceled", err)
		}
	})
}

// --- small assertion/util helpers -------------------------------------------

func assertWithin(t *testing.T, name string, got, base time.Duration) {
	t.Helper()
	lo := time.Duration(float64(base) * (1 - jitterFraction))
	hi := time.Duration(float64(base) * (1 + jitterFraction))
	if got < lo || got > hi {
		t.Errorf("%s = %v, want within [%v, %v] (%.0f%% jitter of %v)", name, got, lo, hi, jitterFraction*100, base)
	}
}

func writeTestJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func gunzip(t *testing.T, gzipBody []byte) []byte {
	t.Helper()
	zr, err := gzip.NewReader(bytes.NewReader(gzipBody))
	if err != nil {
		t.Fatalf("gzip.NewReader: %v", err)
	}
	raw, err := io.ReadAll(zr)
	if err != nil {
		t.Fatalf("gunzip: %v", err)
	}
	return raw
}

func decodeEnvelope(t *testing.T, gzipBody []byte) orgcontract.PushEnvelope {
	t.Helper()
	var env orgcontract.PushEnvelope
	if err := json.Unmarshal(gunzip(t, gzipBody), &env); err != nil {
		t.Fatalf("unmarshal envelope: %v", err)
	}
	return env
}

// bindPub / pubFromCtx stash the bound verification key on the test server so
// the handler (declared before the keypair exists) can reach it.
var testPubKeys = map[string]ed25519.PublicKey{}

func bindPub(srv *httptest.Server, pub ed25519.PublicKey) { testPubKeys[srv.URL] = pub }
func pubFromCtx(r *http.Request) ed25519.PublicKey {
	return testPubKeys["http://"+r.Host]
}

// TestNoteOversizedBatch_PersistsPauseForOtherProcesses pins the H2 breaker
// surface: opening the oversized-batch circuit must leave a DURABLE record, not
// just a log line. The dashboard and `observer org push-status` run in different
// processes from the daemon that parks the loop, so an in-memory flag would
// leave "no telemetry is shipping for the next hour" completely invisible.
func TestNoteOversizedBatch_PersistsPauseForOtherProcesses(t *testing.T) {
	s := newAgentStore(t)
	c := newTestClient(t, s, &memBearerStore{})
	ctx := context.Background()

	before := time.Now().UTC()
	c.noteOversizedBatch(ctx, fmt.Errorf("orgclient.PushOnce: %w: serialized_bytes=250000000 limit_bytes=1048576", ErrBatchTooLarge))

	paused, err := s.LoadPushBreaker(ctx)
	if err != nil {
		t.Fatalf("LoadPushBreaker: %v", err)
	}
	if paused == nil {
		t.Fatal("the oversized-batch pause was not persisted — a parked push loop would be invisible")
	}
	if !strings.Contains(paused.Reason, "limit_bytes=1048576") {
		t.Errorf("Reason = %q, want the serialized-vs-limit diagnostic operators act on", paused.Reason)
	}
	if got := paused.Until.Sub(before); got < oversizedBatchBackoff-time.Minute || got > oversizedBatchBackoff+time.Minute {
		t.Errorf("pause window = %v, want ~%v (the circuit-breaker cadence)", got, oversizedBatchBackoff)
	}

	// A successful cycle closes the circuit — the same call PushLoop makes.
	if err := s.ClearPushBreaker(ctx); err != nil {
		t.Fatalf("ClearPushBreaker: %v", err)
	}
	if paused, err = s.LoadPushBreaker(ctx); err != nil || paused != nil {
		t.Fatalf("circuit still open after a success: %+v, %v", paused, err)
	}
}

// TestStatusReportsOpenPushBreaker pins that the persisted pause reaches the
// EnrolmentState the dashboard + CLI read, not only the store.
func TestStatusReportsOpenPushBreaker(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	c := newTestClient(t, s, bs)
	ctx := context.Background()

	// Status short-circuits on a non-enrolled node, so enrol first.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeTestJSON(w, http.StatusOK, orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: "2026-08-23T00:00:00Z",
			OrgID: "org-1", OrgName: "Acme", UserID: "scim-42", UserEmail: "dev@acme.example",
		})
	}))
	defer srv.Close()
	if _, _, err := c.Enroll(ctx, srv.URL, "tok_id.secret"); err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	if err := s.OpenPushBreaker(ctx, time.Now().UTC().Add(oversizedBatchBackoff), "serialized_bytes=9 limit_bytes=1"); err != nil {
		t.Fatalf("OpenPushBreaker: %v", err)
	}

	st, err := c.Status(ctx)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if st.PushPaused == nil {
		t.Fatal("EnrolmentState.PushPaused is nil while the circuit is open — the dashboard would show a healthy push loop")
	}
	if !strings.Contains(st.PushPaused.Reason, "limit_bytes=1") {
		t.Errorf("PushPaused.Reason = %q", st.PushPaused.Reason)
	}
}
