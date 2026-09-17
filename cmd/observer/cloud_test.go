package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudclient"
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudgateway"
	"github.com/marmutapp/superbased-observer/internal/cloudpop"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// writeCloudTestConfig writes a minimal config.toml whose DB path lives in the
// same temp dir (which also roots the credential file store). Returns
// (configPath, dbPath, dir).
func writeCloudTestConfig(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "observer.db")
	cfgPath := filepath.Join(dir, "config.toml")
	body := "[observer]\ndb_path = \"" + filepath.ToSlash(dbPath) + "\"\n"
	if err := os.WriteFile(cfgPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return cfgPath, dbPath, dir
}

// seedCloudSession inserts one session with the given authority + a few
// actions. authority "" leaves the column NULL (== unknown). Returns the id.
func seedCloudSession(t *testing.T, dbPath, sessionID, authority string) {
	t.Helper()
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	defer database.Close()

	var projectID int64
	if err := database.QueryRowContext(ctx,
		`INSERT INTO projects (root_path, created_at) VALUES (?, '2026-06-09T00:00:00Z') RETURNING id`,
		"/tmp/cloud-cli/"+sessionID).
		Scan(&projectID); err != nil {
		t.Fatalf("insert project: %v", err)
	}
	var auth any
	ver := 0
	if authority != "" {
		auth = authority
		ver = 1
	}
	if _, err := database.ExecContext(ctx,
		`INSERT INTO sessions (id, tool, project_id, model, started_at, ended_at, total_actions, authority, authority_classifier_version)
		 VALUES (?, 'claude-code', ?, 'claude-opus-4-8', '2026-06-09T00:00:00Z', '2026-06-09T00:10:00Z', 3, ?, ?)`,
		sessionID, projectID, auth, ver); err != nil {
		t.Fatalf("insert session: %v", err)
	}
	for i, k := range []string{"read", "edit", "bash"} {
		if _, err := database.ExecContext(ctx,
			`INSERT INTO actions (session_id, project_id, timestamp, action_type, tool, success, target, source_file, source_event_id)
			 VALUES (?, ?, ?, ?, 'claude-code', 1, '/tmp/cloud-cli/main.go', 'f', ?)`,
			sessionID, projectID,
			time.Date(2026, 6, 9, 0, i, 0, 0, time.UTC).Format(time.RFC3339Nano),
			k, sessionID+"-"+k); err != nil {
			t.Fatalf("insert action: %v", err)
		}
	}
}

// openCloudTestStore opens a store handle over dbPath for direct assertions.
func openCloudTestStore(t *testing.T, dbPath string) (*store.Store, func()) {
	t.Helper()
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	return store.New(database), func() { _ = database.Close() }
}

// seedCloudLiveReceipt records a live per-upload consent receipt so the
// gateway's feature lane has something to authorize. Tests that exercise a
// FEATURE call path (upload, results pull) need one: under the R2 consent-gated
// egress posture a node with no live grant makes no request at all, which is
// the whole point of the seam.
func seedCloudLiveReceipt(t *testing.T, st *store.Store, endpoint string) string {
	t.Helper()
	id, err := st.InsertCloudConsentReceipt(context.Background(), store.CloudConsentReceipt{
		AccountPseudonym:      "acct-test",
		Purpose:               string(cloudcontract.PurposeStructuralInsights),
		EnvelopeSchemaVersion: cloudcontract.EnvelopeSchemaVersion,
		Endpoint:              endpoint,
		UploadDigest:          "sha256:seeded-live-receipt",
	})
	if err != nil {
		t.Fatalf("seed consent receipt: %v", err)
	}
	return id
}

// newTestCloudGateway builds the consent-gated egress seam a test drives
// feature calls through, exchanging a dev token so the client is authenticated.
func newTestCloudGateway(t *testing.T, st *store.Store, dir, baseURL string) *cloudgateway.Gateway {
	t.Helper()
	gw, err := cloudgateway.Open(cloudgateway.Options{
		Grants:     st,
		CredDir:    dir,
		BaseURL:    baseURL,
		DevToken:   "wtok",
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("open gateway: %v", err)
	}
	if err := gw.BootstrapExchange(context.Background()); err != nil {
		t.Fatalf("bootstrap exchange: %v", err)
	}
	return gw
}

func runCloudCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := newCloudCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)
	err := cmd.Execute()
	return out.String(), err
}

// TestCloudCommandRegistration confirms the family assembles with every
// subcommand and that it is wired into the root command tree.
func TestCloudCommandRegistration(t *testing.T) {
	want := map[string]bool{
		"status": false, "login": false, "preview": false, "consent": false,
		"sync": false, "logout": false, "delete-account": false,
	}
	for _, sub := range newCloudCmd().Commands() {
		want[sub.Name()] = true
	}
	for name, found := range want {
		if !found {
			t.Errorf("cloud subcommand %q not registered", name)
		}
	}

	var inRoot bool
	for _, c := range newRootCmd().Commands() {
		if c.Name() == "cloud" {
			inRoot = true
		}
	}
	if !inRoot {
		t.Error("`cloud` command is not registered on the root command")
	}
}

// TestCloudPreviewRefusesIneligible proves org and unknown-authority sessions
// are refused with honest copy before any envelope is built.
func TestCloudPreviewRefusesIneligible(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "sorg", "org")
	seedCloudSession(t, dbPath, "sunknown", "") // NULL authority == unknown

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	for _, tc := range []struct {
		id, wantSub string
	}{
		{"sorg", "plane separation"},
		{"sunknown", "unknown"},
		{"smissing", "not found"},
	} {
		_, err := buildCloudEnvelope(ctx, st, tc.id, cloudcontract.PurposeStructuralInsights, nil)
		if err == nil {
			t.Fatalf("%s: expected refusal, got nil", tc.id)
		}
		if !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: refusal %q missing %q", tc.id, err.Error(), tc.wantSub)
		}
	}
}

// TestCloudPreviewBytesMatchConsent proves the bytes a preview shows are the
// same bytes (and digest) that consent binds — the two-digest coherence
// invariant. Building twice is byte-stable, and the recorded receipt +
// enqueued outbox carry the previewed upload digest.
func TestCloudPreviewBytesMatchConsent(t *testing.T) {
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")

	st, cleanup := openCloudTestStore(t, dbPath)
	ctx := context.Background()
	purpose := cloudcontract.PurposeStructuralInsights

	a, err := buildCloudEnvelope(ctx, st, "s1", purpose, nil)
	if err != nil {
		t.Fatalf("build A: %v", err)
	}
	b, err := buildCloudEnvelope(ctx, st, "s1", purpose, nil)
	if err != nil {
		t.Fatalf("build B: %v", err)
	}
	if !bytes.Equal(a.Bytes, b.Bytes) {
		t.Fatal("rebuild produced different bytes (non-deterministic serializer)")
	}
	if a.Digests.Upload != b.Digests.Upload || a.Digests.EvidenceContent != b.Digests.EvidenceContent {
		t.Fatal("rebuild produced different digests")
	}
	cleanup()

	// Run the real consent command with --yes and assert it binds a.Digests.Upload.
	out, err := runCloudCmd(t, "consent",
		"--config", cfgPath,
		"--base-url", "http://cloud.invalid",
		"--session", "s1",
		"--purpose", string(purpose),
		"--yes")
	if err != nil {
		t.Fatalf("consent: %v\n%s", err, out)
	}
	if !strings.Contains(out, a.Digests.Upload) {
		t.Errorf("consent output did not echo the previewed upload digest\n%s", out)
	}

	st2, cleanup2 := openCloudTestStore(t, dbPath)
	defer cleanup2()
	items, err := st2.ListSendableCloudOutbox(ctx)
	if err != nil {
		t.Fatalf("list outbox: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("want 1 enqueued item, got %d", len(items))
	}
	if items[0].UploadDigest != a.Digests.Upload {
		t.Errorf("enqueued upload digest %q != previewed %q", items[0].UploadDigest, a.Digests.Upload)
	}
	rcpt, ok, err := st2.GetCloudConsentReceipt(ctx, items[0].ReceiptID)
	if err != nil || !ok {
		t.Fatalf("get receipt: %v ok=%v", err, ok)
	}
	if rcpt.UploadDigest != a.Digests.Upload {
		t.Errorf("receipt binds upload digest %q != previewed %q", rcpt.UploadDigest, a.Digests.Upload)
	}
}

// fakeCloudServer is a minimal in-test cloud server on 127.0.0.1:0 exercising
// nonce/exchange/jobs(+PoP)/results. It pins the device thumbprint learned at
// exchange and rejects any bearer that is not the token it minted.
type fakeCloudServer struct {
	srv             *httptest.Server
	apiToken        string
	thumbprint      string
	uploads         int
	previewConfirms int // POST /v1/consents/preview-confirmation count
	// lastPreviewConfirmPurposes captures the `purposes` field of the most
	// recent preview-confirmation body.
	lastPreviewConfirmPurposes []string
	rejected                   int
	deletions                  int // POST /v1/deletion-requests count (FF5)
	logouts                    int // POST /v1/logout count (D17)
	// structuralUploads counts POST /v1/structural-insights (W2 rail).
	structuralUploads int
	// structuralAttempts counts every request that REACHED the structural route,
	// including ones structuralHook aborts. It is the "did a body leave the
	// machine?" counter; structuralUploads counts only accepted ones.
	structuralAttempts int
	// structuralHook, when set, runs first on every structural request with the
	// 1-based attempt number. A test uses it to change node-local state
	// mid-flight (the revocation-during-drain case) and may abort the connection
	// with panic(http.ErrAbortHandler) to produce a retryable transport error.
	structuralHook func(attempt int)
	// structuralStatus, when non-zero, overrides the status that route answers
	// — 404/501 drive the "server route has not shipped yet" classification.
	structuralStatus int
	// structuralBodies records the exact bytes each structural upload carried,
	// so a test can prove the STORED snapshot bytes are what was sent.
	structuralBodies [][]byte
	// structuralHeaders records each structural upload's request headers, so a
	// test can prove the R1 standing-grant binding (consent generation, data
	// dictionary digest, source window rule) actually rides the wire.
	structuralHeaders []http.Header
	// communityAttempts counts every request that REACHED
	// POST /v1/community/contribution (the W5 rail), including ones
	// communityHook aborts — the "did a contribution leave the machine?"
	// counter. communityUploads counts only accepted ones.
	communityAttempts int
	communityUploads  int
	// communityHook, when set, runs first on every community request with the
	// 1-based attempt number; it may panic(http.ErrAbortHandler) to produce a
	// retryable transport error.
	communityHook func(attempt int)
	// communityStatus / communityBody, when communityStatus is non-zero,
	// override the answer the community route gives (e.g. a 409
	// cross_device_conflict with a recovery-hinting body).
	communityStatus int
	communityBody   string
	// communityHeaders records each community upload's request headers so a
	// test can prove the standing-grant binding (consent generation, data
	// dictionary digest, source window rule, declared timezone) rides the wire.
	communityHeaders []http.Header
	// logoutStatus, when non-zero, overrides the status the logout route
	// answers, so the best-effort failure path can be driven deterministically.
	logoutStatus   int
	cloudSessionID string // captured from the last /v1/jobs upload body
	// resultsPages, when set, overrides the default /v1/results payload so a
	// test can inject tombstone/boundary pages (FE6). It receives the `after`
	// query value and returns the page to serve.
	resultsPages func(after string) cloudclient.ResultsPage
}

func newFakeCloudServer(t *testing.T) *fakeCloudServer {
	t.Helper()
	f := &fakeCloudServer{apiToken: "sbo-api-live-1"}
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/nonce", func(w http.ResponseWriter, _ *http.Request) {
		writeCloudJSON(w, map[string]string{"nonce": "nonce-1", "expires_at": time.Now().Add(time.Minute).Format(time.RFC3339)})
	})
	mux.HandleFunc("/v1/auth/exchange", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			DevicePublicKey string `json:"device_public_key"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		raw, err := base64.RawURLEncoding.DecodeString(body.DevicePublicKey)
		if err != nil || len(raw) != ed25519.PublicKeySize {
			http.Error(w, "bad device key", http.StatusBadRequest)
			return
		}
		f.thumbprint = cloudpop.Thumbprint(ed25519.PublicKey(raw))
		writeCloudJSON(w, map[string]string{"api_token": f.apiToken, "device_id": "dev-1", "expires_at": time.Now().Add(time.Hour).Format(time.RFC3339)})
	})
	mux.HandleFunc("/v1/jobs", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken {
			// Cross-plane defense: a foreign (e.g. org) bearer is rejected.
			f.rejected++
			http.Error(w, "unauthorized", http.StatusForbidden)
			return
		}
		body := readCloudBody(t, r)
		if r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "missing PoP", http.StatusUnauthorized)
			return
		}
		if _, err := cloudpop.Verify(r.Header.Get("SBO-PoP"), cloudpop.VerifyParams{
			ExpectedMethod:          http.MethodPost,
			ExpectedURL:             "http://" + r.Host + r.URL.Path,
			ExpectedThumbprint:      f.thumbprint,
			ExpectedAccessTokenHash: cloudpop.HashAccessToken(bearer),
			Now:                     time.Now(),
			MaxAge:                  2 * time.Minute,
			MaxSkew:                 time.Minute,
			Body:                    body,
		}); err != nil {
			http.Error(w, "bad PoP: "+err.Error(), http.StatusUnauthorized)
			return
		}
		f.uploads++
		var jobBody struct {
			CloudSessionID string `json:"cloud_session_id"`
		}
		_ = json.Unmarshal(body, &jobBody)
		f.cloudSessionID = jobBody.CloudSessionID
		writeCloudJSON(w, map[string]string{"job_id": "job-1", "status": "queued", "cloud_session_id": jobBody.CloudSessionID})
	})
	// GET /v1/jobs/{id} (observer cloud job): authenticated exactly like the
	// POST /v1/jobs upload above. Only the id the upload above assigned
	// ("job-1") resolves; anything else is the tenant-scoped 404 handleGetJob
	// returns for an unknown or foreign-account job.
	mux.HandleFunc("GET /v1/jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken || r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.PathValue("id") != "job-1" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"code":"not_found","error":"job not found"}`))
			return
		}
		writeCloudJSON(w, map[string]any{
			"id": "job-1", "state": "succeeded", "feature": "session_enrichment",
			"attempts": 1, "created_at": "2026-09-17T10:00:00Z", "updated_at": "2026-09-17T10:05:00Z",
		})
	})
	// Preview-confirmation handshake (the server admits a session-evidence
	// upload only after the exact bytes are preview-confirmed). Authenticated
	// like /v1/jobs; returns the recorded receipt + consent generation.
	mux.HandleFunc("/v1/consents/preview-confirmation", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken || r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body := readCloudBody(t, r)
		f.previewConfirms++
		// lastPreviewConfirmPurposes records the exact `purposes` array this
		// preview-confirmation carried, so a test can prove a bounded upload
		// discloses under BOTH structural_activity_insights and
		// bounded_context_enrichment — the wire payload the server's
		// out-of-purpose check (internal/cloudserver/api/jobs.go) actually reads.
		var decoded struct {
			Purposes []string `json:"purposes"`
		}
		_ = json.Unmarshal(body, &decoded)
		f.lastPreviewConfirmPurposes = decoded.Purposes
		writeCloudJSON(w, map[string]any{"receipt_id": "rcpt-1", "generation": 1})
	})
	// W2 structural-insights rail. Authenticated exactly like /v1/jobs.
	mux.HandleFunc("/v1/structural-insights", func(w http.ResponseWriter, r *http.Request) {
		f.structuralAttempts++
		if f.structuralHook != nil {
			f.structuralHook(f.structuralAttempts)
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken || r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		body := readCloudBody(t, r)
		if f.structuralStatus != 0 {
			http.Error(w, "structural route unavailable", f.structuralStatus)
			return
		}
		f.structuralUploads++
		f.structuralBodies = append(f.structuralBodies, body)
		f.structuralHeaders = append(f.structuralHeaders, r.Header.Clone())
		writeCloudJSON(w, map[string]any{"snapshot_id": "snap-1", "status": "stored", "replay": false})
	})
	// W5 community cohort-benchmarking rail. Authenticated exactly like /v1/jobs.
	mux.HandleFunc("/v1/community/contribution", func(w http.ResponseWriter, r *http.Request) {
		f.communityAttempts++
		if f.communityHook != nil {
			f.communityHook(f.communityAttempts)
		}
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken || r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		_ = readCloudBody(t, r)
		if f.communityStatus != 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(f.communityStatus)
			_, _ = w.Write([]byte(f.communityBody))
			return
		}
		f.communityUploads++
		f.communityHeaders = append(f.communityHeaders, r.Header.Clone())
		w.WriteHeader(http.StatusAccepted)
		writeCloudJSON(w, map[string]any{"status": "stored", "replay": false})
	})
	mux.HandleFunc("/v1/deletion-requests", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken || r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.deletions++
		w.WriteHeader(http.StatusAccepted)
		writeCloudJSON(w, map[string]string{"id": "del-1", "state": "processing"})
	})
	// D17: server-side revocation of the presented device token. Counted so a
	// test can prove the CLI actually called it (or deliberately did not).
	mux.HandleFunc("/v1/logout", func(w http.ResponseWriter, r *http.Request) {
		bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if bearer != f.apiToken || r.Header.Get("SBO-PoP") == "" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		f.logouts++
		if f.logoutStatus != 0 {
			http.Error(w, "logout unavailable", f.logoutStatus)
			return
		}
		writeCloudJSON(w, map[string]string{"status": "signed_out"})
	})
	mux.HandleFunc("/v1/results", func(w http.ResponseWriter, r *http.Request) {
		if f.resultsPages != nil {
			writeCloudJSON(w, f.resultsPages(r.URL.Query().Get("after")))
			return
		}
		if r.URL.Query().Get("after") == "cursor-1" {
			writeCloudJSON(w, cloudclient.ResultsPage{NextCursor: ""})
			return
		}
		// The result's cloud_session_id is the SAME node-minted pseudonym the
		// upload carried, so the node's reverse lookup (cloud_session_map)
		// resolves it back to the local session. A second, unmapped result
		// (a pseudonym this device never minted) proves the honest
		// "not on this device" count/report path.
		writeCloudJSON(w, cloudclient.ResultsPage{
			Results: []cloudcontract.ResultRecord{
				{
					CloudSessionID: f.cloudSessionID,
					ResultID:       "res-1",
					Result: cloudcontract.Result{
						Title:         "seed",
						SchemaVersion: cloudcontract.ResultSchemaVersion,
						Confidence:    cloudcontract.ConfidenceLow,
					},
					Provenance: cloudcontract.ResultProvenance{
						ModelRouteID: "route-a",
						PromptHash:   "hash-a",
						TokensIn:     100,
						TokensOut:    50,
						CostUSD:      0.01,
					},
				},
				{
					CloudSessionID: "cs_never_minted_by_this_device",
					ResultID:       "res-2",
					Result: cloudcontract.Result{
						Title:         "orphan",
						SchemaVersion: cloudcontract.ResultSchemaVersion,
						Confidence:    cloudcontract.ConfidenceLow,
					},
				},
			},
			NextCursor: "cursor-1",
		})
	})

	srv := httptest.NewUnstartedServer(mux)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	srv.Listener = ln
	srv.Start()
	f.srv = srv
	t.Cleanup(srv.Close)
	return f
}

func writeCloudJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func readCloudBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	if r.Body != nil {
		_, _ = buf.ReadFrom(r.Body)
	}
	return buf.Bytes()
}

// TestCloudSyncAgainstFakeServer drives login → consent → sync end-to-end
// against a loopback fake server, asserting the upload+PoP path lands the job
// in `sent` and the results pull advances + persists the cursor.
func TestCloudSyncAgainstFakeServer(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")

	// consent enqueues the job (no network — nil broker for the thumbprint).
	if out, err := runCloudCmd(t, "consent",
		"--config", cfgPath, "--base-url", f.srv.URL,
		"--session", "s1", "--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes"); err != nil {
		t.Fatalf("consent: %v\n%s", err, out)
	}
	// login exchanges for the API token and stores it.
	if out, err := runCloudCmd(t, "login",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	// sync drains the outbox and pulls results.
	out, err := runCloudCmd(t, "sync",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.uploads != 1 {
		t.Errorf("want 1 upload, server saw %d", f.uploads)
	}
	if !strings.Contains(out, "1 sent") {
		t.Errorf("sync output missing send confirmation:\n%s", out)
	}
	// One result is bound to the pseudonym this device minted for s1 (via the
	// upload) and lands locally; the other carries a pseudonym this device
	// never minted, and is reported honestly rather than treated as an error.
	if !strings.Contains(out, "1 associated, 1 for sessions not on this device") {
		t.Errorf("sync output missing honest associated/unassociated counts:\n%s", out)
	}

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()
	items, err := st.ListSendableCloudOutbox(ctx)
	if err != nil {
		t.Fatalf("list outbox: %v", err)
	}
	if len(items) != 0 {
		t.Errorf("outbox still has %d sendable items after a successful send", len(items))
	}
	// The cursor is keyed by the cloud HOST the sync ran against (2026-09-15):
	// the fake server's host here, never the bare legacy key.
	cursor, err := st.LoadCloudResultCursor(ctx, cloudHostKey(f.srv.URL))
	if err != nil {
		t.Fatalf("load cursor: %v", err)
	}
	if cursor != "cursor-1" {
		t.Errorf("results cursor = %q, want cursor-1", cursor)
	}
	if legacy, _ := st.LoadCloudResultCursor(ctx, ""); legacy != "" {
		t.Errorf("bare legacy cursor key was written (%q); the cursor must live under the host key only", legacy)
	}

	// The associated result landed a local cloud_results row for s1, with the
	// wire's stable result id and the mapped provenance fields.
	res, overrides, ok, err := st.GetCloudSessionResult(ctx, "s1")
	if err != nil {
		t.Fatalf("get cloud session result: %v", err)
	}
	if !ok {
		t.Fatal("expected a local cloud result for s1, found none")
	}
	if res.ID != "res-1" {
		t.Errorf("result id = %q, want res-1 (the wire's stable ResultID)", res.ID)
	}
	if res.SessionID != "s1" {
		t.Errorf("result session id = %q, want s1", res.SessionID)
	}
	if res.Provenance.ModelRoute != "route-a" {
		t.Errorf("provenance model route = %q, want route-a", res.Provenance.ModelRoute)
	}
	if res.Provenance.PromptHash != "hash-a" {
		t.Errorf("provenance prompt hash = %q, want hash-a", res.Provenance.PromptHash)
	}
	if res.Provenance.Tokens != 150 {
		t.Errorf("provenance tokens = %d, want 150 (100 in + 50 out)", res.Provenance.Tokens)
	}
	if res.Provenance.CostUSD != 0.01 {
		t.Errorf("provenance cost = %v, want 0.01", res.Provenance.CostUSD)
	}
	if !strings.Contains(res.ResultJSON, `"title":"seed"`) {
		t.Errorf("result json missing the product title field:\n%s", res.ResultJSON)
	}
	if len(overrides) != 0 {
		t.Errorf("expected no overrides on a fresh result, got %d", len(overrides))
	}
	// The unmapped result (res-2, cs_never_minted_by_this_device) landed
	// nowhere on this device — already proven by the honest "1 associated, 1
	// for sessions not on this device" count assertion above, and by the fact
	// that s1's only stored result is res-1.
}

// TestCloudJobLooksUpStatus drives login → consent → sync (which uploads and
// gets back "job-1", exactly like TestCloudSyncAgainstFakeServer) then
// `observer cloud job` against the same fake server: the CLOUD job id
// resolves through the consent-gated read lane, an unknown id gets the honest
// "job not found" line rather than a raw HTTP error, and the LOCAL outbox id
// (job_<hex>, from `consent`'s own output) is refused up front because
// observer stores no mapping from it to the cloud id.
func TestCloudJobLooksUpStatus(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")

	consentOut, err := runCloudCmd(t, "consent",
		"--config", cfgPath, "--base-url", f.srv.URL,
		"--session", "s1", "--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes")
	if err != nil {
		t.Fatalf("consent: %v\n%s", err, consentOut)
	}
	if out, err := runCloudCmd(t, "login",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	if out, err := runCloudCmd(t, "sync",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token"); err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if f.uploads != 1 {
		t.Fatalf("want 1 upload before the job lookup, server saw %d", f.uploads)
	}

	// The known cloud job id ("job-1", the server's fixed answer for the
	// upload above) resolves and prints the status table.
	out, err := runCloudCmd(t, "job", "job-1",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token")
	if err != nil {
		t.Fatalf("job job-1: %v\n%s", err, out)
	}
	for _, want := range []string{"job:             job-1", "state:           succeeded", "feature:         session_enrichment", "attempts:        1"} {
		if !strings.Contains(out, want) {
			t.Errorf("job output missing %q:\n%s", want, out)
		}
	}

	// --json prints the decoded JobStatus as JSON.
	jsonOut, err := runCloudCmd(t, "job", "job-1", "--json",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token")
	if err != nil {
		t.Fatalf("job job-1 --json: %v\n%s", err, jsonOut)
	}
	var decoded struct {
		ID    string `json:"ID"`
		State string `json:"State"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("decode --json output: %v\n%s", err, jsonOut)
	}
	if decoded.ID != "job-1" || decoded.State != "succeeded" {
		t.Fatalf("decoded --json = %+v", decoded)
	}

	// An unknown cloud job id gets the server's tenant-scoped 404, printed as
	// the honest not-found line, not an error exit.
	notFoundOut, err := runCloudCmd(t, "job", "no-such-job",
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token")
	if err != nil {
		t.Fatalf("job no-such-job: unexpected error: %v\n%s", err, notFoundOut)
	}
	if !strings.Contains(notFoundOut, "job not found for this device's account") {
		t.Errorf("job no-such-job output = %q, want the honest not-found line", notFoundOut)
	}

	// A LOCAL outbox id (job_<hex>, as printed by `observer cloud consent`) is
	// refused up front — no lookup exists from it to the cloud job id.
	if !strings.Contains(consentOut, "job_") {
		t.Fatalf("consent output does not carry a local job_ id to test against:\n%s", consentOut)
	}
	localID := ""
	for _, tok := range strings.Fields(consentOut) {
		if strings.HasPrefix(tok, "job_") {
			localID = strings.Trim(tok, ".:,")
			break
		}
	}
	if localID == "" {
		t.Fatalf("could not find a job_ token in consent output:\n%s", consentOut)
	}
	localOut, err := runCloudCmd(t, "job", localID,
		"--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "workos-dev-token")
	if err == nil {
		t.Fatalf("job %s: want a refusal (local outbox id, no cloud mapping), got success:\n%s", localID, localOut)
	}
	if !strings.Contains(err.Error(), "LOCAL outbox id") {
		t.Errorf("job %s: error = %v, want it to explain the local/cloud id distinction", localID, err)
	}
}

// TestCloudAssociateResultPreservesOverrides proves a user override on a
// result field survives a later re-association of the same result id (e.g. a
// regenerated result re-pulled through the sync cursor) — the store's
// aggregate-across-all-results override rule, exercised through the actual
// sync-driven call path (cloudAssociateResult), not just the store directly.
func TestCloudAssociateResultPreservesOverrides(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")

	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	pseudonym, err := st.GetOrCreateCloudSessionPseudonym(ctx, "s1")
	if err != nil {
		t.Fatalf("mint pseudonym: %v", err)
	}

	first := cloudcontract.ResultRecord{
		CloudSessionID: pseudonym,
		ResultID:       "res-1",
		Result: cloudcontract.Result{
			Title:         "original title",
			SchemaVersion: cloudcontract.ResultSchemaVersion,
			Confidence:    cloudcontract.ConfidenceLow,
		},
	}
	ok, err := cloudAssociateResult(ctx, st, first)
	if err != nil {
		t.Fatalf("associate first: %v", err)
	}
	if !ok {
		t.Fatal("expected first result to associate")
	}

	if err := st.SetCloudResultOverride(ctx, "res-1", "title", "user-edited title"); err != nil {
		t.Fatalf("set override: %v", err)
	}

	// A regenerated result re-pulled under the SAME ResultID (the stable wire
	// id) updates the row in place rather than opening a new supersede chain.
	second := cloudcontract.ResultRecord{
		CloudSessionID: pseudonym,
		ResultID:       "res-1",
		Result: cloudcontract.Result{
			Title:         "regenerated title",
			SchemaVersion: cloudcontract.ResultSchemaVersion,
			Confidence:    cloudcontract.ConfidenceMedium,
		},
	}
	ok, err = cloudAssociateResult(ctx, st, second)
	if err != nil {
		t.Fatalf("associate second: %v", err)
	}
	if !ok {
		t.Fatal("expected second result to associate")
	}

	res, overrides, found, err := st.GetCloudSessionResult(ctx, "s1")
	if err != nil {
		t.Fatalf("get cloud session result: %v", err)
	}
	if !found {
		t.Fatal("expected a stored result for s1")
	}
	if res.ID != "res-1" {
		t.Errorf("result id = %q, want res-1 (updated in place)", res.ID)
	}
	if !strings.Contains(res.ResultJSON, `"title":"regenerated title"`) {
		t.Errorf("underlying result json should reflect the regeneration:\n%s", res.ResultJSON)
	}
	ov, ok := overrides["title"]
	if !ok {
		t.Fatal("expected the title override to survive the re-association")
	}
	if ov.UserValue != "user-edited title" {
		t.Errorf("override value = %q, want %q", ov.UserValue, "user-edited title")
	}
}

// TestCloudAssociateResultUnknownPseudonymIsNotAnError proves a result
// carrying a cloud_session_id this device never minted is reported as
// unassociated, not an error.
func TestCloudAssociateResultUnknownPseudonymIsNotAnError(t *testing.T) {
	_, dbPath, _ := writeCloudTestConfig(t)
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()

	rec := cloudcontract.ResultRecord{
		CloudSessionID: "cs_never_minted_by_this_device",
		ResultID:       "res-x",
		Result: cloudcontract.Result{
			Title:         "orphan",
			SchemaVersion: cloudcontract.ResultSchemaVersion,
			Confidence:    cloudcontract.ConfidenceLow,
		},
	}
	ok, err := cloudAssociateResult(context.Background(), st, rec)
	if err != nil {
		t.Fatalf("expected no error for an unmapped pseudonym, got %v", err)
	}
	if ok {
		t.Fatal("expected ok=false for an unmapped pseudonym")
	}
}

// TestCloudCrossPlaneRejection proves an ORG bearer presented to the cloud
// endpoints is rejected, and that org-authority sessions never build a personal
// envelope (the two directions of plane separation the CLI controls).
func TestCloudCrossPlaneRejection(t *testing.T) {
	f := newFakeCloudServer(t)
	_, dbPath, dir := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "sorg", "org")

	// Direction 1: an org-authority session is refused by the pure build gate.
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	if _, err := buildCloudEnvelope(context.Background(), st, "sorg", cloudcontract.PurposeStructuralInsights, nil); err == nil {
		t.Fatal("expected org session to be refused by the personal build gate")
	}

	// Direction 2: an ORG-shaped bearer presented to the cloud /v1/jobs endpoint
	// is rejected. We pre-seed the credential store with an org token (never via
	// exchange) so the client presents it, and the server 403s it.
	cred := cloudcred.Open(dir, nil)
	// New loads-or-creates the device key via cred, so Upload can mint a proof.
	client, err := cloudclient.New(cloudclient.Options{
		BaseURL:    f.srv.URL,
		Cred:       cred,
		MaxRetries: 0,
		Backoff:    func(int) time.Duration { return 0 },
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	// Pre-seed a foreign (org-shaped) bearer WITHOUT an exchange; the server
	// mints no thumbprint for it and rejects the token outright.
	if err := cred.SaveAPIToken("org_bearer_should_be_rejected"); err != nil {
		t.Fatalf("seed org token: %v", err)
	}
	_, upErr := client.Upload(context.Background(), cloudclient.UploadRequest{
		CloudSessionID: "cs-x",
		Feature:        cloudFeatureSessionEnrichment,
		Envelope:       []byte(`{"x":1}`),
		Digests:        cloudcontract.Digests{Upload: cloudpop.BodyDigest([]byte(`{"x":1}`))},
	})
	if upErr == nil {
		t.Fatal("expected the org bearer to be rejected by the cloud endpoint")
	}
	if f.rejected == 0 {
		t.Error("cloud server did not record a rejection of the foreign bearer")
	}
	if !cloudUploadTerminal(upErr) {
		t.Errorf("a 403 should classify terminal, got %v", upErr)
	}
}

// TestCloudSyncRefusesUnapprovedEndpoint is the FD1 CLI regression: consent
// binds endpoint A, but `sync` targets a different origin B. The confirmed
// evidence must be refused (reconfirmation) and must never reach B.
func TestCloudSyncRefusesUnapprovedEndpoint(t *testing.T) {
	approved := newFakeCloudServer(t)
	attacker := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")

	// Consent binds the APPROVED origin's /v1/jobs endpoint.
	if out, err := runCloudCmd(t, "consent", "--config", cfgPath, "--base-url", approved.srv.URL,
		"--session", "s1", "--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes"); err != nil {
		t.Fatalf("consent: %v\n%s", err, out)
	}
	// A token exists for the attacker origin so an upload could otherwise be attempted.
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", attacker.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}
	// Sync against the ATTACKER origin — must be refused, not uploaded.
	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", attacker.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if attacker.uploads != 0 {
		t.Fatalf("evidence reached the unapproved endpoint %d time(s) (FD1)", attacker.uploads)
	}
	if !strings.Contains(out, "need reconfirmation") {
		t.Fatalf("sync should report reconfirmation for the endpoint mismatch:\n%s", out)
	}
}

// TestCloudDeleteAccountRequestsServerDeletion is the FF5 regression: without
// --local-only, `delete-account` must actually issue a server deletion request
// (previously it exited 0 having done nothing). --local-only must NOT call the
// server.
func TestCloudDeleteAccountRequestsServerDeletion(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, _, _ := writeCloudTestConfig(t)
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}

	// --local-only: no server call.
	if out, err := runCloudCmd(t, "delete-account", "--config", cfgPath, "--base-url", f.srv.URL, "--local-only"); err != nil {
		t.Fatalf("local-only delete: %v\n%s", err, out)
	}
	if f.deletions != 0 {
		t.Fatalf("--local-only must not issue a server deletion request, saw %d", f.deletions)
	}

	// login again (local-only cleared the token) then request server deletion.
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("re-login: %v\n%s", err, out)
	}
	out, err := runCloudCmd(t, "delete-account", "--config", cfgPath, "--base-url", f.srv.URL, "--yes")
	if err != nil {
		t.Fatalf("delete-account: %v\n%s", err, out)
	}
	if f.deletions != 1 {
		t.Fatalf("server saw %d deletion requests, want 1 (FF5)", f.deletions)
	}
	if !strings.Contains(out, "del-1") {
		t.Fatalf("delete-account should report the server request id:\n%s", out)
	}
}

// TestCloudPullResultsSkipsTombstone is the FE6 (node half) regression: a
// tombstone/invalid record in a results page must NOT be persisted and must NOT
// supersede a prior real local result — even when it carries the same result id.
func TestCloudPullResultsSkipsTombstone(t *testing.T) {
	f := newFakeCloudServer(t)
	_, dbPath, dir := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	pseudonym, err := st.GetOrCreateCloudSessionPseudonym(ctx, "s1")
	if err != nil {
		t.Fatalf("mint pseudonym: %v", err)
	}
	// Store a REAL result for s1.
	if _, err := cloudAssociateResult(ctx, st, cloudcontract.ResultRecord{
		CloudSessionID: pseudonym, ResultID: "res-real",
		Result: cloudcontract.Result{Title: "real title", SchemaVersion: cloudcontract.ResultSchemaVersion, Confidence: cloudcontract.ConfidenceLow},
	}); err != nil {
		t.Fatalf("store real result: %v", err)
	}

	// Authenticated gateway with a live grant (the results pull is a FEATURE
	// fetch; with no grant it would make no request at all).
	seedCloudLiveReceipt(t, st, f.srv.URL+"/v1/jobs")
	gw := newTestCloudGateway(t, st, dir, f.srv.URL)

	// The server returns a TOMBSTONE carrying the SAME result id (invalid/empty
	// Result body), then stops.
	f.resultsPages = func(after string) cloudclient.ResultsPage {
		if after == "tomb-cur" {
			return cloudclient.ResultsPage{NextCursor: ""}
		}
		return cloudclient.ResultsPage{
			Results:    []cloudcontract.ResultRecord{{CloudSessionID: pseudonym, ResultID: "res-real", Result: cloudcontract.Result{}}},
			NextCursor: "tomb-cur",
		}
	}

	var buf bytes.Buffer
	var assoc int
	if err := gw.FeatureFetch(ctx, func(sess cloudgateway.ReadSession) error {
		var perr error
		assoc, _, perr = cloudPullResults(ctx, st, "", sess, &buf)
		return perr
	}); err != nil {
		t.Fatalf("cloudPullResults: %v\n%s", err, buf.String())
	}
	if assoc != 0 {
		t.Fatalf("tombstone must not associate, got assoc=%d", assoc)
	}
	if !strings.Contains(buf.String(), "tombstone/invalid record") {
		t.Fatalf("expected a tombstone-skip line:\n%s", buf.String())
	}
	// The prior REAL result must still stand — not clobbered by the tombstone.
	res, _, ok, err := st.GetCloudSessionResult(ctx, "s1")
	if err != nil || !ok {
		t.Fatalf("get result: ok=%v err=%v", ok, err)
	}
	if !strings.Contains(res.ResultJSON, "real title") {
		t.Fatalf("tombstone clobbered the real result: %s", res.ResultJSON)
	}
}

// TestCloudResultIsTombstoneHonoursTypedFlag is the FE6 (node half) re-fix
// regression: the typed ResultRecord.Tombstoned flag is authoritative and
// checked before any body inspection. The original fix only skipped records
// with an empty ResultID or a schema-invalid body; a hostile/buggy server that
// emits `{"tombstoned":true}` WITH a nonempty result id and a schema-VALID (but
// stale, deleted) residual body would otherwise pass both checks and be
// persisted as a live result. It must be recognized as a tombstone regardless.
func TestCloudResultIsTombstoneHonoursTypedFlag(t *testing.T) {
	staleValid := cloudcontract.Result{
		Title:         "stale but schema-valid title",
		SchemaVersion: cloudcontract.ResultSchemaVersion,
		Confidence:    cloudcontract.ConfidenceLow,
	}
	// Sanity: the stale body IS schema-valid, so the OLD checks alone would miss it.
	if err := staleValid.Validate(); err != nil {
		t.Fatalf("test setup: stale body must be schema-valid, got %v", err)
	}
	rec := cloudcontract.ResultRecord{
		CloudSessionID: "pseudo-x",
		ResultID:       "res-still-here",
		Tombstoned:     true,
		Result:         staleValid,
	}
	if !cloudResultIsTombstone(rec) {
		t.Fatal("a Tombstoned=true record with a nonempty id and a valid stale body must be a tombstone")
	}
	// And a normal live record with the same valid body is NOT a tombstone.
	live := rec
	live.Tombstoned = false
	if cloudResultIsTombstone(live) {
		t.Fatal("a live record with a valid body must not be treated as a tombstone")
	}
}

// TestCloudPullResultsSkipsTypedTombstone is the FE6 (node half) end-to-end
// re-fix: a typed tombstone carrying a schema-valid stale body, pulled over the
// wire, must not clobber a prior real local result.
func TestCloudPullResultsSkipsTypedTombstone(t *testing.T) {
	f := newFakeCloudServer(t)
	_, dbPath, dir := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")
	st, cleanup := openCloudTestStore(t, dbPath)
	defer cleanup()
	ctx := context.Background()

	pseudonym, err := st.GetOrCreateCloudSessionPseudonym(ctx, "s1")
	if err != nil {
		t.Fatalf("mint pseudonym: %v", err)
	}
	if _, err := cloudAssociateResult(ctx, st, cloudcontract.ResultRecord{
		CloudSessionID: pseudonym, ResultID: "res-real",
		Result: cloudcontract.Result{Title: "real title", SchemaVersion: cloudcontract.ResultSchemaVersion, Confidence: cloudcontract.ConfidenceLow},
	}); err != nil {
		t.Fatalf("store real result: %v", err)
	}

	seedCloudLiveReceipt(t, st, f.srv.URL+"/v1/jobs")
	gw := newTestCloudGateway(t, st, dir, f.srv.URL)

	// A typed tombstone that ALSO carries a nonempty id and a schema-valid stale
	// body — the shape the old id/validate checks would wrongly accept.
	f.resultsPages = func(after string) cloudclient.ResultsPage {
		if after == "tomb-cur" {
			return cloudclient.ResultsPage{NextCursor: ""}
		}
		return cloudclient.ResultsPage{
			Results: []cloudcontract.ResultRecord{{
				CloudSessionID: pseudonym, ResultID: "res-real", Tombstoned: true,
				Result: cloudcontract.Result{Title: "STALE deleted title", SchemaVersion: cloudcontract.ResultSchemaVersion, Confidence: cloudcontract.ConfidenceLow},
			}},
			NextCursor: "tomb-cur",
		}
	}

	var buf bytes.Buffer
	var assoc int
	if err := gw.FeatureFetch(ctx, func(sess cloudgateway.ReadSession) error {
		var perr error
		assoc, _, perr = cloudPullResults(ctx, st, "", sess, &buf)
		return perr
	}); err != nil {
		t.Fatalf("cloudPullResults: %v\n%s", err, buf.String())
	}
	if assoc != 0 {
		t.Fatalf("typed tombstone must not associate, got assoc=%d", assoc)
	}
	res, _, ok, err := st.GetCloudSessionResult(ctx, "s1")
	if err != nil || !ok {
		t.Fatalf("get result: ok=%v err=%v", ok, err)
	}
	if strings.Contains(res.ResultJSON, "STALE deleted title") {
		t.Fatalf("typed tombstone with a valid stale body clobbered the real result: %s", res.ResultJSON)
	}
	if !strings.Contains(res.ResultJSON, "real title") {
		t.Fatalf("real result was lost: %s", res.ResultJSON)
	}
}

// TestCloudSyncReclaimsStrandedSending is the FD4 regression: an outbox item
// stranded in `sending` by a crash-before-mark is reclaimed at the next sync and
// retried to completion.
func TestCloudSyncReclaimsStrandedSending(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, dbPath, _ := writeCloudTestConfig(t)
	seedCloudSession(t, dbPath, "s1", "personal")
	if out, err := runCloudCmd(t, "consent", "--config", cfgPath, "--base-url", f.srv.URL,
		"--session", "s1", "--purpose", string(cloudcontract.PurposeStructuralInsights), "--yes"); err != nil {
		t.Fatalf("consent: %v\n%s", err, out)
	}
	if out, err := runCloudCmd(t, "login", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok"); err != nil {
		t.Fatalf("login: %v\n%s", err, out)
	}

	// Simulate crash-before-mark: force the enqueued item to `sending` with a
	// stale updated_at (older than the reclaim lease).
	ctx := context.Background()
	database, err := dbtemplate.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	stale := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := database.ExecContext(ctx,
		`UPDATE cloud_outbox SET state='sending', updated_at=? WHERE session_id='s1'`, stale); err != nil {
		t.Fatalf("force stranded sending: %v", err)
	}
	_ = database.Close()

	out, err := runCloudCmd(t, "sync", "--config", cfgPath, "--base-url", f.srv.URL, "--dev-token", "wtok")
	if err != nil {
		t.Fatalf("sync: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Reclaimed 1 stranded") {
		t.Fatalf("sync should report reclaiming the stranded item:\n%s", out)
	}
	if f.uploads != 1 {
		t.Fatalf("reclaimed item was not retried/sent: uploads=%d\n%s", f.uploads, out)
	}
}

// TestCloudStatusCreatesNoCredential pins that a read-only command stays
// read-only. Building the network client loads-or-CREATES the device signing
// key, so an eagerly-constructed client would make `status` mint a credential
// and then report it as present — a status line that is true only because the
// act of asking made it true.
func TestCloudStatusCreatesNoCredential(t *testing.T) {
	f := newFakeCloudServer(t)
	cfgPath, _, dir := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "status", "--config", cfgPath, "--base-url", f.srv.URL)
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "device key:          not present") {
		t.Errorf("status on a fresh node must report no device key:\n%s", out)
	}
	if !strings.Contains(out, "structural rail:     not authorized") {
		t.Errorf("status must say the structural rail is unauthorized:\n%s", out)
	}
	if _, err := cloudcred.Open(dir, nil).LoadDeviceKey(); err == nil {
		t.Fatal("`status` created a device key as a side effect of being asked a question")
	}
	if f.uploads+f.logouts+f.deletions+f.structuralUploads != 0 {
		t.Fatal("`status` made a network call")
	}
}

// TestResolveCloudBaseURLPrecedence pins D15's resolution order: --flag beats
// $SBO_CLOUD_BASE_URL beats [cloud].base_url in config.toml beats the built-in
// defaultCloudBaseURL (the hosted service). Nothing set resolves to that default
// so a fresh install signs in out of the box, sourced as "built-in default".
func TestResolveCloudBaseURLPrecedence(t *testing.T) {
	cases := []struct {
		name       string
		flagVal    string
		envVal     string
		cfgBaseURL string
		want       string
		wantSource string
	}{
		{
			name:       "nothing set falls back to the built-in default",
			want:       defaultCloudBaseURL,
			wantSource: "built-in default",
		},
		{
			name:       "toml only",
			cfgBaseURL: "https://toml.example.com",
			want:       "https://toml.example.com",
			wantSource: "[cloud].base_url",
		},
		{
			name:       "env beats toml",
			envVal:     "https://env.example.com",
			cfgBaseURL: "https://toml.example.com",
			want:       "https://env.example.com",
			wantSource: "$" + cloudBaseURLEnv,
		},
		{
			name:       "flag beats env and toml",
			flagVal:    "https://flag.example.com",
			envVal:     "https://env.example.com",
			cfgBaseURL: "https://toml.example.com",
			want:       "https://flag.example.com",
			wantSource: "--base-url",
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(cloudBaseURLEnv, tc.envVal)
			cfg := config.Default()
			cfg.Cloud.BaseURL = tc.cfgBaseURL

			got := resolveCloudBaseURL(tc.flagVal, cfg)
			if got != tc.want {
				t.Errorf("resolveCloudBaseURL(%q, cfg) = %q, want %q", tc.flagVal, got, tc.want)
			}
			if tc.want == "" {
				return
			}
			if gotSource := cloudBaseURLSource(tc.flagVal, cfg); gotSource != tc.wantSource {
				t.Errorf("cloudBaseURLSource(%q, cfg) = %q, want %q", tc.flagVal, gotSource, tc.wantSource)
			}
		})
	}
}

// TestCloudSignInExpiredIsRetryableEverywhere pins that an expired sign-in —
// which wraps the 401 that revealed it — is a CREDENTIAL state for every outbox
// classifier: the row stays retryable (never burned) under a content-free
// class, so the next sync after `observer cloud login` sends it.
func TestCloudSignInExpiredIsRetryableEverywhere(t *testing.T) {
	expired := fmt.Errorf("cloudclient.Upload: %w: the API token was rejected and refreshing the sign-in failed: %w",
		cloudgateway.ErrSignInExpired,
		&cloudclient.APIError{StatusCode: http.StatusUnauthorized, Body: `{"error":"invalid or expired token","code":"unauthorized"}`})
	plain401 := &cloudclient.APIError{StatusCode: http.StatusUnauthorized, Body: `{"code":"unauthorized"}`}

	if status, ok := cloudgateway.HTTPStatus(expired); !ok || status != http.StatusUnauthorized {
		t.Fatalf("precondition: the expired-sign-in error must still carry the 401 (ok=%v status=%d)", ok, status)
	}
	cases := []struct {
		name     string
		terminal func(error) bool
		class    func(error) string
	}{
		{"session-evidence outbox", cloudUploadTerminal, cloudErrClass},
		{"structural rail", cloudStructuralTerminal, cloudStructuralErrClass},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.terminal(expired) {
				t.Errorf("an expired sign-in must be retryable, was classified terminal")
			}
			if got := tc.class(expired); got != cloudErrClassSignInExpired {
				t.Errorf("class = %q, want %q", got, cloudErrClassSignInExpired)
			}
			// The plain (un-healed) 401 keeps its existing classification.
			if !tc.terminal(plain401) {
				t.Errorf("a plain 401 must stay terminal (unchanged behaviour)")
			}
			if got := tc.class(plain401); got != "http_401" {
				t.Errorf("plain 401 class = %q, want http_401", got)
			}
		})
	}
}

// TestCloudStatusReportsSignInPresenceWithoutNetwork pins the status line the
// self-heal adds: it states whether an expired API token CAN heal (persisted
// WorkOS sign-in present) and names the recovery otherwise — read locally,
// against a server that fails the test on any request.
func TestCloudStatusReportsSignInPresenceWithoutNetwork(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		t.Errorf("status must make no network call, got %s %s", r.Method, r.URL.Path)
	}))
	t.Cleanup(srv.Close)
	cfgPath, _, dir := writeCloudTestConfig(t)

	out, err := runCloudCmd(t, "status", "--config", cfgPath, "--base-url", srv.URL)
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "sign-in (WorkOS):    not present — run `observer cloud login`") {
		t.Errorf("fresh node must say there is no sign-in and name the recovery:\n%s", out)
	}

	cred := cloudcred.Open(dir, nil)
	if err := cred.SaveWorkOSRefresh("rt-1"); err != nil {
		t.Fatalf("seed refresh: %v", err)
	}
	t.Cleanup(func() { _ = cred.Clear() })
	out, err = runCloudCmd(t, "status", "--config", cfgPath, "--base-url", srv.URL)
	if err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if !strings.Contains(out, "sign-in (WorkOS):    present — an expired API token is re-exchanged automatically") {
		t.Errorf("a persisted sign-in must be reported as self-heal capable:\n%s", out)
	}
}
