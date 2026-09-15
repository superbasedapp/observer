package api_test

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/api"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/cloudtestpg"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/identity"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/jobs"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// admAttestor is a scripted admission attestor over the resolved-route interface.
type admAttestor struct{ verified bool }

func (a admAttestor) Attest(context.Context, store.RouteInfo, time.Time) (jobs.Attestation, error) {
	return jobs.Attestation{Verified: a.verified}, nil
}

// newHarnessAdmission builds a harness whose Server has the FA6 admission gate
// wired (attestor + credentials), rate limiting disabled.
func newHarnessAdmission(t *testing.T, attestor jobs.ProviderAttestor, creds jobs.CredentialSource) *harness {
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
		RateLimit:       &api.RateLimitConfig{},
		Attestor:        attestor,
		Credentials:     creds,
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

func acctBlobCount(t *testing.T, h *harness, acct string) int {
	t.Helper()
	var n int
	if err := h.store.Pool().QueryRow(context.Background(),
		`SELECT count(*) FROM evidence_blobs WHERE account_id = $1::uuid`, acct).Scan(&n); err != nil {
		t.Fatalf("blob count: %v", err)
	}
	return n
}

// TestFA6AdmissionRefusesUnverifiedWithoutStoringEvidence proves that when the
// admission attestation is unhealthy, the API refuses the job up front (503
// provider_policy_unverified) and never takes custody of the user's evidence.
func TestFA6AdmissionRefusesUnverifiedWithoutStoringEvidence(t *testing.T) {
	h := newHarnessAdmission(t, admAttestor{verified: false}, jobs.StaticCredentials{Key: "k"})
	c := h.login(t, "fa6-unverified")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("FA6: unverified admission status=%d, want 503 body=%s", resp.StatusCode, readAll(resp))
	}
	var body struct {
		Code string `json:"code"`
	}
	decode(t, resp, &body)
	if body.Code != "provider_policy_unverified" {
		t.Fatalf("FA6: code=%q, want provider_policy_unverified", body.Code)
	}
	if got := acctBlobCount(t, h, c.accountID); got != 0 {
		t.Fatalf("FA6: refused admission must store NO evidence, got %d blobs", got)
	}
}

// TestFA6AdmissionRefusesAbsentCredential proves an absent provider credential
// refuses admission before storing evidence (the pre-approval boundary as an
// admission wall, not only a worker wall).
func TestFA6AdmissionRefusesAbsentCredential(t *testing.T) {
	h := newHarnessAdmission(t, admAttestor{verified: true}, jobs.AbsentCredentials{})
	c := h.login(t, "fa6-nocred")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("FA6: absent-credential admission status=%d, want 503 body=%s", resp.StatusCode, readAll(resp))
	}
	if got := acctBlobCount(t, h, c.accountID); got != 0 {
		t.Fatalf("FA6: refused admission must store NO evidence, got %d blobs", got)
	}
}

// TestFA6AdmissionAdmitsWhenVerified proves a verified attestation + present
// credential admits the job (202, evidence stored).
func TestFA6AdmissionAdmitsWhenVerified(t *testing.T) {
	h := newHarnessAdmission(t, admAttestor{verified: true}, jobs.StaticCredentials{Key: "k"})
	c := h.login(t, "fa6-ok")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("FA6: verified admission status=%d, want 202 body=%s", resp.StatusCode, readAll(resp))
	}
	if got := acctBlobCount(t, h, c.accountID); got != 1 {
		t.Fatalf("FA6: admitted job must store evidence, got %d blobs", got)
	}
}

// newHarnessNoAdmissionDeps builds a Server with NO attestor and NO credential
// source — the shape a misconstruction (or a bare api.New) would produce. It
// exists to prove the FA6 gate is fail-closed by DEFAULT, not only when a
// harness happens to wire an unhealthy attestor.
func newHarnessNoAdmissionDeps(t *testing.T) *harness {
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
		RateLimit:       &api.RateLimitConfig{},
		// Attestor + Credentials deliberately omitted.
	}).Handler()
	srv := &httptest.Server{Listener: lis, Config: &http.Server{Handler: handler}}
	srv.Start()
	t.Cleanup(srv.Close)
	return &harness{srv: srv, store: s}
}

// TestFA6AdmissionFailsClosedWhenUnwired is the re-fix regression for the
// NOT-CLOSED finding: a server constructed without an attestor/credential source
// (the credential-absent posture, or a construction bug) must REFUSE every job
// with 503 provider_policy_unverified and take custody of ZERO evidence — not
// silently store it as the old nil-guard skip did.
func TestFA6AdmissionFailsClosedWhenUnwired(t *testing.T) {
	h := newHarnessNoAdmissionDeps(t)
	c := h.login(t, "fa6-unwired")
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})

	resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw))
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("FA6: unwired admission status=%d, want 503 body=%s", resp.StatusCode, readAll(resp))
	}
	var body struct {
		Code string `json:"code"`
	}
	decode(t, resp, &body)
	if body.Code != "provider_policy_unverified" {
		t.Fatalf("FA6: code=%q, want provider_policy_unverified", body.Code)
	}
	if got := acctBlobCount(t, h, c.accountID); got != 0 {
		t.Fatalf("FA6: unwired server must store NO evidence, got %d blobs", got)
	}
}

// TestFE6TombstoneIsTypedNotEmptyEnrichment proves the results endpoint emits a
// deleted result as a TYPED tombstone (tombstoned=true, no title) rather than
// decoding the marker into an empty, schema-inconsistent enrichment.
func TestFE6TombstoneIsTypedNotEmptyEnrichment(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "fe6")
	ctx := context.Background()

	// Admit a job and drive it to a stored result via the store (the API server
	// runs no worker).
	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})
	if resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw)); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	now := time.Now() // AFTER the submit, so available_at <= now for the lease
	lj, err := h.store.LeaseNextJob(ctx, "w", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("lease: %v", err)
	}
	if err := h.store.MarkJobRunning(ctx, c.accountID, lj.JobID, now); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	valid := cloudcontract.Result{Title: "kept title", Confidence: cloudcontract.ConfidenceLow, SchemaVersion: cloudcontract.ResultSchemaVersion}
	vb, _ := json.Marshal(valid)
	if _, committed, err := h.store.CompleteJobWithResult(ctx, c.accountID, lj.JobID, lj.EvidencePK, lj.ReservationID,
		"w", lj.LeaseGeneration, cloudcontract.ResultSchemaVersion, vb, store.ResultProvenance{}, now); err != nil || !committed {
		t.Fatalf("complete: committed=%v err=%v", committed, err)
	}

	// A normal read returns the valid enrichment.
	resp := c.do(c.signedReq("GET", "/v1/results", nil))
	var page struct {
		Results []cloudcontract.ResultRecord `json:"results"`
	}
	decode(t, resp, &page)
	if len(page.Results) != 1 || page.Results[0].Result.Title != "kept title" || page.Results[0].Tombstoned {
		t.Fatalf("pre-delete read wrong: %+v", page.Results)
	}

	// Tombstone the stored result (as account deletion does) WITHOUT revoking the
	// token, then read again with the still-valid token.
	if _, err := h.store.Pool().Exec(ctx,
		`UPDATE analysis_results SET result = '{"tombstoned":true}'::jsonb WHERE account_id=$1::uuid`,
		c.accountID); err != nil {
		t.Fatalf("tombstone: %v", err)
	}
	resp2 := c.do(c.signedReq("GET", "/v1/results", nil))
	var page2 struct {
		Results []cloudcontract.ResultRecord `json:"results"`
	}
	decode(t, resp2, &page2)
	if len(page2.Results) != 1 {
		t.Fatalf("FE6: want 1 result row, got %d", len(page2.Results))
	}
	r := page2.Results[0]
	if !r.Tombstoned {
		t.Fatalf("FE6: deleted result must be a typed tombstone (tombstoned=true), got %+v", r)
	}
	if r.Result.Title != "" {
		t.Fatalf("FE6: tombstone must carry no enrichment title, got %q", r.Result.Title)
	}
}

// TestFE1ReadBoundaryNormalizesText is the FE1 re-fix: the server /v1/results
// read boundary emits NORMALIZED (NFC, control-stripped) text, not the raw
// stored bytes. A stored row whose title is NFD-decomposed ("cafe" + combining
// acute) validates (Normalize accepts and transforms it) but must NOT reach the
// node/JSX sink in decomposed form. This exercises the ACTUAL endpoint over a
// hostile-shaped stored body, not an isolated helper.
func TestFE1ReadBoundaryNormalizesText(t *testing.T) {
	h := newHarness(t)
	c := h.login(t, "fe1")
	ctx := context.Background()

	raw, ud, cd := makeEnvelope(t, false)
	c.previewConfirm(t, ud, cd, []string{"structural_activity_insights"})
	if resp := c.do(c.signedReq("POST", "/v1/intelligence/jobs", raw)); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("submit status=%d body=%s", resp.StatusCode, readAll(resp))
	}
	now := time.Now()
	lj, err := h.store.LeaseNextJob(ctx, "w", []string{store.FeatureSessionEnrichment}, time.Hour, now)
	if err != nil || lj == nil {
		t.Fatalf("lease: %v", err)
	}
	if err := h.store.MarkJobRunning(ctx, c.accountID, lj.JobID, now); err != nil {
		t.Fatalf("mark running: %v", err)
	}
	valid := cloudcontract.Result{Title: "placeholder", Confidence: cloudcontract.ConfidenceLow, SchemaVersion: cloudcontract.ResultSchemaVersion}
	vb, _ := json.Marshal(valid)
	if _, committed, err := h.store.CompleteJobWithResult(ctx, c.accountID, lj.JobID, lj.EvidencePK, lj.ReservationID,
		"w", lj.LeaseGeneration, cloudcontract.ResultSchemaVersion, vb, store.ResultProvenance{}, now); err != nil || !committed {
		t.Fatalf("complete: committed=%v err=%v", committed, err)
	}

	// Overwrite the stored body with an NFD-DECOMPOSED title, simulating any path
	// that could land non-NFC bytes in the row. Built from explicit rune values so
	// no source-literal mangling can collapse the two forms: decomposed = "cafe" +
	// combining acute U+0301; NFC form = "caf" + precomposed U+00E9.
	decomposed := "cafe" + string(rune(0x0301)) + " session"
	composed := "caf" + string(rune(0x00E9)) + " session"
	if decomposed == composed {
		t.Fatal("test setup: decomposed and composed forms must differ in bytes")
	}
	nfd := cloudcontract.Result{Title: decomposed, Confidence: cloudcontract.ConfidenceLow, SchemaVersion: cloudcontract.ResultSchemaVersion}
	nb, _ := json.Marshal(nfd)
	if _, err := h.store.Pool().Exec(ctx,
		`UPDATE analysis_results SET result = $2::jsonb WHERE account_id=$1::uuid`,
		c.accountID, string(nb)); err != nil {
		t.Fatalf("write decomposed body: %v", err)
	}

	resp := c.do(c.signedReq("GET", "/v1/results", nil))
	var page struct {
		Results []cloudcontract.ResultRecord `json:"results"`
	}
	decode(t, resp, &page)
	if len(page.Results) != 1 {
		t.Fatalf("FE1: want 1 result, got %d", len(page.Results))
	}
	got := page.Results[0].Result.Title
	if got == decomposed {
		t.Fatalf("FE1: read boundary emitted the raw NFD-decomposed title unchanged (%q) — it must normalize", got)
	}
	if got != composed {
		t.Fatalf("FE1: read boundary title = %q, want NFC-composed %q", got, composed)
	}
}
