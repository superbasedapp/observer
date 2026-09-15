package cloudgateway

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// dispatch_test.go pins the Sol re-review (2026-09-02) node fixes at the seam:
// the dispatch lease is REQUIRED on both standing rails (N2), runs after
// PreAttempt and is released after the attempt, a refused lease never
// dispatches; cohort benchmarking is directly pinned NOT evidence-uploadable
// (N8); and HTTPError decodes a refusal body's code + recovery hints (F9).

func structuralRequest() StructuralUploadRequest {
	return StructuralUploadRequest{
		Payload: []byte(`{"x":1}`), Period: "2026-08-31", PeriodRuleVersion: 1,
		SchemaVersion: cloudcontract.StructuralSnapshotSchemaVersion, Revision: 1, Digest: "sha256:x",
		ConsentGeneration:    1,
		DataDictionaryDigest: cloudcontract.StructuralDataDictionaryDigest(),
		SourceWindowRule:     "completed_utc_days_trailing_30",
		PreAttempt:           func() error { return nil },
		DispatchLease:        noopLease,
	}
}

// TestUploadsRequireADispatchLease: a standing-rail upload with a PreAttempt
// but NO dispatch lease is refused before any request, on both rails.
func TestUploadsRequireADispatchLease(t *testing.T) {
	srv := noRequestServer(t)
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{liveStandingReceipt()}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatal(err)
	}
	err := g.StandingSend(context.Background(), cloudcontract.PurposeStructuralInsights, func(s StructuralSession) error {
		req := structuralRequest()
		req.DispatchLease = nil
		_, uerr := s.UploadStructural(context.Background(), req)
		return uerr
	})
	if !errors.Is(err, ErrDispatchLeaseRequired) {
		t.Fatalf("structural without a lease: want ErrDispatchLeaseRequired, got %v", err)
	}

	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g2 := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g2.cred.SaveAPIToken("tok"); err != nil {
		t.Fatal(err)
	}
	err = g2.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		req := communityRequestFor(receipt)
		req.DispatchLease = nil
		_, uerr := s.UploadCommunity(context.Background(), req)
		return uerr
	})
	if !errors.Is(err, ErrDispatchLeaseRequired) {
		t.Fatalf("community without a lease: want ErrDispatchLeaseRequired, got %v", err)
	}
}

// TestDispatchLeaseRunsLastAndIsReleasedAfterTheAttempt pins the order: the
// gateway re-resolve, then the caller's PreAttempt, then the lease, then the
// request, then the release. (That the lease's expiry bounds the request is
// pinned on the transport in internal/cloudclient/dispatch_test.go.)
func TestDispatchLeaseRunsLastAndIsReleasedAfterTheAttempt(t *testing.T) {
	var log []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		log = append(log, "request")
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatal(err)
	}
	err := g.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		req := communityRequestFor(receipt)
		req.PreAttempt = func() error { log = append(log, "pre"); return nil }
		req.DispatchLease = func(context.Context) (time.Time, func(), error) {
			log = append(log, "lease")
			return time.Now().Add(DispatchLeaseTTL), func() { log = append(log, "release") }, nil
		}
		_, uerr := s.UploadCommunity(context.Background(), req)
		return uerr
	})
	if err != nil {
		t.Fatalf("upload: %v", err)
	}
	if got := strings.Join(log, ","); got != "pre,lease,request,release" {
		t.Fatalf("order = %s, want pre,lease,request,release", got)
	}
}

// TestDispatchLeaseRefusalNeverDispatches: a refused lease (the receipt was
// revoked/superseded between PreAttempt and the socket) aborts the attempt
// with the refusal, and nothing reaches the network.
func TestDispatchLeaseRefusalNeverDispatches(t *testing.T) {
	srv := noRequestServer(t)
	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatal(err)
	}
	refused := errors.New("lease refused: the receipt was revoked")
	err := g.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		req := communityRequestFor(receipt)
		req.DispatchLease = func(context.Context) (time.Time, func(), error) { return time.Time{}, nil, refused }
		_, uerr := s.UploadCommunity(context.Background(), req)
		return uerr
	})
	if !errors.Is(err, refused) {
		t.Fatalf("want the lease refusal to surface, got %v", err)
	}
}

// TestCohortBenchmarkingIsNotEvidenceUploadable is the DIRECT N8 pin the
// re-review asked for: the community purpose can never authorize a
// session-evidence body, at the rule table AND at the FeatureSend seam, with
// no request made.
func TestCohortBenchmarkingIsNotEvidenceUploadable(t *testing.T) {
	ok, reason := EvidenceUploadable(cloudcontract.PurposeCohortBenchmarking)
	if ok {
		t.Fatal("community_cohort_benchmarking is evidence-uploadable — a grant for one number could send a session body")
	}
	if !strings.Contains(reason, "derived per-window contribution") {
		t.Errorf("the refusal must say what the purpose DOES authorize: %q", reason)
	}
	if ok, _ := StandingGrantable(cloudcontract.PurposeCohortBenchmarking); !ok {
		t.Fatal("community_cohort_benchmarking must still be standing-grantable (the contribution rail)")
	}

	srv := noRequestServer(t)
	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatal(err)
	}
	err := g.FeatureSend(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(UploadSession) error {
		t.Error("FeatureSend handed out an evidence-upload handle under a community grant")
		return nil
	})
	if !errors.Is(err, ErrPurposeNotUploadable) {
		t.Fatalf("want ErrPurposeNotUploadable for a LIVE community grant, got %v", err)
	}
}

// TestHTTPErrorDecodesCodeAndRecoveryHints pins the F9 decode: status, code,
// message and every other string field (the recovery hints) come through.
func TestHTTPErrorDecodesCodeAndRecoveryHints(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte(`{"code":"cross_device_conflict","error":"already synced elsewhere","owner_device_hint":"dev-9","next_window":"2026-10","n":3}`))
	}))
	t.Cleanup(srv.Close)
	receipt := liveCommunityReceipt(srv.URL + "/v1/community/contribution")
	g := newTestGateway(t, &fakeGrants{receipts: []store.CloudConsentReceipt{receipt}}, srv.URL)
	if err := g.cred.SaveAPIToken("tok"); err != nil {
		t.Fatal(err)
	}
	var upErr error
	_ = g.StandingSendCommunity(context.Background(), cloudcontract.PurposeCohortBenchmarking, func(s CommunitySession) error {
		_, upErr = s.UploadCommunity(context.Background(), communityRequestFor(receipt))
		return upErr
	})
	d, ok := HTTPError(upErr)
	if !ok {
		t.Fatalf("HTTPError did not recognise %v", upErr)
	}
	if d.StatusCode != http.StatusConflict || d.Code != "cross_device_conflict" || d.Message != "already synced elsewhere" {
		t.Fatalf("decoded %+v", d)
	}
	if d.Extra["owner_device_hint"] != "dev-9" || d.Extra["next_window"] != "2026-10" {
		t.Fatalf("recovery hints not decoded: %+v", d.Extra)
	}
	if _, ok := d.Extra["n"]; ok {
		t.Error("a non-string field was decoded as a hint")
	}
	if _, ok := HTTPError(errors.New("transport")); ok {
		t.Fatal("a transport error is not an HTTP error")
	}
}
