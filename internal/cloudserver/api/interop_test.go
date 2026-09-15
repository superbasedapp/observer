package api_test

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudclient"
	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
)

// TestCloudClientInteropRoundTrip drives the api.Server with the REAL node
// client (internal/cloudclient) rather than the raw-HTTP testClient helpers
// above — proving the server verifies the exact proof-of-possession format
// the node mints (cloudpop.Create -> cloudpop.Verify), end to end, and that a
// tampered body or a request lacking a valid proof is rejected.
func TestCloudClientInteropRoundTrip(t *testing.T) {
	h := newHarness(t)
	const subject = "mallory"

	// The raw-HTTP testClient handles the one step outside cloudclient's
	// public surface (preview-confirmation) and shares the SAME subject, so
	// both resolve to the same account — receipts are account-scoped, not
	// device-scoped, so the receipt confirmed here is honored for the
	// cloudclient device registered separately below.
	confirmer := h.login(t, subject)
	raw, uploadDigest, contentDigest := makeEnvelope(t, false)
	confirmer.previewConfirm(t, uploadDigest, contentDigest, []string{"structural_activity_insights"})

	cred := cloudcred.Open(t.TempDir(), nil)
	cl, err := cloudclient.New(cloudclient.Options{
		BaseURL:    h.srv.URL,
		Cred:       cred,
		Broker:     &cloudclient.StubBroker{Token: "dev:" + subject},
		HTTPClient: h.srv.Client(),
	})
	if err != nil {
		t.Fatalf("cloudclient.New: %v", err)
	}

	ctx := context.Background()
	if err := cl.Exchange(ctx); err != nil {
		t.Fatalf("cloudclient.Exchange: %v", err)
	}

	upResp, err := cl.Upload(ctx, cloudclient.UploadRequest{
		CloudSessionID: "cs-interop-1",
		Feature:        store.FeatureSessionEnrichment,
		Envelope:       raw,
		Digests:        cloudcontract.Digests{EvidenceContent: contentDigest, Upload: uploadDigest},
	})
	if err != nil {
		t.Fatalf("cloudclient.Upload: %v", err)
	}
	if upResp.JobID == "" {
		t.Fatalf("cloudclient.Upload: empty job id in response: %+v", upResp)
	}

	page, err := cl.Results(ctx, "")
	if err != nil {
		t.Fatalf("cloudclient.Results: %v", err)
	}
	// No worker runs synchronously in this test, so the page is legitimately
	// empty — the point of this call is that it decodes cleanly (next_cursor
	// as a JSON string) rather than erroring on the wire shape.
	if page.Results == nil {
		t.Logf("cloudclient.Results: results=nil (fine — nothing enriched yet)")
	}

	// --- tampered body: server-side digest check must reject it ---
	tampered := append([]byte{}, raw...)
	tampered = bytes.Replace(tampered, []byte(`"duration_seconds": 120`), []byte(`"duration_seconds": 121`), 1)
	if bytes.Equal(tampered, raw) {
		t.Fatal("failed to construct tampered body")
	}
	// Digests.Upload is left EMPTY (not set to a digest over the tampered
	// bytes): the client's own local self-check in Upload() only fires when
	// req.Digests.Upload is non-empty and disagrees with the actual bytes.
	// Leaving it empty lets the tampered request actually reach the server so
	// this exercises the SERVER's digest-mismatch rejection, not the client's
	// local guard.
	_, err = cl.Upload(ctx, cloudclient.UploadRequest{
		CloudSessionID: "cs-interop-tamper",
		Feature:        store.FeatureSessionEnrichment,
		Envelope:       tampered,
	})
	if err == nil {
		t.Fatal("cloudclient.Upload with tampered body: want error, got nil")
	}
	var apiErr *cloudclient.APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("cloudclient.Upload with tampered body: want *cloudclient.APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("tampered upload status=%d body=%s, want 422", apiErr.StatusCode, apiErr.Body)
	}

	// --- stolen token, no valid proof: must be rejected regardless of a
	// genuine bearer token ---
	token, err := cred.LoadAPIToken()
	if err != nil {
		t.Fatalf("cred.LoadAPIToken: %v", err)
	}
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+"/v1/usage", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	// No SBO-PoP header at all — a thief who only captured the bearer token
	// (e.g. from a log or a proxy) cannot mint one without the device's
	// private key.
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatalf("stolen-token request: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("stolen token without PoP: status=%d, want 401", resp.StatusCode)
	}
}
