package cloudclient

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// structural_test.go covers the structural-upload leg's wire shape — in
// particular the R1 standing-grant binding headers the W2 server half
// validates. The node's job is to declare, verbatim, what the developer's
// resolved grant says; a snapshot sent WITHOUT that declaration is one the
// server cannot check against consent, so the client refuses it before
// anything leaves the machine rather than letting the check fail open.

// structuralTestClient signs the client in and returns it plus the server it
// talks to, with `handler` invoked for every structural POST.
func structuralTestClient(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	const token = "sbo-api-live-struct"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/structural-insights", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, cred := newTestClient(t, srv.URL, "wtok")
	if err := cred.SaveAPIToken(token); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}
	return c
}

func validStructuralRequest(payload []byte) StructuralUploadRequest {
	return StructuralUploadRequest{
		Payload:              payload,
		Period:               "2026-08-30",
		PeriodRuleVersion:    1,
		SchemaVersion:        "structural_insights.v1-candidate",
		Revision:             2,
		Digest:               "sha256:abc",
		ConsentGeneration:    7,
		DataDictionaryDigest: "sha256:dictionary",
		SourceWindowRule:     "completed_utc_days_trailing_30",
	}
}

// TestUploadStructuralCarriesTheGrantBindingHeaders pins the wire shape: the
// body is the payload VERBATIM and the grant binding rides beside it in
// headers, never inside the digested bytes.
func TestUploadStructuralCarriesTheGrantBindingHeaders(t *testing.T) {
	payload := []byte(`{"schema_version":"structural_insights.v1-candidate"}`)
	var (
		gotHeader http.Header
		gotBody   []byte
	)
	c := structuralTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotBody = readBody(t, r)
		writeJSON(w, map[string]any{"snapshot_id": "snap-9", "status": "stored", "replay": false})
	})

	resp, err := c.UploadStructural(context.Background(), validStructuralRequest(payload))
	if err != nil {
		t.Fatalf("UploadStructural: %v", err)
	}
	if resp.SnapshotID != "snap-9" || resp.Replay {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body was not sent verbatim: got %q want %q", gotBody, payload)
	}
	for header, want := range map[string]string{
		"SBO-Consent-Generation":     "7",
		"SBO-Data-Dictionary-Digest": "sha256:dictionary",
		"SBO-Source-Window-Rule":     "completed_utc_days_trailing_30",
		"SBO-Feature":                "structural_insights",
		"Content-Type":               "application/json",
	} {
		if got := gotHeader.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if !strings.HasPrefix(gotHeader.Get("Idempotency-Key"), "sbo-idem-struct-") {
		t.Errorf("Idempotency-Key = %q, want the structural prefix", gotHeader.Get("Idempotency-Key"))
	}
}

// TestUploadStructuralRefusesMissingGrantBinding is the fail-closed half: an
// upload with no declared grant binding never reaches the network.
func TestUploadStructuralRefusesMissingGrantBinding(t *testing.T) {
	payload := []byte(`{"schema_version":"structural_insights.v1-candidate"}`)
	requests := 0
	c := structuralTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(w, map[string]any{"snapshot_id": "snap-9"})
	})

	for name, mutate := range map[string]func(*StructuralUploadRequest){
		"no consent generation":     func(r *StructuralUploadRequest) { r.ConsentGeneration = 0 },
		"negative generation":       func(r *StructuralUploadRequest) { r.ConsentGeneration = -1 },
		"no data dictionary digest": func(r *StructuralUploadRequest) { r.DataDictionaryDigest = "" },
	} {
		req := validStructuralRequest(payload)
		mutate(&req)
		if _, err := c.UploadStructural(context.Background(), req); err == nil {
			t.Errorf("%s: UploadStructural succeeded, want a refusal", name)
		}
	}
	if requests != 0 {
		t.Fatalf("a refused upload still made %d request(s) — the check must run before dispatch", requests)
	}
}

// TestStructuralIdempotencyKeyIgnoresTheGrantBinding pins that a retry after a
// consent-generation bump carries the SAME key: the key identifies the WINDOW,
// so the server still replay-acks it instead of storing a duplicate.
func TestStructuralIdempotencyKeyIgnoresTheGrantBinding(t *testing.T) {
	payload := []byte(`{"schema_version":"structural_insights.v1-candidate"}`)
	var keys []string
	c := structuralTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		writeJSON(w, map[string]any{"snapshot_id": "snap-9", "status": "stored"})
	})

	req := validStructuralRequest(payload)
	if _, err := c.UploadStructural(context.Background(), req); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	req.ConsentGeneration = 99
	req.SourceWindowRule = "some_other_rule"
	if _, err := c.UploadStructural(context.Background(), req); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if len(keys) != 2 || keys[0] != keys[1] {
		t.Fatalf("idempotency keys diverged across a grant-binding change: %v", keys)
	}
}
