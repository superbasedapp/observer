package cloudclient

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// community_test.go covers the community-contribution upload leg's wire
// shape — the same R1 standing-grant binding discipline as structural_test.go,
// PLUS the declared-timezone header: a contribution declares its receipt's
// source-window rule and timezone as wire terms (Sol re-review N1/N5).

// communityTestClient signs the client in and returns it, with `handler`
// invoked for every community-contribution POST.
func communityTestClient(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *Client {
	t.Helper()
	const token = "sbo-api-live-community"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/community/contribution", handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	c, cred := newTestClient(t, srv.URL, "wtok")
	if err := cred.SaveAPIToken(token); err != nil {
		t.Fatalf("SaveAPIToken: %v", err)
	}
	return c
}

func validCommunityRequest(payload []byte) CommunityUploadRequest {
	return CommunityUploadRequest{
		Payload:              payload,
		Digest:               "sha256:abc",
		ConsentGeneration:    7,
		DataDictionaryDigest: "sha256:dictionary",
		SourceWindowRule:     "in_progress_utc_month_after_grant",
		DeclaredTimezone:     "UTC",
	}
}

// TestUploadCommunityCarriesTheGrantBindingHeaders pins the wire shape: the
// body is the payload VERBATIM and the FULL grant binding rides beside it in
// headers — generation, dictionary digest, source-window rule and declared
// timezone (the last two were absent before the Sol re-review; N1/N5).
func TestUploadCommunityCarriesTheGrantBindingHeaders(t *testing.T) {
	payload := []byte(`{"schema_version":"community_contribution.v1-candidate"}`)
	var (
		gotHeader http.Header
		gotBody   []byte
	)
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotBody = readBody(t, r)
		writeJSON(w, map[string]any{"contribution_id": "contrib-9", "status": "stored", "replay": false})
	})

	resp, err := c.UploadCommunity(context.Background(), validCommunityRequest(payload))
	if err != nil {
		t.Fatalf("UploadCommunity: %v", err)
	}
	if resp.ContributionID != "contrib-9" || resp.Replay {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if string(gotBody) != string(payload) {
		t.Fatalf("body was not sent verbatim: got %q want %q", gotBody, payload)
	}
	for header, want := range map[string]string{
		"SBO-Consent-Generation":     "7",
		"SBO-Data-Dictionary-Digest": "sha256:dictionary",
		"SBO-Source-Window-Rule":     "in_progress_utc_month_after_grant",
		"SBO-Declared-Timezone":      "UTC",
		"SBO-Feature":                "community_contribution",
		"Content-Type":               "application/json",
	} {
		if got := gotHeader.Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if !strings.HasPrefix(gotHeader.Get("Idempotency-Key"), "sbo-idem-community-") {
		t.Errorf("Idempotency-Key = %q, want the community prefix", gotHeader.Get("Idempotency-Key"))
	}
}

// TestUploadCommunityRefusesMissingGrantBinding is the fail-closed half: an
// upload with no declared grant binding never reaches the network.
func TestUploadCommunityRefusesMissingGrantBinding(t *testing.T) {
	payload := []byte(`{"schema_version":"community_contribution.v1-candidate"}`)
	requests := 0
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(w, map[string]any{"contribution_id": "contrib-9"})
	})

	for name, mutate := range map[string]func(*CommunityUploadRequest){
		"no consent generation":     func(r *CommunityUploadRequest) { r.ConsentGeneration = 0 },
		"negative generation":       func(r *CommunityUploadRequest) { r.ConsentGeneration = -1 },
		"no data dictionary digest": func(r *CommunityUploadRequest) { r.DataDictionaryDigest = "" },
		"no source window rule":     func(r *CommunityUploadRequest) { r.SourceWindowRule = "" },
		"no declared timezone":      func(r *CommunityUploadRequest) { r.DeclaredTimezone = "" },
		"empty payload":             func(r *CommunityUploadRequest) { r.Payload = nil },
		"empty digest":              func(r *CommunityUploadRequest) { r.Digest = "" },
	} {
		req := validCommunityRequest(payload)
		mutate(&req)
		if _, err := c.UploadCommunity(context.Background(), req); err == nil {
			t.Errorf("%s: UploadCommunity succeeded, want a refusal", name)
		}
	}
	if requests != 0 {
		t.Fatalf("a refused upload still made %d request(s) — the check must run before dispatch", requests)
	}
}

// TestCommunityIdempotencyKeyIgnoresTheGrantBinding pins that a retry after a
// consent-generation bump carries the SAME key: the key identifies the
// contribution's content (device + digest), so the server still replay-acks
// it instead of storing a duplicate.
func TestCommunityIdempotencyKeyIgnoresTheGrantBinding(t *testing.T) {
	payload := []byte(`{"schema_version":"community_contribution.v1-candidate"}`)
	var keys []string
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		writeJSON(w, map[string]any{"contribution_id": "contrib-9", "status": "stored"})
	})

	req := validCommunityRequest(payload)
	if _, err := c.UploadCommunity(context.Background(), req); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	req.ConsentGeneration = 99
	if _, err := c.UploadCommunity(context.Background(), req); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if len(keys) != 2 || keys[0] != keys[1] {
		t.Fatalf("idempotency keys diverged across a grant-binding change: %v", keys)
	}
}

// TestCommunityIdempotencyKeyChangesWithDigest pins the other direction: a
// different contribution (different digest) must NOT collide on the same key.
func TestCommunityIdempotencyKeyChangesWithDigest(t *testing.T) {
	payload := []byte(`{"schema_version":"community_contribution.v1-candidate"}`)
	var keys []string
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("Idempotency-Key"))
		writeJSON(w, map[string]any{"contribution_id": "contrib-9", "status": "stored"})
	})

	req := validCommunityRequest(payload)
	if _, err := c.UploadCommunity(context.Background(), req); err != nil {
		t.Fatalf("first upload: %v", err)
	}
	req.Digest = "sha256:def"
	if _, err := c.UploadCommunity(context.Background(), req); err != nil {
		t.Fatalf("second upload: %v", err)
	}
	if len(keys) != 2 || keys[0] == keys[1] {
		t.Fatalf("idempotency keys collided across different digests: %v", keys)
	}
}

// TestUploadCommunityInvokesPreAttemptBeforeEveryRequest pins the FD3 hook
// timing: PreAttempt runs before the physical HTTP attempt, and a non-nil
// error from it aborts without dispatching.
func TestUploadCommunityInvokesPreAttemptBeforeEveryRequest(t *testing.T) {
	payload := []byte(`{"schema_version":"community_contribution.v1-candidate"}`)
	requests := 0
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(w, map[string]any{"contribution_id": "contrib-9", "status": "stored"})
	})

	preAttempts := 0
	req := validCommunityRequest(payload)
	req.PreAttempt = func() error {
		preAttempts++
		return nil
	}
	if _, err := c.UploadCommunity(context.Background(), req); err != nil {
		t.Fatalf("UploadCommunity: %v", err)
	}
	if preAttempts != 1 || requests != 1 {
		t.Fatalf("preAttempts=%d requests=%d, want 1 and 1", preAttempts, requests)
	}

	req2 := validCommunityRequest(payload)
	req2.PreAttempt = func() error { return context.Canceled }
	if _, err := c.UploadCommunity(context.Background(), req2); err == nil {
		t.Fatal("UploadCommunity with a failing PreAttempt succeeded, want a refusal")
	}
	if requests != 1 {
		t.Fatalf("a refused PreAttempt still dispatched a request: requests=%d", requests)
	}
}

// TestUploadCommunityClassifiesHTTPErrors pins that non-2xx responses surface
// as the SAME *APIError taxonomy structural uploads use — no new error type.
func TestUploadCommunityClassifiesHTTPErrors(t *testing.T) {
	payload := []byte(`{"schema_version":"community_contribution.v1-candidate"}`)
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"unregistered cohort"}`))
	})

	_, err := c.UploadCommunity(context.Background(), validCommunityRequest(payload))
	if err == nil {
		t.Fatal("UploadCommunity against a 400 response succeeded, want an error")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error %v is not an *APIError", err)
	}
	if apiErr.StatusCode != http.StatusBadRequest {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, http.StatusBadRequest)
	}
}
