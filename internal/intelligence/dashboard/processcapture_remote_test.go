//go:build !sbo_omit_remote

package dashboard

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// processcapture_remote_test.go is the remote-in half of the process
// capture tests: it drives the remote listener, which a build without the
// remote component (sbo_omit_remote) does not have, so it carries the same
// constraint as the remote controller it pairs with.

// TestProcessCaptureEstimateRefusedOnRemoteListener: the estimate is a Local
// route, like the config editor it serves.
func TestProcessCaptureEstimateRefusedOnRemoteListener(t *testing.T) {
	rc, enc := newReadyRemoteController(t)
	s := newRemoteTestServer(t, Options{Remote: rc})
	h := s.remoteGuardedHandler(rc)
	cookie, csrf := pairSession(t, h, enc)

	req := httptest.NewRequest(http.MethodGet, "/api/process/capture/estimate", nil)
	req.Host = testRemoteHost
	req.Header.Set("Origin", "https://"+testRemoteHost)
	req.AddCookie(cookie)
	req.Header.Set(remoteCSRFHeader, csrf)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("remote GET /api/process/capture/estimate = %d, want 403 (Local route)", rec.Code)
	}
}
