package anthropic

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// TestCompleteNeverFollowsARedirect is RB1 sweep finding RBSW-7: with no
// HTTPClient set, a redirect from the endpoint is not followed, so the API
// key never reaches the redirect target.
func TestCompleteNeverFollowsARedirect(t *testing.T) {
	var hits atomic.Int32
	var leaked atomic.Value
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		leaked.Store(r.Header.Get("X-Api-Key"))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(okBody))
	}))
	defer target.Close()
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+r.URL.Path, http.StatusFound)
	}))
	defer endpoint.Close()

	req := baseRequest()
	req.Endpoint = endpoint.URL
	_, err := (&Client{}).Complete(context.Background(), req)
	if n := hits.Load(); n != 0 {
		t.Fatalf("the redirect target was called %d time(s), with X-Api-Key %q", n, leaked.Load())
	}
	if err == nil {
		t.Fatal("a redirected request succeeded")
	}
}
