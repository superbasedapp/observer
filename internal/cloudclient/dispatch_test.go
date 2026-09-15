package cloudclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"
)

// dispatch_test.go pins the DispatchGuard transport semantics (Sol re-review
// N2): the guard runs AFTER PreAttempt as the last thing before the socket, its
// release runs after the attempt, a refused guard never dispatches, and a lease
// that has already expired bounds the request so it never reaches the wire.

func TestDispatchGuardRunsAfterPreAttemptAndReleasesAfter(t *testing.T) {
	var log []string
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		log = append(log, "request")
		writeJSON(w, map[string]any{"status": "stored"})
	})
	req := validCommunityRequest([]byte(`{"x":1}`))
	req.PreAttempt = func() error { log = append(log, "pre"); return nil }
	req.DispatchGuard = func(context.Context) (time.Time, func(), error) {
		log = append(log, "guard")
		return time.Now().Add(time.Minute), func() { log = append(log, "release") }, nil
	}
	if _, err := c.UploadCommunity(context.Background(), req); err != nil {
		t.Fatalf("UploadCommunity: %v", err)
	}
	if got := strings.Join(log, ","); got != "pre,guard,request,release" {
		t.Fatalf("order = %s, want pre,guard,request,release", got)
	}
}

func TestDispatchGuardRefusalNeverDispatches(t *testing.T) {
	requests := 0
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(w, map[string]any{"status": "stored"})
	})
	refused := errors.New("receipt revoked")
	req := validCommunityRequest([]byte(`{"x":1}`))
	req.DispatchGuard = func(context.Context) (time.Time, func(), error) { return time.Time{}, nil, refused }
	if _, err := c.UploadCommunity(context.Background(), req); !errors.Is(err, refused) {
		t.Fatalf("want the guard refusal, got %v", err)
	}
	if requests != 0 {
		t.Fatalf("a refused guard still dispatched %d request(s)", requests)
	}
}

// TestExpiredDispatchLeaseNeverReachesTheWire is the bound that makes a
// revoke's wait true: an attempt whose lease has already lapsed (the sender
// was descheduled past it) carries an expired deadline and is dead before a
// byte is written.
func TestExpiredDispatchLeaseNeverReachesTheWire(t *testing.T) {
	requests := 0
	c := communityTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(w, map[string]any{"status": "stored"})
	})
	released := 0
	req := validCommunityRequest([]byte(`{"x":1}`))
	req.DispatchGuard = func(context.Context) (time.Time, func(), error) {
		return time.Now().Add(-time.Second), func() { released++ }, nil
	}
	_, err := c.UploadCommunity(context.Background(), req)
	if err == nil {
		t.Fatal("an attempt under an expired lease succeeded")
	}
	if requests != 0 {
		t.Fatalf("an expired lease still reached the server (%d request(s))", requests)
	}
	if released == 0 {
		t.Fatal("the lease was not released after the dead attempt")
	}
}

// TestStructuralUploadHonoursTheDispatchGuard: the structural leg takes the
// same guard (both standing rails lease their dispatch).
func TestStructuralUploadHonoursTheDispatchGuard(t *testing.T) {
	requests := 0
	c := structuralTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		writeJSON(w, map[string]any{"snapshot_id": "s", "status": "stored"})
	})
	refused := errors.New("receipt superseded")
	req := validStructuralRequest([]byte(`{"x":1}`))
	req.DispatchGuard = func(context.Context) (time.Time, func(), error) { return time.Time{}, nil, refused }
	if _, err := c.UploadStructural(context.Background(), req); !errors.Is(err, refused) {
		t.Fatalf("want the guard refusal, got %v", err)
	}
	if requests != 0 {
		t.Fatalf("a refused guard still dispatched %d structural request(s)", requests)
	}
}
