//go:build linux

package sandboxrelayd

import (
	"context"
	"slices"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// claimed_linux_test.go holds the claim test that drives a real hook
// request through the Linux-only bind harness (bind_test.go), so the
// package's other tests typecheck on Windows and darwin (lane RC1).

// TestSessionClaimThroughBind: through a real hook request, a session the
// box starts is a fresh claim and is kept in the FreshStore, and a session
// the node recorded under the run's project before the run (a resumed host
// session, which the P-032 rule lets it speak for) is claimed but neither
// fresh nor kept; each id is looked up once per request.
func TestSessionClaimThroughBind(t *testing.T) {
	tr := newBindTree(t)
	run := bindRun(t, "run-a", tr)
	recorded := map[string]string{"host-own": tr.ws}
	var mu sync.Mutex
	lookups := map[string]int{}
	store := &memFresh{}
	d := &Daemon{FreshStore: store, SessionOwner: func(_ context.Context, id string) (string, error) {
		mu.Lock()
		lookups[id]++
		mu.Unlock()
		return recorded[id], nil
	}}
	h := startBindHarness(t, d, run)
	for _, id := range []string{"box-new", "host-own"} {
		resp := h.send(t, run, sandboxrelay.HookRequest{Stdin: []byte(`{"cwd":"` + tr.ws + `","session_id":"` + id + `"}`)})
		if resp.Refused != "" {
			t.Fatalf("%s: refused %q", id, resp.Refused)
		}
	}
	if c, f := d.SessionClaim("run-a", "box-new"); !c || !f {
		t.Fatalf("the box's own session: claimed %v fresh %v", c, f)
	}
	if c, f := d.SessionClaim("run-a", "host-own"); !c || f {
		t.Fatalf("a resumed host session: claimed %v fresh %v, want claimed and not fresh", c, f)
	}
	if got := store.Fresh("run-a"); !slices.Equal(got, []string{"box-new"}) {
		t.Fatalf("kept fresh ids %v, want only box-new", got)
	}
	mu.Lock()
	defer mu.Unlock()
	for id, n := range lookups {
		if n != 1 {
			t.Errorf("%s looked up %d times in one request", id, n)
		}
	}
}
