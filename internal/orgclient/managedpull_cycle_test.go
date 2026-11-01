package orgclient

import (
	"context"
	"net/http"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestPushCyclePollsTheSandboxRailOnlyWithConsent (SBX-P2E, P1c audit F8 and
// F10) drives a whole push cycle, not the poll step alone: a managed node
// holding enforce.sandbox makes one GET /api/agent/sandbox per cycle, and an
// individual node (or one without the authority) makes none, whatever else
// the cycle does.
func TestPushCyclePollsTheSandboxRailOnlyWithConsent(t *testing.T) {
	cases := []struct {
		name    string
		consent ManagedPullConsent
		want    int
	}{
		{"managed with the authority", ManagedPullConsent{Managed: true, HoldsAuthority: true}, 1},
		{"managed without the authority", ManagedPullConsent{Managed: true}, 0},
		{"individual", ManagedPullConsent{}, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// The consent is the resolver's answer; this drives the cycle
			// around it.
			m := newMPServer(t)
			c, priv, now := managedPullFixture(t, m.srv.URL)
			doc := signFor(t, priv, "sandbox", "scim-42", 1, now.Unix()+3600, `{"schema":"sbo-sandbox-managed-v1"}`)
			var mu sync.Mutex
			hits := 0
			m.set(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/agent/sandbox" {
					mu.Lock()
					hits++
					mu.Unlock()
					writeTestJSON(w, http.StatusOK, doc)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			})
			rec := &recordingSinks{}
			consent := tc.consent
			c.SetManagedPullRails(func(context.Context, orgcontract.ManagedPullRail) ManagedPullConsent { return consent },
				map[string]ManagedPullSink{"sandbox": rec.sink("sandbox")})
			// A rail cycle (the ceiling): the upload's result does not matter.
			_, _ = c.pushCycle(context.Background(), &pushCycleState{}, cycleKind{rails: true})
			mu.Lock()
			got := hits
			mu.Unlock()
			if got != tc.want {
				t.Fatalf("one push cycle made %d sandbox requests, want %d", got, tc.want)
			}
			if out := rec.last(t, "sandbox"); out.InForce != (tc.want == 1) {
				t.Fatalf("sandbox outcome %+v", out)
			}
		})
	}
}
