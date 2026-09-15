package orgclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestPushOnce_BudgetPostureOnlyStillShips is SF-19 end-to-end on the client:
// a node with NO row activity and NO aggregate tier, whose only news is its own
// budget posture, must still deliver an envelope.
//
// It is the sibling of TestPushOnce_AggregateOnlyStillShips and exists because
// the posture was in neither RowCount() nor hasAggregates(): PushOnce
// early-returned PushResult{Empty:true}, the server never heard from a node
// that was actively controlling processes, and the Budgets page reported
// direct_control = not_reported over it.
//
// It also pins the cadence stamp, because the two halves of the fix are
// useless apart: delivering the posture at a 15-minute cadence into a
// server-side 5-minute freshness horizon still reads as not_reported.
func TestPushOnce_BudgetPostureOnlyStillShips(t *testing.T) {
	cases := []struct {
		name         string
		configured   int
		wantInterval int
		why          string
	}{
		{
			name: "unset resolves to the default cadence", configured: 0,
			wantInterval: config.DefaultPushIntervalSeconds,
			why:          "the stamp must be the RESOLVED interval the loop ticks at, not the raw config value",
		},
		{
			name: "the live estate's 15 minutes", configured: 900, wantInterval: 900,
			why: "the exact shape SF-19 was reported against",
		},
		{
			name: "a negative cadence resolves to the default", configured: -5,
			wantInterval: config.DefaultPushIntervalSeconds,
			why:          "pushInterval() clamps, and the wire must never carry a nonsense cadence",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			s.SetBudgetPostureProvider(func() (orgcontract.BudgetPostureRow, bool) {
				return orgcontract.BudgetPostureRow{
					EnforcementPoint: orgcontract.BudgetPointGuard,
					Mode:             "enforce",
					Source:           orgcontract.BudgetSourceOrgAuthoritative,
					FetchState:       orgcontract.BudgetFetchOK,
					FromOrg:          true, LastFetchOK: true, Capped: true,
					Coverage:      orgcontract.BudgetCoverageProxyOnly,
					DirectControl: orgcontract.DirectControlPartial,
				}, true
			})
			bs := &memBearerStore{}

			var env orgcontract.PushEnvelope
			hit := false
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hit = true
				wire, _ := io.ReadAll(r.Body)
				env = decodeEnvelope(t, wire)
				writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{NextCursor: env.CursorTo})
			}))
			defer srv.Close()

			pub := enrolFixture(t, s, bs, srv.URL)
			bindPub(srv, pub)
			// NO seedActivity and NO share tier: the posture is the only news.

			cfg := config.OrgClientConfig{
				Enabled: true, PushIntervalSeconds: tc.configured,
				MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
			}
			c := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
			res, err := c.PushOnce(context.Background())
			if err != nil {
				t.Fatalf("PushOnce: %v", err)
			}
			if res.Empty {
				t.Fatalf("posture-only push reported Empty; the admin would see direct_control=not_reported forever")
			}
			if !hit {
				t.Fatalf("server was never hit for a posture-only batch")
			}
			if env.BudgetPosture == nil {
				t.Fatalf("no budget posture on the wire: %+v", env)
			}
			if env.BudgetPosture.DirectControl != orgcontract.DirectControlPartial {
				t.Errorf("DirectControl = %q, want %q", env.BudgetPosture.DirectControl, orgcontract.DirectControlPartial)
			}
			if got := env.BudgetPosture.PushIntervalSeconds; got != tc.wantInterval {
				t.Errorf("PushIntervalSeconds = %d, want %d — %s", got, tc.wantInterval, tc.why)
			}
			if n := len(env.Sessions) + len(env.Actions) + len(env.TokenUsage); n != 0 {
				t.Errorf("posture-only push unexpectedly carried %d rows", n)
			}
		})
	}
}

// TestPushOnce_NoPostureStaysEmpty is the other direction: a node without the
// rail wired must keep the pre-SF-19 behaviour exactly — no envelope, no
// egress. The fix widens what counts as pushable, it does not make every idle
// node chatty.
func TestPushOnce_NoPostureStaysEmpty(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hit = true
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{})
	}))
	defer srv.Close()
	pub := enrolFixture(t, s, bs, srv.URL)
	bindPub(srv, pub)

	// A provider that reports nothing is the same as no provider at all.
	s.SetBudgetPostureProvider(func() (orgcontract.BudgetPostureRow, bool) {
		return orgcontract.BudgetPostureRow{}, false
	})
	cfg := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
	}
	c := New(cfg, s, bs, "test-version", http.DefaultClient, quietLogger())
	res, err := c.PushOnce(context.Background())
	if err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if !res.Empty || hit {
		t.Fatalf("an idle node with nothing to report pushed anyway (empty=%v, hit=%v)", res.Empty, hit)
	}
}

// compile-time proof the seam used above is the real one.
var _ func(store.BudgetPostureProvider) = (*store.Store)(nil).SetBudgetPostureProvider
