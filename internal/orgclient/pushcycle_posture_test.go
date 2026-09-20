package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// postureSink is a test double for the cmd/observer budget boundary: it
// receives every budget-fetch outcome and republishes the posture the store's
// provider reads at push time - exactly the sink/provider pair the daemon
// wires, minus the guard.
type postureSink struct {
	mu       sync.Mutex
	outcomes []BudgetFetchOutcome
	events   []string // "fetch" / "push" in observed order
	row      orgcontract.BudgetPostureRow
}

func (p *postureSink) sink(o BudgetFetchOutcome) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.outcomes = append(p.outcomes, o)
	p.events = append(p.events, "fetch")
	p.row.FetchState = o.State
	p.row.LastFetchOK = o.State == orgcontract.BudgetFetchOK
	if o.State == orgcontract.BudgetFetchOK {
		p.row.Coverage = orgcontract.BudgetCoverageProxyOnly
	} else {
		p.row.Coverage = orgcontract.BudgetCoverageBudgetRequired
	}
}

func (p *postureSink) provider() (orgcontract.BudgetPostureRow, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.row, true
}

func (p *postureSink) notePush() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.events = append(p.events, "push")
}

// pushAndBudgetServer serves GET /api/agent/budget (a signed doc, or a fixed
// failure status) and accepts the push envelope, recording the last one.
type pushAndBudgetServer struct {
	srv      *httptest.Server
	mu       sync.Mutex
	envelope *orgcontract.PushEnvelope
	pushes   int
}

func newPushAndBudgetServer(t *testing.T, doc *orgcontract.BudgetPolicyDoc, budgetStatus int, sink *postureSink) *pushAndBudgetServer {
	t.Helper()
	ps := &pushAndBudgetServer{}
	ps.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/agent/budget":
			if budgetStatus != 0 {
				w.WriteHeader(budgetStatus)
				return
			}
			writeTestJSON(w, http.StatusOK, doc)
		case r.Method == http.MethodPost:
			sink.notePush()
			wire, _ := io.ReadAll(r.Body)
			env := decodeEnvelope(t, wire)
			ps.mu.Lock()
			ps.envelope = &env
			ps.pushes++
			ps.mu.Unlock()
			writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{NextCursor: env.CursorTo})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ps.srv.Close)
	return ps
}

// primedUnreachable is the posture a restarted daemon publishes before its
// first poll (cmd/observer's initialFetchState): the exact row the demo estate
// saw land on the org one second before the fetch succeeded.
func primedUnreachable() orgcontract.BudgetPostureRow {
	return orgcontract.BudgetPostureRow{
		EnforcementPoint: orgcontract.BudgetPointGuard,
		Mode:             "enforce",
		FetchState:       orgcontract.BudgetFetchUnreachable,
		FromOrg:          true,
		Coverage:         orgcontract.BudgetCoverageBudgetRequired,
	}
}

// wirePostureFixture enrols a client against srv with the budget key pinned,
// the sink installed and the provider primed to `unreachable`.
func wirePostureFixture(t *testing.T, srvURL string, pub ed25519.PublicKey, sink *postureSink) (*Client, *store.Store) {
	t.Helper()
	s := newAgentStore(t)
	bs := &memBearerStore{}
	pushPub := enrolFixture(t, s, bs, srvURL)
	testPubKeys[srvURL] = pushPub
	pinRoutingKey(t, s, encodeStdKey(pub))
	sink.row = primedUnreachable()
	s.SetBudgetPostureProvider(sink.provider)
	c := newTestClient(t, s, bs)
	c.SetBudgetSink(sink.sink)
	return c, s
}

// TestPushCycleCarriesThisCyclesBudgetFetch is the demo-estate finding
// (2026-09-20) pinned at the cycle: the posture on the wire must describe the
// fetch THIS cycle made, which means the budget rail runs BEFORE the envelope
// is built. Before the reorder the first cycle after a restart pushed the
// primed `unreachable` / `budget_required` row and the org only learned the
// truth one full push interval (900 s) later.
//
// One row per fetch outcome, so the ordering is pinned for the failure states
// as well as the happy one: a cycle whose fetch FAILED must ship that failure,
// not a stale ok from the cycle before.
func TestPushCycleCarriesThisCyclesBudgetFetch(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(7, 10_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}

	cases := []struct {
		name         string
		budgetStatus int // 0 = serve the signed doc
		wantState    string
		wantCoverage string
		why          string
	}{
		{
			name: "signed budget served", wantState: orgcontract.BudgetFetchOK,
			wantCoverage: orgcontract.BudgetCoverageProxyOnly,
			why:          "the live shape: fetch succeeds in the same cycle, the org must read ok / proxy_only at once",
		},
		{
			name: "org server 500", budgetStatus: http.StatusInternalServerError,
			wantState: orgcontract.BudgetFetchUnreachable, wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
			why: "a failed fetch is this cycle's truth too - it must not be masked by a prior ok",
		},
		{
			name: "policy channel off (409)", budgetStatus: http.StatusConflict,
			wantState: orgcontract.BudgetFetchChannelOff, wantCoverage: orgcontract.BudgetCoverageBudgetRequired,
			why: "the demo estate's OTHER finding - the org must see channel_off, not the primed unreachable",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &postureSink{}
			ps := newPushAndBudgetServer(t, &doc, tc.budgetStatus, sink)
			c, _ := wirePostureFixture(t, ps.srv.URL, pub, sink)

			state := &pushCycleState{}
			if err := c.pushCycle(context.Background(), state); err != nil {
				t.Fatalf("pushCycle: %v", err)
			}

			sink.mu.Lock()
			events := append([]string(nil), sink.events...)
			outcomes := len(sink.outcomes)
			sink.mu.Unlock()
			if len(events) < 2 || events[0] != "fetch" || events[1] != "push" {
				t.Fatalf("cycle order = %v, want the budget fetch BEFORE the push - %s", events, tc.why)
			}
			if outcomes != 1 {
				t.Fatalf("budget sink poked %d times in one cycle, want 1", outcomes)
			}
			ps.mu.Lock()
			env := ps.envelope
			ps.mu.Unlock()
			if env == nil || env.BudgetPosture == nil {
				t.Fatalf("no budget posture on the wire (envelope=%v)", env != nil)
			}
			if env.BudgetPosture.FetchState != tc.wantState {
				t.Errorf("wire fetch_state = %q, want %q - %s", env.BudgetPosture.FetchState, tc.wantState, tc.why)
			}
			if env.BudgetPosture.Coverage != tc.wantCoverage {
				t.Errorf("wire coverage = %q, want %q", env.BudgetPosture.Coverage, tc.wantCoverage)
			}
			if got := env.BudgetPosture.LastFetchOK; got != (tc.wantState == orgcontract.BudgetFetchOK) {
				t.Errorf("wire last_fetch_ok = %v for fetch_state %q", got, tc.wantState)
			}
		})
	}
}

// TestPushNowCarriesTheCurrentBudgetPosture pins `observer org push-now`'s
// contract: it refreshes the budget rail and THEN pushes, so the envelope
// carries the posture composed from that fetch, not the primed one the
// process started with. The bare PushOnce is the control: it ships whatever
// the provider holds, which is exactly why the CLI must not call it directly.
func TestPushNowCarriesTheCurrentBudgetPosture(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	doc, err := orgcontract.SignBudgetPolicy(priv, "org-1", "scim-42", budgetBody(3, 5_000_000))
	if err != nil {
		t.Fatalf("SignBudgetPolicy: %v", err)
	}

	cases := []struct {
		name      string
		push      func(*Client) (PushResult, error)
		wantState string
		wantFetch int
		why       string
	}{
		{
			name:      "PushNow refreshes first",
			push:      func(c *Client) (PushResult, error) { return c.PushNow(context.Background()) },
			wantState: orgcontract.BudgetFetchOK, wantFetch: 1,
			why: "the operator-triggered push must carry the fetch state at push time",
		},
		{
			name:      "bare PushOnce ships the primed posture (control)",
			push:      func(c *Client) (PushResult, error) { return c.PushOnce(context.Background()) },
			wantState: orgcontract.BudgetFetchUnreachable, wantFetch: 0,
			why: "PushOnce makes no fetch - this is the row the demo estate saw",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sink := &postureSink{}
			ps := newPushAndBudgetServer(t, &doc, 0, sink)
			c, _ := wirePostureFixture(t, ps.srv.URL, pub, sink)

			res, err := tc.push(c)
			if err != nil {
				t.Fatalf("push: %v", err)
			}
			if res.Empty {
				t.Fatalf("posture-only push reported Empty")
			}
			sink.mu.Lock()
			fetches := len(sink.outcomes)
			sink.mu.Unlock()
			if fetches != tc.wantFetch {
				t.Fatalf("budget fetches = %d, want %d - %s", fetches, tc.wantFetch, tc.why)
			}
			ps.mu.Lock()
			env := ps.envelope
			ps.mu.Unlock()
			if env == nil || env.BudgetPosture == nil {
				t.Fatalf("no budget posture on the wire")
			}
			if env.BudgetPosture.FetchState != tc.wantState {
				t.Errorf("wire fetch_state = %q, want %q - %s", env.BudgetPosture.FetchState, tc.wantState, tc.why)
			}
		})
	}

	t.Run("not enrolled touches no rail", func(t *testing.T) {
		sink := &postureSink{}
		s := newAgentStore(t)
		c := newTestClient(t, s, &memBearerStore{})
		c.SetBudgetSink(sink.sink)
		_, err := c.PushNow(context.Background())
		if !errors.Is(err, ErrNotEnrolled) {
			t.Fatalf("err = %v, want ErrNotEnrolled", err)
		}
		if len(sink.outcomes) != 0 {
			t.Errorf("budget sink poked on an unenrolled node: %+v", sink.outcomes)
		}
	})
}
