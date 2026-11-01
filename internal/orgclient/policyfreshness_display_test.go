package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// displayProbeServer serves BOTH the policy-version probe (a mutable rail
// vector) and GET /api/agent/display-policy (a scripted status/document), and
// counts display fetches.
type displayProbeServer struct {
	mu       sync.Mutex
	srv      *httptest.Server
	rails    map[string]int64
	status   int
	doc      any
	fetches  int
	otherHit int
}

func newDisplayProbeServer(t *testing.T) *displayProbeServer {
	t.Helper()
	ds := &displayProbeServer{status: http.StatusNotFound}
	ds.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ds.mu.Lock()
		defer ds.mu.Unlock()
		switch r.URL.Path {
		case orgcontract.PolicyVersionsPath:
			etag := `"pv-test-` + versionKey(ds.rails) + `"`
			w.Header().Set("ETag", etag)
			if r.Header.Get("If-None-Match") == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			writeTestJSON(w, http.StatusOK, orgcontract.PolicyVersionsDoc{RailVersions: ds.rails})
		case "/api/agent/display-policy":
			ds.fetches++
			if ds.status != http.StatusOK {
				writeTestJSON(w, ds.status, map[string]string{"error": "scripted"})
				return
			}
			writeTestJSON(w, http.StatusOK, ds.doc)
		default:
			ds.otherHit++
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ds.srv.Close)
	return ds
}

// TestProbeFetchesDisplayPolicyOnChange pins the display rail inside the
// policy-freshness mechanism, one row per probe: a moved display version
// fetches GET /api/agent/display-policy (and ONLY that rail) and applies a
// signed document, running the display sink once; an unchanged vector fetches
// nothing; a moved version whose fetch 404s, or whose document is unsigned,
// never clears or changes the last verified value and never runs the sink.
func TestProbeFetchesDisplayPolicyOnChange(t *testing.T) {
	ctx := context.Background()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ds := newDisplayProbeServer(t)
	c, s, _ := enrolledClient(t, ds.srv.URL)
	sinkRuns := 0
	c.SetDisplayPolicySink(func() { sinkRuns++ })

	unsigned := mustSignDisplay(t, priv, "org-1", 4, "usd")
	unsigned.Signature = ""
	base := map[string]int64{
		orgcontract.RailBudget: 1, orgcontract.RailPricing: 1, orgcontract.RailBundle: 1,
		orgcontract.RailRouting: 1, orgcontract.RailAnnouncement: 1,
	}
	withDisplay := func(v int64) map[string]int64 {
		m := copyVersions(base)
		m[orgcontract.RailDisplay] = v
		return m
	}
	type held struct {
		has     bool
		value   string
		version int64
	}
	steps := []struct {
		name        string
		rails       map[string]int64
		status      int
		doc         any
		wantFetches int // cumulative display fetches
		wantSink    int // cumulative sink runs
		want        held
	}{
		{name: "first probe is a baseline (pre-display server)", rails: copyVersions(base)},
		{
			name: "upgraded server adds the display key: fetched and applied", rails: withDisplay(1), status: http.StatusOK,
			doc: mustSignDisplay(t, priv, "org-1", 1, "usd"), wantFetches: 1, wantSink: 1, want: held{true, "usd", 1},
		},
		{
			name: "unchanged vector fetches nothing", rails: withDisplay(1), status: http.StatusOK,
			wantFetches: 1, wantSink: 1, want: held{true, "usd", 1},
		},
		{
			name: "display moved: fetched and applied", rails: withDisplay(2), status: http.StatusOK,
			doc: mustSignDisplay(t, priv, "org-1", 2, "tokens"), wantFetches: 2, wantSink: 2, want: held{true, "tokens", 2},
		},
		{
			name: "moved but the rail answers 404: last value kept", rails: withDisplay(3), status: http.StatusNotFound,
			wantFetches: 3, wantSink: 2, want: held{true, "tokens", 2},
		},
		{
			name: "moved but the document is unsigned: refused, value kept", rails: withDisplay(4), status: http.StatusOK,
			doc: unsigned, wantFetches: 4, wantSink: 2, want: held{true, "tokens", 2},
		},
		{
			name: "moved again with a signed document: applied", rails: withDisplay(5), status: http.StatusOK,
			doc: mustSignDisplay(t, priv, "org-1", 5, "usd"), wantFetches: 5, wantSink: 3, want: held{true, "usd", 5},
		},
	}
	for _, st := range steps {
		ds.mu.Lock()
		ds.rails, ds.status, ds.doc = st.rails, st.status, st.doc
		ds.mu.Unlock()
		c.probePolicyVersions(ctx, time.Now(), 0)
		ds.mu.Lock()
		fetches, other := ds.fetches, ds.otherHit
		ds.mu.Unlock()
		if fetches != st.wantFetches {
			t.Fatalf("%s: display fetches = %d, want %d", st.name, fetches, st.wantFetches)
		}
		if other != 0 {
			t.Fatalf("%s: a display-only change fetched %d other rails", st.name, other)
		}
		if sinkRuns != st.wantSink {
			t.Fatalf("%s: sink runs = %d, want %d", st.name, sinkRuns, st.wantSink)
		}
		row, ok, err := s.GetOrgDisplayPolicy(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got := held{has: ok}
		if ok {
			got.value, got.version = row.DeveloperCostDisplay, row.Version
		}
		if got != st.want {
			t.Fatalf("%s: node holds %+v, want %+v", st.name, got, st.want)
		}
	}

	// A vector that stops carrying the key (a stateless collector answered)
	// is not a move: nothing is fetched and nothing is cleared.
	ds.mu.Lock()
	ds.rails = copyVersions(base)
	ds.mu.Unlock()
	c.probePolicyVersions(ctx, time.Now(), 0)
	ds.mu.Lock()
	fetches := ds.fetches
	ds.mu.Unlock()
	if fetches != 5 {
		t.Fatalf("a vector without the display key fetched the rail: %d", fetches)
	}
	if row, ok, _ := s.GetOrgDisplayPolicy(ctx); !ok || row.Version != 5 {
		t.Fatalf("a vector without the display key changed the cache: %+v %v", row, ok)
	}
}

// TestRailFetchersCoverEveryRail keeps the dispatch table honest: every rail
// key the contract defines has exactly one fetch row, and every push-cycle
// rail is a known rail.
func TestRailFetchersCoverEveryRail(t *testing.T) {
	all := []string{
		orgcontract.RailBudget, orgcontract.RailPricing, orgcontract.RailBundle,
		orgcontract.RailRouting, orgcontract.RailAnnouncement, orgcontract.RailDisplay,
		orgcontract.RailGrants,
		orgcontract.RailAgentConfig,
		orgcontract.RailMessages,
	}
	seen := map[string]int{}
	for _, row := range railFetchers {
		for _, k := range row.keys {
			seen[k]++
		}
	}
	for _, k := range all {
		if seen[k] != 1 {
			t.Errorf("rail %q has %d fetch rows, want exactly 1", k, seen[k])
		}
	}
	known := map[string]bool{}
	for _, k := range all {
		known[k] = true
	}
	for k := range pushCycleRails {
		if !known[k] {
			t.Errorf("pushCycleRails names unknown rail %q", k)
		}
	}
}
