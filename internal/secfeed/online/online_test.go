package online

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

type fakeNet struct {
	mu   sync.Mutex
	reqs []string
	osv  func(w http.ResponseWriter, body []byte)
	reg  func(w http.ResponseWriter, r *http.Request)
}

func newFake(t *testing.T, f *fakeNet) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("User-Agent") != UserAgent || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("identifying headers: %v", r.Header)
		}
		b, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		f.reqs = append(f.reqs, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if r.URL.Path == "/v1/querybatch" {
			f.osv(w, b)
			return
		}
		f.reg(w, r)
	}))
	t.Cleanup(srv.Close)
	eps := map[string]string{OSVHost: srv.URL, FeedHost: srv.URL}
	for _, e := range secfeed.Ecosystems() {
		eps[e.MetadataHost] = srv.URL
	}
	return New(Options{HTTP: srv.Client(), Endpoints: eps})
}

func osvEcho(ids map[string][]string) func(http.ResponseWriter, []byte) {
	return func(w http.ResponseWriter, body []byte) {
		var q struct {
			Queries []struct {
				Package struct{ Name string } `json:"package"`
			} `json:"queries"`
		}
		_ = json.Unmarshal(body, &q)
		type vuln struct {
			ID string `json:"id"`
		}
		var res struct {
			Results []struct {
				Vulns []vuln `json:"vulns"`
			} `json:"results"`
		}
		for _, qq := range q.Queries {
			var r struct {
				Vulns []vuln `json:"vulns"`
			}
			for _, id := range ids[qq.Package.Name] {
				r.Vulns = append(r.Vulns, vuln{ID: id})
			}
			res.Results = append(res.Results, r)
		}
		_ = json.NewEncoder(w).Encode(res)
	}
}

func TestLookup(t *testing.T) {
	f := &fakeNet{osv: osvEcho(map[string][]string{"evil": {"MAL-2026-1", "GHSA-x"}})}
	f.reg = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/left-pad", "/evil":
			if !strings.HasPrefix(r.Header.Get("Accept"), "application/vnd.npm.install-v1+json") {
				t.Errorf("npm asked without the abbreviated packument: %q", r.Header.Get("Accept"))
			}
			_, _ = io.WriteString(w, `{"modified":"2016-03-01T00:00:00Z","versions":{"1.0.0":{}}}`)
		case "/pypi/requests/json":
			_, _ = io.WriteString(w, `{"releases":{"1.0":[{"upload_time_iso_8601":"2011-02-14T00:00:00Z"}],"0.1":[{"upload_time_iso_8601":"2011-01-01T00:00:00Z"}]}}`)
		case "/api/v1/crates/serde":
			_, _ = io.WriteString(w, `{"crate":{"created_at":"2014-12-05T20:20:39Z"}}`)
		case "/github.com/!azure/x/@v/list":
			_, _ = io.WriteString(w, "v1.0.0\n")
		default:
			http.NotFound(w, r)
		}
	}
	c := newFake(t, f)
	specs := []secfeed.InstallSpec{
		secfeed.ParseSpec(secfeed.EcoNpm, "left-pad"),
		secfeed.ParseSpec(secfeed.EcoNpm, "evil@1.0.0"),
		secfeed.ParseSpec(secfeed.EcoNpm, "never-registered"),
		secfeed.ParseSpec(secfeed.EcoPyPI, "requests"),
		secfeed.ParseSpec(secfeed.EcoCargo, "serde"),
		secfeed.ParseSpec(secfeed.EcoGo, "github.com/Azure/x"),
		secfeed.ParseSpec(secfeed.EcoNpm, "github:user/repo"),
	}
	got := c.Lookup(context.Background(), specs)
	want := []secfeed.OnlineStatus{secfeed.OnlineAnswered, secfeed.OnlineAnswered, secfeed.OnlineNotFound, secfeed.OnlineAnswered, secfeed.OnlineAnswered, secfeed.OnlineAnswered, secfeed.OnlineFailed}
	for i, w := range want {
		if got[i].Status != w {
			t.Errorf("%s: %s (%s), want %s", specs[i].Spec, got[i].Status, got[i].Reason, w)
		}
	}
	if len(got[1].MalIDs) != 1 || len(got[1].VulnIDs) != 1 {
		t.Errorf("evil ids %+v", got[1])
	}
	if !got[3].FirstPublished.Equal(time.Date(2011, 1, 1, 0, 0, 0, 0, time.UTC)) || got[0].FirstPublished.Year() != 2016 {
		t.Errorf("first published %v %v", got[3].FirstPublished, got[0].FirstPublished)
	}
	if got[6].Reason != ReasonNotPublic {
		t.Errorf("an invalid spec is refused before the network: %+v", got[6])
	}
	for _, r := range f.reqs {
		if strings.Contains(r, "github:") || strings.Contains(r, "user/repo") {
			t.Errorf("an invalid spec reached the network: %s", r)
		}
	}
}

func TestLookupFailuresNeverAnswerFine(t *testing.T) {
	// OSV down: the registry answer alone is incomplete, never "fine".
	f := &fakeNet{osv: func(w http.ResponseWriter, _ []byte) { http.Error(w, "x", http.StatusServiceUnavailable) }}
	f.reg = func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"modified":"2016-03-01T00:00:00Z","versions":{"1.0.0":{}}}`)
	}
	c := newFake(t, f)
	got := c.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")})
	if got[0].Status != secfeed.OnlineFailed || got[0].Reason != ReasonOSV {
		t.Errorf("osv down: %+v", got[0])
	}

	// 429 starts a back-off: the next call does not reach the host.
	f2 := &fakeNet{osv: osvEcho(nil)}
	f2.reg = func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	}
	c2 := newFake(t, f2)
	got = c2.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")})
	if got[0].Reason != ReasonRateLimited {
		t.Errorf("429: %+v", got[0])
	}
	n := len(f2.reqs)
	got = c2.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")})
	if got[0].Reason != ReasonCoolingDown || len(f2.reqs) != n+1 { // only the OSV call goes out
		t.Errorf("cool-down: %+v, %d requests", got[0], len(f2.reqs)-n)
	}

	// A redirect is never followed; a slow host times out at the deadline.
	f3 := &fakeNet{osv: osvEcho(nil)}
	f3.reg = func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			time.Sleep(300 * time.Millisecond)
		}
		http.Redirect(w, r, "https://evil.example/", http.StatusFound)
	}
	c3 := newFake(t, f3)
	got = c3.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "left-pad")})
	if got[0].Status != secfeed.OnlineFailed || got[0].Reason != ReasonHTTPStatus {
		t.Errorf("redirect: %+v", got[0])
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	got = c3.Lookup(ctx, []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "slow")})
	if got[0].Reason != ReasonTimeout && got[0].Reason != ReasonOSV {
		t.Errorf("deadline: %+v", got[0])
	}
}

// TestNPMTwoStep is milestone 2e: npm is read through the abbreviated
// packument; only a recently modified package with few versions is read in
// full (for its creation time), and a recently modified large package is
// never read in full.
func TestNPMTwoStep(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-time.Hour).Format(time.RFC3339)
	many := `{`
	for i := range 40 {
		if i > 0 {
			many += ","
		}
		many += `"1.0.` + strings.Repeat("1", i+1) + `":{}`
	}
	many += `}`
	full := map[string]int{}
	f := &fakeNet{osv: osvEcho(nil)}
	f.reg = func(w http.ResponseWriter, r *http.Request) {
		abbreviated := strings.HasPrefix(r.Header.Get("Accept"), "application/vnd.npm.install-v1+json")
		if !abbreviated {
			full[r.URL.Path]++
		}
		switch {
		case r.URL.Path == "/brand-new" && abbreviated:
			_, _ = io.WriteString(w, `{"modified":"`+recent+`","versions":{"0.0.1":{}}}`)
		case r.URL.Path == "/brand-new":
			_, _ = io.WriteString(w, `{"time":{"created":"`+recent+`"}}`)
		case r.URL.Path == "/typescript" && abbreviated:
			_, _ = io.WriteString(w, `{"modified":"`+recent+`","versions":`+many+`}`)
		case r.URL.Path == "/old-pkg" && abbreviated:
			_, _ = io.WriteString(w, `{"modified":"2019-01-01T00:00:00Z","versions":{"1.0.0":{}}}`)
		default:
			http.NotFound(w, r)
		}
	}
	c := newFake(t, f)
	got := c.Lookup(context.Background(), []secfeed.InstallSpec{
		secfeed.ParseSpec(secfeed.EcoNpm, "brand-new"), secfeed.ParseSpec(secfeed.EcoNpm, "typescript"), secfeed.ParseSpec(secfeed.EcoNpm, "old-pkg"),
	})
	if got[0].Status != secfeed.OnlineAnswered || now.Sub(got[0].FirstPublished) > 2*time.Hour {
		t.Errorf("brand-new: %+v", got[0])
	}
	if got[1].Status != secfeed.OnlineAnswered || !got[1].FirstPublished.IsZero() || full["/typescript"] != 0 {
		t.Errorf("typescript: %+v, full reads %d", got[1], full["/typescript"])
	}
	if got[2].FirstPublished.Year() != 2019 || full["/old-pkg"] != 0 {
		t.Errorf("old-pkg: %+v", got[2])
	}
}

// TestDefaultTransportHonoursProxy is milestone 3d: the default transport
// reads HTTPS_PROXY.
func TestDefaultTransportHonoursProxy(t *testing.T) {
	tr, ok := New(Options{}).http.Transport.(*http.Transport)
	if !ok || tr.Proxy == nil {
		t.Fatal("the default transport has no proxy function")
	}
}

func TestOnlyAllowListedHTTPS(t *testing.T) {
	c := New(Options{})
	for _, raw := range []string{
		"http://registry.npmjs.org/x", "https://registry.npmjs.org.evil.example/x", "https://u:p@registry.npmjs.org/x",
		"https://registry.npmjs.org:8443/x", "https://example.com/x",
	} {
		if _, _, err := c.do(context.Background(), http.MethodGet, raw, nil, 1); ReasonOf(err) != ReasonNotPublic {
			t.Errorf("%s: %v", raw, err)
		}
	}
	hosts := strings.Join(c.AllowedHosts(), " ")
	for _, h := range []string{OSVHost, FeedHost, "registry.npmjs.org", "pypi.org", "crates.io", "proxy.golang.org"} {
		if !strings.Contains(hosts, h) {
			t.Errorf("allow-list lacks %s", h)
		}
	}
}

func TestFeedURL(t *testing.T) {
	if u := FeedURL("security.malicious_packages", "manifest.json"); u != "https://superbased.app/api/security/v1/content/security.malicious_packages/manifest.json" {
		t.Errorf("feed URL %s", u)
	}
}

// TestUnpinnedMalCoverage is lane SEC-D1FIX2 milestone 2a: for an unpinned
// install with MAL- reports, the client reads each report in full; one that
// covers every version marks the answer, a version-specific one does not,
// and a pinned install reads nothing more.
func TestUnpinnedMalCoverage(t *testing.T) {
	f := &fakeNet{osv: osvEcho(map[string][]string{"evil": {"MAL-1"}, "partly": {"MAL-2"}, "pinned": {"MAL-3"}})}
	f.reg = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/vulns/MAL-1":
			_, _ = io.WriteString(w, `{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"evil"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"}]}]}]}`)
		case "/v1/vulns/MAL-2":
			_, _ = io.WriteString(w, `{"id":"MAL-2","affected":[{"package":{"ecosystem":"npm","name":"partly"},"versions":["1.0.1"]}]}`)
		case "/v1/vulns/MAL-3":
			t.Error("a pinned install read the report in full")
		default:
			_, _ = io.WriteString(w, `{"modified":"2016-03-01T00:00:00Z","versions":{"1.0.0":{}}}`)
		}
	}
	c := newFake(t, f)
	got := c.Lookup(context.Background(), []secfeed.InstallSpec{
		secfeed.ParseSpec(secfeed.EcoNpm, "evil"), secfeed.ParseSpec(secfeed.EcoNpm, "partly"), secfeed.ParseSpec(secfeed.EcoNpm, "pinned@1.0.0"),
	})
	if !got[0].MalAllVersions || got[1].MalAllVersions || got[2].MalAllVersions {
		t.Fatalf("coverage %+v", got)
	}
	for i, want := range []policy.InstallVerdict{policy.InstallMalicious, policy.InstallListedVersion, policy.InstallMalicious} {
		spec := []string{"evil", "partly", "pinned@1.0.0"}[i]
		d := secfeed.Decide(secfeed.DecideInput{Spec: secfeed.ParseSpec(secfeed.EcoNpm, spec), Online: got[i], IndexFreshness: content.Fresh})
		if d.Verdict != want {
			t.Errorf("%s: %s, want %s", spec, d.Verdict, want)
		}
	}
	// A record naming another package or id never raises a verdict.
	if all, ok := secfeed.MalCoversEveryVersion([]byte(`{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"other"}}]}`), "MAL-1", secfeed.EcoNpm, "evil"); all || ok {
		t.Error("another package's record")
	}
	if all, _ := secfeed.MalCoversEveryVersion([]byte(`{"id":"MAL-9","affected":[{"package":{"ecosystem":"npm","name":"evil"}}]}`), "MAL-1", secfeed.EcoNpm, "evil"); all {
		t.Error("another id's record")
	}
}

// TestMalReadJobsRoundRobin pins lane SEC-DEPS3 item 12: the MAL- records
// read in full are taken one per unpinned answer per round, so a package
// with many reports cannot use up the cap before another package's first
// report is read; pinned and unanswered lookups read none.
func TestMalReadJobsRoundRobin(t *testing.T) {
	ids := func(p string, n int) []string {
		var out []string
		for i := 0; i < n; i++ {
			out = append(out, fmt.Sprintf("MAL-%s-%d", p, i))
		}
		return out
	}
	specs := []secfeed.InstallSpec{
		secfeed.ParseSpec(secfeed.EcoNpm, "many"),
		secfeed.ParseSpec(secfeed.EcoNpm, "pinned@1.0.0"),
		secfeed.ParseSpec(secfeed.EcoNpm, "few"),
		secfeed.ParseSpec(secfeed.EcoNpm, "failed"),
	}
	out := []secfeed.OnlineAnswer{
		{Status: secfeed.OnlineAnswered, MalIDs: ids("a", 20)},
		{Status: secfeed.OnlineAnswered, MalIDs: ids("p", 3)},
		{Status: secfeed.OnlineAnswered, MalIDs: ids("b", 2)},
		{Status: secfeed.OnlineFailed, MalIDs: ids("f", 2)},
	}
	jobs := malReadJobs(specs, out, 5)
	var got []string
	for _, j := range jobs {
		got = append(got, j.id)
	}
	want := []string{"MAL-a-0", "MAL-b-0", "MAL-a-1", "MAL-b-1", "MAL-a-2"}
	if !slices.Equal(got, want) {
		t.Fatalf("jobs %v, want %v", got, want)
	}
	if n := len(malReadJobs(specs, out, maxMalReads)); n != maxMalReads {
		t.Fatalf("the cap: %d jobs, want %d", n, maxMalReads)
	}
}
