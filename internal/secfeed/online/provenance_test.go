package online

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// npmProvDoc is a recorded-shape abbreviated packument: 1.0.0 without
// provenance, 1.1.0-beta.1 and 1.1.0 with it, 1.2.0 without, 2.0.0-rc.1
// without, and a version that is not semver.
const npmProvDoc = `{"modified":"2019-01-01T00:00:00Z","dist-tags":{"latest":"1.2.0","beta":"1.1.0-beta.1"},"versions":{
"1.0.0":{"dist":{"tarball":"x"}},
"1.1.0-beta.1":{"dist":{"attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/p@1.1.0-beta.1","provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}}},
"1.1.0":{"dist":{"attestations":{"url":"https://registry.npmjs.org/-/npm/v1/attestations/p@1.1.0","provenance":{"predicateType":"https://slsa.dev/provenance/v1"}}}},
"1.2.0":{"dist":{}},
"2.0.0-rc.1":{"dist":{}},
"not-semver":{"dist":{"attestations":{"provenance":{"predicateType":"x"}}}}}}`

// npmNoProvDoc has no version with provenance.
const npmNoProvDoc = `{"modified":"2019-01-01T00:00:00Z","dist-tags":{"latest":"1.0.1"},"versions":{"1.0.0":{"dist":{}},"1.0.1":{"dist":{}}}}`

func TestNPMProvenance(t *testing.T) {
	cases := []struct {
		spec string
		want policy.InstallProvenance
	}{
		{"p@1.1.0", policy.InstallProvenancePresent},
		{"p", policy.InstallProvenanceRegressed},            // latest tag 1.2.0
		{"p@1.2.0", policy.InstallProvenanceRegressed},      // semver order, not document order
		{"p@1.0.0", policy.InstallProvenanceAbsent},         // only later versions had it
		{"p@1.1.0-beta.1", policy.InstallProvenancePresent}, // a prerelease counts
		{"p@beta", policy.InstallProvenancePresent},         // a dist-tag resolves
		{"p@2.0.0-rc.1", policy.InstallProvenanceRegressed}, // after 1.1.0 in semver
		{"p@not-semver", policy.InstallProvenanceUnknown},   // dropped
		{"p@9.9.9", policy.InstallProvenanceUnknown},        // not published
		{"q", policy.InstallProvenanceAbsent},               // none ever
		{"r", policy.InstallProvenanceAbsent},               // an undecodable version entry never fails the verdict
	}
	f := &fakeNet{osv: osvEcho(nil)}
	f.reg = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/p":
			_, _ = io.WriteString(w, npmProvDoc)
		case "/q":
			_, _ = io.WriteString(w, npmNoProvDoc)
		case "/r":
			_, _ = io.WriteString(w, `{"modified":"2019-01-01T00:00:00Z","dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":"odd"}}`)
		default:
			http.NotFound(w, r)
		}
	}
	c := newFake(t, f)
	c.provenance = true
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			f.mu.Lock()
			f.reqs = nil
			f.mu.Unlock()
			got := c.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, tc.spec)})
			if got[0].Status != secfeed.OnlineAnswered || got[0].Provenance != tc.want {
				t.Fatalf("%s: %+v, want provenance %q", tc.spec, got[0], tc.want)
			}
			if n := registryRequests(f); n != 1 {
				t.Fatalf("npm registry requests = %d, want 1", n)
			}
		})
	}
}

// pypiSimple is a recorded-shape simple JSON page for "Sig_Store": 1.0 has
// a provenance file and was first uploaded earliest; 0.9 (an older line,
// uploaded later) has none; 1.1 has a yanked file with provenance and a
// live file without; 2.0 has none.
const pypiSimple = `{"meta":{"api-version":"1.4"},"files":[
{"filename":"sig_store-1.0-py3-none-any.whl","provenance":"https://pypi.org/integrity/sig-store/1.0/sig_store-1.0-py3-none-any.whl/provenance","upload-time":"2024-01-01T00:00:00.000000Z","yanked":false},
{"filename":"Sig.Store-1.0.tar.gz","provenance":null,"upload-time":"2024-01-01T00:00:01.000000Z","yanked":false},
{"filename":"sig-store-0.9.zip","provenance":null,"upload-time":"2024-02-01T00:00:00.000000Z","yanked":false},
{"filename":"sig_store-1.1-py3-none-any.whl","provenance":"https://pypi.org/integrity/x","upload-time":"2024-03-01T00:00:00.000000Z","yanked":"broken"},
{"filename":"sig_store-1.1.tar.gz","provenance":null,"upload-time":"2024-03-02T00:00:00.000000Z","yanked":false},
{"filename":"other_pkg-3.0.tar.gz","provenance":"https://pypi.org/integrity/y","upload-time":"2023-01-01T00:00:00.000000Z","yanked":false},
{"filename":"sig_store-2.0-py3-none-any.whl","provenance":null,"upload-time":"2024-04-01T00:00:00.000000Z","yanked":false}
],"versions":["0.9","1.0","1.1","2.0"]}`

func TestPyPIProvenance(t *testing.T) {
	cases := []struct {
		spec string
		want policy.InstallProvenance
	}{
		{"Sig_Store==1.0", policy.InstallProvenancePresent},   // the wheel has it
		{"sig-store==0.9", policy.InstallProvenanceRegressed}, // uploaded after 1.0
		{"sig-store==1.1", policy.InstallProvenanceRegressed}, // the yanked file is ignored
		{"sig-store", policy.InstallProvenanceRegressed},      // newest upload 2.0
		{"sig-store==3.0", policy.InstallProvenanceUnknown},   // another project's file
	}
	var simpleAccept string
	f := &fakeNet{osv: osvEcho(nil)}
	f.reg = func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/pypi/sig-store/json":
			_, _ = io.WriteString(w, `{"releases":{"1.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]}}`)
		case "/simple/sig-store/":
			simpleAccept = r.Header.Get("Accept")
			_, _ = io.WriteString(w, pypiSimple)
		default:
			http.NotFound(w, r)
		}
	}
	c := newFake(t, f)
	c.provenance = true
	for _, tc := range cases {
		t.Run(tc.spec, func(t *testing.T) {
			f.mu.Lock()
			f.reqs = nil
			f.mu.Unlock()
			got := c.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoPyPI, tc.spec)})
			if got[0].Status != secfeed.OnlineAnswered || got[0].Provenance != tc.want {
				t.Fatalf("%s: %+v, want provenance %q", tc.spec, got[0], tc.want)
			}
			if n := registryRequests(f); n != 2 {
				t.Fatalf("PyPI registry requests = %d, want 2", n)
			}
		})
	}
	if simpleAccept != pypiSimpleAccept {
		t.Errorf("simple page Accept = %q", simpleAccept)
	}
}

func TestPyPIFileVersion(t *testing.T) {
	cases := []struct{ file, name, want string }{
		{"sigstore-4.5.1-py3-none-any.whl", "sigstore", "4.5.1"},
		{"sigstore-4.5.1-1-py3-none-any.whl", "sigstore", "4.5.1"}, // build tag
		{"sigstore-4.5.1.tar.gz", "sigstore", "4.5.1"},
		{"Zope.Interface-5.0.zip", "zope-interface", "5.0"},
		{"zope_interface-5.0.tar.bz2", "zope.interface", "5.0"},
		{"zope-interface-5.0.tar.gz", "zope_interface", "5.0"},
		{"other-1.0.tar.gz", "sigstore", ""},
		{"sigstore-1.0.egg", "sigstore", ""},
		{"sigstore-1.0.whl", "sigstore", ""}, // too few fields
	}
	for _, c := range cases {
		if got := pypiFileVersion(c.file, c.name); got != c.want {
			t.Errorf("pypiFileVersion(%q, %q) = %q, want %q", c.file, c.name, got, c.want)
		}
	}
}

func TestProvenanceOffAndFailures(t *testing.T) {
	pypi := func(simple func(w http.ResponseWriter)) *fakeNet {
		f := &fakeNet{osv: osvEcho(nil)}
		f.reg = func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/pypi/sig-store/json":
				_, _ = io.WriteString(w, `{"releases":{"1.0":[{"upload_time_iso_8601":"2024-01-01T00:00:00Z"}]}}`)
			case "/simple/sig-store/":
				simple(w)
			case "/p":
				_, _ = io.WriteString(w, npmProvDoc)
			default:
				http.NotFound(w, r)
			}
		}
		return f
	}
	spec := []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoPyPI, "sig-store==0.9")}

	// Off: one PyPI request, no state; npm sets no state either.
	f := pypi(func(w http.ResponseWriter) { _, _ = io.WriteString(w, pypiSimple) })
	c := newFake(t, f)
	got := c.Lookup(context.Background(), spec)
	if got[0].Status != secfeed.OnlineAnswered || got[0].Provenance != "" || registryRequests(f) != 1 {
		t.Errorf("off: %+v, %d requests", got[0], registryRequests(f))
	}
	got = c.Lookup(context.Background(), []secfeed.InstallSpec{secfeed.ParseSpec(secfeed.EcoNpm, "p@1.2.0")})
	if got[0].Provenance != "" {
		t.Errorf("off npm: %+v", got[0])
	}

	// A /simple/ failure leaves the verdict answered, provenance unknown.
	for name, h := range map[string]func(w http.ResponseWriter){
		"500":      func(w http.ResponseWriter) { w.WriteHeader(http.StatusInternalServerError) },
		"bad json": func(w http.ResponseWriter) { _, _ = io.WriteString(w, "{") },
		"404":      func(w http.ResponseWriter) { w.WriteHeader(http.StatusNotFound) },
	} {
		f := pypi(h)
		c := newFake(t, f)
		c.provenance = true
		got := c.Lookup(context.Background(), spec)
		if got[0].Status != secfeed.OnlineAnswered || got[0].Reason != "" || got[0].Provenance != policy.InstallProvenanceUnknown {
			t.Errorf("%s: %+v", name, got[0])
		}
	}

	// A 429 on /simple/ cools down only the provenance page, never the
	// verdict's JSON request.
	f = pypi(func(w http.ResponseWriter) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c = newFake(t, f)
	c.provenance = true
	for i := range 2 {
		f.mu.Lock()
		f.reqs = nil
		f.mu.Unlock()
		got := c.Lookup(context.Background(), spec)
		if got[0].Status != secfeed.OnlineAnswered || got[0].Provenance != policy.InstallProvenanceUnknown {
			t.Errorf("429 round %d: %+v", i, got[0])
		}
		want := 2
		if i == 1 {
			want = 1 // the simple page is cooling down; the JSON request is not
		}
		if n := registryRequests(f); n != want {
			t.Errorf("429 round %d: %d registry requests, want %d", i, n, want)
		}
	}

	// Too little time left in the wait: no provenance request.
	f = pypi(func(w http.ResponseWriter) { _, _ = io.WriteString(w, pypiSimple) })
	c = newFake(t, f)
	c.provenance = true
	base := time.Now()
	c.now = func() time.Time { return base }
	ctx, cancel := context.WithDeadline(context.Background(), base.Add(100*time.Millisecond))
	defer cancel()
	got = c.Lookup(ctx, spec)
	if got[0].Status == secfeed.OnlineAnswered && got[0].Provenance != policy.InstallProvenanceUnknown {
		t.Errorf("short wait: %+v", got[0])
	}
	for _, r := range f.reqs {
		if strings.Contains(r, "/simple/") {
			t.Errorf("a provenance request with too little time: %s", r)
		}
	}

	// A private or invalid name makes zero requests.
	f = pypi(func(w http.ResponseWriter) { _, _ = io.WriteString(w, pypiSimple) })
	c = newFake(t, f)
	c.provenance = true
	got = c.Lookup(context.Background(), []secfeed.InstallSpec{
		secfeed.ParseSpec(secfeed.EcoPyPI, "git+https://example.com/x.git"),
		secfeed.ParseSpec(secfeed.EcoNpm, "github:user/repo"),
	})
	if len(f.reqs) != 0 || got[0].Provenance != "" || got[1].Provenance != "" {
		t.Errorf("private/invalid: %v %+v", f.reqs, got)
	}
}

// registryRequests counts the requests that were not the OSV batch.
func registryRequests(f *fakeNet) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.reqs {
		if !strings.HasSuffix(r, "/v1/querybatch") {
			n++
		}
	}
	return n
}

// TestPEP440PreRelease: an unpinned PyPI target skips pre-releases.
func TestPEP440PreRelease(t *testing.T) {
	t.Parallel()
	for v, want := range map[string]bool{"1.0a1": true, "2.0b2": true, "3.0rc1": true, "1.0.dev3": true, "4.0.0-alpha": true, "1.0": false, "2.31.0": false, "1.0.post1": false, "2024.10.1": false} {
		if got := pep440Pre.MatchString(v); got != want {
			t.Errorf("%s: %v", v, got)
		}
	}
}
