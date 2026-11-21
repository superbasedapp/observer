package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// multiMirror serves one kind's envelope and several artifacts and counts
// the GETs of each file.
type multiMirror struct {
	mu   sync.Mutex
	env  []byte
	arts map[string][]byte
	hits map[string]int
}

func (f *multiMirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "Bearer bearer-xyz" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, orgcontract.AgentSecurityContentPath)
	_, file, _ := strings.Cut(rest, "/")
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hits[file]++
	if file == orgcontract.SecurityContentManifestFile {
		_, _ = w.Write(f.env)
		return
	}
	b, ok := f.arts[file]
	if !ok {
		http.Error(w, `{"error":"not_mirrored"}`, http.StatusNotFound)
		return
	}
	_, _ = w.Write(b)
}

func (f *multiMirror) set(t *testing.T, priv ed25519.PrivateKey, version int64, arts map[string][]byte) {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.OSVExport, ManifestVersion: version, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339),
	}
	for n, b := range arts {
		m.Entries = append(m.Entries, content.Entry{Name: n, SizeBytes: int64(len(b)), SHA256: content.HashBytes(b), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
	}
	content.SortEntries(m.Entries)
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	f.mu.Lock()
	f.env, f.arts = b, arts
	f.mu.Unlock()
}

func (f *multiMirror) hitsOf(file string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[file]
}

// TestInstallSecurityContentReusesInstalledArtifacts is the static feed
// mirroring plan's B2 (G5): when the mirror's manifest changes, an artifact
// whose name, size and sha256 match the installed one is not fetched again;
// the changed one is, the new set still verifies and loads, and an
// installed copy changed on disk is fetched again rather than reused.
func TestInstallSecurityContentReusesInstalledArtifacts(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	npm1, npm2, pypi, golang := []byte("npm export v1"), []byte("npm export v2"), []byte("pypi export"), []byte("go export")
	fm := &multiMirror{hits: map[string]int{}}
	fm.set(t, priv, 1, map[string][]byte{"npm.zip": npm1, "PyPI.zip": pypi, "Go.zip": golang})
	srv := httptest.NewServer(fm)
	defer srv.Close()
	c, _, _ := enrolledClient(t, srv.URL)
	st := contentchan.Store{Root: filepath.Join(t.TempDir(), "content")}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	ctx := context.Background()

	cases := []struct {
		name       string
		prepare    func()
		version    int64
		wantFetch  map[string]int // cumulative GETs per artifact after the step
		wantReused int
	}{
		{"first install fetches every artifact", nil, 1, map[string]int{"npm.zip": 1, "PyPI.zip": 1, "Go.zip": 1}, 0},
		{"an npm-only change fetches npm only", func() {
			fm.set(t, priv, 2, map[string][]byte{"npm.zip": npm2, "PyPI.zip": pypi, "Go.zip": golang})
		}, 2, map[string]int{"npm.zip": 2, "PyPI.zip": 1, "Go.zip": 1}, 2},
		{"an installed copy changed on disk is fetched again", func() {
			dir, _ := st.KindDir(content.OSVExport)
			if err := os.WriteFile(filepath.Join(dir, "Go.zip"), []byte("go exporX"), 0o600); err != nil {
				t.Fatal(err)
			}
			fm.set(t, priv, 3, map[string][]byte{"npm.zip": npm2, "PyPI.zip": pypi, "Go.zip": golang})
		}, 3, map[string]int{"npm.zip": 2, "PyPI.zip": 1, "Go.zip": 2}, 2},
	}
	for _, tc := range cases {
		if tc.prepare != nil {
			tc.prepare()
		}
		res, err := c.InstallSecurityContent(ctx, st, content.OSVExport, tr)
		if err != nil || res.Unchanged || res.State.Accepted == nil || res.State.Accepted.ManifestVersion != tc.version {
			t.Fatalf("%s: %+v %v", tc.name, res, err)
		}
		if res.Reused != tc.wantReused {
			t.Errorf("%s: reused %d, want %d", tc.name, res.Reused, tc.wantReused)
		}
		for file, n := range tc.wantFetch {
			if got := fm.hitsOf(file); got != n {
				t.Errorf("%s: %s fetched %d times, want %d", tc.name, file, got, n)
			}
		}
		l, err := st.Load(content.OSVExport, tr, 0)
		if err != nil {
			t.Fatalf("%s: load: %v", tc.name, err)
		}
		for name, want := range map[string][]byte{"npm.zip": npm2, "PyPI.zip": pypi, "Go.zip": golang} {
			if tc.version == 1 && name == "npm.zip" {
				want = npm1
			}
			b, err := l.ReadArtifact(name)
			if err != nil || string(b) != string(want) {
				t.Fatalf("%s: %s: %q %v", tc.name, name, b, err)
			}
		}
	}
	// Nothing staged is left behind.
	ents, _ := os.ReadDir(st.Root)
	for _, e := range ents {
		if strings.HasPrefix(e.Name(), ".incoming-") {
			t.Fatalf("a staged file was left: %s", e.Name())
		}
	}
}
