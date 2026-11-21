package trivydb

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

type entry struct {
	name string
	body string
	typ  byte
}

func layerOf(t *testing.T, entries []entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		typ := e.typ
		if typ == 0 {
			typ = tar.TypeReg
		}
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: typ}
		if typ != tar.TypeReg {
			h.Size, h.Linkname = 0, "/etc/passwd"
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if typ == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

const meta = `{"Version":2,"NextUpdate":"2026-11-05T01:28:23Z","UpdatedAt":"2026-11-04T01:28:23Z"}`

func goodLayer(t *testing.T, db string) []byte {
	return layerOf(t, []entry{{name: "trivy.db", body: db}, {name: "metadata.json", body: meta}, {name: "README", body: "skipped"}})
}

// registry is a fake ghcr.io + blob host behind one TLS server.
type registry struct {
	t        *testing.T
	layer    []byte
	sizeLie  int64
	redirect string // where the blob request redirects ("" = the blob host)
	token    string
	requests atomic.Int64
	uas      []string
}

func digestOf(b []byte) string {
	s := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(s[:])
}

func (g *registry) manifest() []byte {
	size := int64(len(g.layer)) + g.sizeLie
	return []byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"artifactType":"application/vnd.aquasec.trivy.config.v1+json",`+
		`"config":{"mediaType":"application/vnd.oci.empty.v1+json","digest":"sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","size":2},`+
		`"layers":[{"mediaType":%q,"digest":%q,"size":%d,"annotations":{"org.opencontainers.image.title":"db.tar.gz"}}],`+
		`"annotations":{"org.opencontainers.image.created":"2026-11-04T07:27:19Z"}}`, ManifestMediaType, LayerMediaType, digestOf(g.layer), size))
}

func (g *registry) handler(w http.ResponseWriter, r *http.Request) {
	g.requests.Add(1)
	g.uas = append(g.uas, r.UserAgent())
	switch {
	case r.URL.Path == "/token":
		if r.URL.Query().Get("scope") != "repository:aquasecurity/trivy-db:pull" || r.URL.Query().Get("service") != "ghcr.io" {
			http.Error(w, "bad scope", http.StatusBadRequest)
			return
		}
		tok := g.token
		if tok == "" {
			tok = "dG9rZW4="
		}
		_, _ = fmt.Fprintf(w, `{"token":%q}`, tok)
	case r.URL.Path == "/v2/aquasecurity/trivy-db/manifests/2":
		if r.Header.Get("Authorization") != "Bearer dG9rZW4=" || r.Header.Get("Accept") != ManifestMediaType {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		m := g.manifest()
		w.Header().Set("Content-Type", ManifestMediaType)
		w.Header().Set("Docker-Content-Digest", digestOf(m))
		_, _ = w.Write(m)
	case strings.HasPrefix(r.URL.Path, "/v2/aquasecurity/trivy-db/blobs/"):
		to := g.redirect
		if to == "" {
			to = "https://" + BlobHost + "/ghcrblobs/blob?sig=x"
		}
		http.Redirect(w, r, to, http.StatusTemporaryRedirect)
	case r.URL.Path == "/ghcrblobs/blob":
		if r.Header.Get("Authorization") != "" {
			http.Error(w, "the token reached the blob host", http.StatusBadRequest)
			return
		}
		_, _ = w.Write(g.layer)
	default:
		http.NotFound(w, r)
	}
}

func fakeClient(t *testing.T, g *registry) *Client {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(g.handler))
	t.Cleanup(srv.Close)
	eps := map[string]string{}
	for _, h := range AllowedHosts() {
		eps[h] = srv.URL
	}
	return New(Options{Transport: srv.Client().Transport, Endpoints: eps})
}

// TestHostsMatchTheAccept: the lane reaches exactly the hosts the accept
// text names.
func TestHostsMatchTheAccept(t *testing.T) {
	t.Parallel()
	if len(AllowedHosts()) != 2 {
		t.Fatalf("hosts %v", AllowedHosts())
	}
	for _, h := range AllowedHosts() {
		if !strings.Contains(osvdb.TrivyConsentText, h) {
			t.Errorf("the accept text does not name %s", h)
		}
	}
}

// TestRefreshInstallsAndKeepsLastGood: a refresh downloads, verifies and
// unpacks the layer into a generation; the same manifest again downloads
// nothing; a bad layer keeps the installed generation.
func TestRefreshInstallsAndKeepsLastGood(t *testing.T) {
	t.Parallel()
	g := &registry{t: t, layer: goodLayer(t, "BOLT-1")}
	c := fakeClient(t, g)
	s := Store{Root: filepath.Join(t.TempDir(), "db")}
	now := time.Date(2026, 11, 4, 9, 0, 0, 0, time.UTC)
	if !Due(s.State(), now) {
		t.Fatal("nothing installed is not due")
	}
	st, changed, err := s.Refresh(context.Background(), c, now)
	if err != nil || !changed || !st.Installed() {
		t.Fatalf("%+v %v %v", st, changed, err)
	}
	b, err := os.ReadFile(filepath.Join(s.DBDir(st), DBFile))
	if err != nil || string(b) != "BOLT-1" {
		t.Fatalf("%q %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(s.DBDir(st), "README")); err == nil {
		t.Error("an entry outside the two files was unpacked")
	}
	if !strings.HasPrefix(st.Epoch(), "trivy-db@sha256:") || !strings.HasSuffix(st.Epoch(), "/2026-11-04T01:28:23Z") || st.DBBytes != int64(len("BOLT-1")+len(meta)) {
		t.Errorf("epoch %q bytes %d", st.Epoch(), st.DBBytes)
	}
	for _, ua := range g.uas {
		if ua != UserAgent {
			t.Errorf("User-Agent %q", ua)
		}
	}
	// Not due within 6 hours, and not before NextUpdate.
	if Due(st, now.Add(5*time.Hour)) || Due(st, now.Add(7*time.Hour)) {
		t.Error("due too early")
	}
	if !Due(st, time.Date(2026, 11, 5, 2, 0, 0, 0, time.UTC)) {
		t.Error("not due after NextUpdate and 6 hours")
	}
	// The same manifest: a check, no download.
	before := g.requests.Load()
	st2, changed, err := s.Refresh(context.Background(), c, now.Add(time.Hour))
	if err != nil || changed || st2.Generation != st.Generation || g.requests.Load()-before != 2 {
		t.Fatalf("same manifest: %+v %v %v (%d requests)", st2, changed, err, g.requests.Load()-before)
	}
	// A newer layer that does not unpack keeps the installed generation.
	g.layer = layerOf(t, []entry{{name: "metadata.json", body: meta}})
	st3, changed, err := s.Refresh(context.Background(), c, now.Add(2*time.Hour))
	var re *RefreshError
	if !errors.As(err, &re) || re.Reason != ReasonUnpack || changed || st3.Generation != st.Generation || st3.LastError != ReasonUnpack {
		t.Fatalf("bad layer: %+v %v", st3, err)
	}
	if got := s.State(); got.Generation != st.Generation || got.LastError != ReasonUnpack {
		t.Fatalf("state after a failure %+v", got)
	}
	// A good newer layer replaces it and removes the old generation.
	g.layer = goodLayer(t, "BOLT-2")
	st4, changed, err := s.Refresh(context.Background(), c, now.Add(3*time.Hour))
	if err != nil || !changed || st4.Generation == st.Generation || st4.LastError != "" {
		t.Fatalf("newer: %+v %v", st4, err)
	}
	if _, err := os.Stat(filepath.Join(s.Root, st.Generation)); err == nil {
		t.Error("the old generation stayed")
	}
	cache := filepath.Join(t.TempDir(), "run-cache")
	src, err := s.LinkInto(st4, cache)
	if err != nil || src != s.DBDir(st4) {
		t.Fatalf("link %q %v", src, err)
	}
	if b, err := os.ReadFile(filepath.Join(cache, "db", DBFile)); err != nil || string(b) != "BOLT-2" {
		t.Fatalf("through the link: %q %v", b, err)
	}
}

// TestLayerRefusals: a layer whose digest or size differs from the
// manifest, a redirect anywhere but the blob host, and a layer with a link
// or a second copy are refused, and nothing is installed.
func TestLayerRefusals(t *testing.T) {
	t.Parallel()
	cases := map[string]func(*registry){
		"size lie":            func(g *registry) { g.sizeLie = 1 },
		"redirect elsewhere":  func(g *registry) { g.redirect = "https://evil.example/blob" },
		"redirect plain http": func(g *registry) { g.redirect = "http://" + BlobHost + "/ghcrblobs/blob" },
		"symlink entry": func(g *registry) {
			g.layer = layerOf(t, []entry{{name: "trivy.db", typ: tar.TypeSymlink}, {name: "metadata.json", body: meta}})
		},
		"duplicate entry": func(g *registry) {
			g.layer = layerOf(t, []entry{{name: "trivy.db", body: "a"}, {name: "trivy.db", body: "b"}, {name: "metadata.json", body: meta}})
		},
		"wrong metadata version": func(g *registry) {
			g.layer = layerOf(t, []entry{{name: "trivy.db", body: "a"}, {name: "metadata.json", body: `{"Version":1,"UpdatedAt":"2026-11-04T01:28:23Z"}`}})
		},
	}
	for name, mut := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			g := &registry{t: t, layer: goodLayer(t, "BOLT")}
			mut(g)
			s := Store{Root: filepath.Join(t.TempDir(), "db")}
			st, changed, err := s.Refresh(context.Background(), fakeClient(t, g), time.Now())
			if err == nil || changed || st.Installed() || s.State().Installed() {
				t.Fatalf("%+v %v %v", st, changed, err)
			}
		})
	}
}

// TestClientAllowList: only https to the two hosts; no redirect on the
// token or manifest requests; a manifest that is not the artifact is
// refused.
func TestClientAllowList(t *testing.T) {
	t.Parallel()
	g := &registry{t: t, layer: goodLayer(t, "BOLT")}
	c := fakeClient(t, g)
	for _, raw := range []string{"http://ghcr.io/token", "https://evil.example/x", "https://ghcr.io:8443/x"} {
		req, _ := http.NewRequest(http.MethodGet, raw, nil)
		if _, err := c.plain.Do(req); err == nil {
			t.Errorf("%s was fetched", raw)
		}
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			http.Redirect(w, r, "https://"+BlobHost+"/token", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	bad := New(Options{Transport: srv.Client().Transport, Endpoints: map[string]string{RegistryHost: srv.URL, BlobHost: srv.URL}})
	if _, err := bad.Manifest(context.Background()); err == nil {
		t.Error("a redirected token request was followed")
	}
	if err := c.Layer(context.Background(), Manifest{}, io.Discard); !errors.Is(err, ErrManifest) {
		t.Errorf("an empty manifest: %v", err)
	}
}
