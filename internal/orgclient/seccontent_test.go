package orgclient

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// fakeMirror serves one kind's envelope and artifact with ETags, like the
// org server's content route; down makes it answer 503.
type fakeMirror struct {
	env, art      []byte
	artName       string
	down          atomic.Bool
	envGets, gets atomic.Int64
}

func (f *fakeMirror) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.gets.Add(1)
	if r.Header.Get("Authorization") != "Bearer bearer-xyz" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if f.down.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, orgcontract.AgentSecurityContentPath)
	kind, file, _ := strings.Cut(rest, "/")
	if kind != string(content.MaliciousPackages) {
		http.Error(w, `{"error":"not_mirrored"}`, http.StatusNotFound)
		return
	}
	var body []byte
	var etag string
	switch file {
	case "manifest.json":
		f.envGets.Add(1)
		body, etag = f.env, `"`+content.HashBytes(f.env)+`"`
	case f.artName:
		body, etag = f.art, `"`+content.HashBytes(f.art)+`"`
	default:
		http.Error(w, `{"error":"not_mirrored"}`, http.StatusNotFound)
		return
	}
	w.Header().Set("ETag", etag)
	if r.Header.Get("If-None-Match") == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(body)
}

func signedEnvelope(t *testing.T, priv ed25519.PrivateKey, version int64, name string, art []byte) []byte {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.MaliciousPackages, ManifestVersion: version, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(48 * time.Hour).Format(time.RFC3339),
		Entries: []content.Entry{{Name: name, SizeBytes: int64(len(art)), SHA256: content.HashBytes(art), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}}},
	}
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	return b
}

// TestInstallSecurityContentFromTheOrgMirror: a managed node installs a
// mirrored kind through the content channel, revalidates with an ETag, keeps
// its last-known-good through an outage, and refuses content the vendor key
// did not sign (the org server cannot sign content).
func TestInstallSecurityContentFromTheOrgMirror(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	art := []byte("# sbo-malicious-index v1\n")
	fm := &fakeMirror{artName: "malicious.idx", art: art}
	fm.env = signedEnvelope(t, priv, 1, fm.artName, art)
	srv := httptest.NewServer(fm)
	defer srv.Close()
	c, _, _ := enrolledClient(t, srv.URL)
	st := contentchan.Store{Root: t.TempDir() + "/content"}
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}}
	ctx := context.Background()

	res, err := c.InstallSecurityContent(ctx, st, content.MaliciousPackages, tr)
	if err != nil || res.Unchanged || res.State.Accepted == nil || res.State.Accepted.ManifestVersion != 1 {
		t.Fatalf("first install: %+v %v", res, err)
	}
	l, err := st.Load(content.MaliciousPackages, tr, 0)
	if err != nil || l.Freshness != content.Fresh {
		t.Fatalf("load: %+v %v", l, err)
	}
	// Unchanged: a 304 on the envelope, no artifact fetched.
	before := fm.gets.Load()
	res, err = c.InstallSecurityContent(ctx, st, content.MaliciousPackages, tr)
	if err != nil || !res.Unchanged || fm.gets.Load() != before+1 {
		t.Fatalf("revalidation: %+v %v gets=%d", res, err, fm.gets.Load()-before)
	}
	// An outage changes nothing on disk.
	fm.down.Store(true)
	if _, err := c.InstallSecurityContent(ctx, st, content.MaliciousPackages, tr); err == nil {
		t.Fatal("an outage must be reported")
	}
	if l, err := st.Load(content.MaliciousPackages, tr, 0); err != nil || l.State.Accepted.ManifestVersion != 1 {
		t.Fatalf("last-known-good after the outage: %v", err)
	}
	fm.down.Store(false)
	// Content signed by another key (what an org server could forge) is
	// refused and the accepted version stays.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	fm.art = []byte("# sbo-malicious-index v1\nforged\n")
	fm.env = signedEnvelope(t, other, 2, fm.artName, fm.art)
	if _, err := c.InstallSecurityContent(ctx, st, content.MaliciousPackages, tr); content.ReasonOf(err) != content.ContentReasonVendorSig {
		t.Fatalf("forged: %v", err)
	}
	if s, _ := st.State(content.MaliciousPackages); s.Accepted.ManifestVersion != 1 {
		t.Fatalf("a forged envelope moved the accepted version: %+v", s)
	}
	// A kind the mirror does not hold, and an unknown kind.
	if _, err := c.InstallSecurityContent(ctx, st, content.OSVExport, tr); !errors.Is(err, ErrSecurityContentNotMirrored) {
		t.Fatalf("not mirrored: %v", err)
	}
	if _, err := c.InstallSecurityContent(ctx, st, content.SandboxRootfs, tr); err == nil {
		t.Fatal("a sandbox kind is not a security content kind")
	}
}

// TestSecurityContentNotSupported: a server without the relay answers 404
// not_supported, which the node reports as such and keeps what it has.
func TestSecurityContentNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"not_supported"}`, http.StatusNotFound)
	}))
	defer srv.Close()
	c, _, _ := enrolledClient(t, srv.URL)
	st := contentchan.Store{Root: t.TempDir()}
	if _, err := c.InstallSecurityContent(context.Background(), st, content.MaliciousPackages, contentchan.Trust{}); !errors.Is(err, ErrSecurityContentNotSupported) {
		t.Fatalf("not supported: %v", err)
	}
}

// TestSecurityContentKindTable: every security kind of the content channel
// has a row, and no other kind does.
func TestSecurityContentKindTable(t *testing.T) {
	want := map[content.Kind]bool{}
	for _, k := range content.Kinds() {
		if strings.HasPrefix(string(k.Kind), "security.") {
			want[k.Kind] = true
		}
	}
	if len(SecurityContentKinds) != len(want) {
		t.Fatalf("kind table has %d rows, the channel %d security kinds", len(SecurityContentKinds), len(want))
	}
	for _, r := range SecurityContentKinds {
		if !want[r.Kind] || r.Consumer == "" {
			t.Errorf("row %+v", r)
		}
	}
}
