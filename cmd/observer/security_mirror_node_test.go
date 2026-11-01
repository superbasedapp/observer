//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
	"github.com/marmutapp/superbased-observer/internal/secfeed/online"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/store"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// fakeOrgMirror installs vendor-signed kinds it holds, like the org
// client's mirror fetch against a server that has them; down fails every
// fetch.
type fakeOrgMirror struct {
	mu    sync.Mutex
	kinds map[content.Kind]struct {
		env  []byte
		arts map[string][]byte
	}
	calls []content.Kind
	down  bool
}

func (f *fakeOrgMirror) InstallSecurityContent(_ context.Context, st contentchan.Store, kind content.Kind, tr contentchan.Trust) (orgclient.SecurityContentResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, kind)
	if f.down {
		return orgclient.SecurityContentResult{Kind: kind}, errors.New("connection refused")
	}
	k, ok := f.kinds[kind]
	if !ok {
		return orgclient.SecurityContentResult{Kind: kind}, orgclient.ErrSecurityContentNotMirrored
	}
	s, err := st.Install(kind, k.env, k.arts, tr)
	return orgclient.SecurityContentResult{Kind: kind, State: s}, err
}

// signedTestKinds signs the given kinds with a fresh vendor key, points
// depsTrust at it, and returns a mirror holding them.
func signedTestKinds(t *testing.T, arts map[content.Kind]map[string][]byte) *fakeOrgMirror {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	prev := depsTrust
	depsTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}} }
	t.Cleanup(func() { depsTrust = prev })
	f := &fakeOrgMirror{kinds: map[content.Kind]struct {
		env  []byte
		arts map[string][]byte
	}{}}
	now := time.Now().UTC()
	for kind, files := range arts {
		m := content.Manifest{
			Schema: content.SchemaV1, Kind: kind, ManifestVersion: 1, Epoch: 1,
			IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(5 * 24 * time.Hour).Format(time.RFC3339),
		}
		for n, b := range files {
			m.Entries = append(m.Entries, content.Entry{Name: n, SizeBytes: int64(len(b)), SHA256: content.HashBytes(b), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
		}
		content.SortEntries(m.Entries)
		env, err := content.Sign(m, priv)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := content.EncodeEnvelope(env)
		f.kinds[kind] = struct {
			env  []byte
			arts map[string][]byte
		}{b, files}
	}
	return f
}

// managedDepsConfig writes a config selecting security.deps over a store
// enrolled as a managed node.
func managedDepsConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.toml")
	switchConfig(t, cfgPath, filepath.Join(dir, "observer.db"), true)
	_, database, cleanup, err := loadConfigAndDB(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if err := store.New(database).WriteEnrolment(context.Background(), store.Enrolment{
		OrgID: "o", OrgServerURL: "https://org.example", UserID: "u", Tenancy: orgcontract.TenancyManaged,
	}); err != nil {
		t.Fatal(err)
	}
	return cfgPath
}

// TestManagedIndexComesFromTheOrgMirrorOnlyWhenNamed: a managed node never
// reaches the vendor feed; it fetches the index from its org mirror only
// while its managed pull names the mirror; an outage keeps the
// last-known-good and the status says so with the data's freshness.
func TestManagedIndexComesFromTheOrgMirrorOnlyWhenNamed(t *testing.T) {
	srv, hits := feedServer(t, true)
	mal, _ := secfeed.MaliciousFromOSV([][]byte{[]byte(`{"id":"MAL-1","affected":[{"package":{"ecosystem":"npm","name":"evil-pkg"}}]}`)})
	fm := signedTestKinds(t, map[content.Kind]map[string][]byte{
		content.MaliciousPackages: {secfeed.MaliciousArtifact: secfeed.EncodeMalicious(mal)},
		content.PopularNames:      {secfeed.PopularArtifact: secfeed.EncodePopular(map[secfeed.Ecosystem][]string{secfeed.EcoNpm: {"react"}})},
	})
	prevMirror, prevNamed := depsOrgMirror, depsMirrorNamedFor
	t.Cleanup(func() { depsOrgMirror, depsMirrorNamedFor = prevMirror, prevNamed })
	depsOrgMirror = func(context.Context, string) (depsMirrorInstaller, func(), error) { return fm, func() {}, nil }
	named := false
	depsMirrorNamedFor = func(context.Context, config.Config, *store.Store) bool { return named }

	cfgPath := managedDepsConfig(t)
	rt := &depsRuntime{configPath: cfgPath, client: func() *online.Client {
		eps := map[string]string{online.FeedHost: srv.URL, online.OSVHost: srv.URL}
		for _, e := range secfeed.Ecosystems() {
			eps[e.MetadataHost] = srv.URL
		}
		return online.New(online.Options{HTTP: srv.Client(), Endpoints: eps})
	}}
	publicHits := func() int {
		n := 0
		hits.Range(func(_, _ any) bool { n++; return true })
		return n
	}
	// No pull naming the mirror: no request of any kind.
	if err := rt.feedOnce(context.Background()); err != nil {
		t.Fatalf("a managed node with no mirror named is not a failure: %v", err)
	}
	if len(fm.calls) != 0 || publicHits() != 0 {
		t.Fatalf("no mirror named: mirror calls %v, public paths %d", fm.calls, publicHits())
	}
	// Named: both index kinds come from the org mirror, still nothing public.
	named = true
	if err := rt.feedOnce(context.Background()); err != nil {
		t.Fatalf("feed from the mirror: %v", err)
	}
	if len(fm.calls) != 2 || publicHits() != 0 {
		t.Fatalf("named: mirror calls %v, public paths %d", fm.calls, publicHits())
	}
	st := depsContentStore(cfgPath)
	ix, fresh := loadInstallIndex(st, depsTrust())
	if ix == nil || fresh != content.Fresh || !ix.Lookup(secfeed.EcoNpm, "evil-pkg", "").Malicious {
		t.Fatalf("the mirrored index is not in use: %v %s", ix, fresh)
	}
	// An outage keeps the last-known-good and is reported, never clean.
	fm.down = true
	if err := rt.feedOnce(context.Background()); err == nil {
		t.Fatal("an outage must be reported")
	}
	if ix, _ := loadInstallIndex(st, depsTrust()); ix == nil {
		t.Fatal("the outage dropped the last-known-good")
	}
	kinds := []content.Kind{content.MaliciousPackages, content.PopularNames}
	lines := strings.Join(depsMirrorLines(st, depsTrust(), 0, kinds), "\n")
	if !strings.Contains(lines, "version 1, fresh") || !strings.Contains(lines, "last fetch failed") {
		t.Fatalf("status after the outage:\n%s", lines)
	}
	// Past its expiry the same data reads stale, then unknown: never clean.
	later := contentchan.Store{Root: st.Root, Now: func() time.Time { return time.Now().Add(6 * 24 * time.Hour) }}
	if lines := strings.Join(depsMirrorLines(later, depsTrust(), 0, kinds), "\n"); !strings.Contains(lines, "stale") {
		t.Fatalf("expired mirror data must read stale:\n%s", lines)
	}
}

// TestMirrorOSVRemoteFeedsTheLocalDatabase: the OSV exports installed from
// the org mirror refresh the scanners' local database with no request of
// their own, and a file changed after install is refused.
func TestMirrorOSVRemoteFeedsTheLocalDatabase(t *testing.T) {
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	w, _ := zw.Create("MAL-1.json")
	_, _ = w.Write([]byte(`{"id":"MAL-1"}`))
	_ = zw.Close()
	fm := signedTestKinds(t, map[content.Kind]map[string][]byte{content.OSVExport: {osvMirrorEntryName("npm"): zb.Bytes()}})
	st := contentchan.Store{Root: filepath.Join(t.TempDir(), "content")}
	if _, err := fm.InstallSecurityContent(context.Background(), st, content.OSVExport, depsTrust()); err != nil {
		t.Fatal(err)
	}
	l, err := st.Load(content.OSVExport, depsTrust(), 0)
	if err != nil {
		t.Fatal(err)
	}
	db := osvdb.Open(filepath.Join(t.TempDir(), "osv"))
	rep, err := db.Refresh(context.Background(), mirrorOSVRemote{l: l}, []string{"npm", "PyPI"}, time.Now())
	if err != nil || len(rep.Changed) != 1 || rep.Failed["PyPI"] == "" {
		t.Fatalf("refresh %+v %v", rep, err)
	}
	if eps, _ := db.Installed(); eps["npm"] == "" {
		t.Fatalf("npm not installed: %v", eps)
	}
	// A changed file fails the read (same size, other bytes).
	p, _, _ := l.ArtifactPath(osvMirrorEntryName("npm"))
	bad := bytes.Repeat([]byte{'x'}, zb.Len())
	if err := os.WriteFile(p, bad, 0o600); err != nil {
		t.Fatal(err)
	}
	db2 := osvdb.Open(filepath.Join(t.TempDir(), "osv2"))
	rep, _ = db2.Refresh(context.Background(), mirrorOSVRemote{l: l}, []string{"npm"}, time.Now())
	if rep.Failed["npm"] == "" {
		t.Fatalf("a changed export was stored: %+v", rep)
	}
}
