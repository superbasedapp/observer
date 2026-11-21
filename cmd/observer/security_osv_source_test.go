//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secscan/depscan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvnet"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// security_osv_source_test.go is the static feed mirroring plan's section
// 7: the source order of an individual node's OSV databases, walked with no
// network (a fake feed and a fake bucket stand in for the lane).

// fakeOSVFeed serves <kind>/<file> from files, counting requests; down
// fails every request, and missing files answer not published.
type fakeOSVFeed struct {
	files    map[string][]byte
	down     bool
	requests atomic.Int64
}

func (f *fakeOSVFeed) FetchFeedFile(_ context.Context, kind, file, etag string) ([]byte, string, error) {
	f.requests.Add(1)
	if f.down {
		return nil, "", errors.New("test: connection refused")
	}
	b, ok := f.files[kind+"/"+file]
	if !ok {
		return nil, "", fmt.Errorf("test: %w", osvnet.ErrFeedNotPublished)
	}
	tag := fmt.Sprintf(`"%x"`, crc32.ChecksumIEEE(b))
	if etag == tag {
		return nil, "", osvnet.ErrFeedNotModified
	}
	return b, tag, nil
}

func (f *fakeOSVFeed) StreamFeedArtifact(_ context.Context, kind, file string, size int64, w io.Writer) error {
	f.requests.Add(1)
	if f.down {
		return errors.New("test: connection refused")
	}
	b, ok := f.files[kind+"/"+file]
	if !ok || int64(len(b)) != size {
		return errors.New("test: not served")
	}
	_, err := w.Write(b)
	return err
}

// useOSVFeed swaps the signed mirror's network side for the test.
func useOSVFeed(t *testing.T, f *fakeOSVFeed) {
	t.Helper()
	old := depsOSVFeed
	depsOSVFeed = func() osvFeedClient { return f }
	t.Cleanup(func() { depsOSVFeed = old })
}

// bucketRemote is a working fake bucket: every ecosystem's export is body.
type bucketRemote struct {
	body  []byte
	calls atomic.Int64
}

func (b *bucketRemote) meta() osvdb.Meta {
	return osvdb.Meta{LastModified: "Tue, 03 Nov 2026 00:00:00 GMT", CRC32C: osvdb.CRC32CString(crc32.Checksum(b.body, crc32.MakeTable(crc32.Castagnoli))), Size: int64(len(b.body))}
}

func (b *bucketRemote) Head(context.Context, string) (osvdb.Meta, error) {
	b.calls.Add(1)
	return b.meta(), nil
}

func (b *bucketRemote) Get(context.Context, string) (osvdb.Meta, io.ReadCloser, error) {
	b.calls.Add(1)
	return b.meta(), io.NopCloser(bytes.NewReader(b.body)), nil
}

func useBucket(t *testing.T, b *bucketRemote) {
	t.Helper()
	old := depsOSVRemote
	depsOSVRemote = func() osvdb.Remote { return b }
	t.Cleanup(func() { depsOSVRemote = old })
}

// feedTrust stands in a vendor key and, when withFeed, a content-feed key
// for depsTrust, and returns the feed key's private half.
func feedTrust(t *testing.T, withFeed bool) ed25519.PrivateKey {
	t.Helper()
	vpub, _, _ := ed25519.GenerateKey(nil)
	fpub, fpriv, _ := ed25519.GenerateKey(nil)
	tr := contentchan.Trust{VendorKeys: []ed25519.PublicKey{vpub}}
	if withFeed {
		tr.FeedKeys = []ed25519.PublicKey{fpub}
	}
	prev := depsTrust
	depsTrust = func() contentchan.Trust { return tr }
	t.Cleanup(func() { depsTrust = prev })
	return fpriv
}

// feedOSVFiles is a feed-signed security.osv_export set of every
// ecosystem: a base of base ids and a delta adding delta ids.
func feedOSVFiles(t *testing.T, priv ed25519.PrivateKey, ecos []string) map[string][]byte {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.OSVExport, ManifestVersion: 1, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}
	files := map[string][]byte{}
	k := string(content.OSVExport) + "/"
	for _, eco := range ecos {
		base, delta := osvTestZip(t, "0", "A", "B"), osvTestZip(t, "1", "C")
		m.Entries = append(m.Entries,
			content.Entry{Name: osvMirrorEntryName(eco), SizeBytes: int64(len(base)), SHA256: content.HashBytes(base), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}},
			content.Entry{
				Name: osvDeltaEntryName(eco), SizeBytes: int64(len(delta)), SHA256: content.HashBytes(delta), Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
				Delta: &content.DeltaOf{Base: osvMirrorEntryName(eco), BaseSHA256: content.HashBytes(base), Records: 3},
			})
		files[k+osvMirrorEntryName(eco)], files[k+osvDeltaEntryName(eco)] = base, delta
	}
	content.SortEntries(m.Entries)
	env, err := content.SignFeed(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	files[k+contentchan.ManifestFile] = b
	return files
}

// acceptedSourceEnv writes a config with the [security.deps] body extra,
// records the accept, and opens the scan env.
func acceptedSourceEnv(t *testing.T, extra string) *depsScanEnv {
	t.Helper()
	cfgPath, secDir := scanConsentConfig(t)
	if extra != "" {
		f, err := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.WriteString(extra)
		_ = f.Close()
	}
	if _, err := osvdb.RecordConsent(secDir, "cli", "dev", time.Now(), testDepsSigningKey(t, secDir)); err != nil {
		t.Fatal(err)
	}
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.cleanup)
	return e
}

// TestOSVSourceOrder walks the order's rows end to end.
func TestOSVSourceOrder(t *testing.T) {
	ecos := depscan.Ecosystems()
	cases := []struct {
		name string
		// deps is appended to [security.deps].
		deps     string
		withKey  bool
		feed     func(priv ed25519.PrivateKey) *fakeOSVFeed
		wantSrc  string
		wantErr  bool
		feedHits bool
		bucket   bool
		fallback string
	}{
		{
			name: "auto, no content-feed key in the build: the bucket, no feed request",
			feed: func(ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{} }, wantSrc: osvdb.SourceUpstream, bucket: true, fallback: "no content-feed key",
		},
		{
			name: "auto, the signed mirror verifies: the merged feed set, no bucket", withKey: true,
			feed:    func(p ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{files: feedOSVFiles(t, p, ecos)} },
			wantSrc: osvdb.SourceFeed, feedHits: true,
		},
		{
			name: "auto, the mirror is not published: the bucket", withKey: true,
			feed:    func(ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{files: map[string][]byte{}} },
			wantSrc: osvdb.SourceUpstream, feedHits: true, bucket: true, fallback: "not published",
		},
		{
			name: "auto without the fallback, the mirror unreachable: nothing, the bucket untouched", deps: "db_fallback_upstream = false\n", withKey: true,
			feed:    func(ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{down: true} },
			wantErr: true, feedHits: true,
		},
		{
			name: "feed only, the mirror unreachable: nothing, the bucket untouched", deps: "db_source = \"feed\"\n", withKey: true,
			feed:    func(ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{down: true} },
			wantErr: true, feedHits: true,
		},
		{
			name: "upstream: the bucket, no feed request", deps: "db_source = \"upstream\"\n", withKey: true,
			feed:    func(p ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{files: feedOSVFiles(t, p, ecos)} },
			wantSrc: osvdb.SourceUpstream, bucket: true,
		},
		{
			name: "import with nothing imported: nothing, no request", deps: "db_source = \"import\"\n", withKey: true,
			feed:    func(p ed25519.PrivateKey) *fakeOSVFeed { return &fakeOSVFeed{files: feedOSVFiles(t, p, ecos)} },
			wantErr: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			priv := feedTrust(t, c.withKey)
			feed := c.feed(priv)
			useOSVFeed(t, feed)
			bucket := &bucketRemote{body: osvTestZip(t, "u", "U")}
			useBucket(t, bucket)
			e := acceptedSourceEnv(t, c.deps)
			_, blocked, err := e.refreshDB(context.Background())
			if blocked != "" {
				t.Fatalf("blocked: %s", blocked)
			}
			if (err != nil) != c.wantErr {
				t.Fatalf("refresh error %v, want error %v", err, c.wantErr)
			}
			if got := feed.requests.Load() > 0; got != c.feedHits {
				t.Fatalf("feed requests %d, want any=%v", feed.requests.Load(), c.feedHits)
			}
			if got := bucket.calls.Load() > 0; got != c.bucket {
				t.Fatalf("bucket calls %d, want any=%v", bucket.calls.Load(), c.bucket)
			}
			rec, ok := readDepsOSVSource(e.dir)
			if !ok || rec.Source != c.wantSrc || !strings.Contains(rec.Fallback, c.fallback) || (c.wantErr && rec.Error == "") {
				t.Fatalf("source record %+v", rec)
			}
			if c.wantSrc == "" {
				return
			}
			inst, _ := e.db.Installed()
			if inst["npm"] == "" {
				t.Fatalf("npm not installed: %v", inst)
			}
			if c.wantSrc == osvdb.SourceFeed {
				if !strings.HasSuffix(inst["npm"], " source=feed") {
					t.Fatalf("the epoch must name the feed: %q", inst["npm"])
				}
				if got := zipNames(t, filepath.Join(e.db.Dir(), "osv-scalibr", "npm", "all.zip")); got != "A.json,B.json,C.json" {
					t.Fatalf("the installed export is not base + delta: %s", got)
				}
			}
			var status bytes.Buffer
			writeDBSourceState(&status, e)
			if !strings.Contains(status.String(), "from "+osvSourceName(c.wantSrc)) {
				t.Fatalf("status does not name the source:\n%s", status.String())
			}
			if dash := scannerDBStatus(e); dash.LastSource != c.wantSrc || dash.DBSource == "" || len(dash.SourceOrder) == 0 {
				t.Fatalf("Scanners card data %+v", dash)
			}
		})
	}
}

// TestOSVFeedOutageKeepsAFreshSet: once the signed mirror installed a set,
// an outage serves that fresh set again (no flip to the bucket), the ETag
// revalidates an unchanged manifest without any artifact request.
func TestOSVFeedOutageKeepsAFreshSet(t *testing.T) {
	priv := feedTrust(t, true)
	feed := &fakeOSVFeed{files: feedOSVFiles(t, priv, depscan.Ecosystems())}
	useOSVFeed(t, feed)
	bucket := &bucketRemote{body: osvTestZip(t, "u", "U")}
	useBucket(t, bucket)
	e := acceptedSourceEnv(t, "")
	ctx := context.Background()
	if _, _, err := e.refreshDB(ctx); err != nil {
		t.Fatal(err)
	}
	before := feed.requests.Load()
	if _, _, err := e.refreshDB(ctx); err != nil {
		t.Fatal(err)
	}
	if got := feed.requests.Load() - before; got != 1 {
		t.Fatalf("an unchanged manifest cost %d requests, want 1 (the 304)", got)
	}
	feed.down = true
	if _, _, err := e.refreshDB(ctx); err != nil {
		t.Fatal(err)
	}
	if rec, _ := readDepsOSVSource(e.dir); rec.Source != osvdb.SourceFeed || bucket.calls.Load() != 0 {
		t.Fatalf("an outage with a fresh set must keep the feed: %+v, bucket %d", rec, bucket.calls.Load())
	}
}

// TestOSVDBImport: `db import` installs a signed set from a directory with
// no request, needs no accept under db_source = import (it fetches
// nothing), refreshes from it, and refuses a managed node and a set that
// does not verify.
func TestOSVDBImport(t *testing.T) {
	priv := feedTrust(t, true)
	feed := &fakeOSVFeed{}
	useOSVFeed(t, feed)
	bucket := &bucketRemote{body: osvTestZip(t, "u", "U")}
	useBucket(t, bucket)
	src := t.TempDir()
	for k, b := range feedOSVFiles(t, priv, []string{"npm"}) {
		p := filepath.Join(src, filepath.FromSlash(k))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	cfgPath, _ := scanConsentConfig(t)
	f, _ := os.OpenFile(cfgPath, os.O_APPEND|os.O_WRONLY, 0o600)
	_, _ = f.WriteString("db_source = \"import\"\n")
	_ = f.Close()
	e, err := openDepsScanEnv(context.Background(), cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	defer e.cleanup()
	if e.awaitingAccept() || e.downloadBlocked() != "" {
		t.Fatalf("db_source = import must not wait for the accept: %q", e.downloadBlocked())
	}
	var out bytes.Buffer
	if err := runDBImport(context.Background(), &out, e, src); err != nil {
		t.Fatalf("import: %v\n%s", err, out.String())
	}
	if feed.requests.Load() != 0 || bucket.calls.Load() != 0 {
		t.Fatal("an import made a request")
	}
	if inst, _ := e.db.Installed(); !strings.HasSuffix(inst["npm"], " source=import") {
		t.Fatalf("the import did not refresh the databases: %v\n%s", inst, out.String())
	}
	// A set signed by an unknown feed key is refused.
	_, other, _ := ed25519.GenerateKey(nil)
	bad := t.TempDir()
	for k, b := range feedOSVFiles(t, other, []string{"npm"}) {
		p := filepath.Join(bad, filepath.FromSlash(k))
		_ = os.MkdirAll(filepath.Dir(p), 0o700)
		_ = os.WriteFile(p, b, 0o600)
	}
	if err := runDBImport(context.Background(), &out, e, bad); err == nil {
		t.Fatal("an import signed by an unknown key must be refused")
	}
	if err := runDBImport(context.Background(), &out, e, t.TempDir()); err == nil {
		t.Fatal("a directory with no security.osv_export must be refused")
	}
	e.managed = true
	if err := runDBImport(context.Background(), &out, e, src); err == nil || !strings.Contains(err.Error(), "managed node") {
		t.Fatalf("a managed node must refuse the import: %v", err)
	}
}

// TestOSVOldFeedWithoutGitHubActions: a signed set published before the
// GitHub Actions ecosystem joined the store (the feed live on
// superbased.app until the publisher lists it) lists only the eight
// language ecosystems. It still serves those eight; GitHub Actions alone
// falls through the source order: to the bucket under auto, and to its
// last-known-good (nothing installed: database_missing) under feed only,
// with no request to the bucket.
func TestOSVOldFeedWithoutGitHubActions(t *testing.T) {
	// The eight language ecosystems the old feed listed: osv-scanner's
	// required set before the 2026-11-06 coverage review added Pub,
	// SwiftURL, Hex, Hackage and CRAN to it. The newer ones fall through
	// the source order like GitHub Actions.
	eight := []string{"Go", "Maven", "NuGet", "Packagist", "PyPI", "RubyGems", "crates.io", "npm"}
	for _, eco := range eight {
		if !depscan.OSVScannerReads(eco) {
			t.Fatalf("%s is no longer an osv-scanner ecosystem", eco)
		}
	}
	cases := []struct {
		name       string
		deps       string
		ghaBucket  bool
		ghaSources string
	}{
		{name: "auto: GitHub Actions from the bucket, the eight from the feed", ghaBucket: true, ghaSources: osvdb.SourceUpstream},
		{name: "feed only: GitHub Actions stays not installed, the bucket untouched", deps: "db_source = \"feed\"\n"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			priv := feedTrust(t, true)
			feed := &fakeOSVFeed{files: feedOSVFiles(t, priv, eight)}
			useOSVFeed(t, feed)
			bucket := &bucketRemote{body: osvTestZip(t, "u", "U")}
			useBucket(t, bucket)
			e := acceptedSourceEnv(t, c.deps)
			rep, blocked, err := e.refreshDB(context.Background())
			if blocked != "" || err != nil {
				t.Fatalf("refresh: blocked %q err %v", blocked, err)
			}
			inst, _ := e.db.Installed()
			for _, eco := range eight {
				if !strings.HasSuffix(inst[eco], " source=feed") {
					t.Fatalf("%s must come from the feed: %q (installed %v)", eco, inst[eco], inst)
				}
			}
			gha := inst["GitHub Actions"]
			if (gha != "") != c.ghaBucket || (c.ghaBucket && strings.Contains(gha, "source=")) {
				t.Fatalf("GitHub Actions epoch %q, want from the bucket=%v", gha, c.ghaBucket)
			}
			if got := bucket.calls.Load() > 0; got != c.ghaBucket {
				t.Fatalf("bucket calls %d, want any=%v", bucket.calls.Load(), c.ghaBucket)
			}
			if !c.ghaBucket && rep.Failed["GitHub Actions"] == "" {
				t.Fatalf("report %+v: the feed-only node records why GitHub Actions did not refresh", rep)
			}
			rec, ok := readDepsOSVSource(e.dir)
			if !ok || rec.Source != osvdb.SourceFeed || rec.Sources["GitHub Actions"] != c.ghaSources {
				t.Fatalf("source record %+v", rec)
			}
			var status bytes.Buffer
			writeDBSourceState(&status, e)
			if c.ghaBucket && !strings.Contains(status.String(), "GitHub Actions from the OSV bucket") {
				t.Fatalf("status does not name GitHub Actions' source:\n%s", status.String())
			}
		})
	}
}
