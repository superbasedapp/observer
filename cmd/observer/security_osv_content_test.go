//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/contentchan"
	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
	"github.com/marmutapp/superbased-observer/internal/update/content"
)

// osvTestZip is a flat export of the given ids, each record {"id":..,"v":v}.
func osvTestZip(t *testing.T, v string, ids ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	for _, id := range ids {
		w, err := zw.Create(id + ".json")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"id":"` + id + `","v":"` + v + `"}`))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// osvTestSet is one ecosystem's published pair; delta nil publishes the
// base alone.
type osvTestSet struct {
	base, delta []byte
	records     int
	drop        []string
}

// installOSVSet signs (with a test vendor key, stood in for depsTrust) and
// installs a security.osv_export set of version v into st.
func installOSVSet(t *testing.T, st contentchan.Store, priv ed25519.PrivateKey, v int64, sets map[string]osvTestSet) {
	t.Helper()
	now := time.Now().UTC()
	m := content.Manifest{
		Schema: content.SchemaV1, Kind: content.OSVExport, ManifestVersion: v, Epoch: 1,
		IssuedAt: now.Add(-time.Hour).Format(time.RFC3339), ExpiresAt: now.Add(5 * 24 * time.Hour).Format(time.RFC3339),
	}
	arts := map[string][]byte{}
	for eco, s := range sets {
		m.Entries = append(m.Entries, content.Entry{Name: osvMirrorEntryName(eco), SizeBytes: int64(len(s.base)), SHA256: content.HashBytes(s.base), Upstream: content.UpstreamCheck{Method: content.UpstreamNone}})
		arts[osvMirrorEntryName(eco)] = s.base
		if s.delta != nil {
			m.Entries = append(m.Entries, content.Entry{
				Name: osvDeltaEntryName(eco), SizeBytes: int64(len(s.delta)), SHA256: content.HashBytes(s.delta), Upstream: content.UpstreamCheck{Method: content.UpstreamNone},
				Delta: &content.DeltaOf{Base: osvMirrorEntryName(eco), BaseSHA256: content.HashBytes(s.base), Records: s.records, Drop: s.drop},
			})
			arts[osvDeltaEntryName(eco)] = s.delta
		}
	}
	content.SortEntries(m.Entries)
	env, err := content.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := content.EncodeEnvelope(env)
	if _, err := st.Install(content.OSVExport, b, arts, depsTrust()); err != nil {
		t.Fatalf("install v%d: %v", v, err)
	}
}

func osvTestKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(nil)
	pub := priv.Public().(ed25519.PublicKey)
	prev := depsTrust
	depsTrust = func() contentchan.Trust { return contentchan.Trust{VendorKeys: []ed25519.PublicKey{pub}} }
	t.Cleanup(func() { depsTrust = prev })
	return priv
}

func zipNames(t *testing.T, path string) string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	var n []string
	for _, f := range zr.File {
		n = append(n, f.Name)
	}
	sort.Strings(n)
	return strings.Join(n, ",")
}

func loadOSV(t *testing.T, st contentchan.Store) osvContentRemote {
	t.Helper()
	l, err := st.Load(content.OSVExport, depsTrust(), 0)
	if err != nil {
		t.Fatal(err)
	}
	return newOSVContentRemote(st, l, osvdb.SourceFeed)
}

// TestOSVContentRemoteBaseOnly: with no delta entry the remote presents
// the installed base itself, as before.
func TestOSVContentRemoteBaseOnly(t *testing.T) {
	priv := osvTestKey(t)
	st := contentchan.Store{Root: filepath.Join(t.TempDir(), "content")}
	base := osvTestZip(t, "0", "A", "B")
	installOSVSet(t, st, priv, 1, map[string]osvTestSet{"npm": {base: base}})
	r := loadOSV(t, st)
	ctx := context.Background()
	p, meta, err := r.LocalExport(ctx, "npm")
	if err != nil {
		t.Fatal(err)
	}
	want, _, _ := r.l.ArtifactPath(osvMirrorEntryName("npm"))
	if p != want || meta.Size != int64(len(base)) {
		t.Fatalf("base-only export: %s %+v, want %s", p, meta, want)
	}
	if *r.merges != 0 {
		t.Fatal("a base-only set must not merge")
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(st.Root), osvMergedDir)); err == nil {
		t.Fatal("a base-only set must not create the merge cache")
	}
}

// TestOSVContentRemoteMergesDelta: base + delta are presented merged
// (replaced, added and dropped records), the merge runs once per pair and
// is reused by Head and by a later remote, osvdb installs the merged file,
// and a record count that disagrees with the signed entry is refused.
func TestOSVContentRemoteMergesDelta(t *testing.T) {
	priv := osvTestKey(t)
	st := contentchan.Store{Root: filepath.Join(t.TempDir(), "content")}
	ctx := context.Background()
	base := osvTestZip(t, "0", "A", "B", "C")
	delta := osvTestZip(t, "1", "B", "D")
	installOSVSet(t, st, priv, 1, map[string]osvTestSet{
		"npm":  {base: base, delta: delta, records: 3, drop: []string{"C.json"}},
		"PyPI": {base: osvTestZip(t, "0", "P"), delta: osvTestZip(t, "1", "Q"), records: 5}, // wrong count
	})
	r := loadOSV(t, st)
	p, meta, err := r.LocalExport(ctx, "npm")
	if err != nil {
		t.Fatal(err)
	}
	if got := zipNames(t, p); got != "A.json,B.json,D.json" {
		t.Fatalf("merged entries %s", got)
	}
	if !strings.HasPrefix(p, filepath.Join(filepath.Dir(st.Root), osvMergedDir)) {
		t.Fatalf("the merged export is not in the cache: %s", p)
	}
	if meta.LastModified != r.l.Manifest.IssuedAt || meta.CRC32C == "" {
		t.Fatalf("meta %+v", meta)
	}
	if head, err := r.Head(ctx, "npm"); err != nil || head != meta {
		t.Fatalf("Head %+v %v, want %+v", head, err, meta)
	}
	if *r.merges != 1 {
		t.Fatalf("%d merges, want 1 (Head reuses the cache)", *r.merges)
	}
	r2 := loadOSV(t, st)
	if _, err := r2.Head(ctx, "npm"); err != nil || *r2.merges != 0 {
		t.Fatalf("a later remote must reuse the cache: %v, %d merges", err, *r2.merges)
	}
	if _, err := r.Head(ctx, "PyPI"); err == nil || !strings.Contains(err.Error(), "signed entry says 5") {
		t.Fatalf("a record-count mismatch must be refused: %v", err)
	}
	db := osvdb.Open(filepath.Join(t.TempDir(), "osv"))
	rep, err := db.Refresh(ctx, r2, []string{"npm"}, time.Now())
	if err != nil || len(rep.Changed) != 1 {
		t.Fatalf("refresh %+v %v", rep, err)
	}
	if got := zipNames(t, filepath.Join(db.Dir(), "osv-scalibr", "npm", "all.zip")); got != "A.json,B.json,D.json" {
		t.Fatalf("installed export %s", got)
	}
}

// TestOSVContentRemotePrunesStaleMerges: a new delta (or a set that drops
// the delta) makes the old merge stale, and the next remote removes it
// before anything is read.
func TestOSVContentRemotePrunesStaleMerges(t *testing.T) {
	priv := osvTestKey(t)
	st := contentchan.Store{Root: filepath.Join(t.TempDir(), "content")}
	ctx := context.Background()
	npmBase, goBase := osvTestZip(t, "0", "A"), osvTestZip(t, "0", "G")
	installOSVSet(t, st, priv, 1, map[string]osvTestSet{
		"npm": {base: npmBase, delta: osvTestZip(t, "1", "B"), records: 2},
		"Go":  {base: goBase, delta: osvTestZip(t, "1", "H"), records: 2},
	})
	r := loadOSV(t, st)
	for _, eco := range []string{"npm", "Go"} {
		if _, err := r.Head(ctx, eco); err != nil {
			t.Fatal(err)
		}
	}
	cache := filepath.Join(filepath.Dir(st.Root), osvMergedDir)
	installOSVSet(t, st, priv, 2, map[string]osvTestSet{
		"npm": {base: npmBase, delta: osvTestZip(t, "2", "B", "C"), records: 3},
		"Go":  {base: goBase},
	})
	r2 := loadOSV(t, st)
	for _, n := range []string{"npm.merged.zip", "npm.merged.json", "Go.merged.zip", "Go.merged.json"} {
		if _, err := os.Stat(filepath.Join(cache, n)); err == nil {
			t.Errorf("stale %s kept", n)
		}
	}
	p, _, err := r2.LocalExport(ctx, "npm")
	if err != nil || zipNames(t, p) != "A.json,B.json,C.json" || *r2.merges != 1 {
		t.Fatalf("new merge: %v %d", err, *r2.merges)
	}
	if p, _, err := r2.LocalExport(ctx, "Go"); err != nil || strings.HasPrefix(p, cache) {
		t.Fatalf("a base-only ecosystem must present the base: %s %v", p, err)
	}
}
