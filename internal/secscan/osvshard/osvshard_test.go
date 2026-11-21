package osvshard

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvshardkey"
)

// testAffected is one affected entry of a synthetic record.
type testAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions []string `json:"versions,omitempty"`
}

type testRecord struct {
	ID       string         `json:"id"`
	Summary  string         `json:"summary,omitempty"`
	Affected []testAffected `json:"affected"`
}

func aff(eco, name string, versions ...string) testAffected {
	var a testAffected
	a.Package.Ecosystem, a.Package.Name, a.Versions = eco, name, versions
	return a
}

// publishSet is a synthetic publisher over osvshardkey's format functions
// (strip mode: each shard carries each record with only the affected
// entries whose names hash into it). It returns the descriptor and the
// bucket objects by path.
func publishSet(t *testing.T, set, eco string, bits int, recs []testRecord) (osvshardkey.SetDescriptor, map[string][]byte) {
	t.Helper()
	base := osvshardkey.Base(eco)
	byPrefix := map[uint32][]testRecord{}
	for _, r := range recs {
		parts := map[uint32][]testAffected{}
		for _, a := range r.Affected {
			p := osvshardkey.PrefixOf(base, a.Package.Name, bits)
			parts[p] = append(parts[p], a)
		}
		for p, as := range parts {
			cp := r
			cp.Affected = as
			byPrefix[p] = append(byPrefix[p], cp)
		}
	}
	objects := map[string][]byte{}
	byByte := map[int][]osvshardkey.ShardRef{}
	var total int64
	for p, rs := range byPrefix {
		sort.Slice(rs, func(i, j int) bool { return rs[i].ID < rs[j].ID })
		js, err := json.Marshal(rs)
		if err != nil {
			t.Fatal(err)
		}
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write(js)
		_ = zw.Close()
		data := buf.Bytes()
		sum := hashOf(data)
		objects[osvshardkey.ShardPath(set, sum)] = data
		b := osvshardkey.FirstByte(p, bits)
		byByte[b] = append(byByte[b], osvshardkey.ShardRef{Prefix: p, Object: sum, Size: int64(len(data)), Records: len(rs)})
		total += int64(len(data))
	}
	d := osvshardkey.SetDescriptor{
		Schema: osvshardkey.SetSchema, Set: set, Ecosystem: eco, Base: base, Bits: bits, Mode: osvshardkey.ModeStrip,
		Epoch: 3, Records: len(recs), Shards: len(byPrefix), ShardBytes: total,
		MaxShardBytes: osvshardkey.MaxShardBytes, MaxIndexBytes: osvshardkey.MaxIndexBytes,
	}
	bytesSorted := make([]int, 0, len(byByte))
	for b := range byByte {
		bytesSorted = append(bytesSorted, b)
	}
	sort.Ints(bytesSorted)
	for _, b := range bytesSorted {
		refs := byByte[b]
		sort.Slice(refs, func(i, j int) bool { return refs[i].Prefix < refs[j].Prefix })
		raw, err := osvshardkey.EncodeIndex(osvshardkey.IndexFile{Schema: osvshardkey.IndexSchema, Set: set, Bits: bits, Byte: b, Shards: refs}, d)
		if err != nil {
			t.Fatal(err)
		}
		sum := hashOf(raw)
		objects[osvshardkey.IndexPath(set, sum)] = raw
		d.Index = append(d.Index, osvshardkey.IndexRef{Byte: b, Object: sum, Size: int64(len(raw))})
	}
	if _, err := osvshardkey.EncodeSet(d); err != nil {
		t.Fatal(err)
	}
	return d, objects
}

// mapFetcher serves the objects and logs every path asked for.
type mapFetcher struct {
	mu      sync.Mutex
	objects map[string][]byte
	asked   []string
	fail    map[string]bool
}

func (f *mapFetcher) Fetch(_ context.Context, path string, max int64) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, path)
	if f.fail[path] {
		return nil, errors.New("HTTP 503")
	}
	b, ok := f.objects[path]
	if !ok {
		return nil, errors.New("HTTP 404")
	}
	if int64(len(b)) > max {
		return nil, errors.New("over the cap")
	}
	return append([]byte(nil), b...), nil
}

func npmRecords() []testRecord {
	return []testRecord{
		{ID: "GHSA-aaaa-0001", Summary: "lodash", Affected: []testAffected{aff("npm", "lodash", "4.17.20")}},
		// One advisory naming two packages that land in two shards: the node
		// must merge the copies by the union of affected.
		{ID: "GHSA-aaaa-0002", Summary: "two", Affected: []testAffected{aff("npm", "minimist", "1.2.5"), aff("npm", "Left-Pad", "1.0.0")}},
		{ID: "GHSA-aaaa-0003", Summary: "unrelated", Affected: []testAffected{aff("npm", "express", "4.0.0")}},
		{ID: "GHSA-aaaa-0004", Summary: "react", Affected: []testAffected{aff("npm", "react", "0.1.0")}},
	}
}

func TestRunFetchesOnlyPrefixesAndMerges(t *testing.T) {
	t.Parallel()
	d, objs := publishSet(t, "npm", "npm", 13, npmRecords())
	f := &mapFetcher{objects: objs}
	cache := Cache{Dir: filepath.Join(t.TempDir(), CacheDirName)}
	l := Lookup{Fetch: f, Cache: cache}
	names := []string{"lodash", "minimist", "left-pad", "react"}
	ans, err := l.Run(context.Background(), Query{Set: d, Names: names})
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Failed) != 0 {
		t.Fatalf("failed %v", ans.Failed)
	}
	ids := map[string][]byte{}
	for _, r := range ans.Records {
		ids[r.ID] = r.JSON
	}
	if _, ok := ids["GHSA-aaaa-0003"]; ok {
		t.Fatal("a record for a package not asked for was kept")
	}
	for _, want := range []string{"GHSA-aaaa-0001", "GHSA-aaaa-0002", "GHSA-aaaa-0004"} {
		if _, ok := ids[want]; !ok {
			t.Fatalf("missing %s in %v", want, ans.Records)
		}
	}
	var merged testRecord
	if err := json.Unmarshal(ids["GHSA-aaaa-0002"], &merged); err != nil {
		t.Fatal(err)
	}
	if len(merged.Affected) != 2 {
		t.Fatalf("copies not merged by the union of affected: %+v", merged)
	}
	if merged.Summary != "two" {
		t.Fatalf("merge lost a field: %+v", merged)
	}
	// Nothing the node asked for names a package: only digests.
	for _, p := range f.asked {
		for _, n := range names {
			if strings.Contains(strings.ToLower(p), n) {
				t.Fatalf("request %s names package %s", p, n)
			}
		}
		if !strings.HasPrefix(p, "npm/index/") && !strings.HasPrefix(p, "npm/obj/") {
			t.Fatalf("request %s is not a bucket object path", p)
		}
	}
	if ans.Fetched == 0 || ans.Cached != 0 {
		t.Fatalf("fetched %d cached %d", ans.Fetched, ans.Cached)
	}
	// A second walk is served from the cache: no request at all.
	f.asked = nil
	again, err := l.Run(context.Background(), Query{Set: d, Names: names})
	if err != nil {
		t.Fatal(err)
	}
	if len(f.asked) != 0 || again.Cached != ans.Fetched || len(again.Records) != len(ans.Records) {
		t.Fatalf("second walk asked %v (cached %d of %d)", f.asked, again.Cached, ans.Fetched)
	}
}

func TestRunFailuresAreReportedPerName(t *testing.T) {
	t.Parallel()
	d, objs := publishSet(t, "npm", "npm", 13, npmRecords())
	// Corrupt lodash's shard: same path, other bytes.
	lp := osvshardkey.PrefixOf("npm", "lodash", 13)
	var lodashShard string
	for _, r := range d.Index {
		if r.Byte != osvshardkey.FirstByte(lp, 13) {
			continue
		}
		idx, err := osvshardkey.DecodeIndex(objs[osvshardkey.IndexPath("npm", r.Object)], d, r.Byte)
		if err != nil {
			t.Fatal(err)
		}
		s, _ := idx.ShardFor(lp)
		lodashShard = osvshardkey.ShardPath("npm", s.Object)
	}
	objs[lodashShard] = append([]byte{0}, objs[lodashShard][1:]...)
	f := &mapFetcher{objects: objs}
	ans, err := Lookup{Fetch: f}.Run(context.Background(), Query{Set: d, Names: []string{"lodash", "react"}})
	if err != nil {
		t.Fatal(err)
	}
	if !ans.NameFailed("npm", "LoDash") || ans.NameFailed("npm", "react") {
		t.Fatalf("failed = %v", ans.Failed)
	}
	for _, r := range ans.Records {
		if r.ID == "GHSA-aaaa-0001" {
			t.Fatal("a record from a shard that did not verify was kept")
		}
	}
	// An unreachable host fails every name, never an error of the walk.
	down := &mapFetcher{objects: objs, fail: map[string]bool{}}
	for p := range objs {
		down.fail[p] = true
	}
	ans, err = Lookup{Fetch: down}.Run(context.Background(), Query{Set: d, Names: []string{"lodash", "react"}})
	if err != nil || len(ans.Failed) != 2 || len(ans.Records) != 0 {
		t.Fatalf("down: err %v failed %v records %d", err, ans.Failed, len(ans.Records))
	}
	// A name whose first byte has no index file is no failure: nothing keys
	// under it.
	ans, err = Lookup{Fetch: f}.Run(context.Background(), Query{Set: d, Names: []string{"not-a-package-anywhere-xyz"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(ans.Records) != 0 {
		t.Fatalf("records for an unknown name: %v", ans.Records)
	}
}

func TestRunRefusesABadDescriptor(t *testing.T) {
	t.Parallel()
	d, objs := publishSet(t, "npm", "npm", 13, npmRecords())
	d.Mode = "whole"
	f := &mapFetcher{objects: objs}
	if _, err := (Lookup{Fetch: f}).Run(context.Background(), Query{Set: d, Names: []string{"lodash"}}); !errors.Is(err, ErrBadQuery) {
		t.Fatalf("err = %v", err)
	}
	if len(f.asked) != 0 {
		t.Fatal("a bad descriptor made a request")
	}
}

func TestCacheReverifiesAndTrims(t *testing.T) {
	t.Parallel()
	d, objs := publishSet(t, "npm", "npm", 13, npmRecords())
	dir := filepath.Join(t.TempDir(), CacheDirName)
	clock := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	c := Cache{Dir: dir, Now: func() time.Time { clock = clock.Add(time.Minute); return clock }}
	f := &mapFetcher{objects: objs}
	if _, err := (Lookup{Fetch: f, Cache: c}).Run(context.Background(), Query{Set: d, Names: []string{"lodash"}}); err != nil {
		t.Fatal(err)
	}
	// Tamper with every cached file: the next walk re-fetches them.
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err == nil && !fi.IsDir() {
			b, _ := os.ReadFile(p)
			b[len(b)-1] ^= 0xff
			_ = os.WriteFile(p, b, 0o600)
		}
		return nil
	})
	f.asked = nil
	ans, err := (Lookup{Fetch: f, Cache: c}).Run(context.Background(), Query{Set: d, Names: []string{"lodash"}})
	if err != nil || ans.Cached != 0 || len(f.asked) == 0 || len(ans.Records) != 1 {
		t.Fatalf("tampered cache: err %v cached %d asked %v records %d", err, ans.Cached, f.asked, len(ans.Records))
	}
	if c.Bytes() == 0 {
		t.Fatal("nothing cached")
	}
	small := c
	small.MaxBytes = 1
	if err := small.Trim(); err != nil {
		t.Fatal(err)
	}
	if small.Bytes() > 1 {
		t.Fatalf("trimmed cache holds %d bytes", small.Bytes())
	}
	if (Cache{}).Trim() != nil || (Cache{}).Bytes() != 0 {
		t.Fatal("the zero cache")
	}
}

func TestInstallExportAlwaysWritesAFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := InstallExport(dir, "GitHub Actions", nil); err != nil {
		t.Fatal(err)
	}
	p, _ := ExportPath(dir, "GitHub Actions")
	zr, err := zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(zr.File) != 0 {
		t.Fatal("an empty export holds entries")
	}
	_ = zr.Close()
	recs := []Record{{ID: "GHSA-x", JSON: []byte(`{"id":"GHSA-x"}`)}, {ID: "GO-1", JSON: []byte(`{"id":"GO-1"}`)}}
	if err := InstallExport(dir, "Go", recs); err != nil {
		t.Fatal(err)
	}
	p, _ = ExportPath(dir, "Go")
	zr, err = zip.OpenReader(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = zr.Close() }()
	if len(zr.File) != 2 || zr.File[0].Name != "GHSA-x.json" || zr.File[1].Name != "GO-1.json" {
		t.Fatalf("entries %v", zr.File)
	}
	if err := InstallExport(dir, "../x", nil); err == nil {
		t.Fatal("a bad ecosystem name was written")
	}
	if err := InstallExport(dir, "Go", []Record{{ID: "../x", JSON: []byte(`{}`)}}); err == nil {
		t.Fatal("a bad record id was written")
	}
}

func TestSpellings(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		eco, name string
		want      []string
	}{
		{"Go", "github.com/BurntSushi/toml", []string{"github.com/BurntSushi/toml", "github.com/burntsushi/toml"}},
		{"Go", "golang.org/x/net", []string{"golang.org/x/net"}},
		{"npm", "@Scope/Name", []string{"@Scope/Name"}},
		{"PyPI", "", nil},
	} {
		got := Spellings(tc.eco, tc.name)
		if strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("Spellings(%s, %s) = %v, want %v", tc.eco, tc.name, got, tc.want)
		}
	}
}

func TestDecodeShardRefusesBadInput(t *testing.T) {
	t.Parallel()
	gz := func(s string) []byte {
		var b bytes.Buffer
		w := gzip.NewWriter(&b)
		_, _ = w.Write([]byte(s))
		_ = w.Close()
		return b.Bytes()
	}
	want := map[string]bool{"x": true}
	for name, in := range map[string][]byte{
		"not gzip":   []byte("plain"),
		"not array":  gz(`{"id":"A"}`),
		"bad id":     gz(`[{"id":"../a","affected":[{"package":{"ecosystem":"npm","name":"x"}}]}]`),
		"truncated":  gz(`[{"id":"A"`),
		"not object": gz(`[1]`),
	} {
		if _, err := decodeShard(in, "npm", want); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	got, err := decodeShard(gz(`[{"id":"A","affected":[{"package":{"ecosystem":"PyPI","name":"x"}}]},{"id":"B","affected":[{"package":{"ecosystem":"npm","name":"X"}}]}]`), "npm", want)
	if err != nil || len(got) != 1 || !strings.Contains(string(got[0]), `"B"`) {
		t.Fatalf("got %s err %v", got, err)
	}
}
