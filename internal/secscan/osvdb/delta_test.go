package osvdb

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRebaseRules(t *testing.T) {
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	ok := Epoch{CRC32C: "x", FetchedAt: now.Add(-time.Hour), BaseFetchedAt: now.Add(-24 * time.Hour), Watermark: now.Add(-3 * time.Hour)}
	with := func(f func(*Epoch)) Epoch { e := ok; f(&e); return e }
	cases := []struct {
		name   string
		epoch  Epoch
		fileOK bool
		want   string
	}{
		{"not installed", with(func(e *Epoch) { e.CRC32C = "" }), true, "no_export"},
		{"file missing", ok, false, "no_export"},
		{"no watermark", with(func(e *Epoch) { e.Watermark = time.Time{} }), true, "no_watermark"},
		{"base never recorded", with(func(e *Epoch) { e.BaseFetchedAt = time.Time{} }), true, "base_stale"},
		{"base older than 7 days", with(func(e *Epoch) { e.BaseFetchedAt = now.Add(-MaxBaseAge - time.Second) }), true, "base_stale"},
		{"watermark older than 7 days", with(func(e *Epoch) { e.Watermark = now.Add(-MaxWatermarkAge - time.Second) }), true, "watermark_stale"},
		{"three delta failures", with(func(e *Epoch) { e.DeltaFailures = MaxDeltaFailures }), true, "delta_failing"},
		{"two delta failures", with(func(e *Epoch) { e.DeltaFailures = MaxDeltaFailures - 1 }), true, ""},
		{"delta", ok, true, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := rebaseReason(rebaseFacts{Epoch: c.epoch, Now: now, FileOK: c.fileOK}); got != c.want {
				t.Fatalf("got %q, want %q", got, c.want)
			}
		})
	}
}

func TestDeltaLimit(t *testing.T) {
	for entries, want := range map[int]int{-1: MaxDeltaRecords, 0: 1, 9: 1, 40: 4, 19999: 1999, 20000: 2000, 1_000_000: MaxDeltaRecords} {
		if got := deltaLimit(entries); got != want {
			t.Errorf("deltaLimit(%d) = %d, want %d", entries, got, want)
		}
	}
}

// deltaRemote is a fakeRemote that also lists changes and serves records.
type deltaRemote struct {
	fakeRemote
	mods    []Modified // newest first
	records map[string][]byte
	recErr  error
	listErr error
	heads   int
	lists   int
	fetched []string
}

func (d *deltaRemote) Head(ctx context.Context, eco string) (Meta, error) {
	d.heads++
	return d.fakeRemote.Head(ctx, eco)
}

func (d *deltaRemote) ModifiedSince(_ context.Context, _ string, since time.Time, limit int) ([]Modified, bool, error) {
	d.lists++
	if d.listErr != nil {
		return nil, false, d.listErr
	}
	var out []Modified
	for _, m := range d.mods {
		if !m.At.After(since) {
			break
		}
		if len(out) >= limit {
			return out, true, nil
		}
		out = append(out, m)
	}
	return out, false, nil
}

func (d *deltaRemote) Record(_ context.Context, _, id string) ([]byte, error) {
	d.fetched = append(d.fetched, id)
	if d.recErr != nil {
		return nil, d.recErr
	}
	b, ok := d.records[id]
	if !ok {
		return nil, ErrRecordGone
	}
	return b, nil
}

// exportOf is a synthetic export of records R-0..R-<n-1>.
func exportOf(t *testing.T, n int, v string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < n; i++ {
		id := fmt.Sprintf("R-%d", i)
		w, _ := zw.Create(EntryName(id))
		_, _ = w.Write(rec(id, v))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

var (
	newestBase = time.Date(2026, 10, 20, 10, 0, 0, 0, time.UTC)
	t0         = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
)

// newDeltaRemote serves a 40-record export whose newest listed change is
// R-0 at newestBase.
func newDeltaRemote(t *testing.T) *deltaRemote {
	d := &deltaRemote{fakeRemote: fakeRemote{body: map[string][]byte{"npm": exportOf(t, 40, "base")}}, records: map[string][]byte{}}
	d.mods = []Modified{{ID: "R-0", At: newestBase}, {ID: "R-1", At: newestBase.Add(-48 * time.Hour)}}
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("R-%d", i)
		d.records[id] = rec(id, "base")
	}
	return d
}

func zipEntries(t *testing.T, path string) map[string]string {
	t.Helper()
	zr, err := zip.OpenReader(path)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	out := map[string]string{}
	for _, f := range zr.File {
		out[f.Name] = body(t, f)
	}
	return out
}

func TestRefreshDeltaEndToEnd(t *testing.T) {
	s := Open(t.TempDir())
	d := newDeltaRemote(t)
	ctx := context.Background()
	rep, err := s.Refresh(ctx, d, []string{"npm"}, t0)
	if err != nil || len(rep.Changed) != 1 || len(rep.Incremental) != 0 {
		t.Fatalf("base refresh %+v %v", rep, err)
	}
	eps, _ := s.Epochs()
	base := eps["npm"]
	// min(Last-Modified 11:25, newest listed 10:00) less the 2 h margin.
	if want := newestBase.Add(-WatermarkMargin); !base.Watermark.Equal(want) || !base.BaseFetchedAt.Equal(t0) || base.DeltaRecords != 0 {
		t.Fatalf("base epoch %+v, watermark want %s", base, want)
	}
	if strings.Contains(base.String(), "delta=") {
		t.Fatalf("no delta applied yet: %q", base.String())
	}

	// Upstream: R-1 changed, NEW-1 added, R-2 withdrawn.
	at := t0.Add(13 * time.Hour)
	d.records["R-1"] = rec("R-1", "v2")
	d.records["NEW-1"] = rec("NEW-1", "v1")
	delete(d.records, "R-2")
	d.mods = append([]Modified{{ID: "NEW-1", At: at.Add(30 * time.Minute)}, {ID: "R-2", At: at.Add(10 * time.Minute)}, {ID: "R-1", At: at}}, d.mods...)
	d.body["npm"] = exportOf(t, 40, "upstream moved on") // the full export's CRC changes all day
	heads, gets := d.heads, d.gets

	now := t0.Add(24 * time.Hour)
	rep, err = s.Refresh(ctx, d, []string{"npm"}, now)
	// R-0 at newestBase is inside the margin and fetched again (idempotent).
	if err != nil || rep.Incremental["npm"] != 4 || len(rep.Changed) != 1 || rep.Changed[0] != "npm" {
		t.Fatalf("delta refresh %+v %v (fetched %v)", rep, err, d.fetched)
	}
	if d.heads != heads || d.gets != gets {
		t.Fatalf("a delta must not HEAD or GET the full export (heads %d->%d, gets %d->%d)", heads, d.heads, gets, d.gets)
	}
	got := zipEntries(t, filepath.Join(s.Dir(), "osv-scalibr", "npm", "all.zip"))
	if len(got) != 40 || !strings.Contains(got["R-1.json"], "v2") || !strings.Contains(got["NEW-1.json"], "v1") || got["R-2.json"] != "" || !strings.Contains(got["R-5.json"], "base") {
		t.Fatalf("merged export %d entries: R-1 %q NEW-1 %q R-2 %q", len(got), got["R-1.json"], got["NEW-1.json"], got["R-2.json"])
	}
	a, _ := os.ReadFile(filepath.Join(s.Dir(), "osv-scalibr", "npm", "all.zip"))
	b, _ := os.ReadFile(filepath.Join(s.Dir(), "osv-scanner", "npm", "all.zip"))
	if !bytes.Equal(a, b) {
		t.Fatal("osv-scanner must read the same merged export")
	}
	eps, _ = s.Epochs()
	e := eps["npm"]
	if !e.Watermark.Equal(at.Add(30*time.Minute)) || e.DeltaRecords != 4 || e.DeltaFailures != 0 || !e.FetchedAt.Equal(now) {
		t.Fatalf("delta epoch %+v", e)
	}
	if e.CRC32C != base.CRC32C || e.LastModified != base.LastModified || !e.BaseFetchedAt.Equal(t0) {
		t.Fatalf("the base fields must stay the base's: %+v vs %+v", e, base)
	}
	if want := base.String() + " delta=2026-10-21T01:30:00Z"; e.String() != want {
		t.Fatalf("epoch string %q, want %q", e.String(), want)
	}
	if inst, _ := s.Installed(); inst["npm"] != e.String() {
		t.Fatalf("installed %q", inst["npm"])
	}

	// Nothing new: a check only.
	rep, err = s.Refresh(ctx, d, []string{"npm"}, now.Add(6*time.Hour))
	if err != nil || len(rep.Unchanged) != 1 || len(rep.Changed) != 0 || d.heads != heads {
		t.Fatalf("quiet refresh %+v %v", rep, err)
	}
	eps, _ = s.Epochs()
	if !eps["npm"].CheckedAt.Equal(now.Add(6*time.Hour)) || eps["npm"].String() != e.String() {
		t.Fatalf("quiet epoch %+v", eps["npm"])
	}

	// A week after the base: a rebase downloads the full export.
	rep, err = s.Refresh(ctx, d, []string{"npm"}, t0.Add(MaxBaseAge+time.Hour))
	if err != nil || len(rep.Changed) != 1 || len(rep.Incremental) != 0 || d.gets != gets+1 {
		t.Fatalf("weekly rebase %+v %v", rep, err)
	}
	eps, _ = s.Epochs()
	if eps["npm"].DeltaRecords != 0 || strings.Contains(eps["npm"].String(), "delta=") {
		t.Fatalf("a rebase resets the delta: %+v", eps["npm"])
	}
}

func TestRefreshDeltaFailureKeepsLastKnownGoodThenRebases(t *testing.T) {
	s := Open(t.TempDir())
	d := newDeltaRemote(t)
	ctx := context.Background()
	if _, err := s.Refresh(ctx, d, []string{"npm"}, t0); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(s.Dir(), "osv-scalibr", "npm", "all.zip")
	good, _ := os.ReadFile(path)
	before, _ := s.Installed()
	d.mods = append([]Modified{{ID: "R-3", At: t0.Add(time.Hour)}}, d.mods...)
	d.recErr = errors.New("connection reset")
	d.body["npm"] = exportOf(t, 40, "rebased")
	heads := d.heads
	for i := 1; i <= MaxDeltaFailures; i++ {
		rep, _ := s.Refresh(ctx, d, []string{"npm"}, t0.Add(time.Duration(i)*time.Hour))
		if rep.Failed["npm"] == "" || len(rep.Changed) != 0 {
			t.Fatalf("failure %d: %+v", i, rep)
		}
		eps, _ := s.Epochs()
		if eps["npm"].DeltaFailures != i || !strings.Contains(eps["npm"].LastError, "connection reset") {
			t.Fatalf("failure %d epoch %+v", i, eps["npm"])
		}
		if b, _ := os.ReadFile(path); !bytes.Equal(b, good) {
			t.Fatalf("failure %d replaced the last-known-good export", i)
		}
		if after, _ := s.Installed(); after["npm"] != before["npm"] {
			t.Fatalf("failure %d moved the epoch", i)
		}
		if m, _ := filepath.Glob(filepath.Join(s.Dir(), "*", "npm", "*.part")); len(m) != 0 {
			t.Fatalf("leftover partial files %v", m)
		}
	}
	if d.heads != heads {
		t.Fatal("the failing deltas must not HEAD the full export")
	}
	// The third failure makes the next refresh a full one.
	rep, err := s.Refresh(ctx, d, []string{"npm"}, t0.Add(10*time.Hour))
	if err != nil || len(rep.Changed) != 1 || d.heads != heads+1 {
		t.Fatalf("rebase after %d failures %+v %v", MaxDeltaFailures, rep, err)
	}
	eps, _ := s.Epochs()
	if eps["npm"].DeltaFailures != 0 || eps["npm"].LastError != "" || !strings.Contains(zipEntries(t, path)["R-3.json"], "rebased") {
		t.Fatalf("rebased epoch %+v", eps["npm"])
	}
}

func TestRefreshDeltaOverflowRebases(t *testing.T) {
	s := Open(t.TempDir())
	d := newDeltaRemote(t)
	ctx := context.Background()
	if _, err := s.Refresh(ctx, d, []string{"npm"}, t0); err != nil {
		t.Fatal(err)
	}
	// 40 entries: at most 4 records by delta; 5 changed is a rebase.
	for i := 0; i < 5; i++ {
		d.mods = append([]Modified{{ID: fmt.Sprintf("R-%d", 10+i), At: t0.Add(time.Duration(i+1) * time.Minute)}}, d.mods...)
	}
	d.body["npm"] = exportOf(t, 40, "rebased")
	gets := d.gets
	rep, err := s.Refresh(ctx, d, []string{"npm"}, t0.Add(time.Hour))
	if err != nil || len(rep.Changed) != 1 || len(rep.Incremental) != 0 || d.gets != gets+1 || len(d.fetched) != 0 {
		t.Fatalf("overflow must download the full export: %+v %v (gets %d fetched %v)", rep, err, d.gets-gets, d.fetched)
	}
}

func TestRefreshAdoptsWatermarkForInstalledExport(t *testing.T) {
	s := Open(t.TempDir())
	d := newDeltaRemote(t)
	ctx := context.Background()
	// Installed through a remote with no listing (as before this change).
	if _, err := s.Refresh(ctx, &d.fakeRemote, []string{"npm"}, t0); err != nil {
		t.Fatal(err)
	}
	eps, _ := s.Epochs()
	if !eps["npm"].Watermark.IsZero() {
		t.Fatal("a plain Remote never sets a watermark")
	}
	gets := d.gets
	rep, err := s.Refresh(ctx, d, []string{"npm"}, t0.Add(time.Hour))
	if err != nil || len(rep.Unchanged) != 1 || d.gets != gets {
		t.Fatalf("the same object must not download again: %+v %v", rep, err)
	}
	eps, _ = s.Epochs()
	if !eps["npm"].Watermark.Equal(newestBase.Add(-WatermarkMargin)) || !eps["npm"].BaseFetchedAt.Equal(t0) {
		t.Fatalf("the installed export takes a watermark: %+v", eps["npm"])
	}
}

// localRemote serves exports from files on disk.
type localRemote struct {
	fakeRemote
	path string
	meta Meta
}

func (l *localRemote) LocalExport(context.Context, string) (string, Meta, error) {
	return l.path, l.meta, nil
}

func TestRefreshLocalRemoteLinks(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "mirror", "npm.zip")
	_ = os.MkdirAll(filepath.Dir(src), 0o700)
	b := exportOf(t, 3, "mirror")
	if err := os.WriteFile(src, b, 0o600); err != nil {
		t.Fatal(err)
	}
	crc := CRC32CString(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	meta := Meta{LastModified: "2026-10-20T00:00:00Z", CRC32C: crc, Size: int64(len(b))}

	t.Run("crc mismatch is refused", func(t *testing.T) {
		s := Open(filepath.Join(dir, "bad"))
		bad := meta
		bad.CRC32C = "AAAAAA=="
		r := &localRemote{fakeRemote: fakeRemote{body: map[string][]byte{"npm": b}}, path: src, meta: bad}
		rep, _ := s.Refresh(context.Background(), r, []string{"npm"}, t0)
		if !strings.Contains(rep.Failed["npm"], "CRC32C mismatch") {
			t.Fatalf("%+v", rep)
		}
		if _, err := os.Stat(filepath.Join(s.Dir(), "osv-scalibr", "npm", "all.zip")); err == nil {
			t.Fatal("a mismatched file must not be installed")
		}
		if m, _ := filepath.Glob(filepath.Join(s.Dir(), "*", "npm", "*.part")); len(m) != 0 {
			t.Fatalf("leftover partial files %v", m)
		}
		if st, err := os.Stat(src); err != nil || st.Size() != int64(len(b)) {
			t.Fatal("the source file must be untouched")
		}
	})

	t.Run("linked, not streamed", func(t *testing.T) {
		s := Open(filepath.Join(dir, "good"))
		r := &localRemote{fakeRemote: fakeRemote{body: map[string][]byte{"npm": b}}, path: src, meta: meta}
		rep, err := s.Refresh(context.Background(), r, []string{"npm"}, t0)
		if err != nil || len(rep.Changed) != 1 || r.gets != 0 {
			t.Fatalf("%+v %v gets=%d", rep, err, r.gets)
		}
		a, _ := os.Stat(src)
		for _, sub := range []string{"osv-scalibr", "osv-scanner"} {
			got, err := os.Stat(filepath.Join(s.Dir(), sub, "npm", "all.zip"))
			if err != nil || !os.SameFile(a, got) {
				t.Fatalf("%s must be a hard link of the mirror file (err %v)", sub, err)
			}
		}
	})

	t.Run("copied where the link is refused", func(t *testing.T) {
		saved := linkFile
		t.Cleanup(func() { linkFile = saved })
		linkFile = func(string, string) error { return errors.New("cross-device link") }
		s := Open(filepath.Join(dir, "copy"))
		r := &localRemote{fakeRemote: fakeRemote{body: map[string][]byte{"npm": b}}, path: src, meta: meta}
		rep, err := s.Refresh(context.Background(), r, []string{"npm"}, t0)
		if err != nil || len(rep.Changed) != 1 {
			t.Fatalf("%+v %v", rep, err)
		}
		if got, _ := os.ReadFile(filepath.Join(s.Dir(), "osv-scalibr", "npm", "all.zip")); !bytes.Equal(got, b) {
			t.Fatal("the copy must hold the export")
		}
	})
}

func TestEpochsBackwardCompatible(t *testing.T) {
	s := Open(t.TempDir())
	old := `[{"ecosystem":"npm","last_modified":"Tue, 20 Oct 2026 11:25:00 GMT","crc32c":"yZRlqg==","size":10,"fetched_at":"2026-10-20T12:00:00Z","checked_at":"2026-10-20T12:00:00Z"}]`
	if err := os.WriteFile(filepath.Join(s.Dir(), "epochs.json"), []byte(old), 0o600); err != nil {
		t.Fatal(err)
	}
	eps, err := s.Epochs()
	if err != nil {
		t.Fatal(err)
	}
	e := eps["npm"]
	if !e.Installed() || !e.Watermark.IsZero() || !e.BaseFetchedAt.IsZero() || e.DeltaRecords != 0 || e.DeltaFailures != 0 {
		t.Fatalf("decoded %+v", e)
	}
	if e.String() != "Tue, 20 Oct 2026 11:25:00 GMT crc32c=yZRlqg==" {
		t.Fatalf("String changed without a delta: %q", e.String())
	}
	// A watermark alone (a base with no records applied) keeps the string.
	e.Watermark = t0
	if e.String() != "Tue, 20 Oct 2026 11:25:00 GMT crc32c=yZRlqg==" {
		t.Fatalf("String changed without a delta applied: %q", e.String())
	}
	b, _ := json.Marshal(Epoch{Ecosystem: "npm"})
	for _, k := range []string{"watermark", "base_fetched_at", "delta_records", "delta_failures"} {
		if strings.Contains(string(b), k) {
			t.Fatalf("a zero %s must be omitted: %s", k, b)
		}
	}
}

func TestParseHTTPTime(t *testing.T) {
	want := time.Date(2026, 10, 20, 11, 25, 0, 0, time.UTC)
	for _, s := range []string{"Tue, 20 Oct 2026 11:25:00 GMT", "Tuesday, 20-Oct-26 11:25:00 GMT", "Tue Oct 20 11:25:00 2026", "2026-10-20T11:25:00Z"} {
		if got := parseHTTPTime(s); !got.Equal(want) {
			t.Errorf("%q -> %s", s, got)
		}
	}
	if !parseHTTPTime("yesterday").IsZero() {
		t.Error("an unparseable time is zero")
	}
}
