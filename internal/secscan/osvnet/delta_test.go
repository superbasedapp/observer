package osvnet

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/crc32"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/secscan/osvdb"
)

var listTop = time.Date(2026, 11, 2, 17, 30, 3, 387039386, time.UTC)

// listing is a synthetic modified_id.csv of n lines, newest first, one
// minute apart, without a trailing newline after the last line (and with
// one when trailingNL).
func listing(n int, trailingNL bool) ([]byte, []osvdb.Modified) {
	var b bytes.Buffer
	mods := make([]osvdb.Modified, n)
	for i := 0; i < n; i++ {
		mods[i] = osvdb.Modified{ID: fmt.Sprintf("GHSA-%04d-xxxx-yyyy", i), At: listTop.Add(-time.Duration(i) * time.Minute)}
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(mods[i].At.Format(time.RFC3339Nano) + "," + mods[i].ID)
	}
	if trailingNL {
		b.WriteByte('\n')
	}
	return b.Bytes(), mods
}

// listServer serves body as npm/modified_id.csv: with Range support
// (http.ServeContent answers 206 with Content-Range), or ignoring Range
// (200, the whole object).
func listServer(t *testing.T, body []byte, honourRange bool) (*Client, *[]string) {
	t.Helper()
	var mu sync.Mutex
	var ranges []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/npm/modified_id.csv" {
			http.NotFound(w, r)
			return
		}
		mu.Lock()
		ranges = append(ranges, r.Header.Get("Range"))
		mu.Unlock()
		if honourRange {
			http.ServeContent(w, r, "", time.Time{}, bytes.NewReader(body))
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(body)))
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return New(Options{BucketURL: srv.URL}), &ranges
}

func TestModifiedSince(t *testing.T) {
	body, mods := listing(2000, false) // about 100 KB: two chunks
	if body[ListChunk-1] == '\n' || body[ListChunk] == '\n' {
		t.Fatal("the fixture must split a line across the chunk boundary")
	}
	split := bytes.LastIndexByte(body[:ListChunk], '\n')
	inSecond := bytes.Count(body[:split], []byte("\n")) + 3 // a line wholly in the second chunk
	cases := []struct {
		name         string
		since        time.Time
		limit        int
		wantN        int
		wantOverflow bool
		wantReqs     int
	}{
		{"quiet: one small read", mods[0].At, 10, 0, false, 1},
		{"stop in the first chunk", mods[5].At, 100, 5, false, 1},
		{"stop past the split line", mods[inSecond].At, 5000, inSecond, false, 2},
		{"the whole listing", time.Time{}, 5000, 2000, false, 2},
		{"overflow", time.Time{}, 7, 7, true, 1},
	}
	for _, honour := range []bool{true, false} {
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/range=%v", c.name, honour), func(t *testing.T) {
				cl, ranges := listServer(t, body, honour)
				got, overflow, err := cl.ModifiedSince(context.Background(), "npm", c.since, c.limit)
				if err != nil {
					t.Fatal(err)
				}
				if len(got) != c.wantN || overflow != c.wantOverflow {
					t.Fatalf("got %d overflow %v, want %d %v", len(got), overflow, c.wantN, c.wantOverflow)
				}
				for i, m := range got {
					if m.ID != mods[i].ID || !m.At.Equal(mods[i].At) {
						t.Fatalf("line %d: %+v, want %+v", i, m, mods[i])
					}
				}
				if want := c.wantReqs; !honour {
					want = 1
					if len(*ranges) != want {
						t.Fatalf("a server ignoring Range is read in one request: %v", *ranges)
					}
				} else if len(*ranges) != want {
					t.Fatalf("%d range requests %v, want %d", len(*ranges), *ranges, want)
				}
				if honour && (*ranges)[0] != fmt.Sprintf("bytes=0-%d", ListChunk-1) {
					t.Fatalf("first request %q", (*ranges)[0])
				}
			})
		}
	}
}

func TestModifiedSinceEdges(t *testing.T) {
	one, _ := listing(1, true)
	ec := exactChunk()
	cases := []struct {
		name    string
		body    []byte
		wantN   int
		wantErr string
	}{
		{"one line with a trailing newline", one, 1, ""},
		{"empty listing", nil, 0, ""},
		{"exactly one chunk", ec, bytes.Count(ec, []byte{'\n'}), ""},
		{"no comma", []byte("2026-11-02T17:30:03Z GHSA-1\n"), 0, "malformed listing line"},
		{"bad time", []byte("yesterday,GHSA-1\n"), 0, "malformed listing time"},
		{"path-shaped id", []byte("2026-11-02T17:30:03Z,../../x\n"), 0, "malformed listing id"},
		{"an endless line", bytes.Repeat([]byte("a"), 3*ListChunk), 0, "longer than"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cl, _ := listServer(t, c.body, true)
			got, _, err := cl.ModifiedSince(context.Background(), "npm", time.Time{}, 1_000_000)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want %q, got %v", c.wantErr, err)
				}
				return
			}
			if err != nil || len(got) != c.wantN {
				t.Fatalf("got %d %v", len(got), err)
			}
		})
	}
	cl, _ := listServer(t, one, true)
	if _, _, err := cl.ModifiedSince(context.Background(), "../npm", time.Time{}, 1); err == nil {
		t.Fatal("a path-shaped ecosystem must be refused")
	}
}

// exactChunk is a listing of exactly ListChunk bytes ending in a newline,
// so the second read starts at the object's end.
func exactChunk() []byte {
	line := listTop.Format(time.RFC3339Nano) + ",GHSA-"
	var b bytes.Buffer
	for b.Len()+len(line)+64 < ListChunk {
		b.WriteString(line + "aaaa\n")
	}
	pad := ListChunk - b.Len() - len(line) - 1
	b.WriteString(line + strings.Repeat("b", pad) + "\n")
	return b.Bytes()
}

func TestRecord(t *testing.T) {
	big := append([]byte(`{"id":"BIG-1","x":"`), bytes.Repeat([]byte("a"), osvdb.MaxRecordBytes)...)
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		switch r.URL.Path {
		case "/npm/GHSA-1.json":
			_, _ = w.Write([]byte(`{"id":"GHSA-1"}`))
		case "/npm/BIG-1.json":
			_, _ = w.Write(big)
		case "/npm/ERR-1.json":
			w.WriteHeader(http.StatusServiceUnavailable)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Options{BucketURL: srv.URL})
	ctx := context.Background()
	if b, err := c.Record(ctx, "npm", "GHSA-1"); err != nil || string(b) != `{"id":"GHSA-1"}` {
		t.Fatalf("record %q %v", b, err)
	}
	if _, err := c.Record(ctx, "npm", "GONE-1"); !errors.Is(err, osvdb.ErrRecordGone) {
		t.Fatalf("a 404 is ErrRecordGone, got %v", err)
	}
	if _, err := c.Record(ctx, "npm", "ERR-1"); err == nil || errors.Is(err, osvdb.ErrRecordGone) {
		t.Fatalf("a 503 is a failure, not a withdrawal: %v", err)
	}
	if _, err := c.Record(ctx, "npm", "BIG-1"); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("an oversized record must be refused: %v", err)
	}
	n := len(paths)
	for _, id := range []string{"../all", "a/b", ""} {
		if _, err := c.Record(ctx, "npm", id); err == nil {
			t.Fatalf("id %q must be refused", id)
		}
	}
	if len(paths) != n {
		t.Fatal("a refused id must not reach the network")
	}
}

// TestDeltaRefreshThroughLane: the production client is a DeltaRemote, and
// osvdb takes the incremental path through it against a fake bucket: the
// first refresh downloads the export, the second fetches only the listing
// and the changed records (no HEAD, no export GET).
func TestDeltaRefreshThroughLane(t *testing.T) {
	var _ osvdb.DeltaRemote = New(Options{})
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for i := 0; i < 40; i++ {
		w, _ := zw.Create(fmt.Sprintf("R-%d.json", i))
		_, _ = fmt.Fprintf(w, `{"id":"R-%d"}`, i)
	}
	_ = zw.Close()
	export := buf.Bytes()
	crc := osvdb.CRC32CString(crc32.Checksum(export, crc32.MakeTable(crc32.Castagnoli)))
	var mu sync.Mutex
	csv := "2026-11-01T10:00:00Z,R-0\n2026-10-01T10:00:00Z,R-1\n"
	var reqs []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		reqs = append(reqs, r.Method+" "+r.URL.Path)
		body := csv
		mu.Unlock()
		switch r.URL.Path {
		case "/npm/all.zip":
			w.Header().Set("X-Goog-Hash", "crc32c="+crc)
			w.Header().Set("Last-Modified", "Sun, 01 Nov 2026 11:00:00 GMT")
			_, _ = w.Write(export)
		case "/npm/modified_id.csv":
			http.ServeContent(w, r, "", time.Time{}, strings.NewReader(body))
		case "/npm/R-0.json", "/npm/NEW-1.json":
			_, _ = fmt.Fprintf(w, `{"id":%q}`, strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/npm/"), ".json"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Options{BucketURL: srv.URL})
	s := osvdb.Open(t.TempDir())
	now := time.Date(2026, 11, 1, 12, 0, 0, 0, time.UTC)
	if rep, err := s.Refresh(context.Background(), c, []string{"npm"}, now); err != nil || len(rep.Changed) != 1 {
		t.Fatalf("base refresh %+v %v", rep, err)
	}
	eps, _ := s.Epochs()
	if want := time.Date(2026, 11, 1, 8, 0, 0, 0, time.UTC); !eps["npm"].Watermark.Equal(want) {
		t.Fatalf("watermark %s, want %s", eps["npm"].Watermark, want)
	}
	mu.Lock()
	csv = "2026-11-01T13:00:00Z,NEW-1\n" + csv
	reqs = nil
	mu.Unlock()
	rep, err := s.Refresh(context.Background(), c, []string{"npm"}, now.Add(6*time.Hour))
	// R-0 lies inside the watermark margin and is fetched again.
	if err != nil || rep.Incremental["npm"] != 2 {
		t.Fatalf("delta refresh %+v %v", rep, err)
	}
	for _, r := range reqs {
		if strings.HasSuffix(r, "/all.zip") {
			t.Fatalf("a delta must not touch the export: %v", reqs)
		}
	}
	if len(reqs) != 3 {
		t.Fatalf("requests %v: one listing read and two records", reqs)
	}
}

// TestModifiedSinceUnstatedSize: a server that does not state the size
// ("bytes a-b/*") is read until a short chunk or a 416 past the end.
func TestModifiedSinceUnstatedSize(t *testing.T) {
	body := exactChunk()
	var reqs int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqs++
		if r.Header.Get("Range") != fmt.Sprintf("bytes=0-%d", ListChunk-1) {
			w.WriteHeader(http.StatusRequestedRangeNotSatisfiable)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/*", len(body)-1))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(body)
	}))
	defer srv.Close()
	got, overflow, err := New(Options{BucketURL: srv.URL}).ModifiedSince(context.Background(), "npm", time.Time{}, 1_000_000)
	if err != nil || overflow || len(got) != bytes.Count(body, []byte{'\n'}) || reqs != 2 {
		t.Fatalf("got %d overflow %v err %v after %d requests", len(got), overflow, err, reqs)
	}
}
