package osvdb

import (
	"archive/zip"
	"bytes"
	"context"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type fakeRemote struct {
	body    map[string][]byte
	crc     map[string]string // override the header
	gets    int
	headErr error
}

func (f *fakeRemote) meta(eco string) Meta {
	b := f.body[eco]
	crc := CRC32CString(crc32.Checksum(b, crc32.MakeTable(crc32.Castagnoli)))
	if c, ok := f.crc[eco]; ok {
		crc = c
	}
	return Meta{LastModified: "Tue, 20 Oct 2026 11:25:00 GMT", CRC32C: crc, Size: int64(len(b))}
}

func (f *fakeRemote) Head(_ context.Context, eco string) (Meta, error) {
	if f.headErr != nil {
		return Meta{}, f.headErr
	}
	return f.meta(eco), nil
}

func (f *fakeRemote) Get(_ context.Context, eco string) (Meta, io.ReadCloser, error) {
	f.gets++
	return f.meta(eco), io.NopCloser(bytes.NewReader(f.body[eco])), nil
}

func zipOf(t *testing.T, name, body string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, _ := zw.Create(name)
	_, _ = w.Write([]byte(body))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestRefreshDownloadsVerifiesAndSkipsCurrent(t *testing.T) {
	s := Open(t.TempDir())
	r := &fakeRemote{body: map[string][]byte{"npm": zipOf(t, "a.json", "{}")}}
	now := time.Date(2026, 10, 21, 0, 0, 0, 0, time.UTC)
	rep, err := s.Refresh(context.Background(), r, []string{"npm"}, now)
	if err != nil || len(rep.Changed) != 1 {
		t.Fatalf("first refresh: %+v %v", rep, err)
	}
	for _, sub := range []string{"osv-scalibr", "osv-scanner"} {
		if _, err := os.Stat(filepath.Join(s.Dir(), sub, "npm", "all.zip")); err != nil {
			t.Fatalf("%s copy missing: %v", sub, err)
		}
	}
	inst, err := s.Installed()
	if err != nil || inst["npm"] == "" {
		t.Fatalf("installed %v %v", inst, err)
	}
	rep, err = s.Refresh(context.Background(), r, []string{"npm"}, now.Add(time.Hour))
	if err != nil || len(rep.Unchanged) != 1 || r.gets != 1 {
		t.Fatalf("second refresh must not download again: %+v gets=%d", rep, r.gets)
	}
	r.body["npm"] = zipOf(t, "b.json", "{}")
	rep, _ = s.Refresh(context.Background(), r, []string{"npm"}, now.Add(2*time.Hour))
	if len(rep.Changed) != 1 {
		t.Fatalf("a new CRC32C must replace the export: %+v", rep)
	}
	if inst2, _ := s.Installed(); inst2["npm"] == inst["npm"] {
		t.Fatal("the epoch must change with the export")
	}
}

func TestRefreshKeepsLastKnownGood(t *testing.T) {
	s := Open(t.TempDir())
	good := zipOf(t, "a.json", "{}")
	r := &fakeRemote{body: map[string][]byte{"PyPI": good}}
	if _, err := s.Refresh(context.Background(), r, []string{"PyPI"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Installed()
	cases := []struct {
		name string
		set  func()
	}{
		{"crc mismatch", func() { r.body["PyPI"] = zipOf(t, "x.json", "{}"); r.crc = map[string]string{"PyPI": "AAAAAA=="} }},
		{"not a zip", func() { r.body["PyPI"] = []byte("not a zip"); r.crc = nil }},
		{"no crc", func() { r.crc = map[string]string{"PyPI": ""} }},
		{"head fails", func() { r.headErr = errors.New("blocked") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			c.set()
			rep, _ := s.Refresh(context.Background(), r, []string{"PyPI"}, time.Now())
			if rep.Failed["PyPI"] == "" {
				t.Fatalf("%s must fail: %+v", c.name, rep)
			}
			after, _ := s.Installed()
			if after["PyPI"] != before["PyPI"] {
				t.Fatalf("the last verified export must stay: before %q after %q", before["PyPI"], after["PyPI"])
			}
			eps, _ := s.Epochs()
			if eps["PyPI"].LastError == "" {
				t.Fatal("the failure must be recorded")
			}
		})
	}
}

func TestCRC32CString(t *testing.T) {
	// The bucket's documented example: crc32c of "hello world" (base64).
	if got := CRC32CString(crc32.Checksum([]byte("hello world"), crc32.MakeTable(crc32.Castagnoli))); got != "yZRlqg==" {
		t.Fatalf("got %s", got)
	}
}

// TestRefreshCopiesBeforeReplacing pins milestone 2a of lane SEC-D2B: when
// the osv-scanner copy fails, neither file is replaced and the epoch record
// stays the old one, so no new export ever sits under an old record.
func TestRefreshCopiesBeforeReplacing(t *testing.T) {
	s := Open(t.TempDir())
	old := zipOf(t, "a.json", "{}")
	r := &fakeRemote{body: map[string][]byte{"npm": old}}
	if _, err := s.Refresh(context.Background(), r, []string{"npm"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	before, _ := s.Epochs()
	savedLink, savedCopy := linkFile, copyFile
	t.Cleanup(func() { linkFile, copyFile = savedLink, savedCopy })
	linkFile = func(string, string) error { return errors.New("cross-device link") }
	copyFile = func(string, string) error { return errors.New("no space left on device") }
	r.body["npm"] = zipOf(t, "b.json", "{}")
	rep, _ := s.Refresh(context.Background(), r, []string{"npm"}, time.Now())
	if rep.Failed["npm"] == "" || len(rep.Changed) != 0 {
		t.Fatalf("a failed copy must fail the refresh: %+v", rep)
	}
	for _, sub := range []string{"osv-scalibr", "osv-scanner"} {
		b, err := os.ReadFile(filepath.Join(s.Dir(), sub, "npm", "all.zip"))
		if err != nil || !bytes.Equal(b, old) {
			t.Fatalf("%s: the old export must stay in place (err %v)", sub, err)
		}
	}
	after, _ := s.Epochs()
	if after["npm"].CRC32C != before["npm"].CRC32C || after["npm"].LastError == "" {
		t.Fatalf("epoch before %+v after %+v: the record stays old and names the failure", before["npm"], after["npm"])
	}
	if m, _ := filepath.Glob(filepath.Join(s.Dir(), "*", "npm", "*.part")); len(m) != 0 {
		t.Fatalf("leftover partial files %v", m)
	}
	// With the copy working again, a refresh replaces both.
	linkFile, copyFile = savedLink, savedCopy
	if rep, err := s.Refresh(context.Background(), r, []string{"npm"}, time.Now()); err != nil || len(rep.Changed) != 1 {
		t.Fatalf("recovery refresh %+v %v", rep, err)
	}
}

// stallBody sends some bytes, then blocks until it is closed.
type stallBody struct {
	head   []byte
	closed chan struct{}
}

func (b *stallBody) Read(p []byte) (int, error) {
	if len(b.head) > 0 {
		n := copy(p, b.head)
		b.head = b.head[n:]
		return n, nil
	}
	<-b.closed
	return 0, errors.New("use of closed body")
}

func (b *stallBody) Close() error {
	select {
	case <-b.closed:
	default:
		close(b.closed)
	}
	return nil
}

type stallRemote struct{ fakeRemote }

func (r *stallRemote) Get(_ context.Context, eco string) (Meta, io.ReadCloser, error) {
	m := r.meta(eco)
	return m, &stallBody{head: r.body[eco][:10], closed: make(chan struct{})}, nil
}

// TestRefreshBodyDeadline: a server that stops sending is cut off, the
// refresh fails, and the store lock is free for the next refresh.
func TestRefreshBodyDeadline(t *testing.T) {
	s := Open(t.TempDir()).WithBodyDeadlines(50*time.Millisecond, 5*time.Second)
	r := &stallRemote{fakeRemote{body: map[string][]byte{"npm": zipOf(t, "a.json", "{}")}}}
	done := make(chan Report, 1)
	go func() {
		rep, _ := s.Refresh(context.Background(), r, []string{"npm"}, time.Now())
		done <- rep
	}()
	select {
	case rep := <-done:
		if rep.Failed["npm"] == "" {
			t.Fatalf("a stalled body must fail: %+v", rep)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a stalled body held the refresh past its idle deadline")
	}
	ok := &fakeRemote{body: r.body}
	if rep, err := s.Refresh(context.Background(), ok, []string{"npm"}, time.Now()); err != nil || len(rep.Changed) != 1 {
		t.Fatalf("the store lock must be free after a stall: %+v %v", rep, err)
	}
}

func TestLinkInto(t *testing.T) {
	s := Open(t.TempDir())
	r := &fakeRemote{body: map[string][]byte{"npm": zipOf(t, "a.json", "{}")}}
	if _, err := s.Refresh(context.Background(), r, []string{"npm"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "db")
	if err := s.LinkInto(dst, []string{"npm", "PyPI"}); err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(filepath.Join(s.Dir(), "osv-scalibr", "npm", "all.zip"))
	b, err := os.Stat(filepath.Join(dst, "osv-scalibr", "npm", "all.zip"))
	if err != nil || !os.SameFile(a, b) {
		t.Fatalf("the export must be linked, not copied (err %v)", err)
	}
	if _, err := os.Stat(filepath.Join(dst, "osv-scalibr", "PyPI")); err == nil {
		t.Fatal("an ecosystem with no export is skipped")
	}
	saved := linkFile
	t.Cleanup(func() { linkFile = saved })
	linkFile = func(string, string) error { return errors.New("cross-device link") }
	if err := s.LinkInto(filepath.Join(t.TempDir(), "db2"), []string{"npm"}); err == nil {
		t.Fatal("a refused link is an error, never a copy")
	}
}
