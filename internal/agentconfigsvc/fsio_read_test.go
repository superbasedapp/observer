package agentconfigsvc

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestReadRegularFile pins the one capped regular-file read (R-188 F7): a
// normal file is read whole, a file at the cap is read, a file past the cap
// and a FIFO are refused without blocking, a directory is refused, and a
// missing file wraps os.ErrNotExist.
func TestReadRegularFile(t *testing.T) {
	t.Parallel()
	const limit = 64
	cases := []struct {
		name    string
		setup   func(t *testing.T, path string)
		want    []byte
		wantErr string
		missing bool
	}{
		{name: "normal file", setup: writeBytes(`{"disableAllHooks":true}`), want: []byte(`{"disableAllHooks":true}`)},
		{name: "exactly the cap", setup: writeBytes(strings.Repeat("a", limit)), want: bytes.Repeat([]byte("a"), limit)},
		{name: "over the cap", setup: writeBytes(strings.Repeat("a", limit+1)), wantErr: "larger than 64 bytes"},
		{name: "fifo", setup: makeFIFO, wantErr: "not a regular file"},
		{name: "directory", setup: func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}, wantErr: "not a regular file"},
		{name: "missing", setup: func(*testing.T, string) {}, missing: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "settings.json")
			tc.setup(t, path)
			type result struct {
				b   []byte
				err error
			}
			done := make(chan result, 1)
			go func() {
				b, err := ReadRegularFile(path, limit)
				done <- result{b, err}
			}()
			var r result
			select {
			case r = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("ReadRegularFile blocked (a FIFO must be refused, not opened for a writer)")
			}
			switch {
			case tc.missing:
				if !errors.Is(r.err, os.ErrNotExist) {
					t.Fatalf("err %v, want os.ErrNotExist", r.err)
				}
			case tc.wantErr != "":
				if r.err == nil || !strings.Contains(r.err.Error(), tc.wantErr) || r.b != nil {
					t.Fatalf("got %q, %v; want error containing %q", r.b, r.err, tc.wantErr)
				}
			default:
				if r.err != nil || !bytes.Equal(r.b, tc.want) {
					t.Fatalf("got %q, %v; want %q", r.b, r.err, tc.want)
				}
			}
		})
	}
}

func writeBytes(body string) func(t *testing.T, path string) {
	return func(t *testing.T, path string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
