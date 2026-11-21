package osvdb

import (
	"archive/zip"
	"bytes"
	"io"
	"strings"
	"testing"
)

// baseExport is a synthetic export: each id a stored (uncompressed) entry,
// so a raw copy is told apart from a recompression by its method.
func baseExport(t *testing.T, ids ...string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, id := range ids {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: EntryName(id), Method: zip.Store})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write(rec(id, "base"))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
	if err != nil {
		t.Fatal(err)
	}
	return zr
}

func rec(id, v string) []byte { return []byte(`{"id":"` + id + `","v":"` + v + `"}`) }

func entries(t *testing.T, b []byte) map[string]*zip.File {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatalf("merged output is not a zip: %v", err)
	}
	out := map[string]*zip.File{}
	for _, f := range zr.File {
		out[f.Name] = f
	}
	return out
}

func body(t *testing.T, f *zip.File) string {
	t.Helper()
	r, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, _ := io.ReadAll(r)
	return string(b)
}

func TestMergeExport(t *testing.T) {
	cases := []struct {
		name    string
		replace map[string][]byte
		drop    map[string]bool
		want    MergeStats
		wantErr string
		check   func(t *testing.T, got map[string]*zip.File)
	}{
		{
			name: "unchanged entries are copied raw",
			want: MergeStats{Kept: 3, Total: 3},
			check: func(t *testing.T, got map[string]*zip.File) {
				for _, f := range got {
					if f.Method != zip.Store {
						t.Fatalf("%s was recompressed (method %d)", f.Name, f.Method)
					}
				}
			},
		},
		{
			name:    "replace",
			replace: map[string][]byte{"B-2": rec("B-2", "new")},
			want:    MergeStats{Kept: 2, Replaced: 1, Total: 3},
			check: func(t *testing.T, got map[string]*zip.File) {
				if f := got["B-2.json"]; f.Method != zip.Deflate || !strings.Contains(body(t, f), `"new"`) {
					t.Fatalf("B-2 not replaced deflated: method %d body %s", f.Method, body(t, f))
				}
				if got["A-1.json"].Method != zip.Store {
					t.Fatal("an untouched entry must stay raw")
				}
			},
		},
		{
			name:    "add",
			replace: map[string][]byte{"Z-9": rec("Z-9", "new"), "MAL-2026:1": rec("MAL-2026:1", "new")},
			want:    MergeStats{Kept: 3, Added: 2, Total: 5},
			check: func(t *testing.T, got map[string]*zip.File) {
				if got["Z-9.json"] == nil || got["MAL-2026:1.json"] == nil {
					t.Fatalf("added records missing: %v", got)
				}
			},
		},
		{
			name: "drop",
			drop: map[string]bool{"A-1": true, "NOT-THERE": true},
			want: MergeStats{Kept: 2, Dropped: 1, Total: 2},
			check: func(t *testing.T, got map[string]*zip.File) {
				if got["A-1.json"] != nil {
					t.Fatal("a dropped record must be omitted")
				}
			},
		},
		{name: "id mismatch", replace: map[string][]byte{"A-1": rec("A-2", "x")}, wantErr: "names id"},
		{name: "not json", replace: map[string][]byte{"A-1": []byte("<html>")}, wantErr: "not a JSON object"},
		{name: "path-shaped id", replace: map[string][]byte{"../x": rec("../x", "x")}, wantErr: "bad record id"},
		{name: "path-shaped drop", drop: map[string]bool{"a/b": true}, wantErr: "bad record id"},
		{name: "replaced and dropped", replace: map[string][]byte{"A-1": rec("A-1", "x")}, drop: map[string]bool{"A-1": true}, wantErr: "both replaced and dropped"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			st, err := MergeExport(baseExport(t, "A-1", "B-2", "C-3"), c.replace, c.drop, &out)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("want error %q, got %v", c.wantErr, err)
				}
				if out.Len() != 0 {
					t.Fatal("nothing may be written before the records are checked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if st != c.want {
				t.Fatalf("stats %+v, want %+v", st, c.want)
			}
			got := entries(t, out.Bytes())
			if len(got) != st.Total {
				t.Fatalf("%d entries written, stats say %d", len(got), st.Total)
			}
			if c.check != nil {
				c.check(t, got)
			}
		})
	}
}

func TestValidID(t *testing.T) {
	for id, want := range map[string]bool{
		"GHSA-wcjj-9m6g-2fr2": true, "MAL-2026-18459": true, "PYSEC-2024_1.x": true, "DEBIAN:CVE-1": true,
		"": false, ".": false, "..": false, "a/b": false, `a\b`: false, "a b": false, "a%2f": false,
		strings.Repeat("A", MaxIDLength): true, strings.Repeat("A", MaxIDLength+1): false,
	} {
		if ValidID(id) != want {
			t.Errorf("ValidID(%q) = %v, want %v", id, !want, want)
		}
	}
}
