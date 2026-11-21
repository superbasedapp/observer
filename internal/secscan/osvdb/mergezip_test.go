package osvdb

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

// zipOrdered builds a zip of name->body, each entry deflated (method), in the
// given order.
func zipOrdered(t *testing.T, method uint16, names []string, bodies map[string]string) *zip.Reader {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: method})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(bodies[n]))
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

func TestMergeExportZip(t *testing.T) {
	base := zipOrdered(t, zip.Store, []string{"A.json", "B.json", "C.json", "D.json"},
		map[string]string{"A.json": "a0", "B.json": "b0", "C.json": "c0", "D.json": "d0"})
	delta := zipOrdered(t, zip.Deflate, []string{"Z.json", "B.json", "E.json"},
		map[string]string{"Z.json": "z1", "B.json": "b1", "E.json": "e1"})
	var out bytes.Buffer
	st, err := MergeExportZip(base, delta, map[string]bool{"C.json": true}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Kept != 2 || st.Replaced != 1 || st.Added != 2 || st.Dropped != 1 || st.Total != 5 {
		t.Fatalf("stats %+v", st)
	}
	zr, err := zip.NewReader(bytes.NewReader(out.Bytes()), int64(out.Len()))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	if got := strings.Join(names, ","); got != "A.json,B.json,D.json,E.json,Z.json" {
		t.Fatalf("order %s", got)
	}
	got := entries(t, out.Bytes())
	want := map[string]struct {
		body   string
		method uint16
	}{
		"A.json": {"a0", zip.Store}, "B.json": {"b1", zip.Deflate}, "D.json": {"d0", zip.Store},
		"E.json": {"e1", zip.Deflate}, "Z.json": {"z1", zip.Deflate},
	}
	for n, w := range want {
		f := got[n]
		if f == nil || body(t, f) != w.body || f.Method != w.method {
			t.Errorf("%s: want %q method %d (raw copy keeps the source's method)", n, w.body, w.method)
		}
	}
	// Deterministic: the same inputs give the same bytes.
	var again bytes.Buffer
	if _, err := MergeExportZip(base, delta, map[string]bool{"C.json": true}, &again); err != nil || !bytes.Equal(again.Bytes(), out.Bytes()) {
		t.Fatalf("a second merge differs: %v", err)
	}
}

func TestMergeExportZipRefusals(t *testing.T) {
	base := zipOrdered(t, zip.Store, []string{"A.json"}, map[string]string{"A.json": "a"})
	cases := []struct {
		name  string
		delta *zip.Reader
		drop  map[string]bool
	}{
		{"nested delta name", zipOrdered(t, zip.Store, []string{"x/A.json"}, nil), nil},
		{"dot-dot delta name", zipOrdered(t, zip.Store, []string{".."}, nil), nil},
		{"repeated delta name", zipOrdered(t, zip.Store, []string{"B.json", "B.json"}, nil), nil},
		{"both delta and drop", zipOrdered(t, zip.Store, []string{"A.json"}, nil), map[string]bool{"A.json": true}},
		{"bad drop name", zipOrdered(t, zip.Store, nil, nil), map[string]bool{`..\x`: true}},
		{"no delta", nil, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out bytes.Buffer
			if _, err := MergeExportZip(base, c.delta, c.drop, &out); err == nil {
				t.Fatal("want a refusal")
			}
			if out.Len() != 0 {
				t.Fatal("a refusal must write nothing")
			}
		})
	}
}
