package secdast

import (
	"errors"
	"testing"
)

func TestParseTarget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		raw     string
		want    string // Target.String(), "" for a refusal
		loopErr bool   // the refusal is ErrNotLoopback
	}{
		{raw: "http://localhost:3000", want: "http://localhost:3000/"},
		{raw: "http://LOCALHOST:3000/app?x=1#frag", want: "http://localhost:3000/app?x=1"},
		{raw: "https://127.0.0.1:8443/", want: "https://127.0.0.1:8443/"},
		{raw: "http://127.8.9.10:80/", want: "http://127.8.9.10:80/"},
		{raw: "http://[::1]:5173/", want: "http://[::1]:5173/"},
		{raw: "  http://localhost:8080/  ", want: "http://localhost:8080/"},
		// Refusals: remote, private, metadata, names that only resolve to
		// loopback, no port, wrong scheme, credentials.
		{raw: "http://example.com:80/", loopErr: true},
		{raw: "http://10.0.0.5:3000/", loopErr: true},
		{raw: "http://192.168.1.2:3000/", loopErr: true},
		{raw: "http://169.254.169.254:80/", loopErr: true},
		{raw: "http://0.0.0.0:3000/", loopErr: true},
		{raw: "http://localhost.:3000/", loopErr: true},
		{raw: "http://app.localhost:3000/", loopErr: true},
		{raw: "http://127.1:3000/", loopErr: true},
		{raw: "http://[fe80::1%25eth0]:3000/", loopErr: true},
		{raw: "http://localhost/"},
		{raw: "http://localhost:0/"},
		{raw: "http://localhost:70000/"},
		{raw: "http://localhost:08080/"},
		{raw: "ftp://localhost:21/"},
		{raw: "localhost:3000"},
		{raw: "file:///etc/passwd"},
		{raw: "http://user:pw@localhost:3000/"},
		{raw: ""},
	} {
		got, err := ParseTarget(tc.raw)
		if tc.want == "" {
			if err == nil {
				t.Errorf("%q: accepted as %s", tc.raw, got)
			} else if tc.loopErr && !errors.Is(err, ErrNotLoopback) {
				t.Errorf("%q: %v, want ErrNotLoopback", tc.raw, err)
			}
			continue
		}
		if err != nil || got.String() != tc.want {
			t.Errorf("%q: %v %v, want %s", tc.raw, got, err, tc.want)
		}
	}
}

func TestSameOrigin(t *testing.T) {
	t.Parallel()
	tg, err := ParseTarget("http://localhost:3000/app/")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		ref  string
		want string
	}{
		{"main.js", "/app/main.js"},
		{"/static/a.js?v=2", "/static/a.js?v=2"},
		{"http://localhost:3000/b.js", "/b.js"},
		{"//localhost:3000/c.js", "/c.js"},
		{"../d.js.map", "/d.js.map"},
		{"http://localhost:3001/x.js", ""},
		{"https://localhost:3000/x.js", ""},
		{"http://127.0.0.1:3000/x.js", ""},
		{"https://cdn.example.com/x.js", ""},
		{"data:application/json;base64,e30=", ""},
		{"http://localhost/x.js", ""},
	} {
		got, ok := tg.SameOrigin("/app/", tc.ref)
		if (tc.want == "") == ok || got != tc.want {
			t.Errorf("%q: %q %v, want %q", tc.ref, got, ok, tc.want)
		}
	}
}
