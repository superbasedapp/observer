package osvnet

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFeedFetchAndStream(t *testing.T) {
	var gotUA, gotINM []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUA = append(gotUA, r.Header.Get("User-Agent"))
		gotINM = append(gotINM, r.Header.Get("If-None-Match"))
		switch r.URL.Path {
		case "/api/security/v1/content/security.osv_export/manifest.json":
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			_, _ = w.Write([]byte(`{"envelope":1}`))
		case "/api/security/v1/content/security.osv_export/npm.zip":
			_, _ = w.Write([]byte("0123456789"))
		case "/api/security/v1/content/security.osv_export/redirect.zip":
			http.Redirect(w, r, "https://example.com/x", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	c := New(Options{FeedURL: srv.URL})
	ctx := context.Background()
	kind := "security.osv_export"

	b, tag, err := c.FetchFeedFile(ctx, kind, "manifest.json", "")
	if err != nil || string(b) != `{"envelope":1}` || tag != `"v1"` {
		t.Fatalf("fetch: %q %q %v", b, tag, err)
	}
	if _, _, err := c.FetchFeedFile(ctx, kind, "manifest.json", `"v1"`); !errors.Is(err, ErrFeedNotModified) {
		t.Fatalf("a matching ETag must answer not modified: %v", err)
	}
	if _, _, err := c.FetchFeedFile(ctx, "security.agent_cve_table", "manifest.json", ""); !errors.Is(err, ErrFeedNotPublished) {
		t.Fatalf("a 404 must answer not published: %v", err)
	}
	var buf bytes.Buffer
	if err := c.StreamFeedArtifact(ctx, kind, "npm.zip", 10, &buf); err != nil || buf.String() != "0123456789" {
		t.Fatalf("stream: %q %v", buf.String(), err)
	}
	cases := []struct {
		name       string
		kind, file string
		size       int64
	}{
		{"longer than listed", kind, "npm.zip", 5},
		{"shorter than listed", kind, "npm.zip", 20},
		{"no size", kind, "npm.zip", 0},
		{"path-shaped file", kind, "../npm.zip", 10},
		{"dot-dot kind", "..", "npm.zip", 10},
		{"redirect refused", kind, "redirect.zip", 10},
	}
	for _, cs := range cases {
		buf.Reset()
		if err := c.StreamFeedArtifact(ctx, cs.kind, cs.file, cs.size, &buf); err == nil {
			t.Errorf("%s: want a refusal", cs.name)
		}
	}
	for _, ua := range gotUA {
		if ua != UserAgent {
			t.Fatalf("User-Agent %q, want %q", ua, UserAgent)
		}
	}
	_ = gotINM
}

func TestFeedHostIsHTTPSOnly(t *testing.T) {
	c := New(Options{})
	req, _ := http.NewRequest(http.MethodGet, "http://"+FeedHost+"/api/security/v1/content/x/y", nil)
	if _, err := c.HTTPClient().Do(req); err == nil {
		t.Fatal("plain http to the feed host must be refused")
	}
}
