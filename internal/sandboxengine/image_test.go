package sandboxengine

import (
	"context"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// imageFake answers the image endpoints in the published Engine API shapes:
// the pull's newline-delimited JSON progress stream (an error rides the
// stream after a 200), DELETE /images answering 200, 404 or 409, and the
// container list filtered by ancestor.
func imageFake(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sbi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/v1.") {
			p = p[strings.Index(p[1:], "/")+1:]
		}
		switch {
		case p == "/version":
			_, _ = io.WriteString(w, `{"Version":"29.9.2","ApiVersion":"1.52","Platform":{"Name":"Docker Engine - Community"}}`)
		case p == "/images/create":
			if strings.Contains(r.URL.Query().Get("fromImage"), "missing") {
				_, _ = io.WriteString(w, `{"status":"Pulling from x"}`+"\n"+`{"errorDetail":{"message":"manifest unknown"},"error":"manifest unknown"}`+"\n")
				return
			}
			_, _ = io.WriteString(w, `{"status":"Downloading","progressDetail":{"current":10,"total":200},"id":"l1"}`+"\n"+`{"status":"Pull complete","progressDetail":{},"id":"l1"}`+"\n"+`{"status":"Digest: sha256:`+strings.Repeat("a", 64)+`"}`+"\n")
		case strings.HasPrefix(p, "/images/") && r.Method == http.MethodDelete:
			switch {
			case strings.Contains(p, "inuse"):
				w.WriteHeader(409)
				_, _ = io.WriteString(w, `{"message":"conflict: unable to delete (cannot be forced) - image is being used by running container c9"}`)
			case strings.Contains(p, "gone"):
				w.WriteHeader(404)
				_, _ = io.WriteString(w, `{"message":"No such image"}`)
			default:
				if r.URL.Query().Get("force") != "0" {
					t.Errorf("a removal was forced: %s", r.URL.RawQuery)
				}
				_, _ = io.WriteString(w, `[{"Untagged":"x"},{"Deleted":"sha256:aa"}]`)
			}
		case p == "/containers/json":
			if !strings.Contains(r.URL.Query().Get("filters"), `"ancestor"`) {
				t.Errorf("no ancestor filter: %s", r.URL.RawQuery)
			}
			_, _ = io.WriteString(w, `[{"Id":"c9","State":"running","Labels":{}}]`)
		default:
			w.WriteHeader(404)
		}
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return sock
}

func TestImagePullStreamAndRemove(t *testing.T) {
	c, err := New(imageFake(t))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	}
	var evs []PullEvent
	if err := c.ImagePullStream(ctx, "x@sha256:"+strings.Repeat("a", 64), func(e PullEvent) { evs = append(evs, e) }); err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 || evs[0].Total != 200 || evs[0].ID != "l1" || !strings.HasPrefix(evs[2].Status, "Digest: ") {
		t.Fatalf("events %+v", evs)
	}
	err = c.ImagePullStream(ctx, "missing@sha256:"+strings.Repeat("b", 64), nil)
	if err == nil || !strings.Contains(err.Error(), "manifest unknown") {
		t.Fatalf("a stream error must come back: %v", err)
	}
	if err := c.ImageRemove(ctx, "x@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatal(err)
	}
	if err := c.ImageRemove(ctx, "gone@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Fatalf("a gone image is not an error: %v", err)
	}
	if err := c.ImageRemove(ctx, "inuse@sha256:"+strings.Repeat("a", 64)); err == nil || !IsConflict(err) {
		t.Fatalf("an image in use must refuse: %v", err)
	}
	ids, err := c.ContainersUsing(ctx, "x@sha256:"+strings.Repeat("a", 64))
	if err != nil || len(ids) != 1 || ids[0] != "c9" {
		t.Fatalf("containers using %v %v", ids, err)
	}
}
