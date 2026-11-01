package sandboxengine

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// volumeFake answers the volume endpoints with recorded Docker Engine API
// 1.52 shapes (the field names and the 201 / 204 / 404 / 409 answers of the
// published spec; testdata/volume_*.json).
type volumeFake struct {
	mu      sync.Mutex
	created map[string]any
	query   string
	deleted []string
}

func (v *volumeFake) serve(t *testing.T) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/v1.") {
			p = p[strings.Index(p[1:], "/")+1:]
		}
		switch {
		case p == "/version":
			_, _ = io.WriteString(w, `{"Version":"29.9.2","ApiVersion":"1.52","Platform":{"Name":"Docker Engine - Community"}}`)
		case p == "/volumes/create" && r.Method == http.MethodPost:
			var b map[string]any
			_ = json.NewDecoder(r.Body).Decode(&b)
			v.mu.Lock()
			v.created = b
			v.mu.Unlock()
			w.WriteHeader(201)
			b2, _ := os.ReadFile(filepath.Join("testdata", "volume_create_docker_api1.52.json"))
			_, _ = w.Write(b2)
		case p == "/volumes" && r.Method == http.MethodGet:
			v.mu.Lock()
			v.query = r.URL.Query().Get("filters")
			v.mu.Unlock()
			b, _ := os.ReadFile(filepath.Join("testdata", "volume_list_docker_api1.52.json"))
			_, _ = w.Write(b)
		case strings.HasPrefix(p, "/volumes/") && r.Method == http.MethodDelete:
			name := strings.TrimPrefix(p, "/volumes/")
			switch name {
			case "in-use":
				w.WriteHeader(409)
				_, _ = io.WriteString(w, `{"message":"remove in-use: volume is in use - [c0ffee]"}`)
			case "gone":
				w.WriteHeader(404)
				_, _ = io.WriteString(w, `{"message":"get gone: no such volume"}`)
			default:
				v.mu.Lock()
				v.deleted = append(v.deleted, name)
				v.mu.Unlock()
				w.WriteHeader(204)
			}
		default:
			t.Errorf("unexpected %s %s", r.Method, p)
			w.WriteHeader(404)
		}
	}
}

func TestVolumeCalls(t *testing.T) {
	dir, err := os.MkdirTemp("", "sbv")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "e.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	f := &volumeFake{}
	srv := &http.Server{Handler: f.serve(t), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	c, err := New(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	}
	opts := map[string]string{"type": "none", "o": "bind", "device": "/home/dev/.observer/sandbox-oci/tool-cache/v"}
	if err := c.VolumeCreate(ctx, "observer-tool-x", map[string]string{"app.superbased.observer.role": "tool-cache"}, opts); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	created := f.created
	f.mu.Unlock()
	if created["Name"] != "observer-tool-x" || created["Driver"] != "local" {
		t.Fatalf("create body %v", created)
	}
	if do, _ := created["DriverOpts"].(map[string]any); do["o"] != "bind" || do["type"] != "none" {
		t.Fatalf("driver opts %v", created["DriverOpts"])
	}
	vols, err := c.VolumeList(ctx, map[string][]string{"label": {"app.superbased.observer.role=tool-cache"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(vols) != 2 || vols[0].Name > vols[1].Name || vols[1].Labels["app.superbased.observer.cache.version"] != "2.1.309" || vols[0].Options["o"] != "bind" {
		t.Fatalf("list %+v", vols)
	}
	f.mu.Lock()
	q := f.query
	f.mu.Unlock()
	if !strings.Contains(q, "app.superbased.observer.role=tool-cache") {
		t.Fatalf("the list filter %q", q)
	}
	if err := c.VolumeRemove(ctx, "observer-tool-x"); err != nil {
		t.Fatal(err)
	}
	if err := c.VolumeRemove(ctx, "gone"); err != nil {
		t.Fatalf("a gone volume is not an error: %v", err)
	}
	if err := c.VolumeRemove(ctx, "in-use"); err == nil || !IsConflict(err) || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("an in-use volume must refuse by name: %v", err)
	}
}
