package sandboxengine

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// cpEngine is a small recorded-answer engine for the checkpoint calls.
type cpEngine struct {
	t       *testing.T
	sock    string
	info    string
	export  []byte
	restore []byte // what the restore call received
	status  int
}

func newCPEngine(t *testing.T, info string) *cpEngine {
	t.Helper()
	dir, err := os.MkdirTemp("", "sbcp")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := &cpEngine{t: t, sock: filepath.Join(dir, "e.sock"), info: info, status: 200}
	ln, err := net.Listen("unix", e.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(e.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return e
}

func (e *cpEngine) file(w http.ResponseWriter, name string) {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		e.t.Errorf("fixture %s: %v", name, err)
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (e *cpEngine) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	switch {
	case p == "/v1.44/info":
		e.file(w, e.info)
	case p == libpodPrefix+"/info":
		e.file(w, "checkpoint_libpod_info_rootful.json")
	case strings.HasSuffix(p, "/checkpoint") && r.URL.Query().Get("export") == "true":
		if e.status != 200 {
			w.WriteHeader(e.status)
			_, _ = w.Write([]byte(`{"message":"criu not found"}`))
			return
		}
		w.Header().Set("Content-Type", "application/x-tar")
		_, _ = w.Write(e.export)
	case strings.HasSuffix(p, "/restore") && r.URL.Query().Get("import") == "true":
		if r.Header.Get("Content-Type") != "application/x-tar" {
			http.Error(w, "content type", 400)
			return
		}
		e.restore, _ = io.ReadAll(r.Body)
		e.file(w, "checkpoint_libpod_restore_import.json")
	default:
		http.NotFound(w, r)
	}
}

func (e *cpEngine) client(t *testing.T) *Client {
	t.Helper()
	c, err := New(e.sock)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.SetAPIVersion("1.44"); err != nil {
		t.Fatal(err)
	}
	return c
}

func TestRestartFacts(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	live := newCPEngine(t, "checkpoint_info_docker_liverestore.json")
	f, err := live.client(t).RestartFacts(ctx, sandboxoci.EngineDocker)
	if err != nil || !f.LiveRestore || f.ConmonPath != "" {
		t.Fatalf("docker live-restore = %+v %v", f, err)
	}
	nolive := newCPEngine(t, "checkpoint_info_docker_nolive.json")
	if f, err := nolive.client(t).RestartFacts(ctx, sandboxoci.EngineDocker); err != nil || f.LiveRestore {
		t.Fatalf("docker without live-restore = %+v %v", f, err)
	}
	if f, err := nolive.client(t).RestartFacts(ctx, sandboxoci.EnginePodman); err != nil || f.ConmonPath != "/usr/bin/conmon" {
		t.Fatalf("podman = %+v %v", f, err)
	}
}

func TestContainerOCIRuntime(t *testing.T) {
	t.Parallel()
	b, err := os.ReadFile(filepath.Join("testdata", "checkpoint_libpod_inspect_crun.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ContainerOCIRuntime(b); got != "crun" {
		t.Fatalf("runtime = %q", got)
	}
	if ContainerOCIRuntime([]byte("not json")) != "" {
		t.Fatal("garbage read as a runtime")
	}
}

func TestCheckpointExportAndCap(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	e := newCPEngine(t, "checkpoint_info_docker_nolive.json")
	e.export = bytes.Repeat([]byte("x"), 100)
	var buf bytes.Buffer
	n, err := e.client(t).ContainerCheckpointExport(ctx, "c1", &buf, 1000)
	if err != nil || n != 100 || buf.Len() != 100 {
		t.Fatalf("export = %d %v", n, err)
	}
	buf.Reset()
	if _, err := e.client(t).ContainerCheckpointExport(ctx, "c1", &buf, 50); !errors.Is(err, ErrExportCap) {
		t.Fatalf("over the cap = %v", err)
	}
	if buf.Len() > 51 {
		t.Fatalf("wrote %d bytes past a 50 byte cap", buf.Len())
	}
	e.status = 500
	if _, err := e.client(t).ContainerCheckpointExport(ctx, "c1", &buf, 50); err == nil || !strings.Contains(err.Error(), "criu not found") {
		t.Fatalf("engine refusal = %v", err)
	}
}

func TestRestoreImport(t *testing.T) {
	t.Parallel()
	e := newCPEngine(t, "checkpoint_info_docker_nolive.json")
	id, err := e.client(t).ContainerRestoreImport(context.Background(), "observer-sbx-x", strings.NewReader("TARBYTES"))
	if err != nil || !strings.HasPrefix(id, "9c8d") || string(e.restore) != "TARBYTES" {
		t.Fatalf("restore = %q %v (body %q)", id, err, e.restore)
	}
}
