package sandboxengine

import (
	"bufio"
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

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// fakeEngine serves recorded Engine API answers on a unix socket. It keeps
// the order of calls so a test can prove the wait was open before start.
type fakeEngine struct {
	t       *testing.T
	sock    string
	version string // testdata file for /version
	info    string // testdata file for /info

	mu      sync.Mutex
	calls   []string
	started chan struct{}
	exit    int
	creates []map[string]any
}

func newFakeEngine(t *testing.T, version, info string) *fakeEngine {
	t.Helper()
	dir, err := os.MkdirTemp("", "sbe")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &fakeEngine{t: t, sock: filepath.Join(dir, "e.sock"), version: version, info: info, started: make(chan struct{}), exit: 42}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *fakeEngine) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *fakeEngine) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *fakeEngine) file(w http.ResponseWriter, name string) {
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		f.t.Errorf("fixture %s: %v", name, err)
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(b)
}

func (f *fakeEngine) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	// Strip the version prefix the client negotiated.
	if strings.HasPrefix(p, "/v1.") {
		p = p[strings.Index(p[1:], "/")+1:]
	}
	f.record(r.Method + " " + p)
	switch {
	case p == "/_ping":
		_, _ = io.WriteString(w, "OK")
	case p == "/version":
		f.file(w, f.version)
	case p == "/info":
		f.mu.Lock()
		info := f.info
		f.mu.Unlock()
		f.file(w, info)
	case p == "/v4.0.0/libpod/info":
		f.file(w, "libpod_info_rootless.json")
	case p == "/images/present@sha256:aa/json":
		_, _ = io.WriteString(w, `{"Id":"sha256:aa","RepoDigests":["present@sha256:aa"],"Os":"linux","Architecture":"amd64"}`)
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"No such image"}`)
	case p == "/images/create":
		_, _ = io.WriteString(w, `{"status":"Pulling from library/alpine"}`+"\n"+`{"errorDetail":{"message":"dial tcp: lookup registry-1.docker.io: i/o timeout"},"error":"dial tcp: lookup registry-1.docker.io: i/o timeout"}`+"\n")
	case p == "/containers/create":
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.creates = append(f.creates, body)
		f.mu.Unlock()
		if r.URL.Query().Get("name") == "slow" {
			time.Sleep(300 * time.Millisecond)
		}
		if r.URL.Query().Get("name") == "taken" {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"message":"Conflict. The container name is already in use"}`)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Id":"c0ffee","Warnings":[]}`)
	case p == "/containers/c0ffee/wait":
		if r.URL.Query().Get("condition") != sandboxoci.WaitCondition {
			w.WriteHeader(400)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		<-f.started
		_, _ = io.WriteString(w, `{"StatusCode":`+itoa(f.exit)+`,"Error":null}`)
	case p == "/containers/c0ffee/start":
		close(f.started)
		w.WriteHeader(204)
	case p == "/containers/c0ffee/stop":
		w.WriteHeader(304)
	case p == "/containers/c0ffee/resize", p == "/containers/c0ffee/kill":
		w.WriteHeader(200)
	case p == "/containers/c0ffee" && r.Method == http.MethodDelete:
		w.WriteHeader(204)
	case p == "/containers/gone" && r.Method == http.MethodDelete:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"No such container: gone"}`)
	case p == "/containers/c0ffee/json":
		_, _ = io.WriteString(w, `{"Id":"c0ffee","State":{"Status":"running"}}`)
	case p == "/v4.0.0/libpod/containers/c0ffee/json":
		_, _ = io.WriteString(w, `{"Id":"c0ffee","OCIRuntime":"crun"}`)
	case p == "/containers/json":
		_, _ = io.WriteString(w, `[{"Id":"a1","State":"running","Labels":{"app.superbased.observer.run":"r1"}},{"Id":"b2","State":"exited","Labels":{"app.superbased.observer.run":"r2"}}]`)
	case p == "/events":
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, `{"Type":"container","Action":"die","Actor":{"ID":"b2","Attributes":{"app.superbased.observer.run":"r2"}}}`+"\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	case p == "/containers/p500/archive" && r.Method == http.MethodHead:
		// Rootless Podman 5.7.0 on a created container (live check D4).
		w.WriteHeader(500)
	case p == "/containers/c0ffee/archive" && r.Method == http.MethodHead:
		if r.URL.Query().Get("path") == "/lib64/ld-linux-x86-64.so.2" {
			w.Header().Set("X-Docker-Container-Path-Stat", "e30=")
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	case p == "/volumes/create":
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Name":"v"}`)
	case p == "/containers/c0ffee/attach":
		f.attach(w, r)
	default:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"page not found"}`)
	}
}

// attach hijacks the connection the way dockerd does and echoes input in
// upper case, so the test sees both directions.
func (f *fakeEngine) attach(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Upgrade") != "tcp" {
		w.WriteHeader(400)
		return
	}
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 UPGRADED\r\nContent-Type: application/vnd.docker.raw-stream\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\nhello$ ")
	_ = brw.Flush()
	line, err := brw.ReadString('\n')
	if err != nil {
		return
	}
	_, _ = brw.WriteString(strings.ToUpper(line))
	_ = brw.Flush()
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func newClient(t *testing.T, f *fakeEngine) *Client {
	t.Helper()
	c, err := New(f.sock)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestNegotiateRecorded drives the recorded /version answers of API 1.44
// and 1.56 and Podman 5.6's compatible API (1.41).
func TestNegotiateRecorded(t *testing.T) {
	cases := []struct {
		version, info string
		api           string
		engine        sandboxoci.Engine
		mode          sandboxoci.Mode
	}{
		{"version_docker_api1.44.json", "info_docker_rootless.json", "1.44", sandboxoci.EngineDocker, sandboxoci.ModeRootless},
		{"version_docker_api1.56.json", "info_docker_rootless.json", "1.56", sandboxoci.EngineDocker, sandboxoci.ModeRootless},
		{"version_podman_5.6.json", "info_podman_compat.json", "1.41", sandboxoci.EnginePodman, sandboxoci.ModeRootless},
	}
	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			f := newFakeEngine(t, c.version, c.info)
			cl := newClient(t, f)
			ctx := context.Background()
			if err := cl.Ping(ctx); err != nil {
				t.Fatal(err)
			}
			v, err := cl.Version(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if cl.APIVersion() != c.api {
				t.Fatalf("negotiated %s, want %s", cl.APIVersion(), c.api)
			}
			id, verdict := sandboxoci.Classify(v, sandboxoci.InfoFacts{})
			if !verdict.OK() || id.Engine != c.engine {
				t.Fatalf("classify %+v %v", id, verdict)
			}
			info, err := cl.Info(ctx, id.Engine)
			if err != nil {
				t.Fatal(err)
			}
			id, verdict = sandboxoci.Classify(v, info)
			if !verdict.OK() || id.Mode != c.mode {
				t.Fatalf("mode %+v %v", id, verdict)
			}
			if c.engine == sandboxoci.EnginePodman && !strings.Contains(strings.Join(f.callList(), ","), "GET /v4.0.0/libpod/info") {
				t.Fatal("the Podman mode was not read from libpod")
			}
			// The runtime Podman runs containers with (host.ociRuntime.name),
			// read for the known-runtime hint (Linux live check 2026-10-23).
			if c.engine == sandboxoci.EnginePodman && info.PodmanOCIRuntime != "runc" {
				t.Fatalf("Podman's runtime read as %q, want runc", info.PodmanOCIRuntime)
			}
			if c.engine != sandboxoci.EnginePodman && info.PodmanOCIRuntime != "" {
				t.Fatalf("a Docker engine carries a Podman runtime %q", info.PodmanOCIRuntime)
			}
		})
	}
}

func TestDesktopRecorded(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.44.json", "info_desktop.json")
	cl := newClient(t, f)
	v, err := cl.Version(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	info, err := cl.Info(context.Background(), sandboxoci.EngineDocker)
	if err != nil {
		t.Fatal(err)
	}
	if _, verdict := sandboxoci.Classify(v, info); verdict.Code != sandboxoci.VerdictEngineIsDesktopVM {
		t.Fatalf("Docker Desktop's WSL integration was not refused: %v", verdict)
	}
}

// TestLifecycleCalls is the wait-first order: the wait is accepted before
// start, and its status is this run's exit code.
func TestLifecycleCalls(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.56.json", "info_docker_rootless.json")
	cl := newClient(t, f)
	ctx := context.Background()
	if _, err := cl.Version(ctx); err != nil {
		t.Fatal(err)
	}
	id, _, err := cl.ContainerCreate(ctx, "observer-sbx-x", sandboxoci.CreateBody{Image: "img", Tty: true})
	if err != nil || id != "c0ffee" {
		t.Fatalf("create %q %v", id, err)
	}
	if _, _, err := cl.ContainerCreate(ctx, "taken", sandboxoci.CreateBody{}); !IsConflict(err) {
		t.Fatalf("a 409 is not a typed conflict: %v", err)
	}
	wait, err := cl.ContainerWait(ctx, id, sandboxoci.WaitCondition)
	if err != nil {
		t.Fatal(err)
	}
	if err := cl.ContainerStart(ctx, id); err != nil {
		t.Fatal(err)
	}
	select {
	case w := <-wait:
		if w.Err != nil || w.StatusCode != 42 {
			t.Fatalf("wait %+v", w)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the wait never returned")
	}
	calls := strings.Join(f.callList(), ",")
	if strings.Index(calls, "POST /containers/c0ffee/wait") > strings.Index(calls, "POST /containers/c0ffee/start") {
		t.Fatalf("start came before the wait: %s", calls)
	}
	if err := cl.ContainerResize(ctx, id, 40, 120); err != nil {
		t.Fatal(err)
	}
	if err := cl.ContainerKill(ctx, id, "SIGHUP"); err != nil {
		t.Fatal(err)
	}
	if err := cl.ContainerStop(ctx, id, 10*time.Second); err != nil {
		t.Fatalf("a 304 stop is not an error: %v", err)
	}
	if err := cl.ContainerRemove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := cl.ContainerRemove(ctx, "gone"); err != nil {
		t.Fatalf("removing a gone container is not an error: %v", err)
	}
	if b, err := cl.ContainerInspect(ctx, id); err != nil || !strings.Contains(string(b), "running") {
		t.Fatalf("inspect %s %v", b, err)
	}
	if b, err := cl.ContainerInspectLibpod(ctx, id); err != nil || !strings.Contains(string(b), "crun") {
		t.Fatalf("libpod inspect %s %v", b, err)
	}
	if err := cl.VolumeCreate(ctx, "v", map[string]string{"a": "b"}, nil); err != nil {
		t.Fatal(err)
	}
	if ok, err := cl.ContainerPathStat(ctx, id, "/lib64/ld-linux-x86-64.so.2"); err != nil || !ok {
		t.Fatalf("path stat present: %v %v", ok, err)
	}
	if ok, err := cl.ContainerPathStat(ctx, id, "/lib/ld-musl-x86_64.so.1"); err != nil || ok {
		t.Fatalf("path stat absent: %v %v", ok, err)
	}
}

func TestImagesAndPull(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.44.json", "info_docker_rootless.json")
	cl := newClient(t, f)
	ctx := context.Background()
	if _, err := cl.ImagePresent(ctx, "x"); err == nil {
		t.Fatal("a call before negotiation must fail")
	}
	if _, err := cl.Version(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := cl.ImagePresent(ctx, "present@sha256:aa"); err != nil || !ok {
		t.Fatalf("present: %v %v", ok, err)
	}
	if ok, err := cl.ImagePresent(ctx, "absent@sha256:bb"); err != nil || ok {
		t.Fatalf("absent: %v %v", ok, err)
	}
	if id, err := cl.ImageIdentity(ctx, "present@sha256:aa"); err != nil || !id.Present || id.ID != "sha256:aa" || len(id.RepoDigests) != 1 || id.OS+"/"+id.Architecture != "linux/amd64" {
		t.Fatalf("identity: %+v %v", id, err)
	}
	if id, err := cl.ImageIdentity(ctx, "absent@sha256:bb"); err != nil || id.Present {
		t.Fatalf("absent identity: %+v %v", id, err)
	}
	err := cl.ImagePull(ctx, "alpine@sha256:bb")
	if err == nil || !strings.Contains(err.Error(), "i/o timeout") {
		t.Fatalf("the pull's stream error was lost: %v", err)
	}
	if v := sandboxoci.PullFailure(sandboxoci.HostWSL2, sandboxoci.ModeRootless, err.Error()); v.Code != sandboxoci.VerdictEngineCannotPull {
		t.Fatalf("%v", v)
	}
}

func TestListAndEvents(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.44.json", "info_docker_rootless.json")
	cl := newClient(t, f)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := cl.Version(ctx); err != nil {
		t.Fatal(err)
	}
	list, err := cl.ContainerList(ctx, sandboxoci.InstallFilter("inst0000"))
	if err != nil || len(list) != 2 || !list[0].Running || list[1].Running {
		t.Fatalf("list %+v %v", list, err)
	}
	ev, err := cl.Events(ctx, sandboxoci.InstallFilter("inst0000"))
	if err != nil {
		t.Fatal(err)
	}
	select {
	case e := <-ev:
		if e.Action != "die" || e.ID != "b2" || e.Labels[sandboxoci.LabelRun] != "r2" {
			t.Fatalf("event %+v", e)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no event")
	}
	cancel()
}

// TestAttach drives the hijacked stream both ways, including the bytes the
// engine sent right after its upgrade answer.
func TestAttach(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.44.json", "info_docker_rootless.json")
	cl := newClient(t, f)
	ctx := context.Background()
	if _, err := cl.Version(ctx); err != nil {
		t.Fatal(err)
	}
	s, err := cl.ContainerAttach(ctx, "c0ffee")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Close() }()
	br := bufio.NewReader(s)
	prompt := make([]byte, len("hello$ "))
	if _, err := io.ReadFull(br, prompt); err != nil || string(prompt) != "hello$ " {
		t.Fatalf("prompt %q %v", prompt, err)
	}
	if _, err := s.Write([]byte("ls -la\n")); err != nil {
		t.Fatal(err)
	}
	line, err := br.ReadString('\n')
	if err != nil || line != "LS -LA\n" {
		t.Fatalf("echo %q %v", line, err)
	}
	if _, err := cl.ContainerAttach(ctx, "nope"); err == nil {
		t.Fatal("an attach the engine refused succeeded")
	}
}

func TestNewRefusesBadPaths(t *testing.T) {
	for _, p := range []string{"", "rel.sock", "/run/../tmp/x.sock"} {
		if _, err := New(p); err == nil {
			t.Errorf("%q accepted", p)
		}
	}
}

// TestPodmanInfoIDChangesPerCall (live checks 2026-10-22, D2): Podman 5.7's
// compatible /info answers a fresh random ID on each call (the two
// recorded answers differ only there; the ID prefixes are the live ones).
// The same daemon read twice must classify to the same fingerprint, or
// every probe after the first reads socket_untrusted.
func TestPodmanInfoIDChangesPerCall(t *testing.T) {
	f := newFakeEngine(t, "version_podman_5.6.json", "info_podman_5.7_compat_call1.json")
	c := newClient(t, f)
	ctx := context.Background()
	v, err := c.Version(ctx)
	if err != nil {
		t.Fatal(err)
	}
	read := func() (sandboxoci.InfoFacts, sandboxoci.Identity) {
		t.Helper()
		i, err := c.Info(ctx, sandboxoci.EnginePodman)
		if err != nil {
			t.Fatal(err)
		}
		id, verdict := sandboxoci.Classify(v, i)
		if !verdict.OK() {
			t.Fatal(verdict)
		}
		return i, id
	}
	i1, id1 := read()
	f.mu.Lock()
	f.info = "info_podman_5.7_compat_call2.json"
	f.mu.Unlock()
	i2, id2 := read()
	if i1.ID == i2.ID {
		t.Fatal("the two recorded answers carry the same ID")
	}
	if _, verdict := sandboxoci.CompareIdentity(id1, true, id2); !verdict.OK() {
		t.Fatalf("the same podman daemon read twice is untrusted: %v", verdict)
	}
}

// TestContainerPathStatAnswerShapes: Docker answers a created container's
// path stat with 200 or 404; rootless Podman 5.7.0 answers 500 for every
// path (live check 2026-10-22, D4). A 500 is an error IsServerError
// matches, never "absent", so the driver can fall back.
func TestContainerPathStatAnswerShapes(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.56.json", "info_docker_rootless.json")
	c := newClient(t, f)
	ctx := context.Background()
	if _, err := c.Version(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := c.ContainerPathStat(ctx, "c0ffee", "/lib64/ld-linux-x86-64.so.2"); err != nil || !ok {
		t.Fatalf("docker 200: %v %v", ok, err)
	}
	if ok, err := c.ContainerPathStat(ctx, "c0ffee", "/lib/ld-musl-x86_64.so.1"); err != nil || ok {
		t.Fatalf("docker 404: %v %v", ok, err)
	}
	ok, err := c.ContainerPathStat(ctx, "p500", "/bin/bash")
	if ok || err == nil || !IsServerError(err) || IsNotFound(err) {
		t.Fatalf("podman 500: ok %v err %v", ok, err)
	}
}

// TestInfoReadsRuntimes (lane SBX-P3B): a rootful Docker /info that
// registers runsc (`runsc install -- --host-uds=open` writes daemon.json's
// runtimes) is read with its path and runtime arguments, so the oci-runsc
// row's own probe decides the socket bridge; without --host-uds the bridge
// is refused by name. These answers are reconstructed from Docker's
// documented types.Runtime shape ("path", "runtimeArgs") and gVisor's
// install docs, not recorded from a live engine (live check owed).
func TestInfoReadsRuntimes(t *testing.T) {
	for _, tc := range []struct {
		info   string
		bridge bool
	}{
		{"info_docker_rootful_runsc.json", true},
		{"info_docker_rootful_runsc_nouds.json", false},
	} {
		t.Run(tc.info, func(t *testing.T) {
			f := newFakeEngine(t, "version_docker_api1.56.json", tc.info)
			cl := newClient(t, f)
			ctx := context.Background()
			v, err := cl.Version(ctx)
			if err != nil {
				t.Fatal(err)
			}
			info, err := cl.Info(ctx, sandboxoci.EngineDocker)
			if err != nil {
				t.Fatal(err)
			}
			rt, ok := info.Runtimes["runsc"]
			if !ok || rt.Path != "/usr/local/bin/runsc" {
				t.Fatalf("runtimes %+v", info.Runtimes)
			}
			id, verdict := sandboxoci.Classify(v, info)
			if !verdict.OK() || id.Mode != sandboxoci.ModeRootful {
				t.Fatalf("classify %+v %v", id, verdict)
			}
			p, _ := sandboxoci.RuntimeProfileFor(sandboxoci.RuntimeOCIRunsc)
			b, v2 := sandboxoci.CheckRuntime(p, id, info)
			if v2.OK() != tc.bridge {
				t.Fatalf("bridge verdict %v, want ok %v", v2, tc.bridge)
			}
			if tc.bridge && b != sandboxoci.BridgeHostUDS {
				t.Fatalf("bridge %q", b)
			}
			if !tc.bridge && v2.Code != sandboxoci.VerdictSocketBridgeUnavailable {
				t.Fatalf("verdict %v", v2)
			}
		})
	}
}

// TestCreateRunsUnderItsCallersContext (Linux live check 2026-10-23): the
// create is bounded by the caller's context, never cut short by the plain
// request timeout (a first rootless keep-id create on Podman 5.7.0 outlived
// the 30 s client timeout under the helper's 60 s budget), and a caller's
// deadline still ends it.
func TestCreateRunsUnderItsCallersContext(t *testing.T) {
	f := newFakeEngine(t, "version_docker_api1.56.json", "info_docker_rootless.json")
	cl := newClient(t, f)
	if _, err := cl.Version(context.Background()); err != nil {
		t.Fatal(err)
	}
	cl.hc.Timeout = 50 * time.Millisecond // the plain request timeout, shortened
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if id, _, err := cl.ContainerCreate(ctx, "slow", sandboxoci.CreateBody{Image: "img"}); err != nil || id != "c0ffee" {
		t.Fatalf("a slow create under a 5 s context: %q %v", id, err)
	}
	short, cancel2 := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel2()
	if _, _, err := cl.ContainerCreate(short, "slow", sandboxoci.CreateBody{Image: "img"}); err == nil {
		t.Fatal("the caller's deadline did not end the create")
	}
}
