//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// ociFake is a fake Engine API on a unix socket: it records the calls,
// keeps the created body, answers the inspect from it (so the read-back
// sees what was asked for, or a weakened copy), and runs an attach whose
// "container" echoes a line and exits with 42 on "exit".
type ociFake struct {
	t    *testing.T
	sock string
	// weaken edits the inspect answer before it is sent.
	weaken func(m map[string]any)
	// dropFirstAttach closes the first attach right after the prompt.
	dropFirstAttach bool
	// rootless selects the /info answer.
	rootless bool

	mu       sync.Mutex
	calls    []string
	body     sandboxoci.CreateBody
	running  bool
	exited   chan struct{}
	exitOnce sync.Once
	attaches int
	resizes  []string
	removed  []string
	list     []map[string]any
	// paths are the files the fake image holds (path stat answers).
	paths   map[string]bool
	creates int
	// imageEnv is the image's own Config.Env (the image inspect answer).
	imageEnv []string
	// inspect404 answers the container inspect with 404 (the container is
	// gone).
	inspect404 bool
	// pathStat500 answers every archive path stat with 500, the rootless
	// Podman 5.7.0 shape for a created container.
	pathStat500 bool
	// events, when set, feeds the event stream one line per value; the
	// value "CLOSE" ends the stream (the engine went away).
	events chan string
	// down answers the container list and the event stream with 500 (the
	// engine is restarting).
	down bool
	// nulFirst sends a NUL before the prompt, the stray byte the live
	// Docker 29.9.2 launches showed.
	nulFirst bool
	// runscArgs, when set, registers runsc in /info with these runtime
	// arguments (the oci-runsc row, lane SBX-P3B).
	runscArgs []string
	// reportRuntime overrides the runtime the inspect answer reports
	// (default: what the create asked for, else runc).
	reportRuntime string
	// createFails answers the create with 500 (the engine failed the
	// answer, which says nothing about whether it made the container).
	createFails bool
}

func newOCIFake(t *testing.T) *ociFake {
	t.Helper()
	dir, err := os.MkdirTemp("", "ocif")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &ociFake{t: t, sock: filepath.Join(dir, "e.sock"), exited: make(chan struct{}), rootless: true}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *ociFake) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *ociFake) callIndex(s string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, c := range f.calls {
		if c == s {
			return i
		}
	}
	return -1
}

func (f *ociFake) exit() {
	f.exitOnce.Do(func() {
		f.mu.Lock()
		f.running = false
		f.mu.Unlock()
		close(f.exited)
	})
}

func (f *ociFake) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/v1.") {
		p = p[strings.Index(p[1:], "/")+1:]
	}
	f.record(r.Method + " " + p)
	switch {
	case p == "/version":
		_, _ = io.WriteString(w, `{"Version":"29.9.1","ApiVersion":"1.52","Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine"}]}`)
	case p == "/info":
		opts := `["name=seccomp,profile=builtin"]`
		if f.rootless {
			opts = `["name=seccomp,profile=builtin","name=rootless"]`
		}
		runtimes := ""
		if f.runscArgs != nil {
			args, _ := json.Marshal(f.runscArgs)
			runtimes = `,"Runtimes":{"runc":{"path":"runc"},"runsc":{"path":"/usr/local/bin/runsc","runtimeArgs":` + string(args) + `}}`
		}
		_, _ = io.WriteString(w, `{"ID":"fake-daemon","Name":"box","OperatingSystem":"Ubuntu","SecurityOptions":`+opts+runtimes+`}`)
	case p == "/containers/c1/archive" && r.Method == http.MethodHead:
		f.mu.Lock()
		ok := f.paths[r.URL.Query().Get("path")]
		head500 := f.pathStat500
		f.mu.Unlock()
		if head500 {
			// Rootless Podman 5.7.0: 500 for every path of a created
			// container, with no body (live check 2026-10-22, D4).
			w.WriteHeader(500)
			return
		}
		if ok {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(404)
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		f.mu.Lock()
		env := f.imageEnv
		f.mu.Unlock()
		b, _ := json.Marshal(map[string]any{"Id": "sha256:aa", "Config": map[string]any{"Env": env}})
		_, _ = w.Write(b)
	case p == "/containers/create":
		var b sandboxoci.CreateBody
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.body = b
		f.creates++
		fails := f.createFails
		f.mu.Unlock()
		if fails {
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"message":"create failed"}`)
			return
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Id":"c1","Warnings":[]}`)
	case p == "/containers/c1/json":
		f.mu.Lock()
		gone := f.inspect404
		f.mu.Unlock()
		if gone {
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"no such container"}`)
			return
		}
		f.inspect(w)
	case p == "/containers/c1/attach":
		f.attach(w, r)
	case p == "/containers/c1/wait":
		f.mu.Lock()
		check := f.body.Entrypoint
		f.mu.Unlock()
		if len(check) > 2 && check[1] == ociPathCheckVerb {
			// The started path check: answer as the verb would, over
			// the fake image's paths.
			args := check[3:]
			found := make([]bool, len(args))
			f.mu.Lock()
			for i, a := range args {
				found[i] = f.paths[a]
			}
			f.mu.Unlock()
			w.WriteHeader(200)
			_, _ = io.WriteString(w, `{"StatusCode":`+strconv.Itoa(sandboxoci.PathCheckExit(found))+`}`)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-f.exited:
			_, _ = io.WriteString(w, `{"StatusCode":42}`)
		case <-r.Context().Done():
		}
	case p == "/containers/c1/start":
		f.mu.Lock()
		f.running = true
		f.mu.Unlock()
		w.WriteHeader(204)
	case p == "/containers/c1/resize":
		f.mu.Lock()
		f.resizes = append(f.resizes, r.URL.Query().Get("h")+"x"+r.URL.Query().Get("w"))
		f.mu.Unlock()
		w.WriteHeader(200)
	case p == "/containers/c1/stop":
		f.exit()
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/containers/") && r.Method == http.MethodDelete:
		f.mu.Lock()
		f.removed = append(f.removed, strings.TrimPrefix(p, "/containers/"))
		f.mu.Unlock()
		w.WriteHeader(204)
	case p == "/containers/json":
		f.mu.Lock()
		b, _ := json.Marshal(f.list)
		down := f.down
		f.mu.Unlock()
		if down {
			w.WriteHeader(500)
			return
		}
		_, _ = w.Write(b)
	case p == "/events":
		f.mu.Lock()
		down := f.down
		f.mu.Unlock()
		if down {
			w.WriteHeader(500)
			return
		}
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		if f.events == nil {
			<-r.Context().Done()
			return
		}
		for {
			select {
			case <-r.Context().Done():
				return
			case line := <-f.events:
				if line == "CLOSE" {
					return
				}
				_, _ = io.WriteString(w, line+"\n")
				w.(http.Flusher).Flush()
			}
		}
	default:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"not found"}`)
	}
}

// inspect answers with what the create asked for, in the engine's shape.
func (f *ociFake) inspect(w http.ResponseWriter) {
	f.mu.Lock()
	b := f.body
	running := f.running
	f.mu.Unlock()
	rt := "runc"
	if b.HostConfig.Runtime != "" {
		rt = b.HostConfig.Runtime
	}
	if f.reportRuntime != "" {
		rt = f.reportRuntime
	}
	var mounts []map[string]any
	for _, m := range b.HostConfig.Mounts {
		mounts = append(mounts, map[string]any{"Type": m.Type, "Source": m.Source, "Destination": m.Target, "RW": !m.ReadOnly})
	}
	m := map[string]any{
		"State":  map[string]any{"Status": map[bool]string{true: "running", false: "created"}[running], "Running": running, "ExitCode": 0},
		"Config": map[string]any{"User": b.User, "Labels": b.Labels},
		"HostConfig": map[string]any{
			"NetworkMode": b.HostConfig.NetworkMode, "CapDrop": b.HostConfig.CapDrop, "CapAdd": b.HostConfig.CapAdd,
			"SecurityOpt": b.HostConfig.SecurityOpt, "ReadonlyRootfs": b.HostConfig.ReadonlyRootfs, "Privileged": b.HostConfig.Privileged,
			"UsernsMode": b.HostConfig.UsernsMode, "Runtime": rt, "Tmpfs": b.HostConfig.Tmpfs,
			"PidMode": "", "IpcMode": b.HostConfig.IpcMode, "UTSMode": "", "Devices": []any{}, "PidsLimit": b.HostConfig.PidsLimit,
		},
		"Mounts": mounts,
	}
	if f.weaken != nil {
		f.weaken(m)
	}
	_ = json.NewEncoder(w).Encode(m)
}

// attach hijacks: it prints a prompt, then echoes each line; "exit" ends
// the container with 42.
func (f *ociFake) attach(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.attaches++
	n := f.attaches
	f.mu.Unlock()
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = brw.Flush()
	if n == 1 && f.dropFirstAttach {
		// Wait for the start, show the prompt, then drop the transport.
		for i := 0; i < 100; i++ {
			f.mu.Lock()
			up := f.running
			f.mu.Unlock()
			if up {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		_, _ = brw.WriteString("agent$ ")
		_ = brw.Flush()
		return
	}
	if f.nulFirst {
		_, _ = brw.WriteString("\x00")
	}
	_, _ = brw.WriteString("agent$ ")
	_ = brw.Flush()
	for {
		line, err := brw.ReadString('\n')
		if err != nil {
			return
		}
		if strings.TrimSpace(line) == "exit" {
			_, _ = brw.WriteString("bye\r\n")
			_ = brw.Flush()
			f.exit()
			return
		}
		_, _ = brw.WriteString("echo:" + line)
		_ = brw.Flush()
	}
}

// ociRunPlan is a plan file for the fake engine (rootless Docker).
func ociRunPlan(t *testing.T, f *ociFake) ociPlanFile {
	t.Helper()
	ws := t.TempDir()
	v := sandboxoci.VersionFacts{Version: "29.9.1", APIVersion: "1.52", PlatformName: "Docker Engine - Community"}
	id, _ := sandboxoci.Classify(v, sandboxoci.InfoFacts{ID: "fake-daemon", Name: "box", OperatingSystem: "Ubuntu", SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless"}})
	return ociPlanFile{
		Version: ociPlanVersion, Socket: f.sock, Engine: id.Engine, Mode: id.Mode, Fingerprint: id.Fingerprint, APIVersion: "1.52", Host: sandboxoci.HostLinux,
		Create: sandboxoci.CreatePlan{
			RunID: "run0000000000000001", InstallID: "inst000000000001",
			Image:          "alpine@sha256:" + strings.Repeat("a", 64),
			WorkDir:        ws,
			Entrypoint:     []string{"/usr/bin/observer", ociInitVerb, "--"},
			Binds:          []sandboxoci.Bind{{Source: ws, Target: ws}, {Source: "/usr/bin/observer", Target: "/usr/bin/observer", ReadOnly: true}},
			Tmpfs:          []string{"/tmp"},
			Engine:         id.Engine,
			User:           sandboxoci.UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true},
			ReadonlyRootfs: true, EngineSocket: f.sock, ObserverDir: filepath.Join(t.TempDir(), ".observer"),
		},
	}
}

// ociTestTerm is a terminal over pipes with a fixed size.
type ociTestTerm struct {
	inW  *io.PipeWriter
	out  *ociSyncBuf
	term ociTerm
	stop chan string
}

type ociSyncBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *ociSyncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *ociSyncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func newOCITestTerm() *ociTestTerm {
	r, w := io.Pipe()
	tt := &ociTestTerm{inW: w, out: &ociSyncBuf{}, stop: make(chan string, 1)}
	tt.term = ociTerm{in: r, out: tt.out, size: func() (uint16, uint16) { return 40, 120 }, resized: make(chan struct{}), stopped: tt.stop}
	return tt
}

func (tt *ociTestTerm) waitFor(t *testing.T, s string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(tt.out.String(), s) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("terminal never showed %q; it shows %q", s, tt.out.String())
}

// TestOCIRunWaitFirstAndExitStatus is milestone 2's lifecycle against the
// fake engine: the container is read back before anything starts, attached
// and waited on BEFORE start, the agent's exit status (42) is the helper's,
// the initial size reaches the engine, and the container is removed.
func TestOCIRunWaitFirstAndExitStatus(t *testing.T) {
	f := newOCIFake(t)
	tt := newOCITestTerm()
	plan := ociRunPlan(t, f)
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "claude"}, []string{"TERM=xterm"}, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	_, _ = tt.inW.Write([]byte("hello\n"))
	tt.waitFor(t, "echo:hello")
	_, _ = tt.inW.Write([]byte("exit\n"))
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit status %d, want the agent's 42 (out %q)", code, tt.out.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run never ended")
	}
	for _, pair := range [][2]string{
		{"GET /containers/c1/json", "POST /containers/c1/start"},
		{"POST /containers/c1/attach", "POST /containers/c1/start"},
		{"POST /containers/c1/wait", "POST /containers/c1/start"},
	} {
		a, b := f.callIndex(pair[0]), f.callIndex(pair[1])
		if a < 0 || b < 0 || a > b {
			t.Fatalf("%s must come before %s: %v", pair[0], pair[1], f.calls)
		}
	}
	if f.callIndex("POST /containers/c1/stop") >= 0 || f.callIndex("POST /containers/c1/kill") >= 0 {
		t.Fatalf("an exited container was stopped or signalled: %v", f.calls)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.resizes) == 0 || f.resizes[0] != "40x120" {
		t.Fatalf("the terminal size never reached the engine: %v", f.resizes)
	}
	if len(f.removed) != 1 || f.removed[0] != "c1" {
		t.Fatalf("the container was not removed: %v", f.removed)
	}
	if f.body.Entrypoint[len(f.body.Entrypoint)-1] != "claude" || f.body.HostConfig.NetworkMode != "none" {
		t.Fatalf("create body %+v", f.body)
	}
}

// TestOCIRunRefusesAWeakerBuild: a container the engine built weaker than
// planned is removed before it ever starts (built_below_plan).
func TestOCIRunRefusesAWeakerBuild(t *testing.T) {
	f := newOCIFake(t)
	f.weaken = func(m map[string]any) { m["HostConfig"].(map[string]any)["Privileged"] = true }
	tt := newOCITestTerm()
	code := driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	if code != sandboxHelperFailCode || !strings.Contains(tt.out.String(), "built_below_plan") {
		t.Fatalf("code %d out %q", code, tt.out.String())
	}
	if f.callIndex("POST /containers/c1/start") >= 0 || f.callIndex("POST /containers/c1/attach") >= 0 {
		t.Fatalf("a weaker container was attached or started: %v", f.calls)
	}
	if len(f.removed) != 1 {
		t.Fatalf("the refused container was not removed: %v", f.removed)
	}
}

// TestOCIRunRefusesAChangedDaemon is A9's third case at the helper: the
// daemon on the socket is not the one the probe recorded.
func TestOCIRunRefusesAChangedDaemon(t *testing.T) {
	f := newOCIFake(t)
	plan := ociRunPlan(t, f)
	plan.Fingerprint = "someone-else"
	tt := newOCITestTerm()
	if code := driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "claude"}, nil, tt.term); code != sandboxHelperFailCode {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(tt.out.String(), "socket_untrusted") || f.callIndex("POST /containers/create") >= 0 {
		t.Fatalf("a changed daemon was driven: %q %v", tt.out.String(), f.calls)
	}
}

// TestOCIRunReattachesAfterADroppedStream: the attach stream drops while
// the container runs; the helper re-attaches, says so, repaints with the
// two-step resize (columns minus one, then the real size) and the run goes
// on to the agent's own status.
func TestOCIRunReattachesAfterADroppedStream(t *testing.T) {
	f := newOCIFake(t)
	f.dropFirstAttach = true
	tt := newOCITestTerm()
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	}()
	tt.waitFor(t, "re-attached")
	tt.waitFor(t, "missing]\r\nagent$ ")
	_, _ = tt.inW.Write([]byte("exit\n"))
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the run never ended")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.attaches < 2 {
		t.Fatalf("attaches %d", f.attaches)
	}
	joined := strings.Join(f.resizes, ",")
	if !strings.Contains(joined, "40x119,40x120") {
		t.Fatalf("no two-step repaint after the re-attach: %v", f.resizes)
	}
}

// TestOCIRunStopRequest: closing the terminal (SIGHUP to the helper) stops
// the running container through the engine, and the status is kept.
func TestOCIRunStopRequest(t *testing.T) {
	f := newOCIFake(t)
	tt := newOCITestTerm()
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	tt.stop <- "hangup"
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit %d", code)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the stop never ended the run")
	}
	if f.callIndex("POST /containers/c1/stop") < 0 {
		t.Fatalf("no stop: %v", f.calls)
	}
}

// TestOCIReaperRemovesOnlyThisInstallsOrphans: the sweep removes this
// install's containers whose run has no record, and nothing else.
func TestOCIReaperRemovesOnlyThisInstallsOrphans(t *testing.T) {
	f := newOCIFake(t)
	obs := t.TempDir()
	live := "liverun00000001"
	f.list = []map[string]any{
		{"Id": "orphan", "State": "running", "Labels": sandboxoci.Labels("inst000000000001", "deadrun00000001")},
		{"Id": "alive", "State": "running", "Labels": sandboxoci.Labels("inst000000000001", live)},
		{"Id": "theirs", "State": "exited", "Labels": sandboxoci.Labels("otherinstall0001", "deadrun00000002")},
	}
	writeTestRunRecord(t, obs, live)
	rp := &ociReaper{}
	rp.ensure(f.sock, "1.52", "inst000000000001", obs, "")
	defer rp.stop()
	deadline := time.Now().Add(10 * time.Second)
	for rp.sweeps.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.removed, ",") != "orphan" {
		t.Fatalf("removed %v, want only this install's orphan", f.removed)
	}
}

// TestOCIContainerEnv: the box never carries engine endpoints, host socket
// variables, loader hooks or the launcher channel's descriptor and secret.
func TestOCIContainerEnv(t *testing.T) {
	env := ociContainerEnv([]string{
		"PATH=/usr/bin", "HOME=/home/dev", "TERM=xterm", "DOCKER_HOST=unix:///run/docker.sock", "SSH_AUTH_SOCK=/tmp/a",
		"LD_PRELOAD=/x.so", "NODE_OPTIONS=--require x", "XDG_RUNTIME_DIR=/run/user/1000", envOOBFD + "=3", envOOBAuth + "=secret",
		sandboxEnvMarker + "=0", "garbage",
	})
	got := strings.Join(env, " ")
	for _, bad := range []string{"DOCKER_HOST", "SSH_AUTH_SOCK", "LD_PRELOAD", "NODE_OPTIONS", "XDG_RUNTIME_DIR", envOOBFD, envOOBAuth, "garbage", sandboxEnvMarker + "=0"} {
		if strings.Contains(got, bad) {
			t.Errorf("%s reached the box: %s", bad, got)
		}
	}
	for _, good := range []string{"PATH=/usr/bin", "HOME=/home/dev", "TERM=xterm", sandboxEnvMarker + "=1"} {
		if !strings.Contains(got, good) {
			t.Errorf("%s missing: %s", good, got)
		}
	}
}

// writeTestRunRecord writes a minimal relay run record under obs.
func writeTestRunRecord(t *testing.T, obs, runID string) {
	t.Helper()
	ws := t.TempDir()
	rec, err := sandboxrelayd.NewRunRecord(sandboxrelayd.RunRecord{RunID: runID, Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}, Delivery: sandboxrelayd.DeliveryLive})
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
}

// TestOCIInitPID1Contract is the PID 1 contract of section 4.6 (JSP-4),
// with the test binary standing in for the container's entrypoint: the
// agent runs in its own process group (never a new session) which is the
// terminal's foreground, Ctrl-C reaches the agent and not the init, an
// orphan the agent leaves is reaped (no zombie), and the init exits with
// the agent's status.
func TestOCIInitPID1Contract(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Skipf("no pty: %v", err)
	}
	defer func() { _ = ptmx.Close() }()
	script := `trap 'echo GOT_INT; exit 42' INT; (sleep 0.2 &); echo READY; while true; do sleep 0.1; done`
	cmd := exec.Command(os.Args[0], ociInitVerb, "--", "/bin/sh", "-c", script)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = tty, tty, tty
	// The engine makes the TTY the main process's controlling terminal in
	// a new session; do the same.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	_ = tty.Close()
	out := &ociSyncBuf{}
	go func() { _, _ = io.Copy(out, ptmx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "READY") {
		if time.Now().After(deadline) {
			_ = cmd.Process.Kill()
			t.Fatalf("the agent never started: %q", out.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	initPID := cmd.Process.Pid
	agent := ociChildOf(t, initPID)
	// The init ignores SIGTTOU and SIGTTIN itself (it is in the background
	// group of its own terminal), set after the start so the agent does not
	// inherit the ignore (SBX-P3A merge finding F9).
	for _, sig := range []syscall.Signal{syscall.SIGTTOU, syscall.SIGTTIN} {
		if !ociSigIgnored(t, initPID, sig) {
			t.Fatalf("the init does not ignore %v", sig)
		}
	}
	initStat, agentStat := ociProcStat(t, initPID), ociProcStat(t, agent)
	t.Logf("init %d %+v, agent %d %+v, children %s", initPID, initStat, agent, agentStat, ociChildrenRaw(initPID))
	if agentStat.pgrp != agent || agentStat.session != initStat.session {
		t.Fatalf("agent pgrp %d session %d, init session %d: want its own group in the init's session (setpgid, never setsid)", agentStat.pgrp, agentStat.session, initStat.session)
	}
	if agentStat.tpgid != agentStat.pgrp {
		t.Fatalf("terminal foreground group %d, agent group %d", agentStat.tpgid, agentStat.pgrp)
	}
	if initStat.pgrp == agentStat.pgrp {
		t.Fatal("the init shares the agent's group, so it would get Ctrl-C")
	}
	time.Sleep(500 * time.Millisecond)
	if z := ociZombiesOf(initPID); z > 0 {
		t.Fatalf("%d zombie children of the init", z)
	}
	if _, err := ptmx.Write([]byte{3}); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	var code int
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if code != 42 || !strings.Contains(out.String(), "GOT_INT") {
		t.Fatalf("exit %d, output %q: Ctrl-C must reach the agent and its status be the init's", code, out.String())
	}
}

type ociStat struct{ pgrp, session, tpgid int }

func ociProcStat(t *testing.T, pid int) ociStat {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+2:]))
	var s ociStat
	_, _ = fmt.Sscan(f[2], &s.pgrp)
	_, _ = fmt.Sscan(f[3], &s.session)
	_, _ = fmt.Sscan(f[5], &s.tpgid)
	return s
}

func ociChildOf(t *testing.T, pid int) int {
	t.Helper()
	// Children are listed per thread; the inner launch is the oldest one
	// (orphans reparented to the init later are younger).
	child := 0
	for _, f := range strings.Fields(ociChildrenRaw(pid)) {
		var c int
		if _, err := fmt.Sscan(f, &c); err == nil && (child == 0 || c < child) {
			child = c
		}
	}
	if child == 0 {
		t.Fatalf("no child of %d", pid)
	}
	return child
}

func ociZombiesOf(pid int) int {
	entries, _ := os.ReadDir("/proc")
	n := 0
	for _, e := range entries {
		b, err := os.ReadFile(filepath.Join("/proc", e.Name(), "stat"))
		if err != nil {
			continue
		}
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+2:])
		if len(f) > 1 && f[0] == "Z" && f[1] == fmt.Sprint(pid) {
			n++
		}
	}
	return n
}

func ociChildrenRaw(pid int) string {
	tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
	var out []string
	for _, p := range tasks {
		b, _ := os.ReadFile(p)
		out = append(out, strings.TrimSpace(string(b)))
	}
	return strings.Join(out, " ")
}

// TestOCIToolFactsAsksTheImage: a dynamically linked host tool is bound
// only when the image holds its loader, asked through the engine's path
// stat of a created container that never starts and is removed; the answer
// is cached per image and loader.
func TestOCIToolFactsAsksTheImage(t *testing.T) {
	ls, err := filepath.EvalSymlinks("/bin/ls")
	if err != nil {
		t.Skip("no /bin/ls")
	}
	fh, err := os.Open(ls)
	if err != nil {
		t.Skip(err)
	}
	interp, err := sandboxoci.ELFInterp(fh)
	_ = fh.Close()
	if err != nil || interp == "" {
		t.Skip("/bin/ls is not a dynamically linked ELF here")
	}
	f := newOCIFake(t)
	cfg := ociTestConfig(t, true, "oci-runc")
	cfg.Launch.Tools = map[string]config.LaunchToolConfig{"claude-code": {Path: ls}}
	rt := ociTestRuntime(t, cfg)
	rt.launchTools = cfg.Launch.Tools
	d := rt.drivers[sandboxbackend.BackendOCIRunc].(*ociDriver)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	image := "img@sha256:" + strings.Repeat("b", 64)
	// A musl-like image: no glibc loader, so the tool is refused.
	facts, err := d.toolFacts(context.Background(), c, "inst000000000001", image, "claude-code", "0:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if facts.Interp != interp || facts.ImageHasInterp {
		t.Fatalf("facts %+v", facts)
	}
	if _, v := sandboxoci.PlanToolDelivery(facts); v.Code != sandboxoci.VerdictToolUnavailable {
		t.Fatalf("an image without the loader was accepted: %v", v)
	}
	if f.callIndex("POST /containers/c1/start") >= 0 {
		t.Fatal("the probe container was started")
	}
	if len(f.removed) != 1 {
		t.Fatalf("the probe container was not removed: %v", f.removed)
	}
	// A glibc image: bound.
	f.mu.Lock()
	f.paths = map[string]bool{interp: true}
	f.mu.Unlock()
	image2 := "img@sha256:" + strings.Repeat("c", 64)
	facts, err = d.toolFacts(context.Background(), c, "inst000000000001", image2, "claude-code", "0:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got, v := sandboxoci.PlanToolDelivery(facts); !v.OK() || got != sandboxoci.DeliveryHostBind {
		t.Fatalf("%v %v", got, v)
	}
	before := f.creates
	if _, err := d.toolFacts(context.Background(), c, "inst000000000001", image2, "claude-code", "0:0", nil); err != nil {
		t.Fatal(err)
	}
	if f.creates != before {
		t.Fatal("the loader answer was not cached")
	}
}

// TestOCIToolFactsFollowsAScript: a tool that is a #! script is judged by
// the interpreter it names.
func TestOCIToolFactsFollowsAScript(t *testing.T) {
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	script := filepath.Join(dir, "tool")
	if err := os.WriteFile(script, []byte("#!/usr/bin/env sh\necho hi\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := ociTestConfig(t, true, "oci-runc")
	rt := ociTestRuntime(t, cfg)
	prog, _, ok := rt.hostLoader("claude-code", script)
	if !ok || !strings.HasSuffix(filepath.Base(prog), "sh") && !strings.Contains(prog, "dash") && !strings.Contains(prog, "bash") && !strings.Contains(prog, "busybox") {
		t.Fatalf("prog %q ok %v", prog, ok)
	}
}

// TestParseOCIHostArgs: the helper takes the plan, the host services and
// the inner launch from its argv, and refuses anything else.
func TestParseOCIHostArgs(t *testing.T) {
	good := []string{"--plan", "/p.json", "--", "/o", sandbox.HostVerb, "--sock-dir", "/tmp/observer-sbx-r1", "--relay-run", "r1", "--observer-dir", "/home/u/.observer", "--", ociInnerMarker, "/o", "claude", "--resume"}
	plan, h, err := parseOCIHostArgs(good)
	if err != nil || plan != "/p.json" || strings.Join(h.Command, " ") != "/o claude --resume" || h.RelayRun != "r1" {
		t.Fatalf("%q %+v %v", plan, h, err)
	}
	for _, bad := range [][]string{
		{"--plan", "/p.json"},
		{"--plan", "/p.json", "--", "/o", "sandbox-guest", "--"},
		{"--plan", "/p.json", "--", "/o", sandbox.HostVerb, "--sock-dir", "/tmp/x", "--", "/o", "claude"},
		{"--plan", "/p.json", "--", "/o", sandbox.HostVerb, "--sock-dir", "/tmp/x", "--", ociInnerMarker},
	} {
		if _, _, err := parseOCIHostArgs(bad); err == nil {
			t.Errorf("%v parsed", bad)
		}
	}
}

// ociSigIgnored reads whether pid ignores sig (/proc/<pid>/status SigIgn).
func ociSigIgnored(t *testing.T, pid int, sig syscall.Signal) bool {
	t.Helper()
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "SigIgn:"); ok {
			var mask uint64
			if _, err := fmt.Sscanf(strings.TrimSpace(v), "%x", &mask); err != nil {
				t.Fatal(err)
			}
			return mask&(1<<(uint(sig)-1)) != 0
		}
	}
	t.Fatal("no SigIgn line")
	return false
}

// TestOCIRunRefusesAnImageThatSetsRoutingEnv (SBX-P3A merge finding F2): the
// image's own Config.Env is merged under the box's environment, so an image
// that sets a base URL, a proxy, a loader or a git variable is refused
// before anything is created, naming each one.
func TestOCIRunRefusesAnImageThatSetsRoutingEnv(t *testing.T) {
	f := newOCIFake(t)
	bad := []string{"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "LD_PRELOAD", "LD_LIBRARY_PATH", "NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "GIT_SSH_COMMAND", "TOOL_BASE_URL"}
	f.imageEnv = []string{"PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8"}
	for _, k := range bad {
		f.imageEnv = append(f.imageEnv, k+"=http://attacker.example")
	}
	tt := newOCITestTerm()
	code := driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, []string{"TERM=xterm"}, tt.term)
	if code != sandboxHelperFailCode || !strings.Contains(tt.out.String(), "built_below_plan") {
		t.Fatalf("code %d out %q", code, tt.out.String())
	}
	for _, k := range bad {
		if !strings.Contains(tt.out.String(), k) {
			t.Errorf("the refusal does not name %s: %q", k, tt.out.String())
		}
	}
	if f.callIndex("POST /containers/create") >= 0 {
		t.Fatalf("a container was created for a refused image: %v", f.calls)
	}
	// The same image without them runs.
	f2 := newOCIFake(t)
	f2.imageEnv = []string{"PATH=/usr/bin", "LANG=C.UTF-8"}
	tt2 := newOCITestTerm()
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), ociRunPlan(t, f2), []string{"/usr/bin/observer", "claude"}, nil, tt2.term)
	}()
	tt2.waitFor(t, "agent$ ")
	_, _ = tt2.inW.Write([]byte("exit\n"))
	if code := <-done; code != 42 {
		t.Fatalf("an ordinary image did not run: %d %q", code, tt2.out.String())
	}
}

// TestOCIRunRefusesAHostPidNamespace (SBX-P3A merge finding F3): a container
// the engine built in the host's pid namespace (a containers.conf
// pidns="host" default) is removed before it starts.
func TestOCIRunRefusesAHostPidNamespace(t *testing.T) {
	for _, tc := range []struct {
		key, val, rule string
	}{{"PidMode", "host", "pid namespace"}, {"IpcMode", "host", "ipc namespace"}, {"UTSMode", "host", "uts namespace"}} {
		t.Run(tc.key, func(t *testing.T) {
			f := newOCIFake(t)
			f.weaken = func(m map[string]any) { m["HostConfig"].(map[string]any)[tc.key] = tc.val }
			tt := newOCITestTerm()
			code := driveOCIRun(context.Background(), ociRunPlan(t, f), []string{"/usr/bin/observer", "claude"}, nil, tt.term)
			if code != sandboxHelperFailCode || !strings.Contains(tt.out.String(), "built_below_plan: "+tc.rule) {
				t.Fatalf("code %d out %q", code, tt.out.String())
			}
			if f.callIndex("POST /containers/c1/start") >= 0 {
				t.Fatalf("a weaker container was started: %v", f.calls)
			}
		})
	}
}

// TestOCIReaperFollowsTheEventStream (SBX-P3A merge findings F5 and F9): the
// sweep runs again on each burst of this install's events, removes the
// orphan that appeared, and never removes the loader probe container (its
// own role), which a create event would otherwise sweep mid-check.
func TestOCIReaperFollowsTheEventStream(t *testing.T) {
	f := newOCIFake(t)
	f.events = make(chan string, 4)
	obs := t.TempDir()
	live := "liverun00000003"
	writeTestRunRecord(t, obs, live)
	probe := map[string]any{"Id": "probe", "State": "created", "Labels": sandboxoci.ProbeLabels("inst000000000001", "abiprobe0000000001")}
	f.list = []map[string]any{probe, {"Id": "alive", "State": "running", "Labels": sandboxoci.Labels("inst000000000001", live)}}
	rp := &ociReaper{}
	rp.ensure(f.sock, "1.52", "inst000000000001", obs, "")
	defer rp.stop()
	waitSweeps := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for rp.sweeps.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("sweeps %d, want %d", rp.sweeps.Load(), n)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitSweeps(1)
	f.mu.Lock()
	if len(f.removed) != 0 {
		f.mu.Unlock()
		t.Fatalf("the first sweep removed %v (the probe or a live run)", f.removed)
	}
	f.list = append(f.list, map[string]any{"Id": "orphan", "State": "exited", "Labels": sandboxoci.Labels("inst000000000001", "deadrun00000003")})
	f.mu.Unlock()
	f.events <- `{"Type":"container","Action":"die","Actor":{"ID":"orphan","Attributes":{"app.superbased.observer.install":"inst000000000001"}}}`
	waitSweeps(2)
	f.mu.Lock()
	defer f.mu.Unlock()
	if strings.Join(f.removed, ",") != "orphan" {
		t.Fatalf("removed %v, want only the orphan the event announced (never the probe)", f.removed)
	}
}

// TestOCIToolFactsProbeAnswerIsBounded (SBX-P3A merge finding F5): the
// probe container carries its own role; an answer whose probe container went
// away during the check is not kept; a "no loader" answer is reused only for
// ociABINegativeTTL, then asked again.
func TestOCIToolFactsProbeAnswerIsBounded(t *testing.T) {
	ls, err := filepath.EvalSymlinks("/bin/ls")
	if err != nil {
		t.Skip("no /bin/ls")
	}
	fh, err := os.Open(ls)
	if err != nil {
		t.Skip(err)
	}
	interp, err := sandboxoci.ELFInterp(fh)
	_ = fh.Close()
	if err != nil || interp == "" {
		t.Skip("/bin/ls is not a dynamically linked ELF here")
	}
	now := time.Now()
	prevNow, prevTTL := ociABINow, ociABINegativeTTL
	ociABINow = func() time.Time { return now }
	ociABINegativeTTL = time.Minute
	t.Cleanup(func() { ociABINow, ociABINegativeTTL = prevNow, prevTTL })

	f := newOCIFake(t)
	cfg := ociTestConfig(t, true, "oci-runc")
	cfg.Launch.Tools = map[string]config.LaunchToolConfig{"claude-code": {Path: ls}}
	rt := ociTestRuntime(t, cfg)
	rt.launchTools = cfg.Launch.Tools
	d := rt.drivers[sandboxbackend.BackendOCIRunc].(*ociDriver)
	c, err := ociEngineClient(f.sock, "1.52")
	if err != nil {
		t.Fatal(err)
	}
	image := "img@sha256:" + strings.Repeat("9", 64)
	f.mu.Lock()
	f.inspect404 = true
	f.mu.Unlock()
	if _, err := d.toolFacts(context.Background(), c, "inst000000000001", image, "claude-code", "0:0", nil); err == nil || !strings.Contains(err.Error(), "went away") {
		t.Fatalf("a vanished probe gave an answer: %v", err)
	}
	f.mu.Lock()
	if f.body.Labels[sandboxoci.LabelRole] != sandboxoci.RoleABIProbe {
		t.Errorf("the probe container's role is %q, want %q", f.body.Labels[sandboxoci.LabelRole], sandboxoci.RoleABIProbe)
	}
	f.inspect404 = false
	before := f.creates
	f.mu.Unlock()
	facts, err := d.toolFacts(context.Background(), c, "inst000000000001", image, "claude-code", "0:0", nil)
	if err != nil || facts.ImageHasInterp {
		t.Fatalf("facts %+v err %v", facts, err)
	}
	if f.creates != before+1 {
		t.Fatal("the vanished probe's answer was kept")
	}
	if _, err := d.toolFacts(context.Background(), c, "inst000000000001", image, "claude-code", "0:0", nil); err != nil || f.creates != before+1 {
		t.Fatalf("a fresh no-loader answer was not reused: creates %d err %v", f.creates, err)
	}
	now = now.Add(2 * time.Minute)
	if _, err := d.toolFacts(context.Background(), c, "inst000000000001", image, "claude-code", "0:0", nil); err != nil || f.creates != before+2 {
		t.Fatalf("a stale no-loader answer was kept as final: creates %d err %v", f.creates, err)
	}
}

// TestOCIToolFactsFallsBackToAStartedCheck (live check 2026-10-22, D4):
// rootless Podman 5.7.0 answers 500 for every archive path stat of a
// created, never-started container. The driver then asks through a started
// probe container that runs only Observer's own binary (bound read-only),
// with no network, no capabilities, no new privileges and a read-only
// root; its exit code carries the answer. Docker's shape (200 or 404 on a
// created container) never starts anything (TestOCIToolFactsAsksTheImage).
func TestOCIToolFactsFallsBackToAStartedCheck(t *testing.T) {
	ls, err := filepath.EvalSymlinks("/bin/ls")
	if err != nil {
		t.Skip("no /bin/ls")
	}
	fh, err := os.Open(ls)
	if err != nil {
		t.Skip(err)
	}
	interp, err := sandboxoci.ELFInterp(fh)
	_ = fh.Close()
	if err != nil || interp == "" {
		t.Skip("/bin/ls is not a dynamically linked ELF here")
	}
	for _, tc := range []struct {
		name   string
		paths  map[string]bool
		interp bool
	}{{"glibc image", map[string]bool{interp: true}, true}, {"musl-like image", map[string]bool{}, false}} {
		t.Run(tc.name, func(t *testing.T) {
			f := newOCIFake(t)
			f.pathStat500 = true
			f.paths = tc.paths
			cfg := ociTestConfig(t, true, "oci-runc")
			cfg.Launch.Tools = map[string]config.LaunchToolConfig{"claude-code": {Path: ls}}
			rt := ociTestRuntime(t, cfg)
			rt.launchTools = cfg.Launch.Tools
			d := rt.drivers[sandboxbackend.BackendOCIRunc].(*ociDriver)
			c, err := ociEngineClient(f.sock, "1.41")
			if err != nil {
				t.Fatal(err)
			}
			image := "img@sha256:" + strings.Repeat(map[bool]string{true: "d", false: "e"}[tc.interp], 64)
			facts, err := d.toolFacts(context.Background(), c, "inst000000000001", image, "claude-code", "0:0", nil)
			if err != nil {
				t.Fatal(err)
			}
			if facts.ImageHasInterp != tc.interp {
				t.Fatalf("facts %+v, want the loader %v", facts, tc.interp)
			}
			f.mu.Lock()
			body := f.body
			removed := append([]string(nil), f.removed...)
			f.mu.Unlock()
			if f.callIndex("POST /containers/c1/start") < 0 {
				t.Fatal("the started check did not run")
			}
			if len(body.Entrypoint) < 4 || body.Entrypoint[0] != rt.observerBin || body.Entrypoint[1] != ociPathCheckVerb || body.Entrypoint[3] != interp {
				t.Fatalf("the started check runs %v, want only Observer's own binary", body.Entrypoint)
			}
			h := body.HostConfig
			if h.NetworkMode != sandboxoci.NetworkNone || len(h.CapDrop) != 1 || h.CapDrop[0] != sandboxoci.CapAll || !h.ReadonlyRootfs || h.Privileged ||
				len(h.SecurityOpt) != 1 || h.SecurityOpt[0] != sandboxoci.NoNewPrivileges || len(h.Devices) != 0 {
				t.Fatalf("the started check's container is not hardened: %+v", h)
			}
			if len(h.Mounts) != 1 || h.Mounts[0].Source != rt.observerBin || !h.Mounts[0].ReadOnly {
				t.Fatalf("the started check binds %+v, want only the observer binary, read-only", h.Mounts)
			}
			if body.Labels[sandboxoci.LabelRole] != sandboxoci.RoleABIProbe || body.User != "0:0" {
				t.Fatalf("labels %v user %q", body.Labels, body.User)
			}
			if len(removed) != 2 {
				t.Fatalf("removed %v, want both probe containers", removed)
			}
		})
	}
}

// TestOCIPathCheckVerb: the verb inside the probe container only stats its
// paths and answers in the check's range; a bad argv is outside it.
func TestOCIPathCheckVerb(t *testing.T) {
	dir := t.TempDir()
	have := filepath.Join(dir, "have")
	if err := os.WriteFile(have, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code := runOCIPathCheck([]string{"--", have, filepath.Join(dir, "missing")})
	got, err := sandboxoci.DecodePathCheckExit(code, 2)
	if err != nil || !got[0] || got[1] {
		t.Fatalf("exit %d decoded %v %v", code, got, err)
	}
	if _, err := sandboxoci.DecodePathCheckExit(runOCIPathCheck([]string{"--"}), 1); err == nil {
		t.Fatal("an empty path list answered")
	}
}

// waitOCIRemoved waits until the fake engine removed want.
func waitOCIRemoved(t *testing.T, f *ociFake, want string, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		got := strings.Join(f.removed, ",")
		f.mu.Unlock()
		if got == want {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t.Fatalf("removed %v, want %s", f.removed, want)
}

// TestOCIReaperPeriodicSweepRemovesABoxWhoseHelperDied (live check
// 2026-10-22, D6 (a)): the helper and the launcher are SIGKILLed while the
// daemon lives, so no engine event arrives; the periodic sweep (while a run
// is recorded) prunes the dead helper's record, hands it to the run ender
// (D7) and removes the box within one period.
func TestOCIReaperPeriodicSweepRemovesABoxWhoseHelperDied(t *testing.T) {
	f := newOCIFake(t)
	obs := t.TempDir()
	run := "killedrun0000001"
	writeTestRunRecord(t, obs, run)
	f.list = []map[string]any{{"Id": "box", "State": "running", "Labels": sandboxoci.Labels("inst000000000001", run)}}
	var mu sync.Mutex
	var ended []string
	ender := func(rec sandboxrelayd.RunRecord) { mu.Lock(); ended = append(ended, rec.RunID); mu.Unlock() }
	prev := relayGoneRunEnder.Swap(&ender)
	defer relayGoneRunEnder.Store(prev)
	rp := &ociReaper{every: 100 * time.Millisecond}
	rp.ensure(f.sock, "1.52", "inst000000000001", obs, "")
	defer rp.stop()
	deadline := time.Now().Add(10 * time.Second)
	for rp.sweeps.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	early := len(f.removed)
	f.mu.Unlock()
	if early != 0 {
		t.Fatal("the box of a live run was removed")
	}
	// SIGKILL: the helper's liveness lock file stays, held by nobody.
	if err := os.WriteFile(filepath.Join(sandboxrelayd.RunsDir(obs), run+".alive"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	waitOCIRemoved(t, f, "box", 5*time.Second)
	mu.Lock()
	defer mu.Unlock()
	if strings.Join(ended, ",") != run {
		t.Fatalf("the run ender saw %v, want %s", ended, run)
	}
}

// TestOCIReaperIdleWithNothingRecorded: with no run recorded and no box
// seen, the periodic tick does not sweep (an idle install costs nothing).
func TestOCIReaperIdleWithNothingRecorded(t *testing.T) {
	f := newOCIFake(t)
	obs := t.TempDir()
	rp := &ociReaper{every: 20 * time.Millisecond}
	rp.ensure(f.sock, "1.52", "inst000000000001", obs, "")
	defer rp.stop()
	deadline := time.Now().Add(10 * time.Second)
	for rp.sweeps.Load() < 1 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if n := rp.sweeps.Load(); n != 1 {
		t.Fatalf("an idle install swept %d times, want only the start sweep", n)
	}
}

// TestOCIReaperSweepsAfterTheStreamReconnects (live check 2026-10-22,
// D6 (b)): the engine restarts, so the event stream ends and the stream-end
// sweep runs while the engine is down (the list fails); the box of the run
// that ended meanwhile is removed by the sweep after the stream reconnects,
// not left for some later event. The periodic tick is out of the way.
func TestOCIReaperSweepsAfterTheStreamReconnects(t *testing.T) {
	f := newOCIFake(t)
	f.events = make(chan string, 4)
	obs := t.TempDir()
	rp := &ociReaper{every: time.Hour}
	rp.ensure(f.sock, "1.52", "inst000000000001", obs, "")
	defer rp.stop()
	waitN := func(n int64) {
		t.Helper()
		deadline := time.Now().Add(15 * time.Second)
		for rp.sweeps.Load() < n {
			if time.Now().After(deadline) {
				t.Fatalf("sweeps %d, want %d", rp.sweeps.Load(), n)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitN(1)
	f.mu.Lock()
	f.down = true
	f.list = []map[string]any{{"Id": "ended", "State": "exited", "Labels": sandboxoci.Labels("inst000000000001", "endedrun00000001")}}
	f.mu.Unlock()
	f.events <- "CLOSE"
	waitN(2)
	f.mu.Lock()
	removedWhileDown := len(f.removed)
	f.down = false
	f.mu.Unlock()
	if removedWhileDown != 0 {
		t.Fatal("a box was removed while the engine was down")
	}
	waitOCIRemoved(t, f, "ended", 10*time.Second)
}

// TestRelayGoneRunEndEndsOnlyAKilledCLIRun (live check 2026-10-22, D7): a
// dead helper's run is ended with process_gone only when it is a sandboxed
// CLI launch (its CLI left its watch marker); the stale marker goes; a
// dashboard run (no marker) and an unbound record are left alone.
func TestRelayGoneRunEndEndsOnlyAKilledCLIRun(t *testing.T) {
	obs := t.TempDir()
	var got []string
	end := func(_ context.Context, runID, reason string) (bool, error) {
		got = append(got, runID+":"+reason)
		return true, nil
	}
	onGone := relayGoneRunEnd(obs, end, nil)
	watch, _ := sandboxCLIEndPaths(obs, "clirun0001")
	if err := os.MkdirAll(filepath.Dir(watch), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(watch, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	onGone(sandboxrelayd.RunRecord{RunID: "relay1", TerminalRunID: "clirun0001"})
	onGone(sandboxrelayd.RunRecord{RunID: "relay2", TerminalRunID: "dashrun0001"})
	onGone(sandboxrelayd.RunRecord{RunID: "relay3"})
	if strings.Join(got, ",") != "clirun0001:"+store.EndReasonProcessGone {
		t.Fatalf("ended %v", got)
	}
	if _, err := os.Stat(watch); !os.IsNotExist(err) {
		t.Fatalf("the stale watch marker stayed: %v", err)
	}
	// Once: the marker is gone, so a second sweep does not end it again.
	onGone(sandboxrelayd.RunRecord{RunID: "relay1", TerminalRunID: "clirun0001"})
	if len(got) != 1 {
		t.Fatalf("ended again: %v", got)
	}
}

// TestOCIRunOutputHoldsNoNUL (live check 2026-10-22, cosmetic): a NUL in
// the container's output stream never reaches the helper's terminal; the
// rest of the output is unchanged.
func TestOCIRunOutputHoldsNoNUL(t *testing.T) {
	f := newOCIFake(t)
	f.nulFirst = true
	tt := newOCITestTerm()
	plan := ociRunPlan(t, f)
	done := make(chan int, 1)
	go func() {
		done <- driveOCIRun(context.Background(), plan, []string{"/usr/bin/observer", "claude"}, []string{"TERM=xterm"}, tt.term)
	}()
	tt.waitFor(t, "agent$ ")
	_, _ = tt.inW.Write([]byte("exit\n"))
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("the run never ended")
	}
	out := tt.out.String()
	if strings.ContainsRune(out, 0) {
		t.Fatalf("the launch output holds a NUL: %q", out)
	}
	if !strings.Contains(out, "agent$ ") || !strings.Contains(out, "bye") {
		t.Fatalf("output %q", out)
	}
}

// TestOCINoNULWriter: NUL bytes are dropped wherever they sit, the write
// reports the whole input, and a write that is all NUL writes nothing.
func TestOCINoNULWriter(t *testing.T) {
	var b strings.Builder
	w := ociNoNUL{w: &b}
	for _, in := range []string{"\x00observer claude: routing via x\r\n", "a\x00b", "\x00\x00", "plain"} {
		if n, err := w.Write([]byte(in)); err != nil || n != len(in) {
			t.Fatalf("Write(%q) = %d, %v", in, n, err)
		}
	}
	if got := b.String(); got != "observer claude: routing via x\r\nabplain" {
		t.Fatalf("got %q", got)
	}
}
