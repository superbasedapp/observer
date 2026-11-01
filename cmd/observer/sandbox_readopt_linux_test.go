//go:build linux && !sbo_omit_terminals_sandbox_oci_readopt && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxadopt"
	"github.com/marmutapp/superbased-observer/internal/sandboxengine"
	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
	"github.com/marmutapp/superbased-observer/internal/sandboxrelayd"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// raFake is a fake Engine API for re-adoption: rootful Docker (with or
// without live-restore) or rootful Podman with conmon, one or more labelled
// running containers, attach with an echoing agent, wait, stop, remove,
// and libpod's checkpoint export and restore import.
type raFake struct {
	t           *testing.T
	sock        string
	podman      bool
	liveRestore bool
	network     string // the NetworkMode inspect answers ("" = the plan's)

	mu       sync.Mutex
	calls    []string
	bodies   map[string]sandboxoci.CreateBody
	running  map[string]bool
	exited   map[string]chan struct{}
	removed  []string
	export   []byte
	restored []byte
}

func newRAFake(t *testing.T) *raFake {
	t.Helper()
	dir, err := os.MkdirTemp("", "raf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &raFake{
		t: t, sock: filepath.Join(dir, "e.sock"), liveRestore: true,
		bodies: map[string]sandboxoci.CreateBody{}, running: map[string]bool{}, exited: map[string]chan struct{}{},
	}
	ln, err := net.Listen("unix", f.sock)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(f.serve), ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return f
}

func (f *raFake) versionJSON() string {
	if f.podman {
		return `{"Platform":{"Name":"linux/amd64/ubuntu-26.04"},"Components":[{"Name":"Podman Engine","Version":"5.7.0"},{"Name":"Conmon","Version":"conmon version 2.1.13"}],"Version":"5.7.0","ApiVersion":"1.41","MinAPIVersion":"1.24"}`
	}
	return `{"Version":"29.9.2","ApiVersion":"1.52","Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine"}]}`
}

func (f *raFake) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/v1.") {
		p = p[strings.Index(p[1:], "/")+1:]
	}
	f.mu.Lock()
	f.calls = append(f.calls, r.Method+" "+p)
	f.mu.Unlock()
	switch {
	case p == "/version":
		_, _ = io.WriteString(w, f.versionJSON())
	case p == "/info":
		b, _ := json.Marshal(map[string]any{"ID": "fake-daemon", "Name": "box", "OperatingSystem": "Ubuntu", "SecurityOptions": []string{"name=seccomp,profile=builtin"}, "LiveRestoreEnabled": f.liveRestore})
		_, _ = w.Write(b)
	case strings.HasSuffix(p, "/libpod/info"):
		_, _ = io.WriteString(w, `{"host":{"conmon":{"path":"/usr/bin/conmon"},"ociRuntime":{"name":"crun"},"security":{"rootless":false}}}`)
	case p == "/containers/json":
		f.mu.Lock()
		var list []map[string]any
		for id, b := range f.bodies {
			list = append(list, map[string]any{"Id": id, "Labels": b.Labels, "State": map[bool]string{true: "running", false: "exited"}[f.running[id]]})
		}
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(list)
	case strings.HasSuffix(p, "/checkpoint"):
		id := strings.Split(strings.TrimPrefix(p, "/v4.0.0/libpod/containers/"), "/")[0]
		if r.URL.Query().Get("leaveRunning") != "true" {
			f.stop(id)
		}
		w.Header().Set("Content-Type", "application/x-tar")
		_, _ = w.Write(f.export)
	case strings.HasSuffix(p, "/restore"):
		f.mu.Lock()
		f.restored, _ = io.ReadAll(r.Body)
		var body sandboxoci.CreateBody
		_ = json.Unmarshal(f.restored, &body)
		f.bodies["restored1"] = body
		f.running["restored1"] = true
		f.exited["restored1"] = make(chan struct{})
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"Id":"restored1","Err":null}`)
	case strings.HasPrefix(p, "/containers/") || strings.HasPrefix(p, "/v4.0.0/libpod/containers/"):
		rest := strings.TrimPrefix(strings.TrimPrefix(p, "/v4.0.0/libpod"), "/containers/")
		parts := strings.SplitN(rest, "/", 2)
		if r.Method == http.MethodDelete {
			f.stop(parts[0])
			f.mu.Lock()
			delete(f.bodies, parts[0])
			f.removed = append(f.removed, parts[0])
			f.mu.Unlock()
			w.WriteHeader(204)
			return
		}
		verb := ""
		if len(parts) == 2 {
			verb = parts[1]
		}
		f.container(w, r, parts[0], verb)
	default:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"not found"}`)
	}
}

func (f *raFake) stop(id string) {
	f.mu.Lock()
	ch := f.exited[id]
	f.running[id] = false
	f.mu.Unlock()
	if ch != nil {
		select {
		case <-ch:
		default:
			close(ch)
		}
	}
}

func (f *raFake) container(w http.ResponseWriter, r *http.Request, id, verb string) {
	switch verb {
	case "json":
		f.inspect(w, id)
	case "wait":
		f.mu.Lock()
		ch := f.exited[id]
		f.mu.Unlock()
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		if ch == nil {
			return
		}
		select {
		case <-ch:
			_, _ = io.WriteString(w, `{"StatusCode":42}`)
		case <-r.Context().Done():
		}
	case "attach":
		f.attach(w, id)
	case "resize":
		w.WriteHeader(200)
	case "stop", "kill":
		f.stop(id)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func (f *raFake) inspect(w http.ResponseWriter, id string) {
	f.mu.Lock()
	b, ok := f.bodies[id]
	running := f.running[id]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"no such container"}`)
		return
	}
	var mounts []map[string]any
	for _, m := range b.HostConfig.Mounts {
		mounts = append(mounts, map[string]any{"Type": m.Type, "Source": m.Source, "Destination": m.Target, "RW": !m.ReadOnly})
	}
	network := b.HostConfig.NetworkMode
	if f.network != "" {
		network = f.network
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"State":  map[string]any{"Status": map[bool]string{true: "running", false: "exited"}[running], "Running": running, "ExitCode": 0},
		"Config": map[string]any{"User": b.User, "Labels": b.Labels},
		"HostConfig": map[string]any{
			"NetworkMode": network, "CapDrop": b.HostConfig.CapDrop, "CapAdd": b.HostConfig.CapAdd,
			"SecurityOpt": b.HostConfig.SecurityOpt, "ReadonlyRootfs": b.HostConfig.ReadonlyRootfs, "Privileged": false,
			"UsernsMode": b.HostConfig.UsernsMode, "Runtime": "runc", "Tmpfs": b.HostConfig.Tmpfs,
			"PidMode": "", "IpcMode": b.HostConfig.IpcMode, "UTSMode": "", "Devices": []any{}, "PidsLimit": b.HostConfig.PidsLimit,
		},
		"OCIRuntime": "crun",
		"Mounts":     mounts,
	})
}

func (f *raFake) attach(w http.ResponseWriter, id string) {
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
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
			f.stop(id)
			return
		}
		_, _ = brw.WriteString("echo:" + line)
		_ = brw.Flush()
	}
}

func (f *raFake) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

// raRun is one run's on-disk state as the run's own helper left it when it
// was killed: the relay record, an unheld liveness lock, its socket dir and
// the kept plan, plus the running container in the fake.
type raRun struct {
	obs, runID, installID, sockDir, cid string
	plan                                ociPlanFile
	rec                                 sandboxrelayd.RunRecord
}

const raInstall = "inst000000000001"

func raSetup(t *testing.T, f *raFake, runID string) raRun {
	t.Helper()
	return raSetupWith(t, f, runID, nil)
}

// raSetupWith is raSetup with the relay run record shaped by mod first
// (nil leaves it as raSetup writes it).
func raSetupWith(t *testing.T, f *raFake, runID string, mod func(*sandboxrelayd.RunRecord)) raRun {
	t.Helper()
	obs := filepath.Join(t.TempDir(), ".observer")
	if err := os.MkdirAll(filepath.Join(obs, "sandbox-oci"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(obs, "sandbox-oci", "install-id"), []byte(raInstall), 0o600); err != nil {
		t.Fatal(err)
	}
	ws := t.TempDir()
	sockDir, err := os.MkdirTemp("", "observer-sbx-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	eng := readoptReadEngine(context.Background(), raClient(t, f))
	if eng.err != nil {
		t.Fatalf("engine: %v", eng.err)
	}
	id := eng.id
	user, v := sandboxoci.PlanUser(id, 1000, 1000, "", true)
	if !v.OK() {
		t.Fatalf("PlanUser: %v", v)
	}
	api := "1.52"
	if f.podman {
		api = "1.41"
	}
	plan := ociPlanFile{
		Version: ociPlanVersion, Socket: f.sock, Engine: id.Engine, Mode: id.Mode, Fingerprint: id.Fingerprint, APIVersion: api, Host: sandboxoci.HostLinux, AllowRootful: true,
		Create: sandboxoci.CreatePlan{
			RunID: runID, InstallID: raInstall, Image: "node@sha256:" + strings.Repeat("b", 64), WorkDir: ws,
			Entrypoint: []string{"/usr/bin/observer", ociInitVerb, "--"},
			Binds:      []sandboxoci.Bind{{Source: ws, Target: ws}, {Source: sockDir, Target: "/tmp/.observer-sandbox-net", ReadOnly: true}},
			Tmpfs:      []string{"/tmp"}, Engine: id.Engine, User: user, ReadonlyRootfs: true, EngineSocket: f.sock, ObserverDir: obs,
		},
	}
	in := sandboxrelayd.RunRecord{RunID: runID, Tool: "claude-code", ProjectRoot: ws, WorkspaceDir: ws, Roots: []string{ws}}
	if mod != nil {
		mod(&in)
	}
	rec, err := sandboxrelayd.NewRunRecord(in)
	if err != nil {
		t.Fatal(err)
	}
	if err := sandboxrelayd.WriteRun(obs, rec); err != nil {
		t.Fatal(err)
	}
	// The killed helper's lock file: present, held by nobody.
	if err := os.WriteFile(filepath.Join(sandboxrelayd.RunsDir(obs), runID+".alive"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// The plan file the daemon wrote, and the compose's keep.
	planPath := filepath.Join(t.TempDir(), "plan.json")
	pb, _ := json.Marshal(plan)
	if err := os.WriteFile(planPath, pb, 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := sandbox.RelayHostArgv("/usr/bin/observer", sandbox.NetRequest{Egress: sandbox.Egress("none"), HostSocketDir: sockDir, ProxyPort: 8820}, nil, sandbox.RelayRequest{RunID: runID, HostObserverDir: obs})
	if err != nil {
		t.Fatal(err)
	}
	wrap := append(append([]string{"/usr/bin/observer", ociHostVerb, "--plan", planPath, "--"}, host...), ociInnerMarker)
	readoptKeep(obs, runID, planPath, wrap, raLaunchCfg(), "none")
	// The container the dead helper created and started.
	cp := plan.Create
	cp.Entrypoint = append(cp.Entrypoint, "/usr/bin/observer", "claude")
	_, body, err := sandboxoci.BuildCreate(cp)
	if err != nil {
		t.Fatal(err)
	}
	bb, _ := json.Marshal(body)
	var cb sandboxoci.CreateBody
	if err := json.Unmarshal(bb, &cb); err != nil {
		t.Fatal(err)
	}
	cid := "c-" + runID
	f.mu.Lock()
	f.bodies[cid], f.running[cid], f.exited[cid] = cb, true, make(chan struct{})
	f.mu.Unlock()
	return raRun{obs: obs, runID: runID, installID: raInstall, sockDir: sockDir, cid: cid, plan: plan, rec: rec}
}

// raLaunchCfg is the [terminal.sandbox] a test run is launched under.
func raLaunchCfg() config.TerminalSandboxConfig {
	return config.TerminalSandboxConfig{Enabled: true, Backends: []string{"oci-runc"}, Egress: "none"}
}

// raToday sets today's settings and floors for the policy re-check.
func raToday(t *testing.T, cfg config.TerminalSandboxConfig, floors sandboxselect.Floors) {
	t.Helper()
	old := readoptToday
	readoptToday = func() (config.TerminalSandboxConfig, sandboxselect.Floors, error) { return cfg, floors, nil }
	t.Cleanup(func() { readoptToday = old })
}

// raSettings makes the component active (or not) with a bound, and today's
// settings the run's own launch settings.
func raSettings(t *testing.T, active bool, bound time.Duration) {
	t.Helper()
	raToday(t, raLaunchCfg(), sandboxselect.Floors{})
	old := readoptLoadSettings
	readoptLoadSettings = func(context.Context) readoptSettings {
		return readoptSettings{active: active, bound: sandboxadopt.ClampBound(bound)}
	}
	oldCheck := readoptCheckSocket
	readoptCheckSocket = func(ociPlanFile) error { return nil }
	t.Cleanup(func() { readoptLoadSettings, readoptCheckSocket = old, oldCheck })
}

func raClient(t *testing.T, f *raFake) *sandboxengine.Client {
	t.Helper()
	api := "1.52"
	if f.podman {
		api = "1.41"
	}
	c, err := ociEngineClient(f.sock, api)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// raEnder installs a run ender that records what it ended.
func raEnder(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var ended []string
	prev := relayGoneRunEnder.Load()
	fn := func(r sandboxrelayd.RunRecord) {
		mu.Lock()
		ended = append(ended, r.RunID)
		mu.Unlock()
	}
	relayGoneRunEnder.Store(&fn)
	t.Cleanup(func() { relayGoneRunEnder.Store(prev) })
	return &ended
}

// TestReadoptReaperNilGolden: with the seam nil, and with it set while the
// component is off and nothing was ever kept, the reaper's sweep makes the
// same engine calls and removes the same container (the dead helper's run
// is pruned and its box reaped, as before).
func TestReadoptReaperNilGolden(t *testing.T) {
	sweepCalls := func(set bool) ([]string, []string) {
		f := newRAFake(t)
		raSettings(t, false, 0)
		ra := raSetup(t, f, "run0000000000000001")
		_ = os.RemoveAll(readoptDir(ra.obs)) // never kept: the component was off at launch
		raEnder(t)
		old := ociReadoptBeforeSweep
		if !set {
			ociReadoptBeforeSweep = nil
		}
		defer func() { ociReadoptBeforeSweep = old }()
		(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
		return f.callList(), f.removed
	}
	nilCalls, nilRemoved := sweepCalls(false)
	offCalls, offRemoved := sweepCalls(true)
	if strings.Join(nilCalls, "|") != strings.Join(offCalls, "|") || strings.Join(nilRemoved, ",") != strings.Join(offRemoved, ",") {
		t.Fatalf("component off changed the sweep:\nnil: %v %v\noff: %v %v", nilCalls, nilRemoved, offCalls, offRemoved)
	}
	if len(nilRemoved) != 1 {
		t.Fatalf("the dead helper's container was not reaped: %v", nilRemoved)
	}
}

// TestReadoptOfferKeepsTheRun: the sweep offers a run whose helper died on
// rootful Docker with live-restore, re-keys its relay record, and the
// reaper keeps the container; the live-run gate counts it.
func TestReadoptOfferKeepsTheRun(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000002")
	raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 0 {
		t.Fatalf("an offered run's container was reaped: %v", f.removed)
	}
	e := readoptRead(ra.obs, ra.runID)
	if !e.hasOffer || e.offer.Code != sandboxadopt.CodeOffered || e.offer.ContainerID != ra.cid {
		t.Fatalf("offer = %+v", e.offer)
	}
	rec, err := sandboxrelayd.ReadRun(ra.obs, ra.runID)
	if err != nil {
		t.Fatalf("the re-keyed record: %v", err)
	}
	if bytes.Equal(rec.BoxSecret, ra.rec.BoxSecret) || bytes.Equal(rec.LinkSecret, ra.rec.LinkSecret) || rec.ProjectRoot != ra.rec.ProjectRoot {
		t.Fatal("the relay record was not re-keyed with the same attribution")
	}
	if _, err := os.Lstat(filepath.Join(sandboxrelayd.RunsDir(ra.obs), ra.runID+".alive")); err == nil {
		t.Fatal("the dead helper's lock file is still there (a prune would remove the record)")
	}
	if got := readoptLiveCount(); got != 1 {
		t.Fatalf("live count = %d, want 1", got)
	}
	// A second sweep keeps it too.
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 0 {
		t.Fatal("the second sweep reaped the offered run")
	}
}

// TestReadoptHelperAttaches: re-adoption through a fake engine and the new
// helper: the marker says the scrollback is empty, the gap is recorded,
// the relay is served again in the run's own socket dir with the re-keyed
// box record, and the run ends with the agent's status, its container and
// entry gone.
func TestReadoptHelperAttaches(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run0000000000000003")
	raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	rec, _ := sandboxrelayd.ReadRun(ra.obs, ra.runID)
	inR, inW := io.Pipe()
	var out raBuf
	term := ociTerm{in: inR, out: &out, size: func() (uint16, uint16) { return 24, 80 }}
	done := make(chan int, 1)
	go func() {
		code, err := readoptRunHelper(context.Background(), ra.obs, ra.runID, term)
		if err != nil {
			t.Errorf("readoptRunHelper: %v", err)
		}
		done <- code
	}()
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(out.String(), "agent$") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	// The box record in the run's own socket dir carries the new key.
	b, err := os.ReadFile(filepath.Join(ra.sockDir, sandboxrelayd.BoxRecordName))
	if err != nil {
		t.Fatalf("box record: %v", err)
	}
	var box sandboxrelayd.BoxRecord
	_ = json.Unmarshal(b, &box)
	if !bytes.Equal(box.BoxSecret, rec.BoxSecret) {
		t.Fatal("the box record does not carry the re-keyed secret")
	}
	if e := readoptRead(ra.obs, ra.runID); e.offer.ReadoptedAt.IsZero() || e.offer.GapFrom.IsZero() {
		t.Fatalf("the gap was not recorded: %+v", e.offer)
	}
	_, _ = io.WriteString(inW, "exit\n")
	select {
	case code := <-done:
		if code != 42 {
			t.Fatalf("exit code = %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the re-adopted run did not end")
	}
	if !strings.HasPrefix(out.String(), sandboxadopt.RingMarker) {
		t.Fatalf("the terminal does not start with the marker: %q", out.String())
	}
	if len(f.removed) != 1 {
		t.Fatalf("the container was not removed at the end: %v", f.removed)
	}
	if _, err := os.Lstat(readoptRunDir(ra.obs, ra.runID)); err == nil {
		t.Fatal("the entry is still there")
	}
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
		t.Fatal("the run record is still there")
	}
}

// raBuf is a goroutine-safe buffer.
type raBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *raBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *raBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// TestReadoptRefusalsReap: each refused run is reaped as before.
func TestReadoptRefusalsReap(t *testing.T) {
	cases := []struct {
		name string
		edit func(*testing.T, *raFake, raRun)
		code sandboxadopt.Code
	}{
		{"docker without live-restore", func(_ *testing.T, f *raFake, _ raRun) { f.liveRestore = false }, sandboxadopt.CodeEngineEndsRun},
		{"read-back mismatch", func(_ *testing.T, f *raFake, _ raRun) { f.network = "bridge" }, sandboxadopt.CodeBuiltBelowPlan},
		{"tampered record", func(t *testing.T, _ *raFake, ra raRun) {
			if err := os.Chmod(filepath.Join(readoptRunDir(ra.obs, ra.runID), readoptKeptFile), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(readoptRunDir(ra.obs, ra.runID), readoptKeptFile), []byte(`{"v":1,"run_id":"another"}`), 0o644); err != nil {
				t.Fatal(err)
			}
		}, sandboxadopt.CodeRecordMissing},
		{"socket dir replaced", func(t *testing.T, _ *raFake, ra raRun) {
			_ = os.RemoveAll(ra.sockDir)
			if err := os.Symlink(t.TempDir(), ra.sockDir); err != nil {
				t.Fatal(err)
			}
		}, sandboxadopt.CodeProtectedChanged},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := newRAFake(t)
			raSettings(t, true, 0)
			ra := raSetup(t, f, "run000000000000000"+strconv.Itoa(4))
			raEnder(t)
			c.edit(t, f, ra)
			e := readoptRead(ra.obs, ra.runID)
			eng := readoptReadEngine(context.Background(), raClient(t, f))
			ct := sandboxoci.ContainerFact{ID: ra.cid, Running: true, Labels: sandboxoci.Labels(ra.installID, ra.runID)}
			d := sandboxadopt.Decide(readoptFactsFor(context.Background(), raClient(t, f), ra.obs, e, ct, ra.installID, eng, readoptSettings{active: true, bound: time.Minute}, readoptNow()))
			if d.Action != sandboxadopt.ActionReap || d.Code != c.code {
				t.Fatalf("decision = %+v, want reap %s", d, c.code)
			}
			(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
			if len(f.removed) != 1 {
				t.Fatalf("the refused run's container was not reaped: %v", f.removed)
			}
		})
	}
}

// TestReadoptBoundReaps: a run nobody re-adopts within the bound is reaped
// as before, its record handed to the run ender.
func TestReadoptBoundReaps(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, time.Minute)
	ra := raSetup(t, f, "run0000000000000005")
	ended := raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 0 {
		t.Fatal("reaped before the bound")
	}
	old := readoptNow
	readoptNow = func() time.Time { return time.Now().UTC().Add(2 * time.Minute) }
	defer func() { readoptNow = old }()
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 1 {
		t.Fatalf("not reaped after the bound: %v", f.removed)
	}
	if len(*ended) != 1 || (*ended)[0] != ra.runID {
		t.Fatalf("ended = %v", *ended)
	}
	if _, err := os.Lstat(readoptRunDir(ra.obs, ra.runID)); err == nil {
		t.Fatal("the entry outlived its run")
	}
}

// TestReadoptHeldWhileUpdateDeferred: a run under the update deferral is
// held past its bound and counts as live throughout.
func TestReadoptHeldWhileUpdateDeferred(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, time.Minute)
	ra := raSetup(t, f, "run0000000000000006")
	raEnder(t)
	prev := updateLiveDeferredHook.Load()
	updateLiveDeferredHook.Store(&liveDeferredHooks{pending: func() bool { return true }})
	defer updateLiveDeferredHook.Store(prev)
	old := readoptNow
	readoptNow = func() time.Time { return time.Now().UTC().Add(time.Hour) }
	defer func() { readoptNow = old }()
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(f.removed) != 0 {
		t.Fatal("a held run was reaped")
	}
	if e := readoptRead(ra.obs, ra.runID); e.offer.Code != sandboxadopt.CodeHeldForUpdate {
		t.Fatalf("offer = %+v", e.offer)
	}
	if readoptLiveCount() != 1 {
		t.Fatal("a held run does not count as live")
	}
}

// TestReadoptComponentOptIn: the component is opt-in like the drivers: an
// install with no [components] block leaves it off.
func TestReadoptComponentOptIn(t *testing.T) {
	governs, active := sandboxFeatureOptIn(componentstate.Snapshot{}, readoptComponent)
	if !governs || active {
		t.Fatalf("legacy snapshot: governs=%v active=%v", governs, active)
	}
	if g, _ := sandboxFeatureOptIn(componentstate.Snapshot{}, "terminals.sandbox.oci"); g {
		t.Fatal("the feature rule governs a driver")
	}
}

// TestReadoptDashboardInactive404: every route answers 404 while the
// component is off.
func TestReadoptDashboardInactive404(t *testing.T) {
	raSettings(t, false, 0)
	for _, rt := range readoptDashboardRoutes("") {
		method, path, _ := strings.Cut(rt.Pattern, " ")
		rr := httptest.NewRecorder()
		req := httptest.NewRequest(method, path, strings.NewReader(`{"run":"run0000000000000001"}`))
		rt.Handler.ServeHTTP(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("%s answered %d with the component off", rt.Pattern, rr.Code)
		}
	}
}

// TestReadoptEndWaitsForTheRunEnder (audit F3): the first sweep after a
// start runs before the daemon's run ender is set; an offer past its bound
// is then left alone (record, entry and container), as pruneGoneRelayRuns
// leaves a record, and the next sweep with the ender set ends the run.
func TestReadoptEndWaitsForTheRunEnder(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, time.Minute)
	ra := raSetup(t, f, "run00000000000000f3")
	ended := raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if e := readoptRead(ra.obs, ra.runID); !e.hasOffer {
		t.Fatal("the run was not offered")
	}
	// The bound runs out; a fresh daemon starts and sweeps before its relay
	// sets the ender.
	oldNow := readoptNow
	readoptNow = func() time.Time { return time.Now().UTC().Add(2 * time.Minute) }
	t.Cleanup(func() { readoptNow = oldNow })
	prev := relayGoneRunEnder.Load()
	relayGoneRunEnder.Store(nil)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err != nil {
		t.Fatal("the first sweep after start removed the run's record with no ender to end its row")
	}
	if e := readoptRead(ra.obs, ra.runID); !e.hasOffer {
		t.Fatal("the first sweep after start removed the run's entry")
	}
	if len(f.removed) != 0 || len(*ended) != 0 {
		t.Fatalf("the first sweep after start removed %v, ended %v", f.removed, *ended)
	}
	relayGoneRunEnder.Store(prev)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(*ended) != 1 || (*ended)[0] != ra.runID {
		t.Fatalf("the next sweep ended %v", *ended)
	}
	if _, err := sandboxrelayd.ReadRun(ra.obs, ra.runID); err == nil {
		t.Fatal("the run's record outlived its end")
	}
}

// TestReadoptEndByUserFromTheCLI (audit F3): `readopt --end` in a process
// with no run ender (the CLI) declines the offer; the daemon's next sweep
// ends the run through its ender.
func TestReadoptEndByUserFromTheCLI(t *testing.T) {
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run00000000000000f4")
	ended := raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	prev := relayGoneRunEnder.Load()
	relayGoneRunEnder.Store(nil)
	var out bytes.Buffer
	if err := readoptEndByUser(context.Background(), ra.obs, ra.runID, &out); err != nil {
		t.Fatal(err)
	}
	if e := readoptRead(ra.obs, ra.runID); !e.hasOffer || !e.offer.Declined {
		t.Fatal("the CLI end did not decline the offer")
	}
	relayGoneRunEnder.Store(prev)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	if len(*ended) != 1 || len(f.removed) != 1 {
		t.Fatalf("the sweep after the CLI end: ended %v, removed %v", *ended, f.removed)
	}
}

// raKeepPolicy rewrites the run's kept launch settings.
func raKeepPolicy(t *testing.T, ra raRun, edit func(*readoptPolicy)) {
	t.Helper()
	e := readoptRead(ra.obs, ra.runID)
	if !e.keptOK || e.kept.Policy == nil {
		t.Fatalf("no kept launch settings: %v", e.keptErr)
	}
	edit(e.kept.Policy)
	if err := readoptWriteFile(readoptRunDir(ra.obs, ra.runID), readoptKeptFile, e.kept); err != nil {
		t.Fatal(err)
	}
}

// TestReadoptPolicyChanged (audit F4): a re-adoption and a restore
// recompute the plan from today's settings, the org floors and the backend
// list, and refuse policy_changed unless the kept plan is the same or
// stricter: a widened bind, a widened network tier, a delisted row and an
// org floor raised since launch are each refused before the engine is
// touched; a stricter kept plan is re-adopted.
func TestReadoptPolicyChanged(t *testing.T) {
	cases := []struct {
		name  string
		kept  func(*readoptPolicy)
		today func(*config.TerminalSandboxConfig)
		floor sandboxselect.Floors
		want  string // a word of the reason; "" passes
	}{
		{name: "a stricter kept tier passes", today: func(c *config.TerminalSandboxConfig) { c.Egress = "internet" }},
		{
			name: "widened bind", kept: func(p *readoptPolicy) { p.ExtraRWBinds = []string{"/srv/data"} },
			today: func(c *config.TerminalSandboxConfig) { c.ExtraROBinds = []string{"/srv/data"} }, want: "/srv/data (read-write)",
		},
		{name: "widened network tier", kept: func(p *readoptPolicy) { p.Tier = "internet" }, want: "network tier internet"},
		{name: "delisted row", today: func(c *config.TerminalSandboxConfig) { c.Backends = []string{"bwrap"} }, want: "no longer in"},
		{name: "org floor raised since launch", floor: sandboxselect.Floors{OrgMinClass: vocab.ClassHWVM}, want: "organization floor"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newRAFake(t)
			raSettings(t, true, 0)
			ra := raSetup(t, f, "run00000000000000p4")
			raEnder(t)
			(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
			if tc.kept != nil {
				raKeepPolicy(t, ra, tc.kept)
			}
			today := raLaunchCfg()
			if tc.today != nil {
				tc.today(&today)
			}
			raToday(t, today, tc.floor)
			calls := len(f.callList())
			_, err := readoptPrepare(context.Background(), ra.obs, ra.runID)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("re-adopt refused: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), string(sandboxadopt.CodePolicyChanged)) || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("re-adopt = %v, want policy_changed naming %q", err, tc.want)
			}
			if len(f.callList()) != calls {
				t.Fatal("the engine was driven before the policy re-check")
			}
			// The same plan, checkpointed, is refused at restore.
			e := readoptRead(ra.obs, ra.runID)
			e.offer.Checkpointed, e.offer.Export = true, "checkpoint.tar"
			if err := readoptWriteFile(readoptRunDir(ra.obs, ra.runID), readoptOfferFile, e.offer); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			if err := readoptRestore(context.Background(), ra.obs, ra.runID, &out); err == nil || !strings.Contains(err.Error(), string(sandboxadopt.CodePolicyChanged)) {
				t.Fatalf("restore = %v, want policy_changed", err)
			}
			if len(f.callList()) != calls {
				t.Fatal("the restore drove the engine before the policy re-check")
			}
		})
	}
	// An entry kept before the launch settings were recorded is refused.
	f := newRAFake(t)
	raSettings(t, true, 0)
	ra := raSetup(t, f, "run00000000000000p5")
	raEnder(t)
	(&ociReaper{}).sweep(context.Background(), raClient(t, f), ra.installID, ra.obs)
	e := readoptRead(ra.obs, ra.runID)
	e.kept.Policy = nil
	_ = readoptWriteFile(readoptRunDir(ra.obs, ra.runID), readoptKeptFile, e.kept)
	if _, err := readoptPrepare(context.Background(), ra.obs, ra.runID); err == nil || !strings.Contains(err.Error(), "not kept") {
		t.Fatalf("an unrecorded entry = %v", err)
	}
}
