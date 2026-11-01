//go:build linux && !sbo_omit_terminals_sandbox_oci && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxoci"
)

// p3cFake is a fake Engine API for lane SBX-P3C's flows: several containers
// in create order (c1, c2, ...), the setup container of a first-start
// install (it prints a line and exits with installExit once started), the
// agent's container (a prompt that echoes and ends with 42 on "exit"),
// labelled volumes, image inspect answers by reference, the pull stream and
// the image list and removal.
type p3cFake struct {
	t    *testing.T
	sock string

	mu         sync.Mutex
	calls      []string
	bodies     map[string]sandboxoci.CreateBody
	names      map[string]string
	order      []string
	running    map[string]bool
	exited     map[string]chan struct{}
	removed    []string
	volumes    map[string]map[string]any
	volRemoved []string
	// installExit is the setup container's exit status.
	installExit int
	// images answers GET /images/{ref}/json (ref -> inspect body); a ref
	// that is not there is a 404.
	images map[string]map[string]any
	// pullStream is the body of POST /images/create; pulled records the refs.
	pullStream string
	pulled     []string
	// list is GET /images/json; imageRemoved records DELETE /images/{ref};
	// imageInUse answers that removal with 409.
	list         []map[string]any
	imageRemoved []string
	imageInUse   map[string]bool
	// containers answers GET /containers/json (an "ancestor" filter keeps
	// the entries whose "Image" is that reference).
	containers []map[string]any
	// onPull makes a reference present (its inspect answer) once pulled.
	onPull map[string]map[string]any
	// onPullRequest, when set, runs as POST /images/create arrives, before
	// anything is answered (R-037's order test reads the terminal there).
	onPullRequest func()
}

func newP3CFake(t *testing.T) *p3cFake {
	t.Helper()
	dir, err := os.MkdirTemp("", "p3cf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &p3cFake{
		t: t, sock: filepath.Join(dir, "e.sock"),
		bodies: map[string]sandboxoci.CreateBody{}, names: map[string]string{}, running: map[string]bool{},
		exited: map[string]chan struct{}{}, volumes: map[string]map[string]any{}, images: map[string]map[string]any{},
		imageInUse: map[string]bool{}, onPull: map[string]map[string]any{},
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

func (f *p3cFake) record(s string) {
	f.mu.Lock()
	f.calls = append(f.calls, s)
	f.mu.Unlock()
}

func (f *p3cFake) callList() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.calls...)
}

func (f *p3cFake) isInstall(id string) bool {
	b := f.bodies[id]
	return len(b.Entrypoint) > 1 && b.Entrypoint[1] == ociInstallVerb
}

func (f *p3cFake) exit(id string) {
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

func (f *p3cFake) serve(w http.ResponseWriter, r *http.Request) {
	p := r.URL.Path
	if strings.HasPrefix(p, "/v1.") {
		p = p[strings.Index(p[1:], "/")+1:]
	}
	f.record(r.Method + " " + p)
	switch {
	case p == "/version":
		_, _ = io.WriteString(w, `{"Version":"29.9.2","ApiVersion":"1.52","Platform":{"Name":"Docker Engine - Community"},"Components":[{"Name":"Engine"}]}`)
	case p == "/info":
		_, _ = io.WriteString(w, `{"ID":"fake-daemon","Name":"box","OperatingSystem":"Ubuntu","SecurityOptions":["name=seccomp,profile=builtin","name=rootless"]}`)
	case p == "/images/create":
		if hook := f.onPullRequest; hook != nil {
			hook()
		}
		ref := r.URL.Query().Get("fromImage")
		if tag := r.URL.Query().Get("tag"); tag != "" {
			ref += "@" + tag
		}
		f.mu.Lock()
		f.pulled = append(f.pulled, ref)
		stream := f.pullStream
		if img, ok := f.onPull[ref]; ok {
			f.images[ref] = img
		}
		f.mu.Unlock()
		w.WriteHeader(200)
		_, _ = io.WriteString(w, stream)
	case p == "/images/json":
		f.mu.Lock()
		b, _ := json.Marshal(f.list)
		f.mu.Unlock()
		_, _ = w.Write(b)
	case strings.HasPrefix(p, "/images/") && strings.HasSuffix(p, "/json"):
		ref, _ := url.PathUnescape(strings.TrimSuffix(strings.TrimPrefix(p, "/images/"), "/json"))
		f.mu.Lock()
		img, ok := f.images[ref]
		f.mu.Unlock()
		if !ok {
			// The agent's image env check reads any image it runs.
			if strings.Contains(ref, "@sha256:") && !strings.HasPrefix(ref, "ghcr.io/") {
				_, _ = io.WriteString(w, `{"Id":"sha256:aa","Config":{"Env":["PATH=/usr/local/bin:/usr/bin:/bin"]}}`)
				return
			}
			w.WriteHeader(404)
			_, _ = io.WriteString(w, `{"message":"No such image"}`)
			return
		}
		b, _ := json.Marshal(img)
		_, _ = w.Write(b)
	case strings.HasPrefix(p, "/images/") && r.Method == http.MethodDelete:
		ref, _ := url.PathUnescape(strings.TrimPrefix(p, "/images/"))
		f.mu.Lock()
		inUse := f.imageInUse[ref]
		if !inUse {
			f.imageRemoved = append(f.imageRemoved, ref)
		}
		f.mu.Unlock()
		if inUse {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"message":"conflict: unable to delete `+ref+` (cannot be forced) - image is being used by running container c9"}`)
			return
		}
		_, _ = io.WriteString(w, `[{"Untagged":"`+ref+`"}]`)
	case p == "/volumes/create":
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		name, _ := b["Name"].(string)
		f.mu.Lock()
		f.volumes[name] = b
		f.mu.Unlock()
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Name":"`+name+`","Driver":"local"}`)
	case p == "/volumes" && r.Method == http.MethodGet:
		f.mu.Lock()
		var vols []map[string]any
		for name, b := range f.volumes {
			vols = append(vols, map[string]any{"Name": name, "Driver": "local", "Labels": b["Labels"], "Options": b["DriverOpts"]})
		}
		f.mu.Unlock()
		b, _ := json.Marshal(map[string]any{"Volumes": vols})
		_, _ = w.Write(b)
	case strings.HasPrefix(p, "/volumes/") && r.Method == http.MethodDelete:
		name := strings.TrimPrefix(p, "/volumes/")
		f.mu.Lock()
		delete(f.volumes, name)
		f.volRemoved = append(f.volRemoved, name)
		f.mu.Unlock()
		w.WriteHeader(204)
	case p == "/containers/create":
		var b sandboxoci.CreateBody
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		id := "c" + strconv.Itoa(len(f.order)+1)
		f.order = append(f.order, id)
		f.bodies[id] = b
		f.names[r.URL.Query().Get("name")] = id
		f.exited[id] = make(chan struct{})
		f.mu.Unlock()
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"Id":"`+id+`","Warnings":[]}`)
	case p == "/containers/json":
		var filters map[string][]string
		_ = json.Unmarshal([]byte(r.URL.Query().Get("filters")), &filters)
		f.mu.Lock()
		var out []map[string]any
		for _, c := range f.containers {
			if a := filters["ancestor"]; len(a) == 1 && c["Image"] != a[0] {
				continue
			}
			out = append(out, c)
		}
		f.mu.Unlock()
		b, _ := json.Marshal(out)
		_, _ = w.Write(b)
	case strings.HasPrefix(p, "/containers/") && r.Method == http.MethodDelete:
		id := strings.TrimPrefix(p, "/containers/")
		f.mu.Lock()
		f.removed = append(f.removed, id)
		f.mu.Unlock()
		w.WriteHeader(204)
	case strings.HasPrefix(p, "/containers/"):
		rest := strings.TrimPrefix(p, "/containers/")
		id, verb, _ := strings.Cut(rest, "/")
		f.container(w, r, id, verb)
	default:
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"not found"}`)
	}
}

func (f *p3cFake) container(w http.ResponseWriter, r *http.Request, id, verb string) {
	switch verb {
	case "json":
		f.inspect(w, id)
	case "start":
		f.mu.Lock()
		f.running[id] = true
		install := f.isInstall(id)
		f.mu.Unlock()
		w.WriteHeader(204)
		if install {
			go func() {
				time.Sleep(50 * time.Millisecond)
				f.exit(id)
			}()
		}
	case "wait":
		f.mu.Lock()
		ch := f.exited[id]
		install := f.isInstall(id)
		code := 42
		if install {
			code = f.installExit
		}
		f.mu.Unlock()
		w.WriteHeader(200)
		w.(http.Flusher).Flush()
		select {
		case <-ch:
			_, _ = io.WriteString(w, `{"StatusCode":`+strconv.Itoa(code)+`}`)
		case <-r.Context().Done():
		}
	case "attach":
		f.attach(w, id)
	case "resize":
		w.WriteHeader(200)
	case "stop":
		f.exit(id)
		w.WriteHeader(204)
	default:
		w.WriteHeader(404)
	}
}

func (f *p3cFake) inspect(w http.ResponseWriter, id string) {
	f.mu.Lock()
	b, ok := f.bodies[id]
	running := f.running[id]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"message":"no such container"}`)
		return
	}
	rt := "runc"
	if b.HostConfig.Runtime != "" {
		rt = b.HostConfig.Runtime
	}
	var mounts []map[string]any
	for _, m := range b.HostConfig.Mounts {
		mm := map[string]any{"Type": m.Type, "Source": m.Source, "Destination": m.Target, "RW": !m.ReadOnly}
		if m.Type == "volume" {
			mm["Name"] = m.Source
			mm["Source"] = "/var/lib/docker/volumes/" + m.Source + "/_data"
		}
		mounts = append(mounts, mm)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"State":  map[string]any{"Status": map[bool]string{true: "running", false: "created"}[running], "Running": running, "ExitCode": 0},
		"Config": map[string]any{"User": b.User, "Labels": b.Labels},
		"HostConfig": map[string]any{
			"NetworkMode": b.HostConfig.NetworkMode, "CapDrop": b.HostConfig.CapDrop, "CapAdd": b.HostConfig.CapAdd,
			"SecurityOpt": b.HostConfig.SecurityOpt, "ReadonlyRootfs": b.HostConfig.ReadonlyRootfs, "Privileged": false,
			"UsernsMode": b.HostConfig.UsernsMode, "Runtime": rt, "Tmpfs": b.HostConfig.Tmpfs,
			"PidMode": "", "IpcMode": b.HostConfig.IpcMode, "UTSMode": "", "Devices": []any{}, "PidsLimit": b.HostConfig.PidsLimit,
		},
		"Mounts": mounts,
	})
}

func (f *p3cFake) attach(w http.ResponseWriter, id string) {
	conn, brw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = brw.WriteString("HTTP/1.1 101 UPGRADED\r\nConnection: Upgrade\r\nUpgrade: tcp\r\n\r\n")
	_ = brw.Flush()
	f.mu.Lock()
	install := f.isInstall(id)
	ch := f.exited[id]
	f.mu.Unlock()
	if install {
		_, _ = brw.WriteString("added 3 packages in 2s\r\n")
		_ = brw.Flush()
		<-ch
		return
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
			f.exit(id)
			return
		}
		_, _ = brw.WriteString("echo:" + line)
		_ = brw.Flush()
	}
}

// p3cRunPlan is a rootless Docker plan file for the fake.
func p3cRunPlan(t *testing.T, f *p3cFake) ociPlanFile {
	t.Helper()
	ws := t.TempDir()
	v := sandboxoci.VersionFacts{Version: "29.9.2", APIVersion: "1.52", PlatformName: "Docker Engine - Community"}
	id, _ := sandboxoci.Classify(v, sandboxoci.InfoFacts{ID: "fake-daemon", Name: "box", OperatingSystem: "Ubuntu", SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless"}})
	return ociPlanFile{
		Version: ociPlanVersion, Socket: f.sock, Engine: id.Engine, Mode: id.Mode, Fingerprint: id.Fingerprint, APIVersion: "1.52", Host: sandboxoci.HostLinux,
		Create: sandboxoci.CreatePlan{
			RunID: "run0000000000000001", InstallID: "inst000000000001",
			Image:          "node@sha256:" + strings.Repeat("b", 64),
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
