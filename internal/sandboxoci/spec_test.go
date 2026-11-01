package sandboxoci

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const (
	testImage   = "mirror.gcr.io/library/alpine@sha256:5291449c3df73caf6ed85e649dec1b9e818b39a5d8c871e97afc13e9cd5e8fa8"
	testRun     = "RUNID0123456789abc"
	testInstall = "0a1b2c3d4e5f6a7b"
)

// testPlan is the plan the recorded inspect fixtures were built from.
func testPlan(user UserPlan) CreatePlan {
	return CreatePlan{
		RunID: testRun, InstallID: testInstall, Image: testImage,
		WorkDir:    "/home/dev/src/app",
		Entrypoint: []string{"/home/dev/.local/bin/observer", "sandbox-oci-init", "--", "/home/dev/.local/bin/observer", "claude"},
		Env:        []string{"HOME=/home/dev", "TERM=xterm-256color"},
		Binds: []Bind{
			{Source: "/home/dev/src/app", Target: "/home/dev/src/app"},
			{Source: "/home/dev/.local/bin/observer", Target: "/home/dev/.local/bin/observer", ReadOnly: true},
			{Source: "/home/dev/.claude", Target: "/home/dev/.claude"},
			{Source: "/tmp/observer-sbx-" + testRun, Target: "/tmp/observer-sbx-" + testRun, ReadOnly: true},
		},
		HideFiles:      []string{"/home/dev/.claude/.credentials-secret"},
		Tmpfs:          []string{"/home/dev", "/tmp"},
		Engine:         EngineDocker,
		User:           user,
		ReadonlyRootfs: true,
		EngineSocket:   "/run/user/1000/docker.sock",
		ObserverDir:    "/home/dev/.observer",
	}
}

var rootfulUser = UserPlan{Row: "rootful engine (opt-in)", User: "1000:1000"}

// TestBuildCreateHardening pins the fixed hardening of every create body
// (section 4.6, SBX-BE-3).
func TestBuildCreateHardening(t *testing.T) {
	name, body, err := BuildCreate(testPlan(rootfulUser))
	if err != nil {
		t.Fatal(err)
	}
	if name != NamePrefix+"0a1b2c3d-"+testRun {
		t.Errorf("name = %q", name)
	}
	h := body.HostConfig
	switch {
	case h.NetworkMode != "none":
		t.Errorf("network %q", h.NetworkMode)
	case len(h.CapDrop) != 1 || h.CapDrop[0] != "ALL" || len(h.CapAdd) != 0:
		t.Errorf("caps drop %v add %v", h.CapDrop, h.CapAdd)
	case len(h.SecurityOpt) != 1 || h.SecurityOpt[0] != "no-new-privileges":
		t.Errorf("security opts %v", h.SecurityOpt)
	case h.Privileged || h.Init || h.AutoRemove:
		t.Errorf("privileged/init/autoremove set: %+v", h)
	case !h.ReadonlyRootfs:
		t.Error("root filesystem not read-only")
	case h.LogConfig.Type != "none":
		t.Errorf("log driver %q (the log is content-bearing)", h.LogConfig.Type)
	case h.RestartPolicy.Name != "no":
		t.Errorf("restart %q", h.RestartPolicy.Name)
	}
	if !body.Tty || !body.OpenStdin || body.StdinOnce || !body.AttachStdin {
		t.Errorf("tty/stdin shape wrong: %+v", body)
	}
	if body.Labels[LabelRun] != testRun || body.Labels[LabelInstall] != testInstall || body.Labels[LabelRole] != RoleSandbox {
		t.Errorf("labels %v", body.Labels)
	}
	if got := h.Tmpfs["/home/dev"]; !strings.Contains(got, "uid=1000,gid=1000") || !strings.HasPrefix(got, "rw,") {
		t.Errorf("home tmpfs %q", got)
	}
	// Mounts sorted parent first, the hidden file bound to /dev/null ro.
	last := -1
	hidden := false
	for _, m := range h.Mounts {
		if d := mountDepth(m.Target); d < last {
			t.Errorf("mount %s out of order", m.Target)
		} else {
			last = d
		}
		if m.Target == "/home/dev/.claude/.credentials-secret" {
			hidden = m.Source == "/dev/null" && m.ReadOnly
		}
	}
	if !hidden {
		t.Error("the hidden file is not a read-only /dev/null bind")
	}
	if _, err := json.Marshal(body); err != nil {
		t.Fatal(err)
	}
}

// TestBuildCreateRefuses is one case per specRules row.
func TestBuildCreateRefuses(t *testing.T) {
	cases := []struct {
		name string
		edit func(p *CreatePlan)
		want string
	}{
		{"bad run id", func(p *CreatePlan) { p.RunID = "-x" }, "(ids)"},
		{"tag not digest", func(p *CreatePlan) { p.Image = "alpine:3.22" }, "(image)"},
		{"no image", func(p *CreatePlan) { p.Image = "" }, "(image)"},
		{"relative entrypoint", func(p *CreatePlan) { p.Entrypoint = []string{"observer"} }, "(entrypoint)"},
		{"workspace read-only", func(p *CreatePlan) { p.Binds[0].ReadOnly = true }, "(workdir)"},
		{"relative bind", func(p *CreatePlan) { p.Binds = append(p.Binds, Bind{Source: "rel", Target: "/x"}) }, "(paths)"},
		{"bind over /proc", func(p *CreatePlan) { p.Binds = append(p.Binds, Bind{Source: "/x", Target: "/proc/self"}) }, "(paths)"},
		{"duplicate target", func(p *CreatePlan) { p.Tmpfs = append(p.Tmpfs, "/home/dev/src/app") }, "(paths)"},
		{"socket exposed", func(p *CreatePlan) {
			p.Binds = append(p.Binds, Bind{Source: "/run/user/1000", Target: "/run/user/1000"})
		}, "(engine socket)"},
		{"socket unnamed", func(p *CreatePlan) { p.EngineSocket = "" }, "(engine socket)"},
		{"observer dir whole", func(p *CreatePlan) { p.Binds = append(p.Binds, Bind{Source: "/home/dev", Target: "/srv/home"}) }, "(observer dir)"},
		{"observer dir parent without reblind", func(p *CreatePlan) {
			p.Tmpfs = []string{"/tmp"}
			p.Binds = append(p.Binds, Bind{Source: "/home/dev", Target: "/home/dev"})
		}, "(observer dir)"},
		{"engine env", func(p *CreatePlan) { p.Env = append(p.Env, "DOCKER_HOST=unix:///run/docker.sock") }, "(env)"},
		{"preload env", func(p *CreatePlan) { p.Env = append(p.Env, "LD_PRELOAD=/x.so") }, "(env)"},
		{"no user row", func(p *CreatePlan) { p.User = UserPlan{} }, "(user)"},
		{"rootful as root", func(p *CreatePlan) { p.User = UserPlan{Row: "rootful", User: "0:0"} }, "(user)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := testPlan(rootfulUser)
			c.edit(&p)
			_, _, err := BuildCreate(p)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("err = %v, want %s", err, c.want)
			}
		})
	}
}

// TestBuildCreateProjectAtHome: a workspace that is the home directory is
// allowed when the observer dir is blinded again by a tmpfs.
func TestBuildCreateProjectAtHome(t *testing.T) {
	p := testPlan(rootfulUser)
	p.WorkDir = "/home/dev"
	p.Binds[0] = Bind{Source: "/home/dev", Target: "/home/dev"}
	p.Tmpfs = []string{"/tmp", "/home/dev/.observer"}
	if _, _, err := BuildCreate(p); err != nil {
		t.Fatal(err)
	}
}

func TestBuildCreateRootlessRoot(t *testing.T) {
	_, body, err := BuildCreate(testPlan(UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true}))
	if err != nil {
		t.Fatal(err)
	}
	if body.User != "0:0" {
		t.Errorf("user %q", body.User)
	}
}

func TestValidateImageRef(t *testing.T) {
	for ref, ok := range map[string]bool{
		testImage: true,
		"ghcr.io/org/img@sha256:" + strings.Repeat("a", 64): true,
		"alpine":            false,
		"alpine:latest":     false,
		"alpine@sha256:abc": false,
		"ALPINE@sha256:" + strings.Repeat("a", 64): false,
		"": false,
	} {
		if err := ValidateImageRef(ref); (err == nil) != ok {
			t.Errorf("%q: err = %v", ref, err)
		}
	}
}

func TestOrphans(t *testing.T) {
	have := []ContainerFact{
		{ID: "c", Labels: Labels(testInstall, "live-run-0001")},
		{ID: "b", Labels: Labels(testInstall, "dead-run-0001")},
		{ID: "a", Labels: Labels("otherinstall00", "dead-run-0002")},
		{ID: "d", Labels: map[string]string{LabelInstall: testInstall}},
		{ID: "e", Labels: map[string]string{LabelRole: RoleSandbox, LabelInstall: testInstall}},
	}
	got := Orphans(testInstall, have, func(r string) bool { return r == "live-run-0001" })
	if strings.Join(got, ",") != "b,e" {
		t.Fatalf("orphans = %v (another install's container or an unlabelled one must never be reaped)", got)
	}
	f := InstallFilter(testInstall)
	if len(f["label"]) != 2 {
		t.Fatalf("filter %v", f)
	}
}

// TestBuildCreateSendsNoDevices (live checks 2026-10-22, D1): the create
// body states "no devices" as an explicit empty list, the way the docker
// CLI does, never by leaving the key out.
func TestBuildCreateSendsNoDevices(t *testing.T) {
	_, body, err := BuildCreate(testPlan(rootfulUser))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"Devices":[]`) {
		t.Fatalf("the create body does not send Devices: []: %s", raw)
	}
}

// TestTmpfsOwnerPerEngine (live check 2026-10-22, D5): the writable tmpfs
// owner option is the engine's own spelling. Docker keeps uid= and gid=
// (what Docker 29.9.2 accepted and read back); Podman 5.7.0 refuses them
// (`unknown mount option "uid=1000"`) and gets its U option, which chowns
// the tmpfs to the container user. An engine with no row is refused before
// anything is created.
func TestTmpfsOwnerPerEngine(t *testing.T) {
	cases := []struct {
		name    string
		engine  Engine
		user    UserPlan
		want    string
		notWant string
		err     string
	}{
		{"docker rootful", EngineDocker, rootfulUser, ",uid=1000,gid=1000", ",U", ""},
		{"docker rootless", EngineDocker, UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true}, ",uid=0,gid=0", ",U", ""},
		{"podman keep-id", EnginePodman, UserPlan{Row: "rootless podman, keep-id", User: "1000:1000", UsernsMode: "keep-id", ExpectUIDMap: "1000:0:1"}, "mode=0700,U", "uid=", ""},
		{"podman default namespace", EnginePodman, UserPlan{Row: "rootless podman, default namespace", User: "0:0", ContainerRootIsHostUser: true}, "mode=0700,U", "uid=", ""},
		{"no engine", "", rootfulUser, "", "", "(engine)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := testPlan(c.user)
			p.Engine = c.engine
			_, body, err := BuildCreate(p)
			if c.err != "" {
				if err == nil || !strings.Contains(err.Error(), c.err) {
					t.Fatalf("err %v, want %s", err, c.err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			for _, d := range []string{"/home/dev", "/tmp"} {
				got := body.HostConfig.Tmpfs[d]
				if !strings.HasSuffix(got, c.want) && !strings.Contains(got, c.want) {
					t.Errorf("%s tmpfs %q lacks %q", d, got, c.want)
				}
				if strings.Contains(got, c.notWant) {
					t.Errorf("%s tmpfs %q carries %q, which this engine refuses", d, got, c.notWant)
				}
			}
			// The hiding tmpfs carries no owner on either engine.
			p.HideDirs = []string{"/home/dev/.ssh"}
			if _, body, err = BuildCreate(p); err != nil {
				t.Fatal(err)
			}
			if got := body.HostConfig.Tmpfs["/home/dev/.ssh"]; strings.Contains(got, "uid=") || strings.Contains(got, ",U") {
				t.Errorf("hiding tmpfs %q carries an owner", got)
			}
		})
	}
}

// TestBuildCreatePodmanTerminalBody pins the create body a rootless Podman
// gets: a terminal (Tty with stdin open and attached, never closed after
// the first attach), every capability dropped with none added, the
// container user's tmpfs owner in Podman's U form (never uid= or gid=,
// which Podman refuses), no devices, the log driver none, a private IPC
// namespace. The Linux live check of 2026-10-23 saw this body fail on runc
// and pass on crun; the re-check on the Docker sandbox the same day proved
// the cause was the binds' BindOptions (TestBuildCreateBindOptionsPerEngine).
func TestBuildCreatePodmanTerminalBody(t *testing.T) {
	p := testPlan(UserPlan{Row: "rootless podman, keep-id", User: "1000:1000", UsernsMode: "keep-id", ExpectUIDMap: "1000:0:1"})
	p.Engine = EnginePodman
	p.EngineSocket = "/run/user/1000/podman/podman.sock"
	_, body, err := BuildCreate(p)
	if err != nil {
		t.Fatal(err)
	}
	if !body.Tty || !body.OpenStdin || !body.AttachStdin || !body.AttachStdout || !body.AttachStderr || body.StdinOnce {
		t.Errorf("terminal shape %+v", body)
	}
	h := body.HostConfig
	if !reflect.DeepEqual(h.CapDrop, []string{"ALL"}) || h.CapAdd == nil || len(h.CapAdd) != 0 {
		t.Errorf("caps drop %v add %#v", h.CapDrop, h.CapAdd)
	}
	if h.UsernsMode != "keep-id" || h.Runtime != "" || h.IpcMode != "private" || h.LogConfig.Type != "none" || h.Devices == nil || len(h.Devices) != 0 {
		t.Errorf("host config %+v", h)
	}
	for _, d := range []string{"/home/dev", "/tmp"} {
		opts := h.Tmpfs[d]
		if !strings.HasSuffix(opts, ",U") || strings.Contains(opts, "uid=") || strings.Contains(opts, "gid=") {
			t.Errorf("tmpfs %s %q", d, opts)
		}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"CapAdd":[]`) || !strings.Contains(string(raw), `"Devices":[]`) {
		t.Errorf("the empty lists are not sent as []: %s", raw)
	}
}
