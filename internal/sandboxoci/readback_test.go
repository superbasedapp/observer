package sandboxoci

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

var (
	dockerRootful  = Identity{Engine: EngineDocker, Mode: ModeRootful, APIVersion: "1.44"}
	dockerRootless = Identity{Engine: EngineDocker, Mode: ModeRootless, APIVersion: "1.56"}
	podmanRootless = Identity{Engine: EnginePodman, Mode: ModeRootless, Version: "5.6.2"}
)

// TestReadBackRecorded runs the re-check over the recorded inspect answers:
// Docker API 1.44 rootful, Docker API 1.56 rootless (with an image VOLUME),
// and Podman's libpod inspect of a keep-id container, which reports
// UsernsMode "private" and the expanded capability list (JSP-4) and must
// still pass.
func TestReadBackRecorded(t *testing.T) {
	cases := []struct {
		file string
		id   Identity
		user UserPlan
	}{
		{"inspect_docker_v1.44.json", dockerRootful, rootfulUser},
		// Recorded from a live Docker Engine 28.1.1 (API 1.49): the
		// driver's create body sent through the Engine API, which reads
		// back "Devices": null (the live checks' D1 shape).
		{"inspect_docker_v1.49_api_created.json", Identity{Engine: EngineDocker, Mode: ModeRootful, APIVersion: "1.49"}, rootfulUser},
		{"inspect_docker_v1.56.json", dockerRootless, UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true}},
		{"inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{Row: "rootless podman, keep-id", User: "1000:1000", UsernsMode: "keep-id", ExpectUIDMap: "1000:0:1"}},
	}
	for _, c := range cases {
		t.Run(c.file, func(t *testing.T) {
			f, err := ParseInspect(readFixture(t, c.file), c.id.Engine)
			if err != nil {
				t.Fatal(err)
			}
			if v := ReadBack(ReadBackInput{Identity: c.id, Plan: testPlan(c.user), Facts: f}); !v.OK() {
				t.Fatalf("read-back refused a matching container: %v", v)
			}
		})
	}
}

// mutate decodes a fixture, applies edit and re-encodes it.
func mutate(t *testing.T, name string, edit func(m map[string]any)) []byte {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(readFixture(t, name), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func hc(m map[string]any) map[string]any { return m["HostConfig"].(map[string]any) }

// TestReadBackRefuses feeds reshaped, truncated and weakened answers: each
// is built_below_plan (or a parse refusal), never the planned value.
func TestReadBackRefuses(t *testing.T) {
	cases := []struct {
		name string
		file string
		id   Identity
		user UserPlan
		edit func(m map[string]any)
		want string // a read-back rule name, or "parse"
	}{
		{"truncated state", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(m, "State") }, "parse"},
		{"no mounts", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(m, "Mounts") }, "parse"},
		{"no capdrop", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(hc(m), "CapDrop") }, "parse"},
		{"podman compat inspect (no OCIRuntime)", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}, func(m map[string]any) { delete(m, "OCIRuntime") }, "parse"},
		{"privileged", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["Privileged"] = true }, "not privileged"},
		{"bridge network", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["NetworkMode"] = "bridge" }, "network none"},
		{"caps kept", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["CapDrop"] = []any{"NET_RAW"} }, "capabilities dropped"},
		{"cap added", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["CapAdd"] = []any{"SYS_ADMIN"} }, "capabilities dropped"},
		{"podman list short", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}, func(m map[string]any) { hc(m)["CapDrop"] = []any{"CAP_CHOWN"} }, "capabilities dropped"},
		{"docker does not get the podman list", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) {
			hc(m)["CapDrop"] = []any{"CHOWN", "DAC_OVERRIDE", "FOWNER", "FSETID", "KILL", "NET_BIND_SERVICE", "SETFCAP", "SETGID", "SETPCAP", "SETUID", "SYS_CHROOT"}
		}, "capabilities dropped"},
		{"no nnp", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["SecurityOpt"] = []any{} }, "no-new-privileges"},
		{"seccomp off", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) {
			hc(m)["SecurityOpt"] = []any{"no-new-privileges", "seccomp=unconfined"}
		}, "seccomp"},
		{"seccomp off (colon)", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}, func(m map[string]any) {
			hc(m)["SecurityOpt"] = []any{"no-new-privileges", "seccomp:unconfined"}
		}, "seccomp"},
		{"podman pidns host", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}, func(m map[string]any) { hc(m)["PidMode"] = "host" }, "pid namespace"},
		{"docker pid of another container", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["PidMode"] = "container:abc" }, "pid namespace"},
		{"ipc host", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["IpcMode"] = "host" }, "ipc namespace"},
		{"uts host", "inspect_docker_v1.56.json", dockerRootless, UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true}, func(m map[string]any) { hc(m)["UTSMode"] = "host" }, "uts namespace"},
		{"device added", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}, func(m map[string]any) {
			hc(m)["Devices"] = []any{map[string]any{"PathOnHost": "/dev/kvm", "PathInContainer": "/dev/kvm", "CgroupPermissions": "rwm"}}
		}, "devices"},
		{"no pid mode", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(hc(m), "PidMode") }, "parse"},
		{"no uts mode", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(hc(m), "UTSMode") }, "parse"},
		{"no devices", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(hc(m), "Devices") }, "parse"},
		{"devices garbled", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["Devices"] = "all" }, "parse"},
		{"writable root", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["ReadonlyRootfs"] = false }, "read-only root"},
		{"container root on rootful", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { m["Config"].(map[string]any)["User"] = "" }, "user"},
		{"keep-id not applied", "inspect_podman_libpod_v5.6.json", podmanRootless, UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}, func(m map[string]any) {
			hc(m)["IDMappings"] = map[string]any{"UidMap": []any{"0:1000:1", "1:100000:65536"}}
		}, "user namespace"},
		{"docker userns", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["UsernsMode"] = "private" }, "user namespace"},
		{"runsc", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["Runtime"] = "runsc" }, "runtime"},
		{"empty runtime", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["Runtime"] = "" }, "runtime"},
		{"other run label", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) {
			m["Config"].(map[string]any)["Labels"].(map[string]any)[LabelRun] = "someone-else-01"
		}, "labels"},
		{"socket bound in", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) {
			m["Mounts"] = append(m["Mounts"].([]any), map[string]any{"Type": "bind", "Source": "/run/docker.sock", "Destination": "/var/run/docker.sock", "RW": true})
		}, "mounts"},
		{"observer bin writable", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) {
			m["Mounts"].([]any)[1].(map[string]any)["RW"] = true
		}, "mounts"},
		{"workspace missing", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { m["Mounts"] = m["Mounts"].([]any)[1:] }, "mounts"},
		{"home tmpfs missing", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(hc(m)["Tmpfs"].(map[string]any), "/home/dev") }, "mounts"},
		{"npipe mount", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) {
			m["Mounts"] = append(m["Mounts"].([]any), map[string]any{"Type": "npipe", "Source": "x", "Destination": "/x", "RW": true})
		}, "mounts"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseInspect(mutate(t, c.file, c.edit), c.id.Engine)
			if c.want == "parse" {
				if err == nil {
					t.Fatal("a truncated inspect parsed")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			v := ReadBack(ReadBackInput{Identity: c.id, Plan: testPlan(c.user), Facts: f})
			if v.Code != VerdictBuiltBelowPlan || !strings.HasPrefix(v.Reason, c.want+":") {
				t.Fatalf("verdict = %v, want %s", v, c.want)
			}
		})
	}
}

// TestReadBackPidsLimit: a planned pids limit must come back set, and no
// higher than planned; a plan with none checks nothing.
func TestReadBackPidsLimit(t *testing.T) {
	plan := testPlan(rootfulUser)
	plan.PidsLimit = 4096
	for _, c := range []struct {
		name  string
		limit any
		ok    bool
	}{{"as planned", 4096, true}, {"lower", 512, true}, {"absent", nil, false}, {"unlimited", 0, false}, {"minus one", -1, false}, {"higher", 8192, false}} {
		t.Run(c.name, func(t *testing.T) {
			raw := mutate(t, "inspect_docker_v1.44.json", func(m map[string]any) {
				if c.limit == nil {
					delete(hc(m), "PidsLimit")
				} else {
					hc(m)["PidsLimit"] = c.limit
				}
			})
			f, err := ParseInspect(raw, EngineDocker)
			if err != nil {
				t.Fatal(err)
			}
			v := ReadBack(ReadBackInput{Identity: dockerRootful, Plan: plan, Facts: f})
			if v.OK() != c.ok || (!c.ok && !strings.HasPrefix(v.Reason, "pids limit:")) {
				t.Fatalf("verdict %v, want ok=%v", v, c.ok)
			}
		})
	}
}

// TestImageEnvRefusal: an image whose own ENV names a routing, proxy, loader
// or git variable is refused, naming every one; an ordinary image passes.
func TestImageEnvRefusal(t *testing.T) {
	if v := ImageEnvRefusal([]string{"PATH=/usr/local/bin:/usr/bin", "LANG=C.UTF-8", "NODE_ENV=production", "PYTHONUNBUFFERED=1", "GOPATH=/go"}); !v.OK() {
		t.Fatalf("an ordinary image was refused: %v", v)
	}
	bad := []string{
		"ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY", "https_proxy", "LD_PRELOAD", "LD_LIBRARY_PATH",
		"NODE_OPTIONS", "PYTHONPATH", "PYTHONSTARTUP", "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "MYTOOL_BASE_URL", "OBSERVER_PROXY_PORT", "DOCKER_HOST",
	}
	env := []string{"PATH=/usr/bin"}
	for _, k := range bad {
		env = append(env, k+"=x")
	}
	v := ImageEnvRefusal(env)
	if v.Code != VerdictBuiltBelowPlan {
		t.Fatalf("verdict %v", v)
	}
	for _, k := range bad {
		if !strings.Contains(v.Reason, k) {
			t.Errorf("the refusal does not name %s: %s", k, v.Reason)
		}
	}
	named, _, _ := strings.Cut(strings.TrimPrefix(v.Reason, "the image's own environment sets "), ", which")
	for _, n := range strings.Split(named, ", ") {
		if n == "PATH" {
			t.Errorf("PATH named: %s", v.Reason)
		}
	}
}

func TestParseInspectGarbage(t *testing.T) {
	for _, raw := range []string{"", "{", "[]", `{"State":"x"}`} {
		if _, err := ParseInspect([]byte(raw), EngineDocker); err == nil {
			t.Errorf("%q parsed", raw)
		}
	}
}

// TestReadBackNullIsEmpty (live checks 2026-10-22, D1): Docker answers JSON
// null for a list it was never sent ("Devices": null on Docker 26.1.5,
// 28.1.1, 29.8.2 and 29.9.2). Null is the empty list, judged by the rule
// rows on its content: no devices passes, nothing dropped or no security
// option or no mount or no label refuses at its own row, never as a parse
// error and never as the planned value.
func TestReadBackNullIsEmpty(t *testing.T) {
	podmanUser := UserPlan{User: "1000:1000", ExpectUIDMap: "1000:0:1"}
	dockerRootlessUser := UserPlan{Row: "rootless docker", User: "0:0", ContainerRootIsHostUser: true}
	cases := []struct {
		name string
		file string
		id   Identity
		user UserPlan
		edit func(m map[string]any)
		want string // "" passes, else the refusing rule
	}{
		{"docker 29.9 devices null", "inspect_docker_v1.56.json", dockerRootless, dockerRootlessUser, func(m map[string]any) { hc(m)["Devices"] = nil }, ""},
		{"docker 26.1 shape devices null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["Devices"] = nil }, ""},
		{"podman devices null", "inspect_podman_libpod_v5.6.json", podmanRootless, podmanUser, func(m map[string]any) { hc(m)["Devices"] = nil }, ""},
		{"capdrop null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["CapDrop"] = nil }, "capabilities dropped"},
		{"securityopt null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["SecurityOpt"] = nil }, "no-new-privileges"},
		{"mounts null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { m["Mounts"] = nil }, "mounts"},
		{"labels null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { m["Config"].(map[string]any)["Labels"] = nil }, "labels"},
		{"pidslimit null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["PidsLimit"] = nil }, ""},
		{"tmpfs null", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, func(m map[string]any) { hc(m)["Tmpfs"] = nil }, "mounts"},
		{"a device next to a null-safe parse still refuses", "inspect_docker_v1.49_api_created.json", dockerRootful, rootfulUser, func(m map[string]any) {
			hc(m)["Devices"] = []any{map[string]any{"PathOnHost": "/dev/fuse", "PathInContainer": "/dev/fuse", "CgroupPermissions": "rwm"}}
		}, "devices"},
		{"recorded api create, no devices key", "inspect_docker_v1.49_api_created.json", dockerRootful, rootfulUser, func(m map[string]any) { delete(hc(m), "Devices") }, "parse"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseInspect(mutate(t, c.file, c.edit), c.id.Engine)
			if c.want == "parse" {
				if err == nil {
					t.Fatal("an answer without the key parsed")
				}
				return
			}
			if err != nil {
				t.Fatalf("a null field was read as missing: %v", err)
			}
			v := ReadBack(ReadBackInput{Identity: c.id, Plan: testPlan(c.user), Facts: f})
			if c.want == "" {
				if !v.OK() {
					t.Fatalf("refused: %v", v)
				}
				return
			}
			if v.Code != VerdictBuiltBelowPlan || !strings.HasPrefix(v.Reason, c.want+":") {
				t.Fatalf("verdict = %v, want %s", v, c.want)
			}
		})
	}
}

// TestReadBackBareCreateNullForms: the recorded inspect of a bare create on
// Docker Engine 28.1.1 (only an image) carries every null form Docker
// sends (CapDrop, CapAdd, SecurityOpt, Devices, Ulimits and PidsLimit null;
// HostConfig.Tmpfs omitted; top-level Mounts [] and Config.Labels {}). It
// parses, and the re-check refuses it on content.
func TestReadBackBareCreateNullForms(t *testing.T) {
	f, err := ParseInspect(readFixture(t, "inspect_docker_v1.49_bare.json"), EngineDocker)
	if err != nil {
		t.Fatalf("the bare create's null forms did not parse: %v", err)
	}
	if len(f.CapDrop) != 0 || len(f.SecurityOpt) != 0 || len(f.Devices) != 0 || f.PidsLimit != nil || len(f.Mounts) != 0 || f.Labels == nil {
		t.Fatalf("facts %+v", f)
	}
	if v := ReadBack(ReadBackInput{Identity: dockerRootful, Plan: testPlan(rootfulUser), Facts: f}); v.Code != VerdictBuiltBelowPlan {
		t.Fatalf("a bare container passed the re-check: %v", v)
	}
	if _, err := ParseInspect(readFixture(t, "inspect_docker_v1.44.json"), Engine("")); err == nil {
		t.Fatal("an answer from an engine with no recorded shape parsed")
	}
}

// TestReadBackTmpfsOwnerPerEngine (live check 2026-10-22, D5): the
// read-back requires each writable tmpfs to carry the container user as
// owner in the form of the engine that answered: uid= and gid= matching
// the plan's user on Docker, the U option on Podman. Docker's row is the
// shape Docker 29.9.2 read back live; Podman's U shape is the stored option
// list libpod's inspect joins (container_inspect.go), with the defaults
// ProcessOptions appends for a tmpfs (5.7.0 source, not a live inspect).
func TestReadBackTmpfsOwnerPerEngine(t *testing.T) {
	podmanUser := UserPlan{Row: "rootless podman, keep-id", User: "1000:1000", UsernsMode: "keep-id", ExpectUIDMap: "1000:0:1"}
	setTmpfs := func(v string) func(m map[string]any) {
		return func(m map[string]any) {
			hc(m)["Tmpfs"] = map[string]any{"/home/dev": v, "/tmp": v}
		}
	}
	cases := []struct {
		name string
		file string
		id   Identity
		user UserPlan
		edit func(m map[string]any)
		ok   bool
	}{
		{"docker uid and gid", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700,uid=1000,gid=1000"), true},
		{"docker without owner", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700"), false},
		{"docker another uid", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700,uid=0,gid=0"), false},
		{"docker U only", "inspect_docker_v1.44.json", dockerRootful, rootfulUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700,U"), false},
		{"podman U", "inspect_podman_libpod_v5.6.json", podmanRootless, podmanUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700,U,private,tmpcopyup"), true},
		{"podman without U", "inspect_podman_libpod_v5.6.json", podmanRootless, podmanUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700,private,tmpcopyup"), false},
		{"podman uid form", "inspect_podman_libpod_v5.6.json", podmanRootless, podmanUser, setTmpfs("rw,nosuid,nodev,size=1073741824,mode=0700,uid=1000,gid=1000"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f, err := ParseInspect(mutate(t, c.file, c.edit), c.id.Engine)
			if err != nil {
				t.Fatal(err)
			}
			v := ReadBack(ReadBackInput{Identity: c.id, Plan: testPlan(c.user), Facts: f})
			if v.OK() != c.ok {
				t.Fatalf("ok=%v, want %v: %v", v.OK(), c.ok, v)
			}
			if !c.ok && (v.Code != VerdictBuiltBelowPlan || !strings.Contains(v.Reason, "not owned by the container user")) {
				t.Fatalf("refusal %v", v)
			}
		})
	}
}
