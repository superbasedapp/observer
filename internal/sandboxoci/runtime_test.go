package sandboxoci

import (
	"encoding/json"
	"strings"
	"testing"
)

// runtime_test.go: the oci-runsc row (lane SBX-P3B). The runtime column is
// data: the create asks for runsc, the read-back requires the engine to
// report runsc, and the row's own probe decides the socket bridge.

func runscInfo(args ...string) InfoFacts {
	return InfoFacts{ID: "d1", Runtimes: map[string]RuntimeInfo{
		"runc":  {Path: "runc"},
		"runsc": {Path: "/usr/local/bin/runsc", Args: args},
	}}
}

func TestRuntimeProfiles(t *testing.T) {
	runc, ok := RuntimeProfileFor(RuntimeOCIRunc)
	if !ok || runc.CreateRuntime != "" || runc.CrossesKernel || runc.Bridge != BridgeBoundDir {
		t.Fatalf("oci-runc profile %+v", runc)
	}
	runsc, ok := RuntimeProfileFor(RuntimeOCIRunsc)
	if !ok || runsc.CreateRuntime != "runsc" || !runsc.CrossesKernel || runsc.Bridge != BridgeHostUDS {
		t.Fatalf("oci-runsc profile %+v", runsc)
	}
	if _, ok := RuntimeProfileFor("oci-kata"); ok {
		t.Fatal("a row with no profile has one")
	}
}

func TestHostUDSMode(t *testing.T) {
	cases := map[string][]string{
		"open": {"--host-uds=open"},
		"all":  {"--debug", "-host-uds=ALL"},
		"none": {"--host-uds", "none"},
		"":     {"--platform=systrap"},
	}
	for want, args := range cases {
		if got := HostUDSMode(args); got != want {
			t.Errorf("HostUDSMode(%v) = %q, want %q", args, got, want)
		}
	}
}

// TestCheckRuntime: one case per row of the runtime check.
func TestCheckRuntime(t *testing.T) {
	runsc, _ := RuntimeProfileFor(RuntimeOCIRunsc)
	runc, _ := RuntimeProfileFor(RuntimeOCIRunc)
	cases := []struct {
		name string
		p    RuntimeProfile
		id   Identity
		info InfoFacts
		want string
	}{
		{"runc anywhere", runc, podmanRootless, InfoFacts{}, VerdictAvailable},
		{"zero profile is runc", RuntimeProfile{}, dockerRootless, InfoFacts{}, VerdictAvailable},
		{"runsc with host-uds open", runsc, dockerRootful, runscInfo("--host-uds=open"), VerdictAvailable},
		{"runsc with host-uds all", runsc, dockerRootful, runscInfo("--host-uds=all"), VerdictAvailable},
		{"runsc without host-uds", runsc, dockerRootful, runscInfo(), VerdictSocketBridgeUnavailable},
		{"runsc host-uds create only", runsc, dockerRootful, runscInfo("--host-uds=create"), VerdictSocketBridgeUnavailable},
		{"runsc not registered", runsc, dockerRootful, InfoFacts{Runtimes: map[string]RuntimeInfo{"runc": {Path: "runc"}}}, VerdictRuntimeMissing},
		{"runsc on podman", runsc, podmanRootless, runscInfo("--host-uds=open"), VerdictRuntimeMissing},
		{"runsc on rootless docker", runsc, dockerRootless, runscInfo("--host-uds=open"), VerdictRuntimeMissing},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, v := CheckRuntime(c.p, c.id, c.info)
			if v.Code != c.want {
				t.Fatalf("verdict %v, want %s", v, c.want)
			}
			if v.OK() && b == "" {
				t.Fatal("no bridge named")
			}
			if c.want == VerdictSocketBridgeUnavailable && !strings.Contains(v.Reason, "--host-uds=open") {
				t.Fatalf("the remedy is not named: %s", v.Reason)
			}
		})
	}
}

// TestBuildCreateRuntime: an oci-runc body carries no Runtime key (byte
// for byte as before the oci-runsc row); an oci-runsc body asks for runsc;
// an unknown runtime is refused.
func TestBuildCreateRuntime(t *testing.T) {
	p := testPlan(rootfulUser)
	_, body, err := BuildCreate(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), `"Runtime"`) {
		t.Fatalf("an engine-default body names a runtime: %s", raw)
	}
	p.Runtime = "runsc"
	_, body, err = BuildCreate(p)
	if err != nil || body.HostConfig.Runtime != "runsc" {
		t.Fatalf("runsc body %+v %v", body.HostConfig.Runtime, err)
	}
	p.Runtime = "kata-qemu"
	if _, _, err := BuildCreate(p); err == nil {
		t.Fatal("an unknown runtime was accepted")
	}
}

// TestReadBackRuntimeRow: the engine must report the planned runtime.
func TestReadBackRuntimeRow(t *testing.T) {
	base, err := ParseInspect(readFixture(t, "inspect_docker_v1.44.json"), EngineDocker)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name    string
		planned string
		got     string
		ok      bool
	}{
		{"runc plan, runc", "", "runc", true},
		{"runc plan, crun", "", "crun", true},
		{"runc plan, runsc", "", "runsc", false},
		{"runsc plan, runsc", "runsc", "runsc", true},
		{"runsc plan, runc", "runsc", "runc", false},
		{"runsc plan, empty", "runsc", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := testPlan(rootfulUser)
			p.Runtime = c.planned
			f := base
			f.Runtime = c.got
			v := ReadBack(ReadBackInput{Identity: dockerRootful, Plan: p, Facts: f})
			if v.OK() != c.ok {
				t.Fatalf("read-back %v, want ok %v", v, c.ok)
			}
			if !c.ok && (v.Code != VerdictBuiltBelowPlan || !strings.Contains(v.Reason, "runtime")) {
				t.Fatalf("refusal %v", v)
			}
		})
	}
}

// TestProbeRuntimeRow: the ladder's runtime row (P7b) on a rootful Docker
// host with runsc registered, without the host-UDS flag, and on the
// default rootless host.
func TestProbeRuntimeRow(t *testing.T) {
	runsc, _ := RuntimeProfileFor(RuntimeOCIRunsc)
	rootful := func(info InfoFacts) ProbeEnv {
		e := probeEnv()
		e.Config.AllowRootful = true
		e.StatSocket = func(p string) (SocketFacts, error) {
			return SocketFacts{Path: p, Exists: true, IsSocket: true, UID: 0, GID: 999, Mode: 0o660, Parents: goodParents()}, nil
		}
		e.Groups = []uint32{999}
		e.Endpoint = EndpointEnv{Exists: func(p string) bool { return p == "/run/docker.sock" }}
		e.Query = func(string) (VersionFacts, InfoFacts, error) { return dockerVersion, info, nil }
		e.Runtime = runsc
		return e
	}
	if r := Probe(rootful(runscInfo("--host-uds=open"))); !r.Verdict.OK() || r.Bridge != BridgeHostUDS {
		t.Fatalf("healthy runsc host: %+v", r)
	}
	if r := Probe(rootful(runscInfo())); r.Verdict.Code != VerdictSocketBridgeUnavailable || r.Rule != "P7b runtime" {
		t.Fatalf("no host-uds: %v at %s", r.Verdict, r.Rule)
	}
	e := probeEnv()
	e.Runtime = runsc
	if r := Probe(e); r.Verdict.Code != VerdictRuntimeMissing || r.Rule != "P7b runtime" {
		t.Fatalf("rootless host: %v at %s", r.Verdict, r.Rule)
	}
	if r := Probe(probeEnv()); !r.Verdict.OK() || r.Bridge != BridgeBoundDir {
		t.Fatalf("oci-runc host: %+v", r)
	}
}

// TestStateModeAndProjection: projection keys on CrossesKernel, and the
// plan maps each state path onto an indexed per-run directory.
func TestStateModeAndProjection(t *testing.T) {
	if StateModeFor(false) != StateBind || StateModeFor(true) != StateProject {
		t.Fatal("the projection rule does not key on CrossesKernel")
	}
	got, err := PlanProjection("/home/dev/.observer/workspaces/r1.state", "/home/dev", []string{".claude", ".config/x", ".claude"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != (ProjectedDir{Host: "/home/dev/.observer/workspaces/r1.state/0", Target: "/home/dev/.claude"}) ||
		got[1].Target != "/home/dev/.config/x" || got[1].Host != "/home/dev/.observer/workspaces/r1.state/1" {
		t.Fatalf("projection %+v", got)
	}
	for _, bad := range []string{"../etc", "/etc", "", ".", "a/../../b"} {
		if _, err := PlanProjection("/r", "/home/dev", []string{bad}); err == nil {
			t.Errorf("state path %q accepted", bad)
		}
	}
	if _, err := PlanProjection("rel", "/home/dev", nil); err == nil {
		t.Error("a relative root accepted")
	}
}

// TestDeliveryOnProjectedState: an image's own copy of the tool runs only
// on projected state (Opus M19).
func TestDeliveryOnProjectedState(t *testing.T) {
	if d, v := PlanToolDelivery(ToolFacts{ImageHasTool: true, StateProjected: true}); !v.OK() || d != DeliveryImageInstalled {
		t.Fatalf("projected: %s %v", d, v)
	}
	if _, v := PlanToolDelivery(ToolFacts{ImageHasTool: true}); v.OK() {
		t.Fatal("the image's tool ran on the real state")
	}
	if d, v := PlanToolDelivery(ToolFacts{HostBinary: "/usr/bin/claude", StateProjected: true}); !v.OK() || d != DeliveryHostBind {
		t.Fatalf("a static host binary on projected state: %s %v", d, v)
	}
}

// TestRuntimeHintNone (Linux live re-check on the Docker sandbox
// 2026-10-23, N2): the crun hint for rootless Podman on runc is gone with
// its cause (the create's BindOptions, bindOptionsTable), and no engine,
// mode or runtime gets a hint today.
func TestRuntimeHintNone(t *testing.T) {
	runc, _ := RuntimeProfileFor(RuntimeOCIRunc)
	runsc, _ := RuntimeProfileFor(RuntimeOCIRunsc)
	podman := Identity{Engine: EnginePodman, Mode: ModeRootless}
	cases := []struct {
		name string
		p    RuntimeProfile
		id   Identity
		rt   string
	}{
		{"rootless podman on runc", runc, podman, "runc"},
		{"zero profile is oci-runc", RuntimeProfile{}, podman, "runc"},
		{"rootless podman on crun", runc, podman, "crun"},
		{"runtime not read", runc, podman, ""},
		{"rootful podman on runc", runc, Identity{Engine: EnginePodman, Mode: ModeRootful}, "runc"},
		{"docker", runc, Identity{Engine: EngineDocker, Mode: ModeRootless}, "runc"},
		{"a row naming its runtime", runsc, podman, "runc"},
	}
	for _, c := range cases {
		if got := RuntimeHint(c.p, c.id, InfoFacts{PodmanOCIRuntime: c.rt}); got != "" {
			t.Errorf("%s: hint %q", c.name, got)
		}
	}
}
