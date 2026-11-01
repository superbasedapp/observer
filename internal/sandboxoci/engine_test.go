package sandboxoci

import (
	"strings"
	"testing"
)

func bp(b bool) *bool { return &b }

var (
	dockerVersion = VersionFacts{Version: "29.9.1", APIVersion: "1.52", PlatformName: "Docker Engine - Community", Components: []string{"Engine", "containerd", "runc"}}
	podmanVersion = VersionFacts{Version: "5.6.2", APIVersion: "1.41", PlatformName: "linux/amd64/ubuntu-24.04", Components: []string{"Podman Engine", "Conmon", "OCI Runtime (crun)"}}
)

func TestClassify(t *testing.T) {
	cases := []struct {
		name    string
		v       VersionFacts
		i       InfoFacts
		engine  Engine
		mode    Mode
		remap   bool
		verdict string
	}{
		{"rootful docker", dockerVersion, InfoFacts{ID: "abc", SecurityOptions: []string{"name=seccomp,profile=builtin", "name=cgroupns"}}, EngineDocker, ModeRootful, false, VerdictAvailable},
		{"rootless docker", dockerVersion, InfoFacts{ID: "abc", SecurityOptions: []string{"name=seccomp,profile=builtin", "name=rootless", "name=cgroupns"}}, EngineDocker, ModeRootless, false, VerdictAvailable},
		{"userns-remap docker", dockerVersion, InfoFacts{SecurityOptions: []string{"name=userns"}}, EngineDocker, ModeRootful, true, VerdictAvailable},
		{"rootless podman (libpod says)", podmanVersion, InfoFacts{PodmanRootless: bp(true)}, EnginePodman, ModeRootless, false, VerdictAvailable},
		{"rootful podman (libpod overrides a stray option)", podmanVersion, InfoFacts{SecurityOptions: []string{"name=rootless"}, PodmanRootless: bp(false)}, EnginePodman, ModeRootful, false, VerdictAvailable},
		{"desktop by OS", dockerVersion, InfoFacts{OperatingSystem: "Docker Desktop"}, "", "", false, VerdictEngineIsDesktopVM},
		{"desktop by name", dockerVersion, InfoFacts{Name: "docker-desktop"}, "", "", false, VerdictEngineIsDesktopVM},
		{"desktop by kernel", dockerVersion, InfoFacts{KernelVersion: "6.6.32-linuxkit"}, "", "", false, VerdictEngineIsDesktopVM},
		{"unknown engine", VersionFacts{Version: "1.0", PlatformName: "containerd"}, InfoFacts{}, "", "", false, VerdictEngineModeUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, v := Classify(c.v, c.i)
			if v.Code != c.verdict {
				t.Fatalf("verdict %v, want %s", v, c.verdict)
			}
			if !v.OK() {
				return
			}
			if id.Engine != c.engine || id.Mode != c.mode || id.UsernsRemap != c.remap || id.Fingerprint == "" {
				t.Fatalf("identity %+v", id)
			}
		})
	}
}

// TestCompareIdentity is A9's third case: a daemon whose identity changed
// since first use is refused.
func TestCompareIdentity(t *testing.T) {
	a, _ := Classify(dockerVersion, InfoFacts{ID: "daemon-a", SecurityOptions: []string{"name=rootless"}})
	b, _ := Classify(dockerVersion, InfoFacts{ID: "daemon-b", SecurityOptions: []string{"name=rootless"}})
	if first, v := CompareIdentity(Identity{}, false, a); !first || !v.OK() {
		t.Fatal("first use must record")
	}
	if first, v := CompareIdentity(a, true, a); first || !v.OK() {
		t.Fatal("the same daemon must pass")
	}
	if _, v := CompareIdentity(a, true, b); v.Code != VerdictSocketUntrusted {
		t.Fatalf("a changed daemon passed: %v", v)
	}
}

// TestPlanUser is the uid table of section 4.6, one case per row.
func TestPlanUser(t *testing.T) {
	podmanRootful := Identity{Engine: EnginePodman, Mode: ModeRootful}
	cases := []struct {
		name    string
		id      Identity
		uid     int
		userns  PodmanUserns
		rootful bool
		user    string
		userns2 string
		uidmap  string
		verdict string
	}{
		{"rootless podman keep-id (default)", podmanRootless, 1000, "", false, "1000:1000", "keep-id", "1000:0:1", VerdictAvailable},
		{"rootless podman default ns", podmanRootless, 1000, PodmanDefault, false, "0:0", "", "", VerdictAvailable},
		{"rootless docker", dockerRootless, 1000, "", false, "0:0", "", "", VerdictAvailable},
		{"rootful docker opt-in", dockerRootful, 1000, "", true, "1000:1000", "", "", VerdictAvailable},
		{"rootful podman opt-in", podmanRootful, 1000, "", true, "1000:1000", "", "", VerdictAvailable},
		{"rootful without opt-in", dockerRootful, 1000, "", false, "", "", "", VerdictSocketUntrusted},
		{"rootful with a root daemon", dockerRootful, 0, "", true, "", "", "", VerdictEngineModeUnsupported},
		{"userns-remap", Identity{Engine: EngineDocker, Mode: ModeRootful, UsernsRemap: true}, 1000, "", true, "", "", "", VerdictEngineModeUnsupported},
		{"unknown engine", Identity{Engine: "lxd", Mode: ModeRootless}, 1000, "", false, "", "", "", VerdictEngineModeUnsupported},
		{"bad userns setting", podmanRootless, 1000, "auto", false, "", "", "", VerdictEngineModeUnsupported},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, v := PlanUser(c.id, c.uid, c.uid, c.userns, c.rootful)
			if v.Code != c.verdict {
				t.Fatalf("verdict %v, want %s", v, c.verdict)
			}
			if !v.OK() {
				return
			}
			if p.User != c.user || p.UsernsMode != c.userns2 || p.ExpectUIDMap != c.uidmap || p.Row == "" {
				t.Fatalf("plan %+v", p)
			}
			// Container root only where root IS the host user.
			if strings.HasPrefix(p.User, "0:") != p.ContainerRootIsHostUser {
				t.Fatalf("root row %+v", p)
			}
		})
	}
}

func TestJudgeVersion(t *testing.T) {
	cases := []struct {
		id   Identity
		want VersionStatus
	}{
		{Identity{Engine: EngineDocker, APIVersion: "1.43"}, VersionRefused},
		{Identity{Engine: EngineDocker, APIVersion: "1.44"}, VersionTested},
		{Identity{Engine: EngineDocker, APIVersion: "1.52"}, VersionTested},
		{Identity{Engine: EngineDocker, APIVersion: "1.57"}, VersionBeta},
		{Identity{Engine: EngineDocker, APIVersion: ""}, VersionRefused},
		{Identity{Engine: EnginePodman, Version: "4.9.2", APIVersion: "1.41"}, VersionRefused},
		{Identity{Engine: EnginePodman, Version: "4.9.3", APIVersion: "1.41"}, VersionTested},
		{Identity{Engine: EnginePodman, Version: "6.1.4", APIVersion: "1.41"}, VersionBeta},
		{Identity{Engine: "x", Version: "1"}, VersionRefused},
	}
	for _, c := range cases {
		if got, _ := JudgeVersion(c.id); got != c.want {
			t.Errorf("%+v: %s, want %s", c.id, got, c.want)
		}
	}
}

func TestNegotiateAPI(t *testing.T) {
	for in, want := range map[string]string{"1.41": "1.41", "1.44": "1.44", "1.52": "1.52", "1.56": "1.56", "1.60": "1.56", "1.44.1": "1.44"} {
		if got, err := NegotiateAPI(in); err != nil || got != want {
			t.Errorf("%s: %q %v, want %s", in, got, err, want)
		}
	}
	for _, in := range []string{"1.40", "", "x"} {
		if _, err := NegotiateAPI(in); err == nil {
			t.Errorf("%q negotiated", in)
		}
	}
}

func TestInitPlanAndExit(t *testing.T) {
	p := ContainerInit()
	if p.NewSession || !p.NewProcessGroup || !p.Foreground || !p.ReapAll {
		t.Fatalf("plan %+v: never setsid in a container (JSP-4)", p)
	}
	if strings.Join(p.Ignore, ",") != "SIGTTOU,SIGTTIN" {
		t.Fatalf("ignore %v", p.Ignore)
	}
	for _, c := range []struct {
		exited, signaled bool
		code, sig, want  int
	}{{true, false, 42, 0, 42}, {false, true, 0, 15, 143}, {false, true, 0, 2, 130}, {false, false, 0, 0, 255}} {
		if got := ExitCode(c.exited, c.code, c.signaled, c.sig); got != c.want {
			t.Errorf("%+v: %d", c, got)
		}
	}
	if WaitCondition != "next-exit" {
		t.Fatal("the wait must be the next exit, opened before start")
	}
	for _, a := range []HelperAction{ActionAttach, ActionSignal, ActionStop, ActionResize} {
		if Allowed(a, false) || !Allowed(a, true) {
			t.Errorf("%s on a stopped container must be refused (Podman rewrites its exit status)", a)
		}
	}
	if !Allowed(ActionRemove, false) {
		t.Error("remove is the teardown")
	}
}

// TestFingerprintStableFields (live checks 2026-10-22, D2): Podman 5.7's
// compatible /info answers a new random ID on every call, so the Podman
// fingerprint reads only the facts that stay put (host name, storage
// root); Docker's persistent engine id still counts. A changed daemon is
// refused naming the fact that changed.
func TestFingerprintStableFields(t *testing.T) {
	podman57 := VersionFacts{Version: "5.7.0", APIVersion: "1.41", PlatformName: "linux/amd64/ubuntu-26.04", Components: []string{"Podman Engine"}}
	info := func(id, name, root string) InfoFacts {
		return InfoFacts{ID: id, Name: name, DockerRootDir: root, OperatingSystem: "ubuntu", SecurityOptions: []string{"name=seccomp,profile=default", "name=rootless"}, PodmanRootless: bp(true)}
	}
	first, _ := Classify(podman57, info("07523748-3b1c-4c7e-9a51-2f0d8e6b1a90", "box", "/home/agent/.local/share/containers/storage"))
	second, _ := Classify(podman57, info("db60ef60-5e2a-4f19-8c3d-7a4b9e0c2d17", "box", "/home/agent/.local/share/containers/storage"))
	if _, v := CompareIdentity(first, true, second); !v.OK() {
		t.Fatalf("podman's per-call /info ID made the same daemon untrusted: %v", v)
	}
	if _, ok := first.FingerprintFields["engine id"]; ok {
		t.Fatalf("the podman fingerprint covers its random ID: %v", first.FingerprintFields)
	}
	other, _ := Classify(podman57, info("x", "box", "/home/other/.local/share/containers/storage"))
	if _, v := CompareIdentity(first, true, other); v.Code != VerdictSocketUntrusted || !strings.Contains(v.Reason, "its engine root directory changed") {
		t.Fatalf("another podman's storage root passed or was not named: %v", v)
	}
	// Docker: the engine id is stable and counts.
	a, _ := Classify(dockerVersion, InfoFacts{ID: "daemon-a", Name: "box", DockerRootDir: "/var/lib/docker"})
	b, _ := Classify(dockerVersion, InfoFacts{ID: "daemon-b", Name: "box", DockerRootDir: "/var/lib/docker"})
	if _, v := CompareIdentity(a, true, b); v.Code != VerdictSocketUntrusted || !strings.Contains(v.Reason, "its engine id changed") {
		t.Fatalf("a changed docker engine id was not named: %v", v)
	}
	// The digest of a Docker identity is the one recorded before the
	// per-engine table (engine, mode, ID, Name, root dir in that order).
	legacy := a
	legacy.FingerprintFields = nil
	if _, v := CompareIdentity(legacy, true, a); !v.OK() {
		t.Fatalf("a docker identity recorded by an older build no longer matches: %v", v)
	}
	if _, v := CompareIdentity(legacy, true, b); v.Code != VerdictSocketUntrusted || !strings.Contains(v.Reason, "older build") {
		t.Fatalf("an old record's refusal does not say the fact is unknown: %v", v)
	}
	// A rootful daemon behind a rootless one's socket names the mode.
	rootful := a
	rootful.Mode = ModeRootless
	if _, v := CompareIdentity(a, true, rootful); v.Code != VerdictSocketUntrusted || !strings.Contains(v.Reason, "its privilege mode changed") {
		t.Fatalf("a changed mode was not named: %v", v)
	}
}
