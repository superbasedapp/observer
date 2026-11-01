package sandboxoci

import (
	"errors"
	"strings"
	"testing"
)

// TestResolveEndpoint covers A9's TCP case and the default ladder.
func TestResolveEndpoint(t *testing.T) {
	exists := func(set ...string) func(string) bool {
		return func(p string) bool {
			for _, s := range set {
				if s == p {
					return true
				}
			}
			return false
		}
	}
	cases := []struct {
		name, configured string
		env              EndpointEnv
		want, verdict    string
	}{
		{"configured unix", "unix:///run/user/1000/podman/podman.sock", EndpointEnv{}, "/run/user/1000/podman/podman.sock", VerdictAvailable},
		{"configured path", "/run/user/1000/docker.sock", EndpointEnv{DockerHost: "tcp://x:2375"}, "/run/user/1000/docker.sock", VerdictAvailable},
		{"configured tcp", "tcp://127.0.0.1:2375", EndpointEnv{}, "", VerdictSocketUntrusted},
		{"DOCKER_HOST tcp", "", EndpointEnv{DockerHost: "tcp://10.0.0.5:2376"}, "", VerdictSocketUntrusted},
		{"DOCKER_HOST ssh", "", EndpointEnv{DockerHost: "ssh://me@box"}, "", VerdictSocketUntrusted},
		{"DOCKER_HOST relative", "", EndpointEnv{DockerHost: "unix://run/docker.sock"}, "", VerdictSocketUntrusted},
		{"DOCKER_HOST unclean", "", EndpointEnv{DockerHost: "unix:///run/../tmp/docker.sock"}, "", VerdictSocketUntrusted},
		{"DOCKER_HOST unix", "", EndpointEnv{DockerHost: "unix:///run/docker.sock"}, "/run/docker.sock", VerdictAvailable},
		{"CONTAINER_HOST", "", EndpointEnv{ContainerHost: "unix:///run/user/1000/podman/podman.sock"}, "/run/user/1000/podman/podman.sock", VerdictAvailable},
		{"rootless first", "", EndpointEnv{RuntimeDir: "/run/user/1000", Exists: exists("/run/docker.sock", "/run/user/1000/docker.sock")}, "/run/user/1000/docker.sock", VerdictAvailable},
		{"rootful fallback", "", EndpointEnv{RuntimeDir: "/run/user/1000", Exists: exists("/run/docker.sock")}, "/run/docker.sock", VerdictAvailable},
		{"none", "", EndpointEnv{RuntimeDir: "/run/user/1000", Exists: exists()}, "", VerdictEngineUnreachable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, v := ResolveEndpoint(c.configured, c.env)
			if v.Code != c.verdict || got != c.want {
				t.Fatalf("%q %v, want %q %s", got, v, c.want, c.verdict)
			}
		})
	}
}

func goodParents() []PathFact {
	return []PathFact{{Path: "/", UID: 0, Mode: 0o755}, {Path: "/run", UID: 0, Mode: 0o755}, {Path: "/run/user", UID: 0, Mode: 0o755}, {Path: "/run/user/1000", UID: 1000, Mode: 0o700}}
}

// TestValidateSocket covers A9's symlink case and the ownership rules.
func TestValidateSocket(t *testing.T) {
	user := SocketFacts{Path: "/run/user/1000/docker.sock", Exists: true, IsSocket: true, UID: 1000, GID: 1000, Mode: 0o660, Parents: goodParents()}
	root := SocketFacts{Path: "/run/docker.sock", Exists: true, IsSocket: true, UID: 0, GID: 998, Mode: 0o660, Parents: goodParents()[:2]}
	cases := []struct {
		name    string
		f       SocketFacts
		uid     uint32
		groups  []uint32
		rootful bool
		owner   SocketOwner
		verdict string
	}{
		{"own socket", user, 1000, nil, false, OwnerUser, VerdictAvailable},
		{"symlinked parent", func() SocketFacts {
			f := user
			f.Parents = append(goodParents(), PathFact{Path: "/run/user/1000/x", Symlink: true})
			return f
		}(), 1000, nil, false, "", VerdictSocketUntrusted},
		{"socket is a symlink", func() SocketFacts { f := user; f.IsSocket = false; return f }(), 1000, nil, false, "", VerdictSocketUntrusted},
		{"missing", func() SocketFacts { f := user; f.Exists = false; return f }(), 1000, nil, false, "", VerdictEngineUnreachable},
		{"world writable socket", func() SocketFacts { f := user; f.Mode = 0o666; return f }(), 1000, nil, false, "", VerdictSocketUntrusted},
		{"world writable parent", func() SocketFacts { f := user; f.Parents = []PathFact{{Path: "/tmp", Mode: 0o777}}; return f }(), 1000, nil, false, "", VerdictSocketUntrusted},
		{"sticky parent is fine", func() SocketFacts { f := user; f.Parents = []PathFact{{Path: "/tmp", Mode: 0o1777}}; return f }(), 1000, nil, false, OwnerUser, VerdictAvailable},
		{"parent of another user", func() SocketFacts {
			f := user
			f.Parents = []PathFact{{Path: "/home/eve", UID: 1001, Mode: 0o755}}
			return f
		}(), 1000, nil, false, "", VerdictSocketUntrusted},
		{"another user's socket", func() SocketFacts { f := user; f.UID = 1001; return f }(), 1000, nil, false, "", VerdictSocketUntrusted},
		{"rootful without opt-in", root, 1000, []uint32{998}, false, "", VerdictSocketUntrusted},
		{"rootful in group", root, 1000, []uint32{1000, 998}, true, OwnerRoot, VerdictAvailable},
		{"rootful not in group", root, 1000, []uint32{1000}, true, "", VerdictSocketUntrusted},
		{"rootful group read-only", func() SocketFacts { f := root; f.Mode = 0o640; return f }(), 1000, []uint32{998}, true, "", VerdictSocketUntrusted},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			owner, v := ValidateSocket(c.f, c.uid, c.groups, c.rootful)
			if v.Code != c.verdict || owner != c.owner {
				t.Fatalf("%q %v, want %q %s", owner, v, c.owner, c.verdict)
			}
		})
	}
}

func TestCheckOwnerMode(t *testing.T) {
	if !CheckOwnerMode(OwnerUser, dockerRootless).OK() || !CheckOwnerMode(OwnerRoot, dockerRootful).OK() {
		t.Fatal("agreeing owner and mode refused")
	}
	if CheckOwnerMode(OwnerUser, dockerRootful).OK() || CheckOwnerMode(OwnerRoot, dockerRootless).OK() {
		t.Fatal("a substituted socket passed")
	}
}

// probeEnv is a fully healthy rootless Docker host; each case breaks one
// thing.
func probeEnv() ProbeEnv {
	return ProbeEnv{
		Host: HostLinux, Active: true, UID: 1000, GID: 1000,
		Config:   ProbeConfig{Image: testImage},
		Endpoint: EndpointEnv{RuntimeDir: "/run/user/1000", Exists: func(p string) bool { return p == "/run/user/1000/docker.sock" }},
		StatSocket: func(p string) (SocketFacts, error) {
			return SocketFacts{Path: p, Exists: true, IsSocket: true, UID: 1000, GID: 1000, Mode: 0o660, Parents: goodParents()}, nil
		},
		Query: func(string) (VersionFacts, InfoFacts, error) {
			return dockerVersion, InfoFacts{ID: "d1", SecurityOptions: []string{"name=rootless"}}, nil
		},
		ImagePresent: func(string) (bool, error) { return true, nil },
		Resolvers:    func() []string { return []string{"1.1.1.1"} },
	}
}

// TestProbeLadder is one case per ladder row, with a guard that nothing is
// dialled before the socket passed and nothing at all while inactive.
func TestProbeLadder(t *testing.T) {
	dialled := false
	cases := []struct {
		name    string
		edit    func(e *ProbeEnv)
		verdict string
		rule    string
	}{
		{"healthy", func(*ProbeEnv) {}, VerdictAvailable, ""},
		{"macOS", func(e *ProbeEnv) { e.Host = HostOther }, VerdictUnsupportedPlatform, "P1 platform"},
		{"inactive dials nothing", func(e *ProbeEnv) {
			e.Active = false
			e.Query = func(string) (VersionFacts, InfoFacts, error) { dialled = true; return VersionFacts{}, InfoFacts{}, nil }
		}, VerdictDisabledByConfig, "P2 active"},
		{"tcp DOCKER_HOST", func(e *ProbeEnv) { e.Endpoint.DockerHost = "tcp://1.2.3.4:2375" }, VerdictSocketUntrusted, "P3 endpoint"},
		{"symlinked socket dials nothing", func(e *ProbeEnv) {
			e.StatSocket = func(p string) (SocketFacts, error) { return SocketFacts{Path: p, Exists: true, IsSocket: false}, nil }
			e.Query = func(string) (VersionFacts, InfoFacts, error) { dialled = true; return VersionFacts{}, InfoFacts{}, nil }
		}, VerdictSocketUntrusted, "P4 socket"},
		{"stat fails", func(e *ProbeEnv) {
			e.StatSocket = func(string) (SocketFacts, error) { return SocketFacts{}, errors.New("eperm") }
		}, VerdictEngineUnreachable, "P4 socket"},
		{"no answer", func(e *ProbeEnv) {
			e.Query = func(string) (VersionFacts, InfoFacts, error) {
				return VersionFacts{}, InfoFacts{}, errors.New("refused")
			}
		}, VerdictEngineUnreachable, "P5 engine"},
		{"desktop", func(e *ProbeEnv) {
			e.Query = func(string) (VersionFacts, InfoFacts, error) {
				return dockerVersion, InfoFacts{OperatingSystem: "Docker Desktop"}, nil
			}
		}, VerdictEngineIsDesktopVM, "P5 engine"},
		{"user socket answering rootful", func(e *ProbeEnv) {
			e.Query = func(string) (VersionFacts, InfoFacts, error) { return dockerVersion, InfoFacts{ID: "d1"}, nil }
		}, VerdictSocketUntrusted, "P6 owner agrees with mode"},
		{"old docker", func(e *ProbeEnv) {
			old := dockerVersion
			old.APIVersion = "1.43"
			e.Query = func(string) (VersionFacts, InfoFacts, error) {
				return old, InfoFacts{SecurityOptions: []string{"name=rootless"}}, nil
			}
		}, VerdictBackendVersionUntested, "P7 version"},
		{"bad userns", func(e *ProbeEnv) { e.Config.PodmanUserns = "nope" }, VerdictEngineModeUnsupported, "P8 uid table"},
		{"identity changed", func(e *ProbeEnv) {
			e.Recorded = func(string) (Identity, bool) {
				return Identity{Engine: EngineDocker, Mode: ModeRootless, Fingerprint: "other"}, true
			}
		}, VerdictSocketUntrusted, "P9 identity"},
		{"no image", func(e *ProbeEnv) { e.Config.Image = "" }, VerdictImageMissing, "P10 image"},
		{"tag image", func(e *ProbeEnv) { e.Config.Image = "alpine:3" }, VerdictImageMissing, "P10 image"},
		{"image trust refused", func(e *ProbeEnv) {
			e.Config.Image = ""
			e.Config.ImageRefusal = "Observer's default image: artifact_unverified (rollback)"
		}, VerdictArtifactUnverified, "P10 image"},
		{"image absent", func(e *ProbeEnv) { e.ImagePresent = func(string) (bool, error) { return false, nil } }, VerdictImageMissing, "P11 image present"},
		{"WSL2 DNS tunnel", func(e *ProbeEnv) {
			e.Host = HostWSL2
			e.ImagePresent = func(string) (bool, error) { return false, nil }
			e.Resolvers = func() []string { return []string{WSLTunnelResolver} }
		}, VerdictEngineCannotPull, "P11 image present"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			dialled = false
			env := probeEnv()
			c.edit(&env)
			r := Probe(env)
			if r.Verdict.Code != c.verdict {
				t.Fatalf("verdict %v at %s, want %s", r.Verdict, r.Rule, c.verdict)
			}
			if c.rule != "" && r.Rule != c.rule {
				t.Fatalf("rule %s, want %s", r.Rule, c.rule)
			}
			if dialled {
				t.Fatal("the engine was dialled")
			}
			if c.verdict == VerdictEngineCannotPull && !strings.Contains(r.Verdict.Reason, "--dns") {
				t.Fatal("the DNS step is not named")
			}
		})
	}
	r := Probe(probeEnv())
	if !r.FirstUse || r.User.Row != "rootless docker" || r.Socket != "/run/user/1000/docker.sock" {
		t.Fatalf("healthy result %+v", r)
	}
}

func TestPullFailure(t *testing.T) {
	if v := PullFailure(HostWSL2, ModeRootless, "dial tcp: lookup registry-1.docker.io on 10.0.2.3:53: i/o timeout"); v.Code != VerdictEngineCannotPull || !strings.Contains(v.Reason, "--dns") {
		t.Fatalf("%v", v)
	}
	if v := PullFailure(HostLinux, ModeRootless, "lookup x: no such host"); v.Code != VerdictEngineCannotPull {
		t.Fatalf("%v", v)
	}
	if v := PullFailure(HostLinux, ModeRootful, "manifest unknown"); v.Code != VerdictImageMissing {
		t.Fatalf("%v", v)
	}
}
