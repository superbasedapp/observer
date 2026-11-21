package sandboxsetup

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
)

// dockeraccess_test.go pins the F18 residual (fix round 3, item 3): the
// docker-group step is judged from Docker's own rootful socket and this
// user's groups, whichever engine the oci driver would pick, and it does not
// apply while the row uses a rootless engine socket this user owns.

const (
	testUID       = 1000
	testDockerGID = 109
	dockerSock    = "/run/docker.sock"
	podmanSock    = "/run/user/1000/podman/podman.sock"
)

// dockerAccessCases is one row per shape.
var dockerAccessCases = []struct {
	name   string
	access DockerAccess
	// probe is a check's verdict and reason ("": a passive plan).
	verdict, reason string
	wantRule        string
	wantState       StepState
	reasonHas       string
}{
	{
		name:     "in the docker group, Docker only",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID, testDockerGID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: dockerSock},
		wantRule: "docker_reachable", wantState: StateDone,
	},
	{
		name:    "in the docker group while a Podman socket also answers",
		access:  DockerAccess{UID: testUID, Groups: []uint32{testUID, testDockerGID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: podmanSock, EngineUID: testUID},
		verdict: "runtime_missing", reason: "the oci-runsc row runs on docker only (its documented integration); this socket is podman",
		wantRule: "docker_reachable", wantState: StateDone,
	},
	{
		name:     "not in the docker group, a rootless Podman socket answers",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: podmanSock, EngineUID: testUID},
		wantRule: "rootless_engine", wantState: StateNotApplicable, reasonHas: "rootless engine socket",
	},
	{
		name:     "not in the docker group, Docker only",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: dockerSock},
		wantRule: "docker_unreachable", wantState: StateBlocked, reasonHas: "not group read-write",
	},
	{
		name:     "not in the docker group, a stale rootless socket file, passive",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: podmanSock, EngineUID: testUID},
		wantRule: "rootless_engine", wantState: StateNotApplicable, reasonHas: "rootless engine socket",
	},
	{
		name:    "not in the docker group, a check found the rootless socket silent",
		access:  DockerAccess{UID: testUID, Groups: []uint32{testUID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: podmanSock, EngineUID: testUID, EngineAnswered: EngineSilent},
		verdict: "engine_unreachable", reason: "the engine on " + podmanSock + " did not answer: dial unix: connect: connection refused",
		wantRule: "docker_unreachable", wantState: StateBlocked, reasonHas: "not group read-write",
	},
	{
		name:     "not in the docker group, a check found the rootless socket answers",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o660, EngineSocket: podmanSock, EngineUID: testUID, EngineAnswered: EngineAnswered},
		wantRule: "rootless_engine", wantState: StateNotApplicable, reasonHas: "rootless engine socket",
	},
	{
		name:     "a silent rootless socket and no Docker socket",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID}, EngineSocket: podmanSock, EngineUID: testUID, EngineAnswered: EngineSilent},
		wantRule: "no_docker_socket", wantState: StateUnknown,
	},
	{
		name:     "no Docker socket and no engine socket",
		access:   DockerAccess{UID: testUID, Groups: []uint32{testUID}},
		wantRule: "no_docker_socket", wantState: StateUnknown,
	},
}

// TestDockerAccessRules: each row decides its shape, and the oci rows' plans
// read the docker-group step from that fact (a passive plan and, where the
// row names one, after a check that reached Podman's socket).
func TestDockerAccessRules(t *testing.T) {
	for _, tc := range dockerAccessCases {
		t.Run(tc.name, func(t *testing.T) {
			f, rule, ok := dockerAccessDecision(tc.access)
			if rule != tc.wantRule {
				t.Fatalf("rule = %s, want %s", rule, tc.wantRule)
			}
			for _, backend := range []string{sandboxbackend.BackendOCIRunsc, sandboxbackend.BackendOCIRunc} {
				in := base(t, backend)
				if ok {
					in.Facts = map[string]Fact{"docker-group": f}
				}
				if tc.verdict != "" {
					in.Probe = &sandboxselect.Probe{Verdict: tc.verdict, Reason: tc.reason}
				}
				st := stepOf(t, Build(in), "docker-group")
				if st.State != tc.wantState || !strings.Contains(st.Reason, tc.reasonHas) {
					t.Errorf("%s docker-group = %s %q, want %s holding %q", backend, st.State, st.Reason, tc.wantState, tc.reasonHas)
				}
				if strings.Contains(st.Reason+st.Display, "usermod") && st.State != StateBlocked && st.State != StateUnknown {
					t.Errorf("%s: a %s docker-group step still tells the user to join the group: %q %q", backend, st.State, st.Reason, st.Display)
				}
			}
		})
	}
}

// TestDockerAccessGroupNeedsReadWrite: membership alone is not enough; the
// socket's group must read and write it.
func TestDockerAccessGroupNeedsReadWrite(t *testing.T) {
	a := DockerAccess{UID: testUID, Groups: []uint32{testDockerGID}, DockerSocket: dockerSock, DockerGID: testDockerGID, DockerMode: 0o640, EngineSocket: dockerSock}
	if _, rule, _ := dockerAccessDecision(a); rule != "docker_unreachable" {
		t.Fatalf("a group read-only socket: rule %s", rule)
	}
}

// TestEngineAnswerRules is one case per row of engineAnswerRules.
func TestEngineAnswerRules(t *testing.T) {
	cases := []struct {
		verdict string
		want    EngineAnswer
		rule    string
	}{
		{"", EngineUnknown, "not_probed"},
		{"engine_unreachable", EngineSilent, "engine_silent"},
		{"socket_untrusted", EngineUnknown, "socket_refused"},
		{"image_missing", EngineAnswered, "engine_answered"},
	}
	for _, c := range cases {
		got, rule := engineAnswerDecision(c.verdict)
		if got != c.want || rule != c.rule {
			t.Errorf("engineAnswerDecision(%q) = %v %s, want %v %s", c.verdict, got, rule, c.want, c.rule)
		}
		if EngineAnswerFrom(c.verdict) != c.want {
			t.Errorf("EngineAnswerFrom(%q) != %v", c.verdict, c.want)
		}
	}
	if len(cases) != len(engineAnswerRules) {
		t.Fatalf("%d cases for %d rules", len(cases), len(engineAnswerRules))
	}
}
