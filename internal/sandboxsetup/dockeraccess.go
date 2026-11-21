package sandboxsetup

// DockerAccess is what a passive read (stats and the process's own ids, no
// dial) finds about Docker's rootful socket and the engine socket a row
// will use. The caller gathers it; DockerAccessFact judges it.
type DockerAccess struct {
	// UID and Groups are this user's id and every group it is in (the
	// primary group included).
	UID    uint32
	Groups []uint32
	// DockerSocket is Docker's rootful socket path when it exists as a
	// socket ("" when none), with its owner, group and permission bits.
	DockerSocket string
	DockerUID    uint32
	DockerGID    uint32
	DockerMode   uint32
	// EngineSocket is the socket the row's engine will use (the configured
	// one, else the first candidate that exists; "" when none) and its owner.
	EngineSocket string
	EngineUID    uint32
	// EngineAnswered is what a check found about the engine socket: unknown
	// on a passive read (R1: no dial), answered or silent after a check
	// (EngineAnswerFrom).
	EngineAnswered EngineAnswer
}

// EngineAnswer is a check's finding about the engine socket the row uses.
type EngineAnswer int

// EngineAnswer values. The zero value is a passive read's.
const (
	// EngineUnknown: not checked, or the check did not reach the socket.
	EngineUnknown EngineAnswer = iota
	// EngineAnswered: the check's probe got an answer from the engine.
	EngineAnswered
	// EngineSilent: the check's probe found the engine socket did not answer
	// (or no socket at all), so a socket file there is stale.
	EngineSilent
)

// engineAnswerRule is one row of the ordered engine-answer table.
type engineAnswerRule struct {
	name   string
	match  func(verdict string) bool
	answer EngineAnswer
}

// engineAnswerRules read a check's probe verdict as a finding about the
// engine socket, walked top-down (first match wins). Verdicts are spelled as
// strings, as in verdictMap:
//
//   - not_probed: no verdict (a passive plan): unknown.
//   - engine_silent: engine_unreachable (no socket, or one that did not
//     answer): silent.
//   - socket_refused: socket_untrusted (the socket failed validation before
//     any dial): unknown.
//   - engine_answered: any other verdict comes after the engine answered.
var engineAnswerRules = []engineAnswerRule{
	{"not_probed", func(v string) bool { return v == "" }, EngineUnknown},
	{"engine_silent", func(v string) bool { return v == "engine_unreachable" }, EngineSilent},
	{"socket_refused", func(v string) bool { return v == "socket_untrusted" }, EngineUnknown},
	{"engine_answered", func(string) bool { return true }, EngineAnswered},
}

// EngineAnswerFrom reads a check's probe verdict as an EngineAnswer.
func EngineAnswerFrom(verdict string) EngineAnswer {
	a, _ := engineAnswerDecision(verdict)
	return a
}

// engineAnswerDecision walks engineAnswerRules and returns the answer and the
// row that decided it.
func engineAnswerDecision(verdict string) (EngineAnswer, string) {
	for _, r := range engineAnswerRules {
		if r.match(verdict) {
			return r.answer, r.name
		}
	}
	return EngineUnknown, "not_probed"
}

// dockerReachable reports whether this user can open Docker's rootful
// socket: root, the socket's owner, or a member of its group with the group
// read-write bits set.
func (a DockerAccess) dockerReachable() bool {
	if a.DockerSocket == "" {
		return false
	}
	if a.UID == 0 || a.DockerUID == a.UID {
		return true
	}
	if a.DockerMode&0o060 != 0o060 {
		return false
	}
	for _, g := range a.Groups {
		if g == a.DockerGID {
			return true
		}
	}
	return false
}

// rootlessEngine reports whether the engine socket the row will use is a
// rootless one this user owns, not Docker's rootful socket, and no check
// found it silent. Passively a stale rootless socket file still counts (R1:
// no dial); after a check that found it did not answer it does not.
func (a DockerAccess) rootlessEngine() bool {
	return a.EngineSocket != "" && a.EngineSocket != a.DockerSocket && a.UID != 0 && a.EngineUID == a.UID && a.EngineAnswered != EngineSilent
}

// dockerAccessRule is one row of the ordered docker-group table.
type dockerAccessRule struct {
	name string
	// fact answers the row's fact; ok false means the row does not decide.
	fact func(a DockerAccess) (f Fact, ok bool)
}

// dockerAccessRules judge the docker-group step from Docker's own socket and
// this user's groups, whichever engine the oci driver would pick, walked
// top-down (first row that decides wins):
//
//   - docker_reachable: this user can open Docker's socket: done.
//   - rootless_engine: the row uses a rootless engine socket this user owns,
//     and no check found it silent, so Docker's group does not apply: not
//     applicable. A stale rootless socket file a check found silent falls
//     through to the rows below.
//   - docker_unreachable: Docker's socket is there and this user cannot open
//     it: missing (the never step then reads blocked) with that reason.
//   - no_docker_socket: no Docker socket and no rootless engine: no fact (the
//     check or the engine steps say what is missing).
var dockerAccessRules = []dockerAccessRule{
	{"docker_reachable", func(a DockerAccess) (Fact, bool) {
		return Fact{Present: true, Path: a.DockerSocket}, a.dockerReachable()
	}},
	{"rootless_engine", func(a DockerAccess) (Fact, bool) {
		return Fact{NotApplicable: true, Path: a.EngineSocket, Reason: "Not needed here: this sandbox uses your own rootless engine socket " + a.EngineSocket + ", not Docker's."}, a.rootlessEngine()
	}},
	{"docker_unreachable", func(a DockerAccess) (Fact, bool) {
		return Fact{Reason: "Docker's socket " + a.DockerSocket + " is not group read-write for a group you are in."}, a.DockerSocket != ""
	}},
	{"no_docker_socket", func(DockerAccess) (Fact, bool) { return Fact{}, false }},
}

// DockerAccessFact is the docker-group step's passive fact (ok false: no
// fact, the step stays for the check to judge).
func DockerAccessFact(a DockerAccess) (Fact, bool) {
	f, _, ok := dockerAccessDecision(a)
	return f, ok
}

// dockerAccessDecision walks dockerAccessRules and returns the fact, the row
// that decided it and whether there is a fact.
func dockerAccessDecision(a DockerAccess) (Fact, string, bool) {
	for _, r := range dockerAccessRules {
		if f, ok := r.fact(a); ok {
			return f, r.name, true
		}
	}
	return Fact{}, "no_docker_socket", false
}
