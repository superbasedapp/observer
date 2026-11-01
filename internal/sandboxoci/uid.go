package sandboxoci

import (
	"fmt"
	"strconv"
)

// PodmanUserns is the rootless Podman user-namespace choice of
// [terminal.sandbox.oci].podman_userns.
type PodmanUserns string

// The PodmanUserns values. Both leave host-owned files in the workspace
// (spike JSP-4 measured both on Podman 4.9.3 and 5.6.2).
const (
	// PodmanKeepID: --userns=keep-id, the container runs as the host uid.
	PodmanKeepID PodmanUserns = "keep-id"
	// PodmanDefault: the default rootless namespace, container root IS the
	// host user.
	PodmanDefault PodmanUserns = "default"
)

// UserPlan is the uid strategy one engine mode gets (section 4.6 uid
// table): the container User, the user-namespace mode the create asks for,
// and what the read-back must find.
type UserPlan struct {
	// Row names the uid table row, for the evidence and the refusal text.
	Row string
	// User is the container User field ("1000:1000", "0:0").
	User string
	// UsernsMode is the HostConfig.UsernsMode to send ("" for the
	// engine's default, "keep-id" for Podman keep-id).
	UsernsMode string
	// ExpectUIDMap is the entry Podman's uid map must contain for a
	// keep-id run ("<host uid>:0:1"); empty for every other row.
	ExpectUIDMap string
	// ContainerRootIsHostUser: container uid 0 is the host user (rootless
	// rows), so running as root is the intended row, not an escalation.
	ContainerRootIsHostUser bool
}

// uidRow is one row of the uid table: the engine and mode it matches and
// how it builds the plan. A nil build refuses the mode.
type uidRow struct {
	name   string
	match  func(id Identity, userns PodmanUserns) bool
	build  func(uid, gid int) UserPlan
	refuse string
}

func ids(uid, gid int) string { return strconv.Itoa(uid) + ":" + strconv.Itoa(gid) }

// uidTable is section 4.6's uid table walked top-down; the first matching
// row wins. A rootful engine never runs container root: its row uses the
// host uid and gid, and a daemon run as root is refused (it would make the
// "host uid" root, JSP-4's root-owned setuid case).
var uidTable = []uidRow{
	{
		name:   "userns-remap",
		match:  func(id Identity, _ PodmanUserns) bool { return id.UsernsRemap },
		refuse: "a Docker daemon with userns-remap has no row in the uid table: files the agent writes would belong to a remapped uid",
	},
	{
		name: "rootless podman, keep-id",
		match: func(id Identity, u PodmanUserns) bool {
			return id.Engine == EnginePodman && id.Mode == ModeRootless && u != PodmanDefault
		},
		build: func(uid, gid int) UserPlan {
			return UserPlan{User: ids(uid, gid), UsernsMode: string(PodmanKeepID), ExpectUIDMap: strconv.Itoa(uid) + ":0:1"}
		},
	},
	{
		name:  "rootless podman, default namespace",
		match: func(id Identity, u PodmanUserns) bool { return id.Engine == EnginePodman && id.Mode == ModeRootless },
		build: func(int, int) UserPlan { return UserPlan{User: "0:0", ContainerRootIsHostUser: true} },
	},
	{
		name:  "rootless docker",
		match: func(id Identity, _ PodmanUserns) bool { return id.Engine == EngineDocker && id.Mode == ModeRootless },
		build: func(int, int) UserPlan { return UserPlan{User: "0:0", ContainerRootIsHostUser: true} },
	},
	{
		name: "rootful engine (opt-in)",
		match: func(id Identity, _ PodmanUserns) bool {
			return id.Mode == ModeRootful && (id.Engine == EngineDocker || id.Engine == EnginePodman)
		},
		build: func(uid, gid int) UserPlan { return UserPlan{User: ids(uid, gid)} },
	},
}

// PlanUser picks the uid strategy for the engine on the socket, for the
// host user uid:gid. allowRootful is [terminal.sandbox.oci].allow_rootful;
// a rootful engine without it is refused before anything is created.
func PlanUser(id Identity, uid, gid int, userns PodmanUserns, allowRootful bool) (UserPlan, Verdict) {
	if userns != "" && userns != PodmanKeepID && userns != PodmanDefault {
		return UserPlan{}, refuse(VerdictEngineModeUnsupported, fmt.Sprintf("[terminal.sandbox.oci].podman_userns %q is not keep-id or default", userns))
	}
	for _, r := range uidTable {
		if !r.match(id, userns) {
			continue
		}
		if r.build == nil {
			return UserPlan{}, refuse(VerdictEngineModeUnsupported, r.refuse)
		}
		if id.Mode == ModeRootful {
			if !allowRootful {
				return UserPlan{}, refuse(VerdictSocketUntrusted, "the engine on this socket is rootful, and a rootful engine socket is root-equivalent; set [terminal.sandbox.oci].allow_rootful = true to use it, or run rootless Docker or Podman")
			}
			if uid == 0 {
				return UserPlan{}, refuse(VerdictEngineModeUnsupported, "the daemon runs as root, so the host uid is root and a rootful engine would run container root; run Observer as your own user")
			}
		}
		p := r.build(uid, gid)
		p.Row = r.name
		return p, pass()
	}
	return UserPlan{}, refuse(VerdictEngineModeUnsupported, "the engine's mode ("+string(id.Engine)+" "+string(id.Mode)+") has no row in the uid table")
}
