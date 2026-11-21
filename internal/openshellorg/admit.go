package openshellorg

import (
	"slices"
	"strings"
)

// The front's admit table (g1-design.md section 7.6, lane G3): the
// request-shape half of rows F1 to F7, which the front evaluates itself
// before it asks the api role's decide (DecideCall, the ledger half). It is
// walked top-down by the call's full gRPC method name; the first row naming
// the method decides which decide RPC the call is, and a method no row names
// is refused rpc_not_allowed (row F7) whatever else it carries.
//
// The rest of the request-shape rules live here too, so the front's code is
// a walk over data rather than a ladder of conditionals:
//   - ClassifyExec picks row F4a (the bracketed clone) or F4 for a one-shot
//     exec by its argv shape;
//   - SameClone compares a clone request with the recorded clone argv and
//     the fixed clone environment byte for byte;
//   - IsReturnVerb names the guest's return verbs, which row F4 refuses
//     while the run's recorded return_to_node is false.

// The gRPC service and method names the table names.
const (
	ServiceOpenShell = "/openshell.v1.OpenShell/"
	MethodHealth     = "/grpc.health.v1.Health/Check"
	// FrontHealthService is the service name the front's health answers
	// for (row F1), since OpenShellServer has no health RPC of its own.
	FrontHealthService = "superbased.openshell.front"
)

// admitRow is one row of the admit table.
type admitRow struct {
	ID      string
	Methods []string
	RPC     RPC
}

// admitTable is the request-shape half of the admit table. Every method a
// node may call through the front is named here; nothing else is.
var admitTable = []admitRow{
	{ID: "F1", Methods: []string{MethodHealth}, RPC: RPCHealth},
	{ID: "F2", Methods: []string{ServiceOpenShell + "CreateSandbox"}, RPC: RPCCreateSandbox},
	{ID: "F3", Methods: []string{ServiceOpenShell + "GetSandbox"}, RPC: RPCGetSandbox},
	{ID: "F3", Methods: []string{ServiceOpenShell + "GetSandboxPolicyStatus"}, RPC: RPCGetPolicyStatus},
	{ID: "F3", Methods: []string{ServiceOpenShell + "GetSandboxLogs"}, RPC: RPCGetSandboxLogs},
	{ID: "F3", Methods: []string{ServiceOpenShell + "WatchSandbox"}, RPC: RPCWatchSandbox},
	// F4a is chosen from F4's ExecSandbox by ClassifyExec.
	{ID: "F4", Methods: []string{ServiceOpenShell + "ExecSandbox"}, RPC: RPCExecSandbox},
	{ID: "F4", Methods: []string{ServiceOpenShell + "ExecSandboxInteractive"}, RPC: RPCExecInteractive},
	{ID: "F6", Methods: []string{ServiceOpenShell + "DeleteSandbox"}, RPC: RPCDeleteSandbox},
}

// Admit walks the admit table for a full method name. It answers the row,
// the decide RPC and ReasonNone, or row F7 with rpc_not_allowed. A refused
// method is still reported to the api role (as the RPC named by the
// method's last element) so the audit records the refusal.
func Admit(fullMethod string) (row string, rpc RPC, reason Reason) {
	for _, r := range admitTable {
		if slices.Contains(r.Methods, fullMethod) {
			return r.ID, r.RPC, ReasonNone
		}
	}
	return "F7", DeniedRPC(fullMethod), ReasonRPCNotAllowed
}

// AdmittedMethods lists every method the table admits (the front's tests
// walk it against the generated service description).
func AdmittedMethods() []string {
	var out []string
	for _, r := range admitTable {
		out = append(out, r.Methods...)
	}
	return out
}

// DeniedRPC is the name a refused method is reported under: its last path
// element, cut to a safe length.
func DeniedRPC(fullMethod string) RPC {
	name := fullMethod
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if len(name) > 64 {
		name = name[:64]
	}
	return RPC(name)
}

// CloneRequest is the shape of a one-shot exec the front compares with the
// recorded clone.
type CloneRequest struct {
	Command      []string
	Env          map[string]string
	Workdir      string
	TTY          bool
	NoLoginShell bool
	Stdin        int
}

// ClassifyExec answers RPCClone for an exec whose argv is a git clone (so
// the front runs row F4a, whose decide returns the recorded argv to compare
// with), RPCExecSandbox otherwise.
func ClassifyExec(command []string) RPC {
	if len(command) >= 2 && (command[0] == "git" || strings.HasSuffix(command[0], "/git")) {
		for _, a := range command[1:] {
			if a == "clone" {
				return RPCClone
			}
			if !strings.HasPrefix(a, "-") {
				break
			}
		}
	}
	return RPCExecSandbox
}

// SameClone reports whether a clone request equals the recorded argv and
// the fixed clone shape byte for byte.
func SameClone(recorded []string, got CloneRequest) bool {
	if len(recorded) == 0 || !slices.Equal(recorded, got.Command) {
		return false
	}
	want := CloneEnv()
	if got.TTY || !got.NoLoginShell || got.Workdir != "" || got.Stdin != 0 || len(got.Env) != len(want) {
		return false
	}
	for k, v := range want {
		if gv, ok := got.Env[k]; !ok || gv != v {
			return false
		}
	}
	return true
}

// returnVerbs are the guest's return verbs (design 4.6 and row F4): the
// front refuses an exec that runs one while the run's recorded
// return_to_node is false.
var returnVerbs = []string{"--diff", "--bundle"}

// guestVerb is the guest command the return verbs belong to.
const guestVerb = "sandbox-guest"

// IsReturnVerb reports whether an exec's argv runs one of the guest's
// return verbs, directly or as a word of a shell command line (the check
// matches the words anywhere in the argv, so `sh -c "observer sandbox-guest
// --diff"` is caught as well; OSH-74 records what it cannot stop).
func IsReturnVerb(command []string) bool {
	var words []string
	for _, a := range command {
		words = append(words, strings.Fields(a)...)
	}
	if !slices.Contains(words, guestVerb) {
		return false
	}
	for _, v := range returnVerbs {
		if slices.Contains(words, v) {
			return true
		}
	}
	return false
}

// UploadCapBytes is the most one-shot exec stdin the front forwards for one
// run (the upload of design 4.2 travels in parts of at most 3 MiB, each a
// one-shot exec). The interactive relay and agent streams are not counted:
// they carry model traffic for the whole run, bounded by the relay's own
// flow control and the run's lifetime.
const UploadCapBytes int64 = 2 << 30

// FrontRecheck is how often the front repeats the per-call check (row F0)
// on an open stream; a refusal closes the stream (design 3.3).
const FrontRecheckSeconds = 30

// DisconnectGraceSeconds is how long a cut interactive stream must stay
// unanswered by a new call for the run before the front reports
// disconnected (design 3.6 H2: the stream lost for 60 s mid-run).
const DisconnectGraceSeconds = 60
