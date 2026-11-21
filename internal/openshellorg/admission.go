package openshellorg

import "strings"

// The gateway's durable mutation admission (FX3 item 2, live finding
// F-L3P4-6), as OpenShell 0.1.6 implements it in
// crates/openshell-server/src/grpc/mutation_replay.rs (run, and the Mutation
// impls there and in mutation_replay/ordinary.rs and streaming.rs):
//
//   - what is admitted: a call of one of the gateway's Mutation types (the
//     sandbox, provider, workspace, template and config mutations, plus
//     ExecSandbox and ExecSandboxInteractive, whose Start frame carries the
//     id) that carries a NON-EMPTY request_id. run() returns
//     M::execute(...) before any admission when the id is empty ("Empty IDs
//     preserve the existing RPC contract"); reads (GetSandbox, ListSandboxes,
//     WatchSandbox, the logs and policy status) are not Mutation types and
//     are never admitted;
//   - per which caller: hash_json([provider, issuer, identity.subject]), so
//     the token's subject at the gateway. The front calls as the member (its
//     member gateway token's subject), the org worker as its own service
//     subject; the box and the node are not callers;
//   - the budget: MAX_ADMISSIONS_PER_CALLER = 1000 admission records per
//     caller, each kept SUCCESS_TTL_MS = 24 h after it succeeded; past it
//     every admitted call answers ResourceExhausted "caller has reached the
//     durable mutation admission limit; unresolved requests require
//     reconciliation" until records expire.
//
// The org never asks the gateway to replay an exec (an exec is never
// retried with the same id, and the gateway replays no exec output:
// streaming.rs "Launch admission only: output and interactive input are
// never replayed"), so every exec the front and the worker send carries an
// empty request id and costs no admission. So do the worker's idempotent
// cleanup calls (FX3-A2, orchestrator decision): its DeleteSandbox (a
// missing box answers NotFound, which the worker reads as gone), its
// DeleteProvider (allow_missing) and its StopSandbox, so a busy org can
// never exhaust the worker's one budget and leave boxes running. Every
// create keeps its id: the create's deterministic id is what makes a
// retried create at most once.

// GatewayAdmissionsPerCaller is the 0.1.6 gateway's admission records per
// caller (MAX_ADMISSIONS_PER_CALLER).
const GatewayAdmissionsPerCaller = 1000

// GatewayAdmissionHours is how long an admission record counts after it
// succeeded (SUCCESS_TTL_MS, in hours).
const GatewayAdmissionHours = 24

// GatewayAdmissionLimitText is the 0.1.6 gateway's refusal of an admitted
// call past the budget (a substring of its ResourceExhausted message).
const GatewayAdmissionLimitText = "durable mutation admission limit"

// IsAdmissionLimit reports whether a gateway answer's message is the
// admission-limit refusal.
func IsAdmissionLimit(message string) bool {
	return strings.Contains(message, GatewayAdmissionLimitText)
}

// GatewayCall is one kind of call the org sends the gateway.
type GatewayCall string

// The calls a run can cost, by the caller they are charged to.
const (
	GatewayCreate GatewayCall = "CreateSandbox"
	// GatewayDelete is the node's delete through the front (as the member).
	GatewayDelete GatewayCall = "DeleteSandbox"
	// GatewayCleanupDelete is the worker's delete (a reap, the drain).
	GatewayCleanupDelete  GatewayCall = "DeleteSandbox (worker)"
	GatewayAttach         GatewayCall = "AttachSandboxProvider"
	GatewayDetach         GatewayCall = "DetachSandboxProvider"
	GatewayCreateProvider GatewayCall = "CreateProvider"
	GatewayDeleteProvider GatewayCall = "DeleteProvider"
	GatewayStop           GatewayCall = "StopSandbox"
	GatewayStart          GatewayCall = "StartSandbox"
	GatewayExec           GatewayCall = "ExecSandbox"
	GatewayExecLive       GatewayCall = "ExecSandboxInteractive"
	GatewayGet            GatewayCall = "GetSandbox"
)

// admittedCalls is the request-id table: true is a call the org sends with
// a request id (so the gateway admits it and it counts), false one it sends
// with none (an exec, the worker's idempotent cleanup) or that has none (a
// read).
var admittedCalls = map[GatewayCall]bool{
	GatewayCreate: true, GatewayDelete: true, GatewayAttach: true, GatewayDetach: true,
	GatewayCreateProvider: true, GatewayStart: true,
	GatewayCleanupDelete: false, GatewayDeleteProvider: false, GatewayStop: false,
	GatewayExec: false, GatewayExecLive: false, GatewayGet: false,
}

// CleanupRequestID is the request id of the worker's idempotent cleanup
// calls (DeleteSandbox, DeleteProvider, StopSandbox): none, so they are not
// admitted (FX3-A2).
func CleanupRequestID() string { return "" }

// Admitted reports whether the org's call of kind c counts against the
// caller's admission budget.
func Admitted(c GatewayCall) bool { return admittedCalls[c] }

// ExecRequestID is the request id of every exec the org sends the gateway:
// none, so the exec is not admitted (see the package comment above).
func ExecRequestID() string { return "" }

// RunCost is what one run costs each caller's admission budget.
type RunCost struct {
	// Member is the member's own budget (the front's calls as the member).
	Member int `json:"member"`
	// Worker is the org worker's budget (its service subject), shared by
	// every member's runs.
	Worker int `json:"worker"`
}

// runCostRows are the calls each run shape makes, walked in order: the
// first matching row wins (one test case per row).
var runCostRows = []struct {
	name   string
	match  func(privateClone, held bool) bool
	member []GatewayCall
	worker []GatewayCall
}{
	{
		"private clone, held and resumed", func(p, h bool) bool { return p && h },
		[]GatewayCall{GatewayCreate, GatewayAttach, GatewayDetach, GatewayDelete},
		[]GatewayCall{GatewayCreateProvider, GatewayDeleteProvider, GatewayStop, GatewayStart},
	},
	{
		"private clone", func(p, _ bool) bool { return p },
		[]GatewayCall{GatewayCreate, GatewayAttach, GatewayDetach, GatewayDelete},
		[]GatewayCall{GatewayCreateProvider, GatewayDeleteProvider},
	},
	{
		"held and resumed", func(_, h bool) bool { return h },
		[]GatewayCall{GatewayCreate, GatewayDelete},
		[]GatewayCall{GatewayStop, GatewayStart},
	},
	{
		"a plain run", func(bool, bool) bool { return true },
		[]GatewayCall{GatewayCreate, GatewayDelete},
		nil,
	},
}

// RunCostFor counts the admitted calls of one run shape (a run the member
// ends itself; a box the worker reaps costs the worker nothing: its delete
// is cleanup).
func RunCostFor(privateClone, held bool) RunCost {
	for _, r := range runCostRows {
		if !r.match(privateClone, held) {
			continue
		}
		var c RunCost
		for _, k := range r.member {
			if Admitted(k) {
				c.Member++
			}
		}
		for _, k := range r.worker {
			if Admitted(k) {
				c.Worker++
			}
		}
		return c
	}
	return RunCost{}
}

// AdmissionBudget is the gateway budget a surface shows (the admin page and
// the state API).
type AdmissionBudget struct {
	// PerCallerPerDay is the gateway's admission records per caller.
	PerCallerPerDay int `json:"per_caller_per_day"`
	// WindowHours is how long a record counts.
	WindowHours int `json:"window_hours"`
	// PlainRun and PrivateCloneRun are what one run costs.
	PlainRun        RunCost `json:"plain_run"`
	PrivateCloneRun RunCost `json:"private_clone_run"`
	// CollectOrDiscard is what the worker's collect or discard of a stopped
	// or ending box costs: the start that brings the box up to read its
	// work (F-P6-6, measured live in phase 6a: 1 each).
	CollectOrDiscard RunCost `json:"collect_or_discard"`
	// RunsPerMemberPerDay is the plain runs one member can start a day.
	RunsPerMemberPerDay int `json:"runs_per_member_per_day"`
	// Note says what counts, in one sentence.
	Note string `json:"note"`
}

// Budget is the admission budget of the tested gateway (0.1.6).
func Budget() AdmissionBudget {
	plain := RunCostFor(false, false)
	return AdmissionBudget{
		PerCallerPerDay: GatewayAdmissionsPerCaller, WindowHours: GatewayAdmissionHours,
		PlainRun: plain, PrivateCloneRun: RunCostFor(true, false), CollectOrDiscard: CollectCost(),
		RunsPerMemberPerDay: GatewayAdmissionsPerCaller / max(plain.Member, 1),
		Note: "OpenShell 0.1.6 admits at most 1000 mutations per caller in 24 h: the box create and delete " +
			"(and a private clone's provider attach and detach) count against the member, a private clone's " +
			"provider create, a resume's start and the start that a collect or discard of a stopped or ending box " +
			"needs against the org's worker; execs, reads and the worker's cleanup (its deletes and stops) do not count",
	}
}

// collectCalls are the admitted calls of the worker's collect or discard of
// a stopped or ending box: it starts the box to read its work, then its
// delete is cleanup (F-P6-6).
var collectCalls = []GatewayCall{GatewayStart, GatewayCleanupDelete}

// CollectCost counts collectCalls (the worker's budget).
func CollectCost() RunCost {
	var c RunCost
	for _, k := range collectCalls {
		if Admitted(k) {
			c.Worker++
		}
	}
	return c
}
