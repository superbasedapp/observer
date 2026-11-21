package openshellorg

import (
	"testing"
)

// Lane G3's pure tables: the admit table (one case per row, plus the
// adversarial shapes), the soundness table and the request ids.

func TestAdmitTableRows(t *testing.T) {
	cases := []struct {
		method string
		row    string
		rpc    RPC
		reason Reason
	}{
		{MethodHealth, "F1", RPCHealth, ReasonNone},
		{ServiceOpenShell + "CreateSandbox", "F2", RPCCreateSandbox, ReasonNone},
		{ServiceOpenShell + "GetSandbox", "F3", RPCGetSandbox, ReasonNone},
		{ServiceOpenShell + "GetSandboxPolicyStatus", "F3", RPCGetPolicyStatus, ReasonNone},
		{ServiceOpenShell + "GetSandboxLogs", "F3", RPCGetSandboxLogs, ReasonNone},
		{ServiceOpenShell + "WatchSandbox", "F3", RPCWatchSandbox, ReasonNone},
		{ServiceOpenShell + "ExecSandbox", "F4", RPCExecSandbox, ReasonNone},
		{ServiceOpenShell + "ExecSandboxInteractive", "F4", RPCExecInteractive, ReasonNone},
		{ServiceOpenShell + "DeleteSandbox", "F6", RPCDeleteSandbox, ReasonNone},
		// Row F7: everything else.
		{ServiceOpenShell + "ListSandboxes", "F7", "ListSandboxes", ReasonRPCNotAllowed},
		{ServiceOpenShell + "ForwardTcp", "F7", "ForwardTcp", ReasonRPCNotAllowed},
		{ServiceOpenShell + "AttachSandboxProvider", "F7", "AttachSandboxProvider", ReasonRPCNotAllowed},
		{ServiceOpenShell + "DetachSandboxProvider", "F7", "DetachSandboxProvider", ReasonRPCNotAllowed},
		{ServiceOpenShell + "BeginRootfsTarStaging", "F7", "BeginRootfsTarStaging", ReasonRPCNotAllowed},
		{ServiceOpenShell + "StopSandbox", "F7", "StopSandbox", ReasonRPCNotAllowed},
		{ServiceOpenShell + "StartSandbox", "F7", "StartSandbox", ReasonRPCNotAllowed},
		{ServiceOpenShell + "SuspendSandbox", "F7", "SuspendSandbox", ReasonRPCNotAllowed},
		{ServiceOpenShell + "CreateSshSession", "F7", "CreateSshSession", ReasonRPCNotAllowed},
		{ServiceOpenShell + "ExposeService", "F7", "ExposeService", ReasonRPCNotAllowed},
		{ServiceOpenShell + "UpdateConfig", "F7", "UpdateConfig", ReasonRPCNotAllowed},
		{ServiceOpenShell + "ApproveDraftChunk", "F7", "ApproveDraftChunk", ReasonRPCNotAllowed},
		{ServiceOpenShell + "CreateProvider", "F7", "CreateProvider", ReasonRPCNotAllowed},
		{ServiceOpenShell + "AddWorkspaceMember", "F7", "AddWorkspaceMember", ReasonRPCNotAllowed},
		{ServiceOpenShell + "GetGatewayInfo", "F7", "GetGatewayInfo", ReasonRPCNotAllowed},
		{"/grpc.health.v1.Health/Watch", "F7", "Watch", ReasonRPCNotAllowed},
		{"/evil.Service/CreateSandbox", "F7", "CreateSandbox", ReasonRPCNotAllowed},
	}
	for _, c := range cases {
		row, rpc, r := Admit(c.method)
		if row != c.row || rpc != c.rpc || r != c.reason {
			t.Errorf("%s: %s %s %q, want %s %s %q", c.method, row, rpc, r, c.row, c.rpc, c.reason)
		}
	}
}

func TestClassifyExecAndReturnVerbs(t *testing.T) {
	cases := []struct {
		argv    []string
		clone   bool
		return_ bool
	}{
		{[]string{"git", "clone", "--", "https://h/r", BoxWorkspace}, true, false},
		{[]string{"/usr/bin/git", "-c", "x", "clone"}, false, false}, // "x" is not a flag: not a clone shape the front brackets
		{[]string{"/usr/bin/git", "--no-pager", "clone", "u"}, true, false},
		{[]string{"git", "status"}, false, false},
		{[]string{"sh", "-c", "git clone u"}, false, false},
		{[]string{"observer", "sandbox-guest", "--diff"}, false, true},
		{[]string{"/home/sandbox/.observer/bin/observer", "sandbox-guest", "--bundle"}, false, true},
		{[]string{"sh", "-c", "observer sandbox-guest --diff > /tmp/x"}, false, true},
		{[]string{"observer", "sandbox-guest", "--relay-stdio"}, false, false},
		{[]string{"echo", "--diff"}, false, false},
	}
	for _, c := range cases {
		if got := ClassifyExec(c.argv) == RPCClone; got != c.clone {
			t.Errorf("%v: clone %v", c.argv, got)
		}
		if got := IsReturnVerb(c.argv); got != c.return_ {
			t.Errorf("%v: return verb %v", c.argv, got)
		}
	}
}

func TestSameClone(t *testing.T) {
	rec := []string{"git", "clone", "--", "https://git.example.com/o/r", BoxWorkspace}
	good := CloneRequest{Command: append([]string(nil), rec...), Env: map[string]string{"GIT_TERMINAL_PROMPT": "0"}, NoLoginShell: true}
	if !SameClone(rec, good) {
		t.Fatal("the recorded clone was refused")
	}
	mut := []func(c *CloneRequest){
		func(c *CloneRequest) { c.Command[3] += "x" },
		func(c *CloneRequest) { c.Command = append(c.Command, "--upload-pack=x") },
		func(c *CloneRequest) { c.TTY = true },
		func(c *CloneRequest) { c.NoLoginShell = false },
		func(c *CloneRequest) { c.Workdir = "/" },
		func(c *CloneRequest) { c.Stdin = 1 },
		func(c *CloneRequest) { c.Env = map[string]string{"GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "x"} },
		func(c *CloneRequest) { c.Env = nil },
	}
	for i, m := range mut {
		c := good
		c.Command = append([]string(nil), rec...)
		c.Env = map[string]string{"GIT_TERMINAL_PROMPT": "0"}
		m(&c)
		if SameClone(rec, c) {
			t.Errorf("mutation %d was accepted as the clone", i)
		}
	}
	if SameClone(nil, good) {
		t.Fatal("a run without a recorded clone accepted one")
	}
}

func TestSoundnessTable(t *testing.T) {
	ok := Observed{
		Reached: true, Version: "0.1.6", DeclaredVersion: "0.1.6", TestedVersions: []string{"0.1.6"},
		Drivers: []string{"docker"}, Settings: map[string]string{"proposal_approval_mode": "unset", "agent_policy_proposals_enabled": "unset"},
		AttestedDigest: "d", AttestedRevision: "7", SettingsRevision: "7",
	}
	if rep := EvaluateSoundness(ok); !rep.Sound || len(rep.Unsound()) != 0 {
		t.Fatalf("a sound gateway: %+v", rep)
	}
	cases := []struct {
		name string
		mut  func(o *Observed)
		fact FactID
		want FactVerdict
	}{
		{"unreached", func(o *Observed) { o.Reached = false }, FactReachable, VerdictUnsound},
		{"unreached api unknown", func(o *Observed) { o.Reached = false }, FactDockerDriver, VerdictUnknown},
		{"untested version", func(o *Observed) { o.Version = "0.1.7" }, FactVersionTested, VerdictUnsound},
		{"undeclared version", func(o *Observed) { o.DeclaredVersion = "0.1.5" }, FactVersionDeclared, VerdictUnsound},
		{"no docker", func(o *Observed) { o.Drivers = []string{"kubernetes"} }, FactDockerDriver, VerdictUnsound},
		{"proposals on", func(o *Observed) { o.Settings = map[string]string{"agent_policy_proposals_enabled": "true"} }, FactProposalsOff, VerdictUnsound},
		{"approval auto", func(o *Observed) { o.Settings = map[string]string{"proposal_approval_mode": "auto"} }, FactApprovalManual, VerdictUnsound},
		{"global policy", func(o *Observed) { o.GlobalPolicies = 1 }, FactNoGlobalPolicy, VerdictUnsound},
		{"unattested", func(o *Observed) { o.AttestedDigest = "" }, FactBindMountsOff, VerdictUnattested},
		{"stale", func(o *Observed) { o.SettingsRevision = "8" }, FactOIDC, VerdictStale},
		{"no revision reported", func(o *Observed) { o.SettingsRevision = "" }, FactTelemetryOff, VerdictAttested},
	}
	for _, c := range cases {
		o := ok
		c.mut(&o)
		rep := EvaluateSoundness(o)
		var got FactVerdict
		for _, f := range rep.Facts {
			if f.ID == c.fact {
				got = f.Verdict
			}
		}
		if got != c.want || rep.Sound != c.want.Sound() {
			t.Errorf("%s: %s = %s (sound %v), want %s", c.name, c.fact, got, rep.Sound, c.want)
		}
	}
}

func TestRequestUUIDs(t *testing.T) {
	for range 100 {
		if id := RandomRequestUUID(); !IsRequestUUID(id) {
			t.Fatalf("%q", id)
		}
	}
	a, b := RunRequestUUID("o", "r", "create"), RunRequestUUID("o", "r", "delete")
	if !IsRequestUUID(a) || a == b || a != RunRequestUUID("o", "r", "create") {
		t.Fatalf("%q %q", a, b)
	}
	// The front's box-keyed family (G3-A16): deterministic, v4, and never
	// equal to the run-keyed family for the same strings.
	c := BoxRequestUUID("o", "r", "create")
	if !IsRequestUUID(c) || c == a || c != BoxRequestUUID("o", "r", "create") || c == BoxRequestUUID("o", "r2", "create") {
		t.Fatalf("box request id %q", c)
	}
	for _, bad := range []string{"", "obsr-abc", "00000000-0000-0000-0000-000000000000", "AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA"} {
		if IsRequestUUID(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
}
