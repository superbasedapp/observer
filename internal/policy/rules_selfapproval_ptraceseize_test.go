package policy

import "testing"

// TestSelfApprovalStraceSwitch (lane ptrace, PT-96): turning on the
// sandbox's strace switch (it lifts PTRACE_SEIZE from the syscall filter)
// is the person's call on this machine; an agent's POST to the route is
// denied by R-165 (any spelling of loopback), and the read stays allowed.
// `observer config set` of the key needs no row: the CLI refuses the key
// (it is owned by the route), and an edit of config.toml is R-160's.
func TestSelfApprovalStraceSwitch(t *testing.T) {
	t.Parallel()
	cases := []coreRuleCase{
		sh("POST the switch on", `curl -X POST -H 'X-Observer-Confirm: t' -H 'Content-Type: application/json' -d '{"enabled":true}' http://127.0.0.1:8821/api/terminal/sandbox/ptrace-seize`, "R-165", DecisionDeny),
		sh("POST through localhost", `curl -X POST -d '{"enabled":true}' http://localhost:8821/api/terminal/sandbox/ptrace-seize`, "R-165", DecisionDeny),
		sh("POST through a mapped loopback", `curl -X POST -d '{"enabled":true}' 'http://[::ffff:127.0.0.1]:8821/api/terminal/sandbox/ptrace-seize'`, "R-165", DecisionDeny),
		sh("GET the switch is a read", `curl http://127.0.0.1:8821/api/terminal/sandbox/ptrace-seize`, "", 0),
	}
	runCoreRuleCases(t, cases, "R-165")
}
