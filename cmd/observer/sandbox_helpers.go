package main

import (
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// sandbox_helpers.go dispatches the two network-tier helper verbs of the
// terminal sandbox (security ledger SR27-SBX-1, docs/sandboxed-terminals.md
// "Network tiers"). They are argv[1] of the observer binary itself:
//
//   - sandbox.HostVerb runs OUTSIDE the sandbox as the PTY child: it owns the
//     per-run unix sockets (model-proxy forward + egress gateway) and spawns
//     bwrap.
//   - sandbox.GuestVerb runs INSIDE the sandbox's private network namespace:
//     it listens on the in-namespace loopback ports, pipes them to those
//     sockets, and spawns the real launcher.
//
// They are dispatched from main() BEFORE cobra and BEFORE the trusted OOB
// launcher channel is opened: the helpers must pass the inherited OOB fd
// through untouched so the real `observer <tool>` launcher inside the sandbox
// is the one that authenticates it. They are not cobra commands on purpose -
// no help entry, no config load, no side effects beyond the sockets.

// sandboxHelperFuncs is the dispatch table (one row per helper verb).
var sandboxHelperFuncs = map[string]func(args []string) int{
	sandbox.HostVerb:  runSandboxHost,
	sandbox.GuestVerb: runSandboxGuest,
}

// sandboxHelperDispatch runs a sandbox network helper when argv names one,
// returning its exit code and true; otherwise (0, false).
func sandboxHelperDispatch(argv []string) (int, bool) {
	if len(argv) < 2 {
		return 0, false
	}
	run, ok := sandboxHelperFuncs[argv[1]]
	if !ok {
		return 0, false
	}
	return run(argv[2:]), true
}
