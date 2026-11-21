// Package promptjudgecases holds the shared secret-gate cases of the
// organization's coding-agent prompt judge (planeb.admission node lane),
// for tests only (lane adm-p2 lows, N3). The org admin's simulate test
// (cmd/observer-org) and the node daemon's test (cmd/observer) both run
// every case through their own real path, the simulate's node route and
// the daemon's evaluateCodingAdmission wrapper, against the same expected
// outcome, so the two are proven to agree without either test calling the
// other's code. Pure data: no I/O.
package promptjudgecases
