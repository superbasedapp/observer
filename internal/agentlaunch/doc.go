// Package agentlaunch is the pure request vocabulary and decision logic for
// a scriptable agent launch (`observer launch`, decision P-228, design
// docs/plans/discovery-cli-2026-11-03.md section 4.1, phase 1b).
//
// It owns three things and nothing else:
//
//   - Normalize: the ordered validation rows a launch request walks before
//     anything is spawned (tool is a launchable registry row, the project
//     directory is absolute, the workspace source is one of the closed four,
//     the source-specific fields are consistent, no field can smuggle an
//     option or a control character). Both the CLI (before dialing the
//     daemon) and the daemon (before it calls the terminal service) run the
//     same rows, so the two can never disagree about what a valid request is.
//   - Choose: the table-driven choice of sandbox backend against the
//     daemon's own probed rows. "auto" never takes a beta row (ruling
//     P-062), an explicit backend is judged on its own row, and a requested
//     sandbox that cannot be built is a refusal, never an unsandboxed launch.
//   - the closed refusal codes the attach socket and the CLI report.
//
// The launch itself stays in internal/termsvc (LaunchFresh), reached from
// cmd/observer through the dashboard's own launch-gate walk; this package
// imports no database/sql, net/http, os/exec or fsnotify (imports_test.go)
// and its types never cross that seam: the caller maps a Normalized request
// onto the terminal service's plain-string request.
package agentlaunch
