// Package sandboxopenshell is the pure planner of the OpenShell sandbox row
// (OpenShell plan doc 04 Part I R2.5 and R2.6 phase O1, build plan 05
// section 2, lane O1A). OpenShell is one more pluggable sandbox backend: a
// registry row in internal/sandboxbackend, this planner, one driver behind
// registerSandboxDriver in cmd/observer (lane O1B), a component row and an
// omit tag.
//
// What it computes, with no I/O:
//
//   - Compile: the OpenShell policy document (version: 1) and the Docker
//     driver mounts (--driver-config-json) from the shipped inputs only (rule
//     W2): the effective [terminal.sandbox] and [terminal.sandbox.openshell]
//     values (Settings), the run's mount scope and its bind plan. It adds no
//     mount the bind plan did not name, except the home (a tmpfs, or a
//     read-only bind). It is not the floor gate: selection is
//     (sandboxselect), so Compile reads no floor.
//   - CreateArgv, ListArgv, GetArgv, DeleteArgv: the fixed argv of the
//     `openshell` CLI (lane O0 chose the CLI as the control interface; there
//     is no SDK and no new go.mod dependency).
//   - The tested-version table (floor v0.1.6; an untested version is
//     refused) and the version-scoped CLI outcome table (the exact not-found
//     text of a version; any other text reads unknown, never gone).
//   - The probe verdict table: platform, CLI present, gateway reachable and
//     authenticated, version in the table, driver, Landlock ABI, Observer's
//     own runtime canary (doctor ok is never enough: upstream #4133), and
//     the gateway-wide bind-mount opt-in. First failing row wins.
//   - The label grammar the labelled reaper (lane O1B) selects on.
//
// The facts it encodes from lane O0's live run (receipt
// _spikes/openshell/receipts/linux-2026-10-31-f04566.json) are cited where
// they are used. The package imports no database/sql, net/http, os/exec or
// fsnotify (imports_test.go pins it); the driver files are its only
// importers (tests/invariant/openshell_boundary_test.go).
package sandboxopenshell
