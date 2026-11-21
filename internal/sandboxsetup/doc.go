// Package sandboxsetup is the pure planning core of sandbox installation
// lifecycle management (plan of record
// docs/plans/sandbox-installation-lifecycle-plan-2026-11-06.md, sections 3.2
// and 3.3): what a sandbox backend needs on this host, what Observer may do
// about each missing piece, and the ordered steps that set the backend up.
//
// It owns only what is sandbox-specific:
//
//   - the PREREQUISITE table (prereqs.go): one row per thing a backend can
//     need (a host program, a kernel feature, a group, a service, signed
//     content, an engine image, an account, a credential, a consent, a
//     config key), with how it is detected and, per host and host family,
//     what Observer may do about it (a Class) and how (a Channel);
//   - the VERDICT map (verdicts.go): which driver probe verdict means which
//     prerequisite is missing;
//   - the PLANNER (plan.go): Build turns a backend's registry row
//     (sandboxbackend.Capability.Setup, the ordered prerequisite ids), the
//     host's facts and the switches in force into a Plan of Steps, through
//     one ordered rule table (planRules).
//
// Everything else stays with its one owner: install channels, the lifecycle
// vocabulary and the package-manager table are internal/toolinstall's; the
// install record is the tool_installs table behind internal/store; running a
// step is cmd/observer's runner, which dispatches on a Step's Channel, never
// on a backend id; the decision whether a row can run at all is
// internal/sandboxselect's.
//
// The package is pure: no database/sql, net/http, os/exec or fsnotify, and it
// imports only internal/toolinstall, internal/sandboxbackend,
// internal/sandboxselect, internal/sandboxvocab and the standard library
// (imports_test.go). Facts are gathered by the caller and passed in.
//
// Download pins (pins.go, lane download) fill the package-level pins slice;
// an owed pin never downloads (its step reads as a guide), so no digest is
// ever invented.
package sandboxsetup
