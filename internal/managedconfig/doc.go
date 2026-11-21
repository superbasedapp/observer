// Package managedconfig loads the local component ceiling (modular
// packaging plan docs/plans/modular-packaging-plan-2026-10-07.md section
// 6.2.2, rev N2; lane MP-GOVF): the machine owner's MDM-pinned, explicit
// allow-set of components plus the catalog version it was resolved against.
// A managed org may widen the binary within vendor-built distros by default
// (operator ruling Q14, D-374); the ceiling is the opt-in for an enterprise
// that needs more, and nothing the org publishes can exceed it.
//
// The ceiling is NOT read through internal/config. That loader honours
// --config, project files and environment overrides; this one reads one
// fixed per-OS source that no flag, environment variable or project file
// can redirect (pinned by imports_test.go, which also forbids any
// environment read in this package):
//
//   - Linux and other unix: /etc/superbased/managed.toml, opened with
//     O_NOFOLLOW, root-owned, not group or world writable, every parent
//     directory root-owned and not group or world writable.
//   - macOS: the MDM managed-preferences domain
//     /Library/Managed Preferences/app.superbased.observer.plist (converted
//     by /usr/bin/plutil), else /Library/Application Support/SuperBased/
//     managed.toml, both with the same ownership checks.
//   - Windows: HKLM\SOFTWARE\Policies\SuperBased\Observer, values
//     Components (REG_MULTI_SZ) and CatalogVersion (REG_DWORD), refused
//     unless only Administrators, SYSTEM or TrustedInstaller can write it.
//
// Fail-closed (fourth-pass M1): a ceiling source that exists but is
// unreadable, malformed or fails an ownership check yields core only when no
// valid ceiling was ever read, or the caller's last-known explicit set when
// one was; either way updates and distro transitions are refused until the
// source is valid again, and Result.FailedCheck names the check. The daemon,
// observer hook, bare launchers, doctor and the updater all call Load.
//
// The same source may also carry the attach policy (attach.go; plan 06
// section 19.3 rule 2 way 3 and rule 3 row 1, plan 07 M8.6): the
// organization server URL this machine attaches to, the attach method (a
// closed vocabulary: idp) and a lock. LoadAttach decides it. An unlocked URL
// is the default target of a bare `observer enroll`; a locked one becomes
// internal/attachrule's row-1 lock, so the node refuses attaching to any
// other server and disconnecting. A source with attach keys and no ceiling
// is a valid source with no ceiling (ErrNoCeiling, StatusNone); a source that
// fails a check makes the attach policy AttachStatusInvalid, and the node
// refuses every destination change until it is fixed.
//
// The decisions (ceiling.go, attach.go, acl.go) are pure and table-driven;
// the per-OS readers (source_*.go) only collect a Probe.
package managedconfig
