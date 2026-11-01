// Package hookbridge is the pure core of the fail-closed Windows hook bridge
// (surface-gap ruling AW-37, decision D12): `observer hook-bridge`, run by
// the Windows observer.exe, starts the WSL daemon's `observer hook` through
// wsl.exe for the tool-gate events of an ENFORCING MANAGED node, and turns
// "wsl.exe could not start the hook" into a block, which a shell trailer
// cannot do portably across the shells that read one settings file.
//
// Two halves meet here:
//
//   - the hook side: `observer hook ... --bridge-sentinel` maps every exit
//     code other than 0 and 2 to SentinelExit (HookExit), so the bridge can
//     tell "the hook ran and answered non-blocking" from anything wsl.exe
//     itself returns;
//   - the bridge side: Decide is the ordered table that maps how the run
//     ended to the exit the host sees, and Argv builds wsl.exe's argument
//     list from the entry's validated fields.
//
// No I/O: the process, the streams and the fail-closed reply live in
// cmd/observer (hookbridge.go); imports_test.go pins it pure. The writer
// that puts the bridge in a tool's settings is switched off behind live
// check LC6 (integration.WriterKindHookBridge, DEC-12).
package hookbridge
