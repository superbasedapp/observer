// Package depdriver is the secscan.Driver of the linked OSV-SCALIBR
// inventory driver (security.scan.scalibr, security pillar plan sections
// 4.4 and 8.4) and the shared result path of both dependency drivers.
//
// The SCALIBR scan never runs in the caller's process: Scan starts the
// caller's own binary again (`observer security scan-child`) through the
// injected shared runner internal/extrun, under the caps in ScalibrLimits
// (the match peaks at about 600 MB, JSP-9b), with the depscan.ChildRequest
// on stdin, and reads the depscan.ChildResponse from stdout. A build
// without SCALIBR starts no process and reports "not scanned"
// (not_compiled).
//
// Result turns either driver's inventory and per-ecosystem match results
// into the normalized secscan.Result through depscan: grouped findings on
// the "osv" adapter row, the coverage table, the engine identity with the
// database epochs.
//
// It holds no I/O of its own beyond what is injected (the runner); it
// belongs to security.deps and is compiled out with sbo_omit_security_deps.
package depdriver
