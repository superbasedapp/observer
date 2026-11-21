// Package secreachgovuln is the only importer of golang.org/x/vuln (OS and
// CI vulnerability scanning plan section 14.5 item 3b, spike RG-0 "Answer":
// binary mode first). It runs govulncheck IN PROCESS through
// golang.org/x/vuln/scan in `-mode binary -format json`, against a
// database directory the caller wrote (the matched OSV records as a flat
// list of <id>.json files; no Go vulnerability database is built or
// downloaded), and hands back govulncheck's JSON stream. It reads the
// output nowhere else: interpretation is internal/secreachgo's and
// internal/secreach's.
//
// What it links: x/vuln (BSD-3-Clause plus the Go PATENTS grant) and,
// through it, golang.org/x/tools and golang.org/x/telemetry (both
// BSD-3-Clause plus PATENTS), none of which the observer binary links
// otherwise. The component security.reach.go (omit tag
// sbo_omit_security_reach_go, or sbo_omit_security) compiles it out:
// stub.go is the omitted build's API (Compiled false, every call
// ErrNotCompiled), and it imports nothing from x/vuln, so the three modules
// leave the binary (tests/invariant/security_reach_go_binary_test.go).
//
// The rules it keeps (RG-0 section G4):
//
//   - the database is always a file:// URL to a local directory (Run
//     refuses anything else), so the client never opens a connection;
//   - binary mode only: no source mode, so no Go toolchain is executed
//     (govulncheck's one `go env GOROOT` probe finds no go on the scan
//     child's empty PATH and is ignored);
//   - the environment handed to govulncheck is empty, never the process's;
//   - the caller detects a stripped binary BEFORE calling Run
//     (internal/secreachgo.Inspect): govulncheck would otherwise substitute
//     every known vulnerable symbol and report false function-level traces.
//
// It runs only inside the dependency scan child (`observer security
// scan-child`, internal/secscan/scalibrchild), under the shared runner's
// memory and wall caps; never in the daemon.
package secreachgovuln
