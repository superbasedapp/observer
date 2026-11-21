// Package secshellrisk classifies the supply-chain risks of a build script:
// the run: blocks of a CI workflow and the RUN lines of a Dockerfile (OS and
// CI vulnerability scanning plan
// docs/plans/os-and-ci-vulnerability-scanning-plan-2026-11-04.md sections
// 4.1 and 5.1). It is the one owner of three questions both rule sets ask:
//
//   - an OS package install with no version (apt-get, apt, apk, dnf, yum,
//     microdnf, tdnf, zypper), rule rows S-753 and S-780;
//   - a language package install with no version or lock, read through the
//     install gate's own parser (internal/secfeed InstallsFromCommands,
//     injected as LangInstalls because it belongs to the security.deps
//     component), rule rows S-754 and S-781;
//   - remote content piped into an interpreter, decided by guard rule
//     R-170's own matcher (policy.RemoteCodePipe), rule rows S-755 and
//     S-782.
//
// Scripts are parsed with the guard shell parser (internal/policy
// ParseCommand), never run. The input is untrusted repository text: hits
// carry a kind, a fixed detail word and a line offset, never script text.
//
// The package is pure: no SQL, no HTTP, no process, no filesystem
// (imports_test.go).
package secshellrisk
