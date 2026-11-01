// Package extrun is the one hardened runner for external programs (joint
// security and sandbox roadmap, shared piece F0-2; security plan section 4.4
// "Running external engines safely" and section 8.6 execution rules; sandbox
// plan section 11.3 and the section 4.2 vendor CLI environment rules).
//
// A caller hands the Runner one Request: the owning component id, the
// program (a registry BinaryResolveSpec resolved through internal/toolresolve,
// or an absolute path chosen elsewhere, such as a scanner manifest), its
// arguments, the environment it may see, the expected digests and the caps.
// The Runner then, in order:
//
//  1. resolves the program to an absolute path (never a bare name through
//     PATH; the production resolver is toolresolve with the command-wrapping
//     shim exclusion that toolresolve/host.NewEnv sets);
//  2. checks the executable itself (absolute, a regular file, no symlink
//     unless the request allows one, then the link's final target is what
//     runs and what is hashed; no Windows batch or script shim);
//  3. records the SHA-256 of the binary, of every declared companion file and
//     of every companion executable (Program.CompanionExecs: gosec runs go,
//     Opengrep runs git), and refuses the run when an expected digest does
//     not match; a companion executable may put its directory on PATH and
//     is asked its version first, so the run record carries the toolchain
//     (Result.Toolchain);
//  4. builds a minimal environment from an explicit list (nothing is
//     inherited unless named, and secret-shaped or loader-injection names are
//     refused even when named), plus what the request's Engine profile adds:
//     the git hardening, a locale, and an engine-owned HOME and
//     XDG_CACHE_HOME inside the request's CacheDir;
//  5. resolves the caps (wall time, stdout and stderr bytes, memory, child
//     processes, CPU time, file size) and reports, per cap, whether this OS
//     enforces it, enforces it only on a best-effort basis, or cannot
//     enforce it at all, with its unit and, after the run, the mechanism
//     that held it; a cap is never claimed where the executor cannot hold
//     it;
//  6. optionally hands the plan to an injected IsolationProvider (the sandbox
//     plan's isolation engine, roadmap F0-11, fills it in later; nil means
//     the program runs directly);
//  7. runs it through the one injected Executor seam and classifies the
//     outcome through an ordered table, and the exit status through the
//     Engine's exit-code table (ClassifyExit). The executor holds the run
//     with the first rung of the ordered containment table it can set up
//     (ContainmentRungs: a job object, a per-run cgroup v2, the isolation
//     pid namespace, else the process group, labelled "not contained") and
//     records the rung on the run (Result.Containment).
//
// The package is PURE (CLAUDE.md "Module Boundaries" rule 1): every decision
// above is table-driven code over data, and all I/O (the resolver, the file
// inspector, the hasher, the environment read and the process start) is
// injected. imports_test.go pins it free of os, os/exec, syscall, net,
// database/sql and fsnotify. The production wiring, including the process
// group kill on Linux and macOS and the job object on Windows, lives in the
// sibling package internal/extrun/host.
//
// No existing call site uses the runner yet (this is additive). The obvious
// first consumers, each moved over by the lane that first needs it, are:
// gitview.RunReadOnly (read-only git), the Plans & limits vendor CLIs in
// internal/planlimitsnet (codex app-server, kiro-cli, amp, auggie), the
// tailnet and SSH probes (internal/tailnet, internal/sshforward), the
// commit scanner's git log, the benchmark arena drivers, the security plan's
// scanner drivers (opengrep, osv-scanner, gitleaks, user-configured SARIF
// drivers) and the sandbox plan's vendor CLIs (docker, podman,
// cloud-hypervisor, gh and the rest of its driver rows).
//
// internal/extrun/extruntest is the fake exec seam (a recording Executor and
// an in-memory file table) for tests of the runner and of its consumers.
//
// Every run names its owning component (Request.Component) so the
// Surface.Processes declaration test in tests/invariant can check, through a
// fake Executor, that a component only starts the binaries its catalog row
// declares (DeclaresProcess is the matching rule).
package extrun
