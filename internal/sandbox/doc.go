// Package sandbox is the PURE bwrap sandbox planner for B9 sandboxed
// terminals. It owns the bubblewrap (bwrap) vocabulary — the exact 0.4.0-floor
// flag set and its load-bearing order — and produces two things from injected
// probes and grounded DATA, never from ambient I/O:
//
//   - Probe(Env) Availability — the platform/backend readiness ladder
//     (GOOS → bwrap on PATH → version ≥ 0.4.0 → user-namespace canary),
//     classified into a closed verdict vocabulary rendered identically by the
//     launcher, dashboard, and doctor.
//   - BuildPlan(Request) (Plan, error) + Plan.Argv(inner) — the ordered bwrap
//     argv that tmpfs-blinds $HOME, ro-binds the derived tool/observer
//     binaries and runtime ladder, rw-binds ~/.observer and this run's
//     workspace, and masks foreign-OS mounts (the WSL /mnt/c-class amendment
//     A1). The order is load-bearing and mutation-proofed: the home tmpfs must
//     precede every under-home bind, and the ~/.observer/workspaces tmpfs must
//     precede the workspace rw bind. Every plan also runs in a private PID
//     namespace, drops the host sockets and interop the read-only root would
//     expose (SocketSweepDirs, HostSocketPaths, GuestUnsetEnv), and applies
//     the protective overlays last, including placeholders for protected
//     paths that do not exist yet, which Plan.HostArgv hands to the host
//     helper to create before bwrap runs (security ledger SR27-SBX-2).
//
// The package is PURE (CLAUDE.md "Module Boundaries" #1): all I/O — bwrap
// lookup, version read, and the canary smoke run — is injected through the Env
// struct of funcs (the internal/toolresolve pattern). imports_test.go pins it
// free of os/exec, database/sql, net/http, fsnotify, internal/adapter and
// internal/integration; the real exec of bwrap lives in one cmd file, and the
// per-tool bind DATA (integration.SandboxSpec's StateRW/StateRO) crosses the
// seam as plain []string so this planner never imports the registry.
//
// EnvMarker is the ONE owner of the OBSERVER_SANDBOX wire constant that the
// hook posture layer (U9) and cmd set on child processes launched inside the
// boundary; every other layer imports it from here.
package sandbox
