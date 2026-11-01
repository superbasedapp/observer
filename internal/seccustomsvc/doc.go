// Package seccustomsvc is the I/O side of the user-configured scanner
// driver (security pillar plan section 8.6, Phase D3; component
// security.scan.custom). The pure rules live in internal/seccustom; this
// package reads the manifest file, discovers executables through
// internal/toolresolve (the shim exclusion on), checks and hashes them,
// keeps the accepted records, and runs a driver through the hardened runner
// internal/extrun, isolated through the injected extrun.IsolationFactory
// where the isolation component can run it.
//
// It is the ONE writer of the driver records: files under
// ~/.observer/security/custom/ (the global config directory the dashboard
// writes, which guard rule R-160 protects from agent writes). Nothing is
// read from a project, a repository or the environment: cloning a
// repository never means code execution on the next scan.
//
// Every accept or change writes an audit line (audit.jsonl beside the
// records) and raises an agent_config finding ("a scanner was added or
// changed"), so a manifest planted outside the dashboard is visible.
//
// Compiled out with sbo_omit_security_scan_custom (and the module root's
// sbo_omit_security).
//
// This file carries no build tag on purpose (the D-535 precedent of
// internal/aggregatesvc): with sbo_omit_security the package still exists,
// empty, so the omit-tag test run of a package that holds a tagged file
// does not fail with every file excluded.
package seccustomsvc
