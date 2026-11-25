// Package config loads and validates the SuperBased Observer configuration.
//
// Config is sourced from (in order): defaults → ~/.observer/config.toml →
// per-project .observer/config.toml → OBSERVER_<SECTION>_<KEY> env vars.
// See spec §16.
//
// config.go holds the root Config type, Default, Load and Validate. Each
// [section]'s types live in a file named for the section (proxy.go,
// guard.go, terminal.go, and so on). TerminalSandboxConfig, the hosted
// sandbox sub-table and the [remote] and [org_client] types stay in
// config.go because invariants and lints pin text in that file.
package config
