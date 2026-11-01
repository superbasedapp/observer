// Package service is the pure-logic layer behind `observer service`:
// it renders the systemd unit (Linux) and the per-user launchd
// LaunchAgent (macOS, launchd.go) that supervise `observer start`, and
// constructs the systemctl/journalctl/launchctl argv the command executes.
//
// Boundary: rendering + argv only. Supervisor detection, unit and plist
// writes, and process execution live in cmd/observer/service.go and
// cmd/observer/service_launchd.go. See
// docs/teams-getting-started.md and docs/daemon-restart-runbook.md (the
// daemon IS the proxy on :8820 — restarting the service while a route
// is active drops that session).
package service
