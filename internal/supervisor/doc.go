// Package supervisor detects whether the Observer node daemon is kept
// running by a process supervisor: the systemd user unit, the launchd agent
// or the Windows service the templates in deploy/supervisor/ install.
//
// Why it matters (lane P1): on a managed node the daemon keeps AI tools
// routed through its own proxy. Those routes stay in the tools' config files
// while the daemon is down, so a daemon that is not restarted after a crash,
// a failed update or a reboot leaves every routed tool getting
// ConnectionRefused. A supervisor restarts it. Observer never requires one
// and never refuses anything without one; `observer doctor` and the admin
// integrity view only say so.
//
// Detect is pure: the decision is a table walked over facts a Probe supplies
// (environment, file existence, a Windows service lookup). OSProbe is the one
// place those facts are read from the real machine.
package supervisor
