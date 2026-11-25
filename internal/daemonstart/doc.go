// Package daemonstart is the pure decision an `observer <tool>` launcher walks
// when it finds the Observer daemon down (operator ruling L-169, 2026-11-24):
// a developer who runs a launcher while the daemon is down expects Observer
// to come up, so the launcher starts the daemon first and then launches
// routed, exactly as when the daemon was up. Going direct or refusing (the
// proxy-down fallback rows, cmd/observer proxy_fallback.go) is what happens
// only when the daemon cannot come up.
//
// It owns four tables and nothing else:
//
//   - Decide: the ordered rows that say proceed (the proxy serves), leave it
//     to the fallback (nothing to start here), refuse to start (the daemon
//     belongs to another OS context, or the port is held by something that
//     is not Observer), wait (a daemon is already starting), or start.
//   - ChooseMechanism: how to start the daemon this install owns: its
//     systemd user unit, its launchd agent, the binary its Windows sign-in
//     entry names, else `observer start` in the background.
//   - OtherContextFor: whether this machine's daemon lives in another OS
//     context (the WSL daemon a Windows `observer.exe` bridges its hooks
//     into), where a second daemon would open a second database.
//   - the copy: one line per outcome, so every launcher says the same thing.
//
// Every fact is resolved by the caller (cmd/observer launch_autostart.go)
// and passed in as plain data; nothing here dials, execs, reads a file or
// takes a lock (imports_test.go pins it).
package daemonstart
