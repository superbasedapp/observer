// Package browserhost writes the Chromium native-messaging host manifest
// for the opt-in browser-capture extension — the 4th `observer init` consent
// step (docs/plans/browser-extension-and-m365-copilot-proposal-2026-07-10.md
// §10.2). It is the peer of internal/hook.Registry.Register for the browser
// rail: where hook registration edits an AI tool's own config file, this
// writes the per-browser NativeMessagingHosts manifest that lets a Chromium-
// family browser launch `observer browser hook` as a native-messaging host.
//
// The manifest SHAPE is identical across Chrome / Edge / Brave / Chromium;
// only the directory differs — a small per-browser × per-OS lookup TABLE
// (CLAUDE.md #5, decision logic is table-driven, not a switch on browser
// name). Detection is "a Chromium-family browser profile dir exists"; a
// browser whose profile dir is absent is skipped, never fabricated.
//
// No SQL / HTTP / fsnotify — this is a filesystem-only writer, injected the
// home dir + GOOS so tests sandbox it.
package browserhost
