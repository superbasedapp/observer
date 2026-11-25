// Package hostfiles embeds the browser-capture native-messaging host files
// (the Node stdio host + its launcher) and exposes a single WriteHost helper
// that drops them into a stable per-user directory at install time.
//
// It is the browser rail's peer of internal/hook/hermesplugin: where the
// hermes package embeds a Python bridge and stamps OBSERVER_BIN into it, this
// package embeds host.js + host-launcher.sh and stamps OBSERVER_BIN /
// OBSERVER_CONFIG / the node interpreter path into the launcher. The shipped
// observer binary carries no dependency on the repo checkout — after
// `observer init --browser` the host EXISTS under the observer dir and the
// per-browser manifest (internal/browserhost) points its "path" at the
// written launcher, so there is nothing left to hand-edit.
//
// Two files ship:
//
//   - host.js          — the native-messaging stdio host (verbatim; it reads
//     OBSERVER_BIN / OBSERVER_CONFIG from the environment the launcher sets).
//   - host-launcher.sh — the executable the manifest "path" points at; its
//     {{OBSERVER_BIN}} / {{OBSERVER_CONFIG}} / {{NODE_BIN}} markers are
//     substituted at write time. It gets the exec bit; host.js does not.
//
// Re-running WriteHost is idempotent: existing files are overwritten with the
// freshly-stamped copies — the no-op upgrade `observer init --browser`
// performs after an `npm i -g @superbased/observer` refresh.
//
// No SQL / HTTP / fsnotify — a filesystem-only writer, injected the target
// dir + env so tests sandbox it.
package hostfiles
