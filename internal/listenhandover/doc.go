// Package listenhandover passes the API proxy's listening socket from a
// daemon to the process image that replaces it, so a restart keeps the
// proxy port answering (operator ruling L-168 (ii), 2026-11-24).
//
// The daemon IS the proxy. A restart that closes the socket and binds it
// again gives every AI tool routed through it ConnectionRefused for the
// seconds in between, and a running session already holds the proxy's base
// URL in its own environment, so taking the route off its config file does
// not reach it. A socket that stays open does: the kernel keeps completing
// connections into the socket's backlog while the old image shuts down and
// the new one starts, and the new image accepts them. Nothing is refused.
//
// The mechanism is the classic execve hand-over: before the restart the
// daemon duplicates the listener's descriptor (Prepare); right before the
// in-place re-exec it clears close-on-exec on that duplicate and names it in
// the environment (ExecEnv). The new image claims it at once (Claim: marks
// it close-on-exec again so no child it spawns inherits it, and removes the
// variables), and the proxy adopts it only when it listens on the address
// the proxy is configured for (Listen); otherwise it is closed and the
// proxy binds as before. Pausable lets the old image stop accepting while
// it waits for in-flight requests, so connections made meanwhile wait in
// the backlog for the new image instead of extending the drain.
//
// Unix only (execve). On Windows Supported is false and every function is a
// no-op or an error, so the restart there keeps its own refusal.
//
// The package speaks net and os only; it knows nothing of the proxy, the
// dashboard or a service manager (pinned by imports_test.go).
package listenhandover
