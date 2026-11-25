package config

import "time"

// This file holds the config types of [browser]: the browser-extension
// ingest listener.

// BrowserConfig is the [browser] surface — the opt-in browser-chatbot
// capture rail (docs/plans/browser-extension-and-m365-copilot-proposal-
// 2026-07-10.md §5). LOCAL-ONLY, never distributed via the org policy
// registry (same posture as [predict]/[routing]/[cachewarm]). Same
// partial-merge invariant as CacheTrackConfig: an install with no [browser]
// section inherits the Default() seed (receiver AVAILABLE but the loopback
// LISTENER OFF — the native-messaging bridge is the default binding; the
// HTTP listener is the opt-in alternate). The daemon is the CEILING
// authority on what is stored (§5.1): GranularityCeiling clamps whatever
// the extension sends.
type BrowserConfig struct {
	// Enabled gates the whole browser rail on the daemon side. When false
	// the loopback listener never starts (the native-messaging hook path is
	// unaffected — it opens the DB directly like every CLI hook). Default
	// true so the rail is ready the moment the operator installs the
	// extension; the extension itself is opt-in regardless.
	Enabled bool `toml:"enabled"`
	// Listener configures the opt-in loopback HTTP receiver — the alternate
	// to the default native-messaging bridge.
	Listener BrowserListenerConfig `toml:"listener"`
	// Sites holds per-site enable toggles keyed by the *-web tool name
	// (chatgpt-web/claude-web/perplexity-web/gemini-web/copilot-web). A
	// missing key means "enabled" (fail-open — the extension's own per-site
	// toggle is the primary control; this is the daemon backstop). Set a key
	// false to make the daemon DROP that site's turns regardless of what the
	// extension sends.
	Sites map[string]bool `toml:"sites"`
	// GranularityCeiling is the daemon's maximum stored granularity
	// (§5.1: "usage_only" | "redacted" | "full"). The daemon is the final
	// authority on what is STORED, so the effective granularity of every
	// turn is min(what the extension sent, this ceiling). Default "full":
	// Observer is a local-first observability tool and browser capture
	// follows the same posture as every coding-agent adapter — full
	// prompt/response content stored NODE-LOCALLY (the scrub.Scrubber
	// secrets pass still applies; nothing leaves the node without the
	// [org_client.share] opt-in). The extension discovers this ceiling via
	// the native-messaging `config` event and sends at exactly this level;
	// an operator who wants less sets "redacted" or "usage_only" here (one
	// lever, dashboard-editable). An empty/unknown value is treated as
	// usage_only by the normalizer (fail-closed).
	GranularityCeiling string `toml:"granularity_ceiling"`
	// RetentionDays bounds how long browser rows are kept (rides the
	// existing retention machinery — 0 = keep forever / inherit the global
	// retention). Default 0.
	RetentionDays int `toml:"retention_days"`
	// IngestTimeoutMS bounds the browser-capture DB ingest path
	// (ingestBrowserTurn → store.Ingest). It is DELIBERATELY DECOUPLED from
	// the blocking-hook timeout ([observer.hooks].timeout_ms, ~500ms): by the
	// time this deadline applies the browser hook has ALREADY ACKed the
	// extension on stdout and runs as a detached child, so keeping it short
	// protects nothing — it only sheds captured turns whenever the daemon
	// briefly holds the SQLite write lock (a WAL checkpoint on a large DB, a
	// batch insert) even though the 30s busy_timeout would ride the
	// contention out. Default 35000 (35s); a zero / negative value resolves
	// to the default via IngestTimeout(). Same partial-merge rule as the
	// other [browser] keys — an install with no [browser] section inherits
	// the default.
	IngestTimeoutMS int `toml:"ingest_timeout_ms"`
}

// defaultBrowserIngestTimeoutMS is the fallback browser-capture ingest
// deadline used when [browser].ingest_timeout_ms is unset or non-positive.
// 35s: it must EXCEED the 30s SQLite busy_timeout (db.Open pragma) so a
// maximum-length write-lock wait is ridden out rather than cut off mid-wait
// (a 15s deadline still dropped turns whenever the daemon held the lock
// 15–30s). The pile-up trade-off — every captured turn is its own detached
// hook child, so a long deadline means more concurrent waiters — is accepted
// for this lane: browser-turn arrival is human-paced (single-digit per
// minute), and drops stay legible in browser-health.json telemetry.
const defaultBrowserIngestTimeoutMS = 35000

// maxBrowserIngestTimeoutMS caps [browser].ingest_timeout_ms. It exists so the
// daemon's end-to-end browser-ingest work is GUARANTEED to finish before the
// native-messaging host gives up on it: host.js
// (internal/browserhost/hostfiles/host.js) replies to Chrome after its
// HOST_INGEST_CAP_MS reply cap (40000ms) and then Chrome tears down the
// Windows→WSL bridge, killing a still-running ingest child. Because
// cmd/observer/browser.go now bounds db.Open + store.Ingest under IngestTimeout()
// (started BEFORE db.Open, whose SQLite busy_timeout can wait 30s), the real
// child runtime is <= IngestTimeout(); clamping that to 35000ms holds it ~5s
// below the 40000ms host cap. Keep the two constants in sync — host.js carries
// the matching cross-reference comment on HOST_INGEST_CAP_MS.
const maxBrowserIngestTimeoutMS = 35000

// IngestTimeout returns the browser-capture ingest deadline as a
// time.Duration. A zero or negative IngestTimeoutMS (unset, or an operator
// clamp) resolves to the generous default so the detached, post-ACK DB write
// is never starved by the short blocking-hook timeout; a value above
// maxBrowserIngestTimeoutMS is clamped DOWN so the end-to-end bound can never
// exceed the native host's reply cap even if Validate is bypassed (e.g. a
// programmatically-built config in a test).
func (b BrowserConfig) IngestTimeout() time.Duration {
	ms := b.IngestTimeoutMS
	if ms <= 0 {
		ms = defaultBrowserIngestTimeoutMS
	}
	if ms > maxBrowserIngestTimeoutMS {
		ms = maxBrowserIngestTimeoutMS
	}
	return time.Duration(ms) * time.Millisecond
}

// BrowserListenerConfig is the [browser.listener] sub-surface — the opt-in
// loopback HTTP receiver (internal/ingest/browser). The native-messaging
// bridge is the default binding; this is the alternate for deployments that
// prefer HTTP. Its own dedicated port, never :8820 / the dashboard mux.
type BrowserListenerConfig struct {
	// Enabled gates the loopback listener. Default FALSE — the
	// native-messaging bridge is the default receiver; turn this on only
	// when a deployment routes captured turns over HTTP instead.
	Enabled bool `toml:"enabled"`
	// ListenAddr is the host:port bind. Default 127.0.0.1:8821. A
	// non-loopback host is refused unless AllowNonLoopback is set.
	ListenAddr string `toml:"listen_addr"`
	// AllowNonLoopback permits a non-loopback bind (default false — the
	// network-posture guard).
	AllowNonLoopback bool `toml:"allow_non_loopback"`
	// Token is the shared secret the loopback receiver requires in the
	// X-SBO-Browser-Token header (defense-in-depth for the clientless,
	// default-off ingress — A4). Empty means the daemon auto-generates one at
	// start and persists it 0600 next to the observer DB
	// (browser-ingest-token), so an operator never has to set it by hand; set
	// it explicitly only to pin a known value.
	Token string `toml:"token"`
}
