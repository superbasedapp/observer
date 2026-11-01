package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/browserhost"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// newBrowserCmd implements `observer browser hook <event>`. The browser
// extension's native-messaging host invokes this with a captured-turn JSON
// payload on STDIN — the sibling of `observer hook <tool> <event>` for the
// CLI adapters, but for the browser rail.
//
// Like the CLI hook path it opens db.Open directly (works even when the
// daemon isn't running) and MUST never fail hard: parse/DB errors are logged
// to stderr and swallowed so the browser's native-messaging port never sees
// a crash.
//
// `--config <path>` propagates the daemon's config so the DB write lands on
// the same observer.db the daemon is using.
func newBrowserCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "browser <subcommand>",
		Short: "Browser-extension capture bridge",
		Long: "Landing point for the opt-in MV3 browser extension. The\n" +
			"extension's native-messaging host invokes `observer browser hook\n" +
			"<event>` with a captured-turn JSON payload on stdin.",
	}

	hookCmd := &cobra.Command{
		Use:   "hook <event>",
		Short: "Ingest a captured browser-chatbot turn from stdin",
		Long: "Reads a captured-turn JSON payload (the browserchat wire\n" +
			"contract) from stdin, normalizes it, and writes it to the\n" +
			"observer DB via the unchanged store.Ingest seam. Errors are\n" +
			"logged to stderr and swallowed - never blocks the browser.",
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			event := ""
			if len(args) > 0 {
				event = args[0]
			}
			handleBrowserHook(cmd.Context(), event, configPath)
		},
	}
	hookCmd.Flags().StringVar(&configPath, "config", "", "Path to observer config.toml - when set, hook DB writes land on the config's observer.db (matches the daemon)")
	cmd.AddCommand(hookCmd)

	var healthConfigPath string
	healthCmd := &cobra.Command{
		Use:   "health",
		Short: "Show the last health beacon relayed by the browser extension",
		Long: "Prints the per-site health the browser extension has relayed\n" +
			"through the native-messaging host (site, status, reason, age).\n" +
			"A stale or empty table means the extension isn't talking to the\n" +
			"host - the fastest way to see a broken manifest or degraded parser.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runBrowserHealth(cmd.OutOrStdout(), healthConfigPath)
		},
	}
	healthCmd.Flags().StringVar(&healthConfigPath, "config", "", "Path to observer config.toml - resolves the observer dir the health file lives in")
	cmd.AddCommand(healthCmd)
	return cmd
}

// handleBrowserHook parses the captured-turn payload on stdin, normalizes it
// through internal/adapter/browserchat, and ingests the resulting events.
// The event argument is accepted for symmetry with the CLI hook path (a
// future capture/heartbeat/health event class) but is currently informational
// only — the payload's `site` field is the real discriminator.
func handleBrowserHook(ctx context.Context, event, configPath string) {
	label := "browser"
	if event != "" {
		label = "browser:" + event
	}

	// Read ONE byte past the ingest cap so an over-limit body is DETECTED
	// rather than silently truncated into invalid JSON. A truncated body used
	// to parse-fail and drop the whole turn (token metadata included) while
	// still ack'ing "ok" and leaving the health file unable to even key the
	// loss — see the over-limit branch below.
	body, _ := io.ReadAll(io.LimitReader(os.Stdin, browserIngestCapBytes+1))
	overLimit := len(body) > browserIngestCapBytes
	if overLimit {
		body = body[:browserIngestCapBytes]
	}
	body = bytes.TrimPrefix(body, []byte{0xEF, 0xBB, 0xBF})

	// The config event is REQUEST/RESPONSE, not fire-and-forget: it must emit
	// the daemon's effective browser policy as the ONLY stdout output so
	// host.js can relay it verbatim to the extension. The immediate
	// {"status":"ok"} ack is therefore SUPPRESSED for it — the ack write moved
	// below this dispatch decision, so config's config-JSON is stdout's sole
	// content. Every other event keeps the ack-first, work-detached behavior.
	if event == "config" {
		emitBrowserConfig(configPath, label, body)
		return
	}

	// Ack immediately on stdout — the native-messaging host relays this to
	// the extension; it must never wait on the DB path.
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"status": "ok"})

	if len(body) == 0 {
		return
	}

	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-browser: %s config: %v\n", label, err)
		return
	}
	if !cfg.Browser.Enabled {
		return // rail disabled on the daemon side — drop the turn, fail-soft.
	}
	// A health beacon (event "health") is recorded to a small node-local file
	// so daemon-side failures are LEGIBLE (A6) — it never touches the DB /
	// store.Ingest path. host.js routes payload.type=="health" here.
	if event == "health" {
		// A beacon from an extension speaking a protocol this observer does
		// not support is not merged: its fields may mean something else
		// (lane MP-ART). The config handshake already recorded the refusal.
		if r := browserhost.Refusal(browserhost.ParseHello(body).Protocol); r != "" {
			fmt.Fprintf(os.Stderr, "observer-browser: %s health refused: %s\n", label, r)
			return
		}
		if err := recordBrowserHealth(ctx, cfg, body); err != nil {
			fmt.Fprintf(os.Stderr, "observer-browser: %s health: %v\n", label, err)
		}
		return
	}
	healthPath := filepath.Join(browserObserverDir(cfg), browserHealthFileName)
	// Over-limit capture: the payload exceeded the ingest cap and the tail was
	// truncated, so the JSON is no longer valid — attempting to normalize it
	// would drop the turn AND lose the token metadata with only a swallowed
	// stderr line. Record an EXPLICIT, keyed drop instead (best-effort site
	// from the leading bytes; "unknown" when the truncation left them
	// unparseable), so the operator can see WHY turns are vanishing even
	// though the extension's beacon says "ok". Ack semantics are unchanged —
	// the "ok" ack was already written above.
	if overLimit {
		// Drain the rest of stdin before returning. The native-messaging host
		// wrote the FULL (over-cap) frame to our stdin and, under the
		// reply-after-exit contract, is waiting for us to exit before it acks
		// Chrome. If we exit while megabytes are still queued in the pipe, the
		// host's write side takes an async EPIPE. host.js guards that with a
		// child-stdin 'error' handler, but draining here avoids the error
		// entirely (finding 4 — cheap belt-and-suspenders). Bounded by
		// whatever the extension sent.
		_, _ = io.Copy(io.Discard, os.Stdin)
		site, _, _ := peekBrowserTurn(body)
		if site == "" {
			site = "unknown"
		}
		// Bounded the same way as every other health-telemetry write (MED
		// finding): this is the drop record's ONLY chance to be recorded, and
		// it must not be lost to an indefinite flock wait either — ctx here
		// still carries no deadline of its own (workCtx below hasn't been
		// created yet), so withBrowserHealthLock falls back to its own short
		// bounded timeout.
		recordBrowserCapture(ctx, healthPath, captureOutcome{site: site, dropReason: browserIngestCapDropReason})
		return
	}

	// Bound the END-TO-END DB work (db.Open + store.Ingest) under ONE deadline
	// started BEFORE db.Open — not just the insert. db.Open can itself wait up
	// to the 30s SQLite busy_timeout (locks) and run migrations, so a deadline
	// that starts only after it opens leaves the host's HOST_INGEST_CAP_MS (40s
	// — see host.js) reply cap unable to bound the child's real runtime: the
	// host would ack Chrome, Chrome would tear down the WSL bridge, and a
	// still-running ingest child would be killed mid-write (the original
	// silent-loss bug). config.BrowserConfig.IngestTimeout() is clamped to
	// config.maxBrowserIngestTimeoutMS (35s), held below the 40s host cap with
	// margin, so this whole span is guaranteed to finish before the host gives
	// up. The native host holds the browser's ack until this process EXITS
	// (host.js reply-after-exit contract — required on the Windows wsl.exe
	// bridge, where Chrome's post-ack teardown would kill a still-running
	// ingest), so this deadline IS the user-visible ack latency ceiling; a
	// short deadline protects nothing here — it only drops captured turns when
	// the daemon momentarily holds the SQLite write lock (a WAL checkpoint on a
	// large DB, a batch insert), even though the 30s busy_timeout would ride
	// out the contention. The generous window gives that busy_timeout headroom.
	workCtx, cancel := context.WithTimeout(ctx, cfg.Browser.IngestTimeout())
	defer cancel()
	database, err := db.Open(workCtx, db.Options{Path: cfg.Observer.DBPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-browser: %s db: %v\n", label, err)
		return
	}
	defer database.Close()

	st := store.New(database)
	guardBrowserHookStore(cfg, st, os.Stderr)
	if err := ingestBrowserTurn(workCtx, st, body, cfg.Browser, healthPath); err != nil {
		fmt.Fprintf(os.Stderr, "observer-browser: %s ingest: %v\n", label, err)
	}
}

// guardBrowserHookStore composes the guard onto the native-messaging hook's
// short-lived store so a captured browser prompt runs the post-hoc capture
// lane at ingest, exactly like every watcher-ingested prompt (PGC-2 / P3).
// Before this the five *-web rows were rescan-only: nothing evaluated a
// browser prompt until an operator ran `observer guard rescan`. The hook
// flavour of the guard (buildHookGuard: lazy DB opens, no project-roots
// scan) keeps the host's reply-after-exit ack latency where it was; the
// pre-send lookup reuses the store this process already holds. A disabled
// guard, or a construction failure, leaves the store unguarded (fail-open
// at composition, the same contract as every hook path).
func guardBrowserHookStore(cfg config.Config, st *store.Store, stderr io.Writer) {
	if !cfg.Guard.Enabled || cfg.Guard.Mode == "off" {
		return
	}
	g := buildHookGuard(cfg, stderr)
	if g == nil {
		return
	}
	g.SetPromptPreSendLookup(preSendPromptLookup(st, nil))
	st.SetGuard(g)
}

// browserConfigResponse is the daemon's effective browser policy, emitted by
// the `observer browser hook config` event and relayed VERBATIM to the
// extension by host.js as the native-messaging response. It is how the
// extension follows the daemon's configured granularity with zero user
// configuration: the extension sends at min(any explicit user granularity,
// this Granularity), so it never sends more content than the daemon stores.
// Every field is a NON-sensitive daemon-side toggle — no DB, no content.
type browserConfigResponse struct {
	Type        string          `json:"type"`
	Granularity string          `json:"granularity"`
	Enabled     bool            `json:"enabled"`
	Sites       map[string]bool `json:"sites"`
	// Degraded flags a fail-closed fallback (a config-load error) so the
	// extension can tell a real daemon policy from the safe default.
	Degraded bool `json:"degraded,omitempty"`

	// Native-host protocol handshake (lane MP-ART, T-601), additive: an
	// older extension ignores these. ProtocolMin / ProtocolMax are the
	// extension protocols this observer accepts; Refused (with Reason)
	// answers an extension whose protocol is outside that range, and
	// Enabled is then false so capture stays off.
	ProtocolMin     int    `json:"protocol_min"`
	ProtocolMax     int    `json:"protocol_max"`
	ObserverVersion string `json:"observer_version,omitempty"`
	Refused         bool   `json:"refused,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// withHandshake stamps the host's protocol range on a config reply and, for
// a refused extension protocol, turns capture off with the reason.
func (r browserConfigResponse) withHandshake(h browserhost.Hello) browserConfigResponse {
	r.ProtocolMin, r.ProtocolMax, r.ObserverVersion = browserhost.ProtocolMin, browserhost.ProtocolMax, version
	if reason := browserhost.Refusal(h.Protocol); reason != "" {
		r.Enabled, r.Refused, r.Reason = false, true, reason
	}
	return r
}

// normalizeBrowserGranularity maps a raw [browser].granularity_ceiling string
// to the closed §5.1 vocabulary (usage_only | redacted | full), collapsing an
// empty / unknown value to the usage_only floor — the same fail-safe the
// browserchat normalizer applies. Table-driven (a set membership), not a
// nested branch, so a new level is one map entry.
func normalizeBrowserGranularity(s string) string {
	known := map[string]struct{}{
		browserGranularityUsageOnly: {},
		browserGranularityRedacted:  {},
		browserGranularityFull:      {},
	}
	if _, ok := known[strings.TrimSpace(s)]; ok {
		return strings.TrimSpace(s)
	}
	return browserGranularityUsageOnly
}

// The section 5.1 granularity vocabulary the [browser] config and the
// extension speak. Spelled out here, not taken from
// internal/adapter/browserchat, so the bridge builds without the
// browser-chat adapters (lane MP-L1D, T-598);
// TestBrowserGranularityMatchesTheAdapter pins them to the adapter's own
// constants in every build that has it.
const (
	browserGranularityUsageOnly = "usage_only"
	browserGranularityRedacted  = "redacted"
	browserGranularityFull      = "full"
)

// emitBrowserConfig handles the `observer browser hook config` event. The
// extension asks the daemon for its effective browser policy so it can send at
// exactly the daemon's configured granularity ceiling — the single lever,
// zero user configuration. Config is loaded FRESH (config.Load), so the ceiling
// is hot without a daemon restart, exactly like every other browser hook. It
// NEVER opens the DB. The config JSON is printed as the ONLY stdout line
// (host.js relays it verbatim); a config-load error still prints a valid,
// fail-closed usage_only default so the extension always gets a parseable
// answer. Deprecation/warning noise from config.Load goes to stderr, so it
// never pollutes the relayed stdout line.
//
// body is the config request itself: its handshake fields (protocol and
// extension_version, lane MP-ART) are recorded to the node-local
// browser-extension.json, best-effort, before the reply, and an extension
// protocol this observer does not support is answered with refused:true and
// capture off.
func emitBrowserConfig(configPath, label string, body []byte) {
	hello := browserhost.ParseHello(body)
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "observer-browser: %s config: %v\n", label, err)
		_ = json.NewEncoder(os.Stdout).Encode(browserConfigResponse{
			Type:        "config",
			Granularity: browserGranularityUsageOnly,
			Enabled:     true,
			Sites:       map[string]bool{},
			Degraded:    true,
		}.withHandshake(hello))
		return
	}
	if err := browserhost.RecordSeen(browserObserverDir(cfg), hello, nowMillisFn()); err != nil {
		fmt.Fprintf(os.Stderr, "observer-browser: %s handshake record: %v\n", label, err)
	}
	sites := cfg.Browser.Sites
	if sites == nil {
		sites = map[string]bool{}
	}
	_ = json.NewEncoder(os.Stdout).Encode(browserConfigResponse{
		Type:        "config",
		Granularity: normalizeBrowserGranularity(cfg.Browser.GranularityCeiling),
		Enabled:     cfg.Browser.Enabled,
		Sites:       sites,
	}.withHandshake(hello))
}

// ingestBrowserTurn is the ONE OWNER of the browser-capture normalize →
// store.Ingest path. Both the native-messaging hook (above) and the loopback
// listener (cmd/observer/start.go) funnel a raw captured-turn body through
// here, so the transport is a deployment detail, not a schema fork. It
// enforces the daemon's side of the §5.1 precedence — the per-site enable
// toggle and the granularity ceiling — before anything is stored.
//
// A site the daemon has toggled off is dropped silently (nil error). An
// unparseable / unknown-site body returns the normalize error for the caller
// to log; the caller never crashes on it.
//
// healthPath is the node-local browser-health.json the C1 capture telemetry
// is recorded to (ingested / dropped / synthetic counters). It is recorded
// BEFORE this function returns — the durable, legible drop signal that
// survives the hook child's exit, since the stderr the caller logs to is lost
// (host.js exits before the detached async hook child prints). "" disables
// telemetry (test call sites that don't assert on it).
func ingestBrowserTurn(ctx context.Context, st *store.Store, body []byte, bc config.BrowserConfig, healthPath string) error {
	if !browserSiteEnabled(body, bc) {
		return nil // per-site daemon toggle is off — intentional drop, not a loss.
	}
	site, synthetic, idSourceNone := peekBrowserTurn(body)
	// A turn from an extension speaking a protocol this observer does not
	// support is refused with a recorded reason, never half-understood (lane
	// MP-ART). Both transports (native host and loopback listener) land here.
	if reason := browserhost.Refusal(browserhost.ParseHello(body).Protocol); reason != "" {
		recordBrowserCapture(ctx, healthPath, captureOutcome{site: site, dropReason: reason})
		return fmt.Errorf("refused: %s", reason)
	}
	toolEvents, tokenEvents, err := normalizeBrowserChatTurn(body, bc.GranularityCeiling)
	if err != nil {
		// A real loss (unknown site, malformed body). Record it durably so
		// the operator can see turns are being dropped even though the
		// extension's beacon says "ok".
		recordBrowserCapture(ctx, healthPath, captureOutcome{site: site, dropReason: err.Error()})
		return fmt.Errorf("normalize: %w", err)
	}
	if len(toolEvents) == 0 && len(tokenEvents) == 0 {
		return nil
	}
	if _, err := st.Ingest(ctx, toolEvents, tokenEvents, store.IngestOptions{}); err != nil {
		recordBrowserCapture(ctx, healthPath, captureOutcome{site: site, dropReason: "insert: " + err.Error()})
		return fmt.Errorf("insert: %w", err)
	}
	// Landed. Count it, and flag id-less (B1-synthesized) ingests so the
	// operator can confirm id-less turns are self-healing into the DB. Only a
	// turn keyed under the timestamp+fingerprint fallback (NEITHER a
	// conversation nor a message id) is synthetic — a turn grouped by a real
	// message id is not (LOW-1).
	recordBrowserCapture(ctx, healthPath, captureOutcome{site: site, ingested: true, synthetic: synthetic, idSourceNone: idSourceNone})
	return nil
}

// captureOutcome is the C1 per-turn telemetry recordBrowserCapture folds into
// the node-local health file. Exactly one of ingested / dropReason is set on a
// given call; synthetic is meaningful only alongside ingested.
type captureOutcome struct {
	site      string
	ingested  bool
	synthetic bool
	// idSourceNone records that the ingested turn's payload's id_source
	// NORMALIZES to "none" (JS LOW fix + Go re-review LOW fix) — no real
	// conversation-id provenance, whether the payload said "none" literally
	// or carried an empty/unknown/oversized value the adapter's closed enum
	// collapses to "none" too (browserchat.NormalizeIDSource — the SAME
	// mapping internal/adapter/browserchat.buildMetadata applies when it
	// actually stores the turn, so this telemetry counter can't diverge from
	// what lands in the DB). Meaningful only alongside ingested.
	idSourceNone bool
	dropReason   string
}

// peekBrowserTurn extracts the fields ingestBrowserTurn needs for telemetry
// WITHOUT a full normalize: the site (telemetry key), whether the turn is
// SYNTHETIC — ingested under the synthesized session key because it carried
// NEITHER a conversation id NOR a message id (B1 / LOW-1) — and whether the
// payload's id_source normalizes to "none" (JS LOW fix + Go re-review LOW
// fix: the extension obtained no real conversation-id provenance, OR sent a
// garbage/omitted value the adapter's closed enum would ALSO collapse to
// "none"). The synthetic decision is delegated to
// browserchat.IsSyntheticSessionKey, and the id-source decision to
// browserchat.NormalizeIDSource — both the ONE OWNER of their respective
// rule, so neither counter can drift from what sessionKeyFor / buildMetadata
// actually do at ingest time. A body we can't parse yields ("", false,
// false); the normalize step surfaces the real error.
func peekBrowserTurn(body []byte) (site string, synthetic, idSourceNone bool) {
	var peek struct {
		Site           string `json:"site"`
		ConversationID string `json:"conversation_id"`
		MessageID      string `json:"message_id"`
		IDSource       string `json:"id_source"`
	}
	if err := json.Unmarshal(body, &peek); err != nil {
		return "", false, false
	}
	synthetic, idSourceNone = browserChatIDFlags(peek.ConversationID, peek.MessageID, peek.IDSource)
	return peek.Site, synthetic, idSourceNone
}

// recordBrowserCapture folds one capture outcome into the node-local health
// file. It touches ONLY the capture-telemetry fields (Ingested / Dropped /
// Synthetic / …) — the beacon's Status/Reason are preserved (HIGH-1), except
// that a site seen only via capture (never a beacon) gets an inferred Status
// so the health line isn't blank. The whole load→merge→write runs under a
// cross-process advisory lock so concurrent hook children and the loopback
// listener never lose each other's counter bumps (HIGH-2). Best-effort: an
// empty path or an unkeyable site is a no-op, and a write/lock error is
// swallowed (capture visibility must never crash the hook).
//
// ctx bounds the underlying flock acquisition (Go re-review MED fix):
// telemetry is best-effort and must never block longer than ctx's own
// deadline (the caller's durability work deadline, when it has one) or
// browserHealthLockTimeout, whichever is sooner — see withBrowserHealthLock.
//
// Ingest-gated status-freshness rule (JS MED-4 residual): ONLY a SUCCESSFUL
// ingest (oc.ingested) refreshes the normal-priority status-freshness stamp
// (LastStatusPriority/LastStatusAt) and may infer a healthy "ok" status. A
// failed capture (normalize/insert drop) still bumps the Dropped/last_drop_*
// counters and refreshes liveness (RecordedAt), but it MUST NOT mark the site
// healthy or extend idle-suppression protection — otherwise a site that only
// FAILS would keep a stale "healthy" status and suppress the very idle beacon
// that exists to surface a churning / failing endpoint. That silent lie is
// exactly what the MED-4 fix exists to prevent.
func recordBrowserCapture(ctx context.Context, path string, oc captureOutcome) {
	now := nowMillisFn()
	_ = updateBrowserHealth(ctx, path, oc.site, func(e browserHealthEntry) browserHealthEntry {
		// Promote a legacy/unstamped entry to an explicit status-freshness
		// stamp BEFORE this capture mutates it, so its frozen LastStatusAt is
		// keyed to the PRE-capture RecordedAt — not a value this capture is
		// about to refresh (mirrors recordBrowserHealth's top-of-closure
		// promotion). Without this a legacy entry receiving only FAILED
		// captures would slide RecordedAt forward and, via a later lazy
		// promotion, stay idle-protected forever (JS MED-4).
		e = promoteLegacyStatusStamp(e)
		if oc.ingested {
			e.Ingested++
			if oc.synthetic {
				e.Synthetic++
				e.LastSyntheticAt = now
			}
			if oc.idSourceNone {
				e.IDSourceNone++
			}
		}
		if oc.dropReason != "" {
			e.Dropped++
			e.LastDropReason = oc.dropReason
			e.LastDropAt = now
		}
		// RecordedAt doubles as "last capture activity" so the health line
		// shows a fresh age and eviction keeps active sites. It is LIVENESS,
		// not status freshness — refreshed on every outcome (ingest OR drop).
		e.RecordedAt = now
		if e.Status == "" {
			// A capture-only site (no beacon yet) still needs a status to
			// render; a real beacon Status is left untouched. A failed-only
			// capture infers "degraded" (the honest drop status), never "ok".
			if oc.dropReason != "" && !oc.ingested {
				e.Status = "degraded"
			} else {
				e.Status = "ok"
			}
		}
		// ONLY a successful ingest is a NORMAL-priority status source, so only
		// a successful ingest refreshes the immutable status-freshness stamp —
		// keeping a genuinely active (successfully capturing) site's
		// idle-suppression protection current (JS MED-4). A drop leaves
		// LastStatusPriority/LastStatusAt untouched, so a site that only fails
		// ages out of protection and the idle beacon surfaces it.
		if oc.ingested {
			e.LastStatusPriority = statusPriorityNormal
			e.LastStatusAt = now
		}
		return e
	})
}

// --- A6: browser-capture health beacon (node-local, file-backed) ----------

// browserHealthFileName is the node-local file the health beacons land in,
// next to the observer DB. Best-effort, bounded, 0600.
const browserHealthFileName = "browser-health.json"

// browserIngestCapBytes bounds a single captured-turn payload read from
// stdin. A body larger than this is truncated at the wire and can no longer
// be parsed as JSON; handleBrowserHook detects the over-limit case (by
// reading one byte past the cap) and records an explicit keyed drop rather
// than silently losing the turn. The extension SHOULD cap its per-field
// content well below this so a legitimate turn never approaches the limit —
// see the deferred extension-side per-field cap note.
const browserIngestCapBytes = 8 * 1024 * 1024

// browserIngestCapDropReason is the durable, keyed drop reason recorded to the
// node-local health file when a captured-turn payload exceeds
// browserIngestCapBytes. Distinct from a normalize/insert failure so the
// operator can tell "the extension sent too much" apart from a parser bug.
const browserIngestCapDropReason = "payload exceeds 8MiB ingest cap"

// maxHealthSites bounds the health map so a hostile/looping extension can't
// grow the file unboundedly. Far above the five *-web sites in play.
const maxHealthSites = 32

// browserHealthBeacon is the compact health signal the service worker relays
// over the SAME native-messaging channel as captured turns (type=="health").
type browserHealthBeacon struct {
	Type   string `json:"type"`
	Site   string `json:"site"`
	Status string `json:"status"` // "ok" | "degraded"
	Reason string `json:"reason,omitempty"`
	TS     int64  `json:"ts,omitempty"` // client epoch millis
	// Priority ranks the beacon (JS MED-4). Idle heartbeats send
	// "low"; every real status (ok / ok-degraded-id / degraded) sends
	// "normal". A missing value is treated as "normal" (backward-compat with
	// older bridges). A "low" beacon must NOT overwrite a Status/Reason that
	// a recent normal-priority capture or beacon set — see
	// statusSetByRecentNormal.
	Priority string `json:"priority,omitempty"`
}

// Status-priority ranking (JS MED-4). An idle heartbeat carries
// statusPriorityLow and must not stomp a Status/Reason set by a recent
// normal-priority source; a genuinely stale / never-captured site still
// accepts the idle signal (it's the useful "extension is alive but this site
// isn't producing" evidence).
const (
	statusPriorityNormal = "normal"
	statusPriorityLow    = "low"
)

// statusFreshnessWindowMs is how long a normal-priority Status (set by a real
// capture or a non-idle beacon) is protected from being overwritten by an
// idle (low-priority) heartbeat. Ten minutes: long enough to span a quiet gap
// between turns, short enough that a truly stale site eventually accepts the
// idle status.
const statusFreshnessWindowMs int64 = 10 * 60 * 1000

// nowMillisFn yields the current epoch-millis instant for the browser-health
// path. It is a package var (not a direct time.Now call) so tests can advance
// a virtual clock and exercise multi-beacon idle-suppression aging without
// waiting real wall-clock time (JS MED-4 rolling-refresh case). Production
// always uses the real clock.
var nowMillisFn = func() int64 { return time.Now().UnixMilli() }

// normalizeBeaconPriority maps a raw beacon priority to the ranking vocabulary,
// defaulting missing / unknown values to statusPriorityNormal so an older
// bridge (which never sends priority) keeps its statuses authoritative.
func normalizeBeaconPriority(p string) string {
	if strings.TrimSpace(p) == statusPriorityLow {
		return statusPriorityLow
	}
	return statusPriorityNormal
}

// browserHealthEntry is one site's last-seen health, as persisted. The
// beacon fields (Status/Reason/TS) are owned by the extension's health
// beacon; the capture-telemetry fields (Ingested/Dropped/…) are owned by the
// daemon-side ingest path (C1). Both write the same entry, each touching only
// its own fields. Every new field is omitempty so the JSON stays backward-
// compatible: a file written by an older daemon simply lacks them, and a
// reader tolerates the zero values.
type browserHealthEntry struct {
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	TS         int64  `json:"ts,omitempty"`          // client-reported epoch millis
	RecordedAt int64  `json:"recorded_at,omitempty"` // daemon-side epoch millis

	// Status-provenance stamp (JS MED-4). LastStatusPriority records whether
	// the CURRENT Status/Reason was set by a normal- or low-priority source,
	// and LastStatusAt when (daemon-side epoch millis). Together they let an
	// idle (low-priority) beacon refuse to stomp a recent normal-priority
	// status while still setting the status on a stale / never-captured site.
	// An entry written by an older daemon lacks these (both zero); the reader
	// falls back to the "has landed captures" heuristic in
	// statusSetByRecentNormal.
	LastStatusPriority string `json:"last_status_priority,omitempty"`
	LastStatusAt       int64  `json:"last_status_at,omitempty"`

	// C1 capture telemetry — the durable, legible signal that turns are
	// actually landing (or being dropped), independent of the extension's
	// self-reported "ok" beacon. A drop recorded here survives the hook
	// child's exit, unlike the stderr line that host.js never sees.
	Ingested        int64  `json:"ingested,omitempty"`          // turns that reached store.Ingest
	Dropped         int64  `json:"dropped,omitempty"`           // turns lost to a normalize/insert error
	LastDropReason  string `json:"last_drop_reason,omitempty"`  // most recent drop's error text
	LastDropAt      int64  `json:"last_drop_at,omitempty"`      // daemon-side epoch millis of last drop
	Synthetic       int64  `json:"synthetic,omitempty"`         // ingested turns that arrived id-less (B1)
	LastSyntheticAt int64  `json:"last_synthetic_at,omitempty"` // daemon-side epoch millis of last id-less ingest

	// IDSourceNone counts ingested turns whose payload's id_source
	// NORMALIZES to "none" — either reported literally, or an empty/unknown/
	// oversized value the adapter's closed enum
	// (browserchat.NormalizeIDSource) collapses to "none" too (Go re-review
	// LOW fix: this counter is computed with the SAME normalizer so it can
	// never under-count relative to what the adapter actually stores). It
	// means the JS side obtained NO real conversation-id provenance (neither
	// request, stream, nor resume) and fell back to a synthetic key (JS LOW
	// fix). It correlates with — but is measured independently of — the
	// Go-side Synthetic counter (which keys off the derived session-key
	// tier), so a divergence between the two is itself a useful signal about
	// where id-lessness originates.
	IDSourceNone int64 `json:"id_source_none,omitempty"`
}

// browserHealthFile is the on-disk shape.
type browserHealthFile struct {
	Sites map[string]browserHealthEntry `json:"sites"`
}

// browserObserverDir returns the observer dir (where the DB + node-local
// files live) for cfg — the DBPath's directory.
func browserObserverDir(cfg config.Config) string {
	return filepath.Dir(cfg.Observer.DBPath)
}

// recordBrowserHealth parses a health beacon and MERGES it into the
// node-local health file. It updates ONLY the beacon-owned fields
// (Status/Reason/TS/RecordedAt) and preserves the capture-telemetry counters
// the ingest path wrote (HIGH-1) — the old code replaced the whole entry,
// zeroing Ingested/Dropped/Synthetic on every beacon. The whole
// load→merge→write runs under the same cross-process lock as the capture
// path (HIGH-2). Best-effort: a malformed beacon is a soft no-op — health
// visibility must never block or crash the browser's native-messaging port.
//
// ctx bounds the underlying flock acquisition the same way it does for
// recordBrowserCapture (Go re-review MED fix) — see withBrowserHealthLock.
func recordBrowserHealth(ctx context.Context, cfg config.Config, body []byte) error {
	var b browserHealthBeacon
	if err := json.Unmarshal(body, &b); err != nil {
		return fmt.Errorf("parse: %w", err)
	}
	if b.Site == "" {
		return nil // nothing to key on — drop.
	}
	if b.Status == "" {
		b.Status = "ok"
	}
	priority := normalizeBeaconPriority(b.Priority)
	path := filepath.Join(browserObserverDir(cfg), browserHealthFileName)
	now := nowMillisFn()
	return updateBrowserHealth(ctx, path, b.Site, func(e browserHealthEntry) browserHealthEntry {
		// Give a legacy/unstamped entry an explicit status-freshness stamp
		// BEFORE the suppression decision, keyed to its pre-refresh
		// RecordedAt, so idle suppression ages it out via the immutable
		// LastStatusAt instead of the liveness RecordedAt (JS MED-4). Runs
		// inside this updateBrowserHealth flock; idempotent (no-op once
		// stamped).
		e = promoteLegacyStatusStamp(e)
		if priority == statusPriorityLow && statusSetByRecentNormal(e, now) {
			// Idle heartbeat: the site already has a recent normal-priority
			// status. Refresh liveness (RecordedAt / TS) so the site isn't
			// evicted and the age stays honest, but do NOT stomp the
			// Status/Reason a real capture or non-idle beacon set — and do
			// NOT touch LastStatusAt, so only real activity extends the
			// protection window (JS MED-4).
			e.TS = b.TS
			e.RecordedAt = now
			return e
		}
		// Beacon owns ONLY these fields; capture counters survive the merge.
		e.Status = b.Status
		e.Reason = b.Reason
		e.TS = b.TS
		e.RecordedAt = now
		e.LastStatusPriority = priority
		e.LastStatusAt = now
		return e
	})
}

// statusSetByRecentNormal reports whether the entry's CURRENT Status was set
// by a normal-priority source (a real capture or a non-idle beacon) recently
// enough that an idle (low-priority) heartbeat must not overwrite it (JS
// MED-4). The freshness window is statusFreshnessWindowMs (10 min).
//
// It keys ONLY on the immutable status-freshness stamp (LastStatusAt), never
// on the liveness RecordedAt. RecordedAt is refreshed by every SUPPRESSED
// idle beacon, so keying suppression on it would protect an idle-only site
// forever — defeating the endpoint-churn canary the idle beacon exists to
// surface (the MED-4 rolling-refresh bug). Legacy/unstamped entries
// (LastStatusPriority == "") are given a normal stamp BEFORE they reach this
// check by promoteLegacyStatusStamp, so an unstamped entry with a real status
// never lands here un-aged.
//
// Precedence:
//   - No status yet → not protected (an idle beacon SHOULD set the first
//     status; that's the useful signal).
//   - An explicit normal-priority stamp within the window → protected.
//   - Otherwise (stale normal stamp, an unstamped/unpromotable entry, or a
//     prior low-priority status) → not protected; the idle beacon may refine
//     the status.
func statusSetByRecentNormal(e browserHealthEntry, now int64) bool {
	if e.Status == "" {
		return false
	}
	if e.LastStatusPriority == statusPriorityNormal && e.LastStatusAt > 0 {
		return now-e.LastStatusAt <= statusFreshnessWindowMs
	}
	return false
}

// promoteLegacyStatusStamp gives a legacy/unstamped health entry an explicit
// normal-priority status provenance, keyed to its CURRENT (pre-refresh)
// RecordedAt, so subsequent idle-beacon suppression can age it out via the
// immutable LastStatusAt instead of the liveness RecordedAt (JS MED-4).
//
// Why it's needed: an entry written by a pre-stamp daemon carries a real
// Status backed by landed captures (Ingested > 0) but no LastStatusPriority.
// Every SUPPRESSED idle beacon refreshes RecordedAt, so if suppression keyed
// on RecordedAt a legacy entry receiving idle beacons every few minutes would
// slide RecordedAt forever and stay idle-protected forever. Promoting the
// entry once — to LastStatusAt = its RecordedAt at first contact — freezes the
// status-freshness instant: idle beacons refresh RecordedAt but never
// LastStatusAt, so the entry correctly ages out statusFreshnessWindowMs after
// promotion.
//
// Idempotent: once LastStatusPriority is set this is a no-op, so an entry is
// promoted at most once. Callers invoke it inside the updateBrowserHealth
// flock, so the stamp is transactional with the merge.
func promoteLegacyStatusStamp(e browserHealthEntry) browserHealthEntry {
	if e.LastStatusPriority == "" && e.Status != "" && e.Ingested > 0 {
		e.LastStatusPriority = statusPriorityNormal
		e.LastStatusAt = e.RecordedAt
	}
	return e
}

// updateBrowserHealth runs a locked load→mutate→write transaction on the
// node-local health file. The entire read-modify-write is serialized across
// processes (concurrent `observer browser hook` children + the loopback
// listener) by a flock on <path>.lock, so no writer clobbers another's
// fields (HIGH-2). mutate receives the (possibly zero) existing entry for
// site and returns the updated one; because it starts from the existing
// entry and touches only its own fields, the OTHER writer's fields survive
// the round-trip (HIGH-1). An empty path or site is a no-op. Any lock/IO
// error is returned for the caller to log or swallow — telemetry must never
// crash a caller.
//
// ctx bounds the flock wait (Go re-review MED fix) — see withBrowserHealthLock.
func updateBrowserHealth(ctx context.Context, path, site string, mutate func(browserHealthEntry) browserHealthEntry) error {
	if path == "" || site == "" {
		return nil
	}
	return withBrowserHealthLock(ctx, path, func() error {
		hf, err := loadBrowserHealthFileForUpdate(path)
		if err != nil {
			// A transient read failure or a failed quarantine: abort the
			// update rather than replace the file with a fresh empty one
			// (which would silently zero every site's counters) or overwrite a
			// corrupt primary we couldn't preserve (MED-2a/b).
			return err
		}
		if hf.Sites == nil {
			hf.Sites = map[string]browserHealthEntry{}
		}
		hf.Sites[site] = mutate(hf.Sites[site])
		evictOldestHealth(hf.Sites, maxHealthSites)
		return writeBrowserHealthFile(path, hf)
	})
}

// browserHealthLockTimeout bounds how long a SINGLE health-telemetry write
// waits to acquire the cross-process flock (withBrowserHealthLock) when the
// caller's ctx carries no deadline of its own, or carries one further out
// than this. Health telemetry is best-effort (A6/C1) and must never block
// longer than this even if another process is wedged holding
// browser-health.json.lock — and it must never, combined with the rest of a
// hook child's work, outlive the native-messaging host's 40s reply cap (see
// handleBrowserHook's IngestTimeout() commentary). Five seconds is generous
// for a few bytes of JSON but nowhere near the 35s work deadline, so it
// leaves ample margin even when the flock is contended right up to the
// caller's own deadline.
//
// Go re-review MED fix: previously the flock acquisition
// (lockFileExclusive) blocked indefinitely, so a wedged contender could hold
// a hook child past the 40s host cap and get it killed mid-write —
// reintroducing the very teardown loss the work deadline exists to prevent.
//
// A var, not a const, only so tests can shorten the wait; production never
// assigns it.
var browserHealthLockTimeout = 5 * time.Second

// browserHealthLockPollInterval is how long withBrowserHealthLock sleeps
// between NONBLOCKING lock attempts while contended. Short enough that a
// freed lock is grabbed promptly, long enough that a busy-wait against a
// long-held lock stays cheap.
const browserHealthLockPollInterval = 25 * time.Millisecond

// errLockWouldBlock is the sentinel tryLockFileExclusive
// (browser_health_lock_{unix,windows}.go) returns when the exclusive lock is
// currently held by another owner, distinct from a real syscall error. It is
// declared here (not in an OS file) so both build tags share one identity and
// withBrowserHealthLock can errors.Is against it on every platform.
var errLockWouldBlock = errors.New("lock would block")

// withBrowserHealthLock serializes a health-file transaction across processes
// with an exclusive advisory lock on a dedicated <path>.lock file (never the
// data file itself, so the lock survives the atomic-rename swap). The lock is
// held for the whole load→merge→write and released on return. flock's
// per-open-file-description semantics mean even two goroutines in ONE process
// (each opening its own fd) mutually exclude — so the concurrency test with N
// in-process writers converges to N (HIGH-2).
//
// The wait to ACQUIRE the lock is bounded (Go re-review MED fix): at most
// browserHealthLockTimeout, clamped further down to ctx's own deadline when
// it has one sooner (e.g. the 35s browser-ingest work deadline) — so
// best-effort telemetry can never outlive the deadline that governs the
// hook child's total runtime. If ctx has ALREADY expired, the acquisition is
// skipped outright rather than attempted-then-abandoned.
//
// Acquisition is true cancellable NONBLOCKING polling (Go re-review MED
// fix): tryLockFileExclusive (LOCK_NB / LOCKFILE_FAIL_IMMEDIATELY) is retried
// on a short interval, and between attempts the timer and ctx.Done() are
// checked. On timeout or cancellation the fd is closed SYNCHRONOUSLY and the
// function returns immediately — there is NO background goroutine still
// blocked in flock and NO leaked fd, which the earlier blocking-goroutine +
// releaseAbandonedHealthLock approach could leak once per timeout under a
// long-held lock. fn() runs only on the acquired path, and the lock is
// released exactly once via the deferred unlock.
//
// ctx is also re-checked BEFORE every acquisition attempt (including the
// first) and again IMMEDIATELY AFTER a successful acquisition (Go re-review
// LOW fix): an already-canceled/expired ctx must never reach fn(), even when
// the lock is uncontended and the very first nonblocking attempt succeeds —
// the `wait`/deadline computation below only catches an absolute deadline
// that has ALREADY passed, not a ctx canceled via context.WithCancel (which
// carries no deadline at all). If ctx has expired by the time the lock is
// acquired, the fd is unlocked and closed and fn() never runs.
//
// An absolute expiresAt clock is checked ALONGSIDE ctx.Err() before every
// attempt and immediately after acquisition (Go re-review LOW fix): the poll
// loop's select races timer.C against ticker.C, and once both channels are
// ready Go picks between them pseudo-randomly, so a ctx with no deadline at
// all (context.Background()) could otherwise have the ticker branch chosen
// over the timer branch on the very iteration the budget expires, letting a
// lock freed just past the budget be acquired and fn() run past it.
// expiresAt is computed once from the SAME `wait` used to size the timer, so
// it can never fire before the timer legitimately could.
func withBrowserHealthLock(ctx context.Context, path string, fn func() error) error {
	lockPath := path + ".lock"
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o755); err != nil {
		return fmt.Errorf("mkdir lock dir: %w", err)
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600) //nolint:gosec // G304: path derived from the daemon's own config dir.
	if err != nil {
		return fmt.Errorf("open lock: %w", err)
	}

	wait := browserHealthLockTimeout
	if dl, ok := ctx.Deadline(); ok {
		if remaining := time.Until(dl); remaining < wait {
			wait = remaining
		}
	}
	if wait <= 0 {
		_ = f.Close()
		return fmt.Errorf("acquire lock: deadline already passed - skipping best-effort health telemetry")
	}

	// expiresAt is the absolute-clock counterpart to the timer below,
	// computed once from the SAME wait budget. Checking it explicitly (in
	// addition to ctx.Err()) before every attempt closes the race where
	// select's pseudo-random choice between a ready timer.C and a
	// simultaneously-ready ticker.C picks the ticker — which, for a ctx with
	// no deadline (context.Background()), would otherwise let the loop keep
	// polling and potentially acquire a lock freed just past the budget.
	expiresAt := time.Now().Add(wait)

	timer := time.NewTimer(wait)
	defer timer.Stop()
	ticker := time.NewTicker(browserHealthLockPollInterval)
	defer ticker.Stop()

	for {
		// Re-check ctx AND the absolute expiry BEFORE every attempt,
		// including the first: an already-canceled/expired ctx, or a budget
		// that has already elapsed, must never reach fn(), even when the
		// lock is uncontended and the very first tryLockFileExclusive would
		// otherwise succeed (Go re-review LOW fixes — the deadline-based
		// `wait` check above only catches an ALREADY-PASSED absolute
		// deadline; a ctx canceled via context.WithCancel with no deadline
		// at all slips past it, and ctx.Err() alone misses the
		// timer-vs-ticker select race described above).
		if err := ctx.Err(); err != nil {
			_ = f.Close()
			return fmt.Errorf("acquire lock: %w - skipping best-effort health telemetry", err)
		}
		if time.Now().After(expiresAt) {
			_ = f.Close()
			return fmt.Errorf("acquire lock: timed out after %s waiting on %s - skipping best-effort health telemetry", wait, lockPath)
		}
		lockErr := tryLockFileExclusive(f)
		if lockErr == nil {
			// Re-check immediately after acquisition too: ctx may have been
			// canceled, or the budget may have elapsed, in the window
			// between the checks above and the syscall. Release what we
			// just took rather than let fn() run past the boundary.
			if err := ctx.Err(); err != nil {
				_ = unlockFile(f)
				_ = f.Close()
				return fmt.Errorf("acquire lock: %w - skipping best-effort health telemetry", err)
			}
			if time.Now().After(expiresAt) {
				_ = unlockFile(f)
				_ = f.Close()
				return fmt.Errorf("acquire lock: timed out after %s waiting on %s - skipping best-effort health telemetry", wait, lockPath)
			}
			defer func() { _ = unlockFile(f); _ = f.Close() }()
			return fn()
		}
		if !errors.Is(lockErr, errLockWouldBlock) {
			_ = f.Close()
			return fmt.Errorf("acquire lock: %w", lockErr)
		}
		// Contended: wait a short interval and retry, unless the acquisition
		// budget or ctx has run out — in which case close the fd synchronously
		// and give up without leaking a goroutine.
		select {
		case <-timer.C:
			_ = f.Close()
			return fmt.Errorf("acquire lock: timed out after %s waiting on %s - skipping best-effort health telemetry", wait, lockPath)
		case <-ctx.Done():
			_ = f.Close()
			return fmt.Errorf("acquire lock: %w - skipping best-effort health telemetry", ctx.Err())
		case <-ticker.C:
			// retry the nonblocking attempt
		}
	}
}

// loadBrowserHealthFileForUpdate reads the health file INSIDE the write
// transaction. It distinguishes: absent (ENOENT → a fresh empty file, the
// normal first write); empty (fresh); a TRANSIENT read error (permission /
// I-O — returned as an error so the caller ABORTS rather than replacing the
// file with a fresh empty one that silently zeros every site's counters,
// MED-2a); and corrupt (present but unparseable JSON). On corruption it
// QUARANTINES the raw bytes to a UNIQUE <path>.bad-<pid-rand> sidecar
// (MED-2c: concurrent quarantines never clobber each other) and starts fresh,
// so a single malformed byte can never silently zero every OTHER site's
// counters (HIGH-2c). If the quarantine rename FAILS, it returns the error
// WITHOUT starting fresh (MED-2b): overwriting the primary would destroy the
// only forensic copy, so the update aborts and the corrupt file is left
// intact for the next attempt.
func loadBrowserHealthFileForUpdate(path string) (browserHealthFile, error) {
	var hf browserHealthFile
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path derived from the daemon's own config dir.
	if err != nil {
		if os.IsNotExist(err) {
			return hf, nil // absent → fresh empty; normal first write.
		}
		// Transient permission / I-O error: abort the update. Replacing the
		// file on a read blip would silently zero every site's counters
		// (MED-2a).
		return hf, fmt.Errorf("read health file %s: %w", path, err)
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return hf, nil // empty file → fresh.
	}
	if err := json.Unmarshal(raw, &hf); err != nil {
		// Corrupt: quarantine the raw bytes to a UNIQUE sidecar and start
		// fresh. If the rename fails, abort WITHOUT overwriting the primary so
		// the forensic copy survives (MED-2b).
		bad := path + ".bad-" + quarantineSuffix()
		if rerr := os.Rename(path, bad); rerr != nil {
			return browserHealthFile{}, fmt.Errorf("quarantine corrupt health file %s: %w", path, rerr)
		}
		fmt.Fprintf(os.Stderr, "observer-browser: health file %s corrupt (%v) - quarantined to %s, starting fresh\n", path, err, bad)
		return browserHealthFile{}, nil
	}
	return hf, nil
}

// quarantineSuffix returns a per-quarantine unique suffix (pid + random hex)
// so two processes quarantining a corrupt health file concurrently never
// rename onto the SAME .bad sidecar and clobber each other's forensic copy
// (MED-2c). Falls back to pid + nanotime if the RNG is unavailable.
func quarantineSuffix() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err == nil {
		return fmt.Sprintf("%d-%s", os.Getpid(), hex.EncodeToString(b[:]))
	}
	return fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
}

// loadBrowserHealthFile reads the health file, tolerating absence / bad JSON
// by returning an empty file (best-effort recovery).
func loadBrowserHealthFile(path string) browserHealthFile {
	var hf browserHealthFile
	raw, err := os.ReadFile(path) //nolint:gosec // G304: path derived from the daemon's own config dir.
	if err != nil {
		return hf
	}
	_ = json.Unmarshal(raw, &hf)
	return hf
}

// writeBrowserHealthFile writes the health file 0600 via a PER-PROCESS UNIQUE
// temp file + atomic rename. os.CreateTemp mints a fresh name (mkstemp-style,
// 0600) so two writers never share one ".tmp" and truncate/rename each
// other's half-written bytes (HIGH-2b) — belt-and-suspenders even though
// withBrowserHealthLock already serializes writers. A concurrent reader never
// sees a partial file (the rename is atomic).
func writeBrowserHealthFile(path string, hf browserHealthFile) error {
	raw, err := json.MarshalIndent(hf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	tmpName := tmp.Name()
	// Remove the temp on any early-return error path; a no-op after a
	// successful rename (the file no longer exists there).
	defer func() { _ = os.Remove(tmpName) }()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// evictOldestHealth trims the map to at most max entries, dropping the oldest
// recorded first (a bound on a hostile/looping extension).
func evictOldestHealth(sites map[string]browserHealthEntry, max int) {
	for len(sites) > max {
		var oldestKey string
		var oldest int64 = 1<<63 - 1
		for k, v := range sites {
			if v.RecordedAt < oldest {
				oldest, oldestKey = v.RecordedAt, k
			}
		}
		delete(sites, oldestKey)
	}
}

// runBrowserHealth prints the recorded per-site health — the honest,
// in-scope operator surface for A6 (a dashboard card / GET /api/browser/health
// is a noted follow-up). An empty/missing file means the extension hasn't
// relayed anything: the manifest may be broken or the extension not loaded.
func runBrowserHealth(out io.Writer, configPath string) error {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
	if err != nil {
		return fmt.Errorf("browser health: config: %w", err)
	}
	path := filepath.Join(browserObserverDir(cfg), browserHealthFileName)
	hf := loadBrowserHealthFile(path)
	if len(hf.Sites) == 0 {
		fmt.Fprintf(out, "no browser health beacons recorded yet (%s)\n", path)
		fmt.Fprintln(out, "  if you've loaded the extension and used a site, the native-messaging host")
		fmt.Fprintln(out, "  or manifest may be broken - check `observer init --browser` output.")
		return nil
	}
	names := make([]string, 0, len(hf.Sites))
	for s := range hf.Sites {
		names = append(names, s)
	}
	sort.Strings(names)
	now := time.Now().UnixMilli()
	fmt.Fprintf(out, "browser capture health (%s):\n", path)
	for _, s := range names {
		e := hf.Sites[s]
		line := fmt.Sprintf("  %-14s %-9s %s", s, e.Status, healthAge(now, e.RecordedAt))
		if e.Reason != "" {
			line += "  - " + e.Reason
		}
		// C1 capture telemetry — the honest landed-vs-dropped surface. Shown
		// whenever any capture activity has been recorded for the site.
		if e.Ingested > 0 || e.Dropped > 0 || e.Synthetic > 0 || e.IDSourceNone > 0 {
			seg := fmt.Sprintf("%d ingested, %d dropped", e.Ingested, e.Dropped)
			if e.Synthetic > 0 {
				seg += fmt.Sprintf(", %d id-less", e.Synthetic)
			}
			if e.IDSourceNone > 0 {
				seg += fmt.Sprintf(", %d no-id-source", e.IDSourceNone)
			}
			if e.Reason != "" {
				line += "  (" + seg + ")"
			} else {
				line += "  - " + seg
			}
		}
		fmt.Fprintln(out, line)
		// A drop is the signal the whole C1 change exists to make visible —
		// call it out on its own warn line with the reason and recency.
		if e.Dropped > 0 {
			reason := e.LastDropReason
			if reason == "" {
				reason = "unknown"
			}
			fmt.Fprintf(out, "    warn: %d dropped (last: %s, %s)\n", e.Dropped, reason, healthAge(now, e.LastDropAt))
		}
	}
	return nil
}

// healthAge renders a millis-epoch instant as a human "<dur> ago" string,
// or "unknown age" when the instant is unset.
func healthAge(now, then int64) string {
	if then <= 0 {
		return "unknown age"
	}
	return fmt.Sprintf("%s ago", time.Duration(now-then)*time.Millisecond)
}

// --- A4: shared loopback-ingress token -------------------------------------

// resolveBrowserIngestToken returns the shared token the loopback browser
// receiver requires. Precedence: an explicit [browser.listener].token, else
// an auto-generated token persisted 0600 as browser-ingest-token in the
// observer dir (so the clientless, default-off listener is never
// unauthenticated without the operator having to set anything).
func resolveBrowserIngestToken(cfg config.Config) (string, error) {
	if t := cfg.Browser.Listener.Token; t != "" {
		return t, nil
	}
	return resolveLocalTokenFile(filepath.Join(browserObserverDir(cfg), "browser-ingest-token"))
}

// resolveLocalTokenFile returns the shared secret stored at path, generating
// and persisting a fresh 32-byte random one (0600) when the file is missing
// or empty. One owner for every daemon-generated listener token (the browser
// rail, the OTLP receiver's non-loopback gate).
//
// The file is a credential, so it is trusted only in a shape no other local
// account can read or redirect (P3-27): a symlink or any non-regular file is
// refused (fail closed); a file another account owns is refused; a regular
// file of ours with group or other bits is repaired to 0600 before use. A new
// file is created exclusively, so a file planted between the check and the
// write is never written through, and owner-only on every OS
// (fsatomic.CreateOwnerOnly: 0600, or on Windows a protected DACL granting
// this user and SYSTEM only, R-160).
func resolveLocalTokenFile(path string) (string, error) {
	tok, err := readLocalTokenFile(path)
	if err != nil || tok != "" {
		return tok, err
	}
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate token: %w", err)
	}
	tok = hex.EncodeToString(buf)
	// 0700: a directory this creates holds a credential (audit F6 of lane
	// p1proxyauth); an existing directory keeps its own mode.
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil { //nolint:gosec // G703: false positive; this node's own local token file from its config or ~/.observer default, the operator's own path
		return "", fmt.Errorf("mkdir: %w", err)
	}
	f, err := fsatomic.CreateOwnerOnly(path)
	if errors.Is(err, os.ErrExist) {
		// An empty token file of ours (checked above), or a concurrent
		// creator: take a token another process wrote, else replace the
		// empty file.
		if again, rerr := readLocalTokenFile(path); rerr != nil || again != "" {
			return again, rerr
		}
		if rmErr := os.Remove(path); rmErr != nil { //nolint:gosec // G703: false positive; this node's own local token file from its config or ~/.observer default, the operator's own path
			return "", fmt.Errorf("replace empty token file: %w", rmErr)
		}
		f, err = fsatomic.CreateOwnerOnly(path)
	}
	if err != nil {
		return "", fmt.Errorf("persist token: %w", err)
	}
	if _, err := f.WriteString(tok + "\n"); err != nil {
		_ = f.Close()
		return "", fmt.Errorf("persist token: %w", err)
	}
	if err := f.Close(); err != nil {
		return "", fmt.Errorf("persist token: %w", err)
	}
	return tok, nil
}

// readLocalTokenFile reads an existing token file under the rules above. A
// missing file is ("", nil); an empty one is ("", nil) too.
func readLocalTokenFile(path string) (string, error) {
	info, err := os.Lstat(path) //nolint:gosec // G703: false positive; this node's own local token file from its config or ~/.observer default, the operator's own path
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("token file %s is not a regular file (a symlink or special file); refusing to use it", path)
	}
	if err := ensureTokenFilePrivate(path, info); err != nil {
		return "", err
	}
	f, err := os.Open(path) //nolint:gosec // G304: path derived from the daemon's own config dir.
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	defer func() { _ = f.Close() }()
	if opened, serr := f.Stat(); serr != nil || !os.SameFile(info, opened) {
		return "", fmt.Errorf("token file %s changed while it was being read; refusing to use it", path)
	}
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return "", fmt.Errorf("token file: %w", err)
	}
	return string(bytes.TrimSpace(raw)), nil
}

// browserSiteEnabled reports whether the daemon accepts this turn's site.
// The extension's own per-site toggle is the primary control; this is the
// daemon backstop. A missing key means enabled (fail-open); a key set false
// drops the site. A body we can't peek at (bad JSON) is left to the
// normalizer to reject with a real error, so we return true here.
func browserSiteEnabled(body []byte, bc config.BrowserConfig) bool {
	if len(bc.Sites) == 0 {
		return true
	}
	var peek struct {
		Site string `json:"site"`
	}
	if err := json.Unmarshal(body, &peek); err != nil || peek.Site == "" {
		return true
	}
	enabled, ok := bc.Sites[peek.Site]
	if !ok {
		return true // no explicit toggle → enabled
	}
	return enabled
}
