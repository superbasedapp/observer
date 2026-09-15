package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudautosync.go is the arc-2 R2a BACKGROUND SYNC SERVICE (divergence-
// remediation plan rev 4.1 §2 R2(a): "background sync for the standing grant —
// APPROVED (consent-gated)").
//
// # The design, and why it keeps zero-egress
//
// Operator ruling R2 approved background egress AFTER consent, but the node's
// zero-egress invariant is structural: tests/invariant/cloud_egress_test.go pins
// that the always-on daemon PACKAGES (internal/watcher, internal/proxy,
// internal/store, internal/hook) transitively import NONE of the cloud network
// lane (cloudclient/cloudpop/cloudcred), and that the lane is reachable only
// through the consent-gated internal/cloudgateway seam.
//
// An in-process daemon goroutine that composed the gateway and egressed on a
// timer would technically pass that pin (the daemon binary already links the
// gateway for the `observer cloud` subcommands), but it would move the daemon
// from "makes no network call on its own" to "egresses in-process on a timer".
// So R2a instead makes the manual command the code path a schedule reuses: the
// daemon SPAWNS `observer cloud sync` as a SUBPROCESS. This file links NOTHING
// from the cloud lane — only os/exec, config, and internal/store (already
// linked by the daemon for unrelated reasons, and used here only to read the
// content-free cloud_enrich_policy row live — never cloudclient/cloudpop/
// cloudcred/cloudgateway) — and the subprocess is the exact consent-gated CLI
// a human runs, which sends nothing without a live grant. The invariant
// therefore holds for free:
//
//   - the daemon entry packages gain no new import (they never see this file);
//   - the network lane stays reachable only from cloudgateway, inside the
//     short-lived child process, which resolves the live grant fail-closed
//     before any request — pre-consent, revoked, and page-load-before-consent
//     all send zero bytes, identical to a manual `observer cloud sync`.
//
// Concurrency with a manual run is safe: the store's outbox has an idempotency
// key, a `sending` lease, and FD4 stale-`sending` reclaim, so two overlapping
// syncs never double-send.
//
// The daemon wiring is opt-in via [cloud].auto_sync (default OFF) OR the
// developer's own `observer cloud enable` (background enrichment implies a
// sync cadence is useless without a sync — see
// docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md §4 W3) — see
// start.go. The same subprocess trigger is also the documented cron/systemd
// path for operators who do not run `observer start` (see
// docs/plans/arc2-stream3-w3b-r2a-notes-2026-09-02.md).

// cloudSyncSpawner runs one `observer cloud sync` and returns its combined
// output. It is an injectable seam so tests exercise the scheduler WITHOUT
// spawning a real process or touching the network.
type cloudSyncSpawner func(ctx context.Context, configPath string) ([]byte, error)

// cloudAutoSyncSpawnTimeout bounds one `observer cloud sync` spawn. A sync
// uploads every sendable item and pulls results; the client itself bounds
// each individual HTTP request at 30s, so this is a whole-run CEILING (many
// requests across a possibly-large outbox), not a per-request budget —
// mirrors cloudautoenrich.go's cloudAutoEnrichSpawnTimeout.
const cloudAutoSyncSpawnTimeout = 15 * time.Minute

// defaultCloudSyncSpawner self-execs `observer cloud sync [--config <path>]`.
// It inherits the daemon's environment (so SBO_CLOUD_BASE_URL and the OS
// keychain resolve exactly as they would for a manual run) and is bounded by
// ctx: a daemon shutdown cancels an in-flight sync.
func defaultCloudSyncSpawner(ctx context.Context, configPath string) ([]byte, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve observer binary: %w", err)
	}
	args := []string{"cloud", "sync"}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	return exec.CommandContext(ctx, self, args...).CombinedOutput()
}

// runCloudAutoSyncFromConfig is the daemon entry point (called from a fail-soft
// g.Go in start.go). It loads config and opens the store ONCE for the life of
// the loop — since the value-upgrade plan's W3 (2026-09-15), auto-sync is no
// longer purely a static [cloud].auto_sync opt-in: it also runs whenever the
// developer's cloud_enrich_policy row (`observer cloud enable`) is on with
// background enabled, which can flip live from the dashboard/CLI, so the
// scheduler must be able to re-check it on every tick without a daemon
// restart. Fail-soft: a config-load or DB-open error is swallowed, because
// the daemon has already warned about it elsewhere and a background
// convenience must never break startup.
func runCloudAutoSyncFromConfig(ctx context.Context, out, errOut io.Writer, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	runCloudAutoSync(ctx, cfg, store.New(database), configPath, out, errOut, defaultCloudSyncSpawner)
}

// runCloudAutoSync is the scheduler. Unlike the pre-W3 design it can no
// longer decide once at startup whether it will ever have anything to do —
// [cloud].auto_sync is a static config-file opt-in, but the enrichment
// policy's Background flag is live — so it always announces its cadence and
// enters the loop; cloudAutoSyncActive re-evaluates both conditions on every
// tick, and a tick with neither active spawns nothing.
func runCloudAutoSync(ctx context.Context, cfg config.Config, st *store.Store, configPath string, out, errOut io.Writer, spawn cloudSyncSpawner) {
	// The base URL is always resolvable (resolveCloudBaseURL falls back to the
	// built-in default), so an active tick always has an endpoint. There is
	// no "idle — no base URL" state to announce anymore; sync stays consent-gated,
	// so a schedule with no live grant is a no-op, not an egress.
	interval := time.Duration(cfg.Cloud.ResolvedCloudAutoSyncMinutes()) * time.Minute
	fmt.Fprintf(out, "  cloud auto-sync → every %s (spawns `observer cloud sync`; consent-gated — nothing is sent without a live grant)\n", interval)
	cloudAutoSyncLoop(ctx, cfg, st, configPath, interval, errOut, spawn)
}

// cloudAutoSyncActive reports whether the CURRENT tick should spawn a sync:
// either the static [cloud].auto_sync opt-in, or the developer's standing
// enrichment policy being on with background enabled. st may be nil (a test,
// or a config/DB-open that failed upstream) — a nil store simply means the
// live half of the check can never be true, matching the pre-115-schema
// degrade-to-off convention the rest of the cloud CLI follows.
func cloudAutoSyncActive(ctx context.Context, cfg config.Config, st *store.Store) bool {
	if cfg.Cloud.AutoSync {
		return true
	}
	if st == nil {
		return false
	}
	policy, ok, err := st.GetCloudEnrichPolicy(ctx)
	return err == nil && ok && policy.Level != store.CloudEnrichOff && policy.Background
}

// cloudAutoSyncLoop is the bounded ticker loop, split out so a test can drive it
// at a sub-second interval without waiting for the real cadence. It re-checks
// cloudAutoSyncActive on every tick, fires the spawn only while active, and
// logs a bounded tail of a failing subprocess; a context cancel (daemon
// shutdown) ends it promptly and swallows the racing spawn's error as
// shutdown noise.
func cloudAutoSyncLoop(ctx context.Context, cfg config.Config, st *store.Store, configPath string, interval time.Duration, errOut io.Writer, spawn cloudSyncSpawner) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if !cloudAutoSyncActive(ctx, cfg, st) {
				continue
			}
			spawnCtx, cancel := context.WithTimeout(ctx, cloudAutoSyncSpawnTimeout)
			out, err := spawn(spawnCtx, configPath)
			timedOut := errors.Is(spawnCtx.Err(), context.DeadlineExceeded)
			cancel()
			if ctx.Err() != nil {
				return // shutdown raced the spawn; the error, if any, is shutdown noise.
			}
			if err != nil {
				suffix := ""
				if timedOut {
					suffix = fmt.Sprintf(" (timed out after %s)", cloudAutoSyncSpawnTimeout)
				}
				fmt.Fprintf(errOut, "cloud auto-sync: `observer cloud sync` failed%s: %v\n%s", suffix, err, cloudAutoSyncTail(out))
			}
		}
	}
}

// cloudAutoSyncTail returns a bounded tail of a subprocess's output for a log
// line, so a large sync report cannot flood the daemon log.
func cloudAutoSyncTail(b []byte) string {
	const max = 1024
	if len(b) <= max {
		return string(b)
	}
	return "…" + string(b[len(b)-max:])
}
