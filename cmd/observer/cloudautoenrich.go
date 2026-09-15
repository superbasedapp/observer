package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"time"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// cloudautoenrich.go is the value-upgrade plan's W3 BACKGROUND ENRICHMENT
// loop (docs/plans/cloud-intelligence-value-upgrade-plan-2026-09-14.md §4 W3
// "background by default"): once the developer has turned Cloud Intelligence
// on with background enrichment enabled (internal/store/cloudpolicy.go's
// cloud_enrich_policy row, `observer cloud enable`), sessions that have gone
// quiet are enrolled WITHOUT the developer running `observer cloud consent`
// by hand for every one.
//
// # Zero-egress, exactly like R2a's auto-sync (cloudautosync.go)
//
// This file links NOTHING from the cloud network lane — only os/exec,
// config, and internal/store (already linked by the daemon for unrelated
// reasons; it never touches cloudclient/cloudpop/cloudcred/cloudgateway). It
// SPAWNS `observer cloud consent --session <id> --purpose <p> --yes` as a
// subprocess, the identical consent-gated CLI a developer would type
// themselves. Consenting only RECORDS a receipt and enqueues an outbox item —
// it makes no network call — so this loop's own egress is exactly zero; the
// auto-sync loop (or a manual `observer cloud sync`) is what actually sends,
// under its own separate consent gate. Two independently-gated steps, same
// as the interactive flow, just both automated.
//
// # What decides whether a session is a candidate
//
// internal/store.ListCloudAutoEnrichCandidates does the real filtering
// (personal authority, quiet long enough, enough actions, not already
// outboxed or resulted, and not currently under a durable
// cloud_enrich_skips backoff — see below). This file's job is scheduling:
// read the developer's live policy every tick (so a dashboard change
// applies without a daemon restart), and record/clear that durable skip so
// a session whose consent spawn just failed is not retried every tick.
//
// # The durable skip (2026-09-16 follow-up)
//
// A session whose spawn fails is recorded via
// internal/store.Store.RecordCloudEnrichSkip (table cloud_enrich_skips,
// migration 120) with an exponential backoff, NODE-LOCAL and content-free
// (a short fixed error CLASS token only, never subprocess output). Before
// this the guard was an in-memory map inside cloudAutoEnrichLoop: a daemon
// restart forgot it, so a session that can never succeed (a malformed
// transcript, say) was retried on the very next tick after every restart,
// and the candidate join kept growing to include it forever. Putting the
// exclusion in ListCloudAutoEnrichCandidates's own SQL (rather than
// filtering candidates again here) means the backoff survives a restart and
// there is exactly one place that decides candidacy.

// cloudConsentSpawner runs one `observer cloud consent --session <id>
// --purpose <p> --yes` and returns its combined output. Injectable so tests
// exercise the scheduler without spawning a real process.
type cloudConsentSpawner func(ctx context.Context, sessionID, purpose, configPath string, generation int64) ([]byte, error)

// defaultCloudConsentSpawner self-execs `observer cloud consent`. It inherits
// the daemon's environment, exactly like defaultCloudSyncSpawner.
func defaultCloudConsentSpawner(ctx context.Context, sessionID, purpose, configPath string, generation int64) ([]byte, error) {
	self, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve observer binary: %w", err)
	}
	args := []string{"cloud", "consent", "--session", sessionID, "--purpose", purpose, "--yes", "--background-generation", strconv.FormatInt(generation, 10)}
	if configPath != "" {
		args = append(args, "--config", configPath)
	}
	return exec.CommandContext(ctx, self, args...).CombinedOutput()
}

// cloudAutoEnrichSpawnTimeout bounds one `observer cloud consent` spawn. It
// only records a receipt and enqueues locally (no network), so 90s is
// generous headroom, not a network budget.
const cloudAutoEnrichSpawnTimeout = 90 * time.Second

// cloudAutoEnrichErrClassSpawnFailed / cloudAutoEnrichErrClassSpawnTimeout
// are the content-free error CLASS tokens recorded on
// internal/store's durable cloud_enrich_skips row (RecordCloudEnrichSkip)
// when a consent spawn fails — never subprocess output.
const (
	cloudAutoEnrichErrClassSpawnFailed  = "consent_spawn_failed"
	cloudAutoEnrichErrClassSpawnTimeout = "spawn_timeout"
)

// cloudAutoEnrichFirstTickDelay is how long the loop waits before its first
// sweep, so a daemon that is still finishing startup work (migrations,
// watcher backfill) isn't immediately competing for the DB.
const cloudAutoEnrichFirstTickDelay = 30 * time.Second

// runCloudAutoEnrichFromConfig is the daemon entry point (a fail-soft g.Go in
// start.go, beside runCloudAutoSyncFromConfig). It loads config and opens the
// store ONCE for the life of the loop; the developer's policy is re-read from
// that same open store on every tick, so a dashboard `observer cloud enable`/
// `disable` takes effect on the next tick with no daemon restart. A
// config-load or DB-open error is swallowed — the daemon already warned about
// it elsewhere, and a background convenience must never break startup.
func runCloudAutoEnrichFromConfig(ctx context.Context, out, errOut io.Writer, configPath string) {
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return
	}
	defer cleanup()
	st := store.New(database)
	interval := time.Duration(cfg.Cloud.ResolvedCloudAutoEnrichIntervalMinutes()) * time.Minute
	quietFor := time.Duration(cfg.Cloud.ResolvedCloudAutoEnrichQuietMinutes()) * time.Minute
	fmt.Fprintf(out, "  cloud auto-enrich → every %s (spawns `observer cloud consent` for sessions that ended >= %s ago; only while Cloud Intelligence is on with background enabled)\n",
		interval, quietFor)
	cloudAutoEnrichLoop(ctx, st, configPath, interval, quietFor, cloudAutoEnrichMinActions, cloudAutoEnrichLimit,
		cloudAutoEnrichFirstTickDelay, out, errOut, defaultCloudConsentSpawner)
}

// cloudAutoEnrichMinActions / cloudAutoEnrichLimit are the sweep's per-tick
// bounds (plan §W3.3): at least this many actions before a session counts as
// worth naming, and at most this many candidates enqueued per tick so one
// catch-up sweep after a long-off period can't flood the outbox at once.
const (
	cloudAutoEnrichMinActions = 3
	cloudAutoEnrichLimit      = 25
)

// cloudAutoEnrichLoop is the bounded scheduler, split out so a test can drive
// it with a tiny firstDelay/interval and a fake store/spawner. It fires once
// after firstDelay, then every interval, until ctx is cancelled.
func cloudAutoEnrichLoop(
	ctx context.Context,
	st *store.Store,
	configPath string,
	interval, quietFor time.Duration,
	minActions, limit int,
	firstDelay time.Duration,
	out, errOut io.Writer,
	spawn cloudConsentSpawner,
) {
	var lastOn *bool // nil = no tick has run yet; announce the first observed state.

	fire := func() {
		policy, ok, perr := st.GetCloudEnrichPolicy(ctx)
		on := perr == nil && ok && policy.Level != store.CloudEnrichOff && policy.Background
		if lastOn == nil || *lastOn != on {
			state := on
			lastOn = &state
			if on {
				fmt.Fprintf(out, "cloud auto-enrich: active — background enrichment is on (policy %s)\n", policy.Level)
			} else {
				fmt.Fprintln(out, "cloud auto-enrich: idle — Cloud Intelligence is off, or background enrichment is off")
			}
		}
		if perr != nil || !on {
			return
		}
		purpose, ok := policy.PurposeName()
		if !ok {
			return
		}
		candidates, cerr := st.ListCloudAutoEnrichCandidates(ctx, policy.Since, quietFor, minActions, limit, time.Now().UTC())
		if cerr != nil {
			fmt.Fprintf(errOut, "cloud auto-enrich: list candidates: %v\n", cerr)
			return
		}
		// The candidate query above already excludes any session under a
		// live cloud_enrich_skips backoff (durable, survives a restart), so
		// there is no in-memory re-check here — the DB is the single source
		// of truth for candidacy.
		for _, c := range candidates {
			if err := st.CheckCloudBackgroundPolicy(ctx, policy.Generation, purpose); err != nil {
				return
			}
			spawnCtx, cancel := context.WithTimeout(ctx, cloudAutoEnrichSpawnTimeout)
			outb, serr := spawn(spawnCtx, c.SessionID, purpose, configPath, policy.Generation)
			timedOut := errors.Is(spawnCtx.Err(), context.DeadlineExceeded)
			cancel()
			if ctx.Err() != nil {
				return // shutdown raced the spawn.
			}
			if serr != nil {
				errClass := cloudAutoEnrichErrClassSpawnFailed
				suffix := ""
				if timedOut {
					errClass = cloudAutoEnrichErrClassSpawnTimeout
					suffix = fmt.Sprintf(" (timed out after %s)", cloudAutoEnrichSpawnTimeout)
				}
				if rerr := st.RecordCloudEnrichSkip(ctx, c.SessionID, errClass, time.Now().UTC()); rerr != nil {
					fmt.Fprintf(errOut, "cloud auto-enrich: record skip for session %s: %v\n", c.SessionID, rerr)
				}
				fmt.Fprintf(errOut, "cloud auto-enrich: consent for session %s failed%s: %v\n%s", c.SessionID, suffix, serr, cloudAutoSyncTail(outb))
				continue
			}
			if cerr := st.ClearCloudEnrichSkip(ctx, c.SessionID); cerr != nil {
				fmt.Fprintf(errOut, "cloud auto-enrich: clear skip for session %s: %v\n", c.SessionID, cerr)
			}
		}
	}

	t := time.NewTimer(firstDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			fire()
			t.Reset(interval)
		}
	}
}
