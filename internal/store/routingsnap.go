package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/routing"
	"github.com/marmutapp/superbased-observer/internal/sessiongauge"
)

// RoutingRefresher assembles routing.Snapshot from store signals on a
// ticker and publishes it via atomic.Pointer — the §R5 architecture:
// the refresher owns the SQL, the engine reads memory only, every
// query here runs OFF the proxy hot path (§R9.2).
//
// MODULE-BOUNDARY NOTE — this file produces the engine's INPUT
// (routing.Snapshot), mirroring the store-owned cachetrack.Engine
// precedent. The DECISION-ROW seam in routing.go keeps its own
// SQL-shaped types; that boundary is unchanged.
//
// Cadence is split by signal cost and freshness need:
//   - fast tick (default 3s): passive health counters (§R12.3) +
//     per-session warm-prefix sizes (§R13) — small indexed queries
//     over short windows.
//   - slow tick (default 60s): budget burn (§R14), latency p75,
//     subscription-window cadence (§R15) — heavier aggregates that
//     change slowly.
//
// Staleness: Current() marks the snapshot Stale once it ages past
// staleAfter — the engine then fails open (§R9.2): better an unrouted
// turn than a decision off dead signals.
type RoutingRefresher struct {
	store    *Store
	resolver *routing.TierResolver
	price    routing.PriceFn

	now        func() time.Time
	fastEvery  time.Duration
	slowEvery  time.Duration
	staleAfter time.Duration

	snap atomic.Pointer[routing.Snapshot]

	// mu serializes the single-writer discipline: every mutation of
	// policy / breakers / slow and every snapshot publish runs under it,
	// so the Run ticker, RefreshNow, and the P0-7 ReloadPolicy can never
	// interleave a half-built state. Current() stays lock-free (it only
	// atomic-loads snap), so the proxy hot path never touches mu.
	mu sync.Mutex
	// Single-writer state (only a Run/RefreshNow/ReloadPolicy holder of
	// mu touches these): the live policy, breaker memory, and the
	// slow-tick cache merged into each publish.
	policy   routing.Policy
	breakers map[string]*breakerMemory
	slow     slowSignals

	// testFailPublishAfterHealth is a test seam: when non-nil, publish
	// invokes it AFTER computeHealth has mutated breaker memory and
	// returns its error. Production leaves it nil. Used by the
	// ReloadPolicy breaker-rollback test (P0-7 SHOULD-FIX 2).
	testFailPublishAfterHealth func() error
}

// breakerMemory is the §R12.3 circuit-breaker timing state per model.
type breakerMemory struct {
	openedAt time.Time
}

// slowSignals caches the slow-tick aggregates between slow refreshes.
type slowSignals struct {
	budgetBurn []routing.BudgetBurnState
	latencyP75 map[string]int64
	window     *routing.WindowState
	// windows is the Tokenomics context-window table
	// (LoadModelContextWindows) the capability filter's fit check reads
	// through Snapshot.ContextWindow. Refreshed on the slow tick so a
	// feed sync or an org pricing delivery reaches the live router
	// without a restart.
	windows sessiongauge.Windows
}

// Breaker thresholds (§R12.3). Passive: computed from the observed
// api_turns http_status stream, no probing.
const (
	breakerWindow      = 10 * time.Minute
	breakerMinTurns    = 4
	breakerOpenRate    = 0.5
	breakerDegradeRate = 0.25
	breakerCooldown    = 60 * time.Second
)

// NewRoutingRefresher builds a refresher over the compiled policy.
// price may be nil (no dollar math); resolver must be non-nil.
func NewRoutingRefresher(s *Store, policy routing.Policy, resolver *routing.TierResolver, price routing.PriceFn) *RoutingRefresher {
	return &RoutingRefresher{
		store:      s,
		policy:     policy,
		resolver:   resolver,
		price:      price,
		now:        time.Now,
		fastEvery:  3 * time.Second,
		slowEvery:  60 * time.Second,
		staleAfter: 30 * time.Second,
		breakers:   map[string]*breakerMemory{},
	}
}

// Current returns the latest published snapshot, marked Stale when it
// has aged past the staleness horizon. Nil until the first refresh.
func (r *RoutingRefresher) Current() *routing.Snapshot {
	snap := r.snap.Load()
	if snap == nil {
		return nil
	}
	if r.now().Sub(snap.GeneratedAt) > r.staleAfter {
		stale := *snap
		stale.Stale = true
		return &stale
	}
	return snap
}

// Run drives the refresh loop until ctx cancels. The first refresh is
// immediate so the proxy seam has a snapshot before traffic arrives.
func (r *RoutingRefresher) Run(ctx context.Context) {
	if err := r.RefreshNow(ctx); err != nil {
		r.store.logWarn(ctx, "routing: initial snapshot refresh", err)
	}
	fast := time.NewTicker(r.fastEvery)
	slow := time.NewTicker(r.slowEvery)
	defer fast.Stop()
	defer slow.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-slow.C:
			r.mu.Lock()
			if err := r.refreshSlow(ctx); err != nil {
				r.store.logWarn(ctx, "routing: slow snapshot refresh", err)
			}
			if err := r.publish(ctx); err != nil {
				r.store.logWarn(ctx, "routing: snapshot publish", err)
			}
			r.mu.Unlock()
		case <-fast.C:
			r.mu.Lock()
			if err := r.publish(ctx); err != nil {
				r.store.logWarn(ctx, "routing: snapshot publish", err)
			}
			r.mu.Unlock()
		}
	}
}

// RefreshNow performs one full (slow + fast) refresh and publish —
// startup and tests. Serialized with the Run ticker and ReloadPolicy
// via the single-writer mutex.
func (r *RoutingRefresher) RefreshNow(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.refreshSlow(ctx); err != nil {
		return err
	}
	return r.publish(ctx)
}

// ReloadPolicy atomically swaps the refresher's live policy AND every
// policy-derived signal (the slow-tick budget/window cache, the
// breaker memory that publish's computeHealth mutates, and the
// published snapshot, whose session path-class hits and budget/rate
// bands are all policy-derived) in ONE transaction, serialized with
// Run/RefreshNow via the single-writer mutex (P0-7 §4.2/SF-A). It
// builds the new slow cache and a complete new snapshot against the
// captured new policy; on ANY failure it RESTORES the prior policy +
// slow cache + breakers and leaves the published snapshot untouched,
// so a mid-reload failure leaves all policy-derived refresher state on
// the prior version (fail-safe — never a torn or half-upgraded
// snapshot; P0-7 SHOULD-FIX 2 closes the breaker-memory leak where a
// failed publish left breaker mutations behind).
//
// This is the concrete shape of the "complete v2 snapshot first" fold:
// the caller (liveRouter.ReloadOrgPolicy) publishes in the strict order
// refresher-snapshot -> live policy -> RoutingStateHandle, so the P0-6
// reporter can never observe the router effective at the new version
// while the refresher still serves the old version's budget/path
// inputs.
func (r *RoutingRefresher) ReloadPolicy(ctx context.Context, policy routing.Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	prevPolicy := r.policy
	prevSlow := r.slow
	prevBreakers := cloneBreakers(r.breakers)
	r.policy = policy
	if err := r.refreshSlow(ctx); err != nil {
		r.policy = prevPolicy
		r.slow = prevSlow
		r.breakers = prevBreakers
		return fmt.Errorf("store.RoutingRefresher.ReloadPolicy: slow: %w", err)
	}
	if err := r.publish(ctx); err != nil {
		r.policy = prevPolicy
		r.slow = prevSlow
		r.breakers = prevBreakers
		return fmt.Errorf("store.RoutingRefresher.ReloadPolicy: publish: %w", err)
	}
	return nil
}

// cloneBreakers deep-copies the breaker map so a failed ReloadPolicy
// publish can restore the pre-mutation memory (computeHealth mutates
// breakers in place via breakerStateFor).
func cloneBreakers(in map[string]*breakerMemory) map[string]*breakerMemory {
	if in == nil {
		return nil
	}
	out := make(map[string]*breakerMemory, len(in))
	for k, v := range in {
		cp := *v
		out[k] = &cp
	}
	return out
}

// publish runs the fast-signal queries, merges the cached slow
// signals, and swaps the snapshot in.
func (r *RoutingRefresher) publish(ctx context.Context) error {
	now := r.now()
	health, err := r.computeHealth(ctx, now)
	if err != nil {
		return fmt.Errorf("store.RoutingRefresher: health: %w", err)
	}
	if r.testFailPublishAfterHealth != nil {
		if herr := r.testFailPublishAfterHealth(); herr != nil {
			return herr
		}
	}
	cacheReads, err := r.store.selectRecentSessionCacheReads(ctx, now.Add(-2*time.Hour))
	if err != nil {
		return fmt.Errorf("store.RoutingRefresher: session cache reads: %w", err)
	}
	sessions, err := r.computeSessionActivity(ctx, now)
	if err != nil {
		return fmt.Errorf("store.RoutingRefresher: session activity: %w", err)
	}
	snap := &routing.Snapshot{
		GeneratedAt:      now,
		Price:            r.price,
		Tiers:            r.resolver.Table(),
		Health:           health,
		LatencyP75Ms:     r.slow.latencyP75,
		BudgetBurn:       r.slow.budgetBurn,
		Window:           r.slow.window,
		ContextWindow:    r.slow.windows.Resolve,
		SessionCacheRead: cacheReads,
		Sessions:         sessions,
	}
	r.snap.Store(snap)
	return nil
}

// refreshSlow recomputes the slow aggregates into the cache.
func (r *RoutingRefresher) refreshSlow(ctx context.Context) error {
	now := r.now()
	burn, err := r.computeBudgetBurn(ctx, now)
	if err != nil {
		return fmt.Errorf("store.RoutingRefresher: budget burn: %w", err)
	}
	lat, err := r.computeLatencyP75(ctx, now.AddDate(0, 0, -7))
	if err != nil {
		return fmt.Errorf("store.RoutingRefresher: latency: %w", err)
	}
	win, err := r.computeWindowState(ctx, now)
	if err != nil {
		return fmt.Errorf("store.RoutingRefresher: window: %w", err)
	}
	// The window table degrades rather than failing the slow refresh: a
	// load error on both runtime rungs keeps the last good table (an
	// unknown window never excludes a candidate, so an empty one is the
	// fail-open direction, never a wrong exclusion).
	windows, werr := r.store.LoadModelContextWindows(ctx)
	if werr != nil && r.slow.windows != nil {
		windows = r.slow.windows
	}
	r.slow = slowSignals{budgetBurn: burn, latencyP75: lat, window: win, windows: windows}
	return nil
}

// ---------------------------------------------------------------- budget burn

// computeBudgetBurn sums cost_usd per configured scope over ROLLING
// windows (day = 24h, week = 7d, month = 30d — rolling rather than
// calendar: smoother degradation, no reset-spike gaming; documented in
// docs/model-routing.md). Spend is the authoritative api_turns.cost_usd
// stamped at insert time (§R14 — never estimated here).
func (r *RoutingRefresher) computeBudgetBurn(ctx context.Context, now time.Time) ([]routing.BudgetBurnState, error) {
	if len(r.policy.BudgetScopes) == 0 {
		return nil, nil
	}
	// One query per distinct window, then per-scope aggregation Go-side
	// (tier scopes need the resolver — not expressible in SQL).
	byWindow := map[string][]routingSpendRow{}
	for _, sc := range r.policy.BudgetScopes {
		if _, done := byWindow[sc.Window]; done {
			continue
		}
		rows, err := r.store.selectRoutingSpend(ctx, now.Add(-budgetWindowDuration(sc.Window)))
		if err != nil {
			return nil, err
		}
		byWindow[sc.Window] = rows
	}
	out := make([]routing.BudgetBurnState, 0, len(r.policy.BudgetScopes))
	for _, sc := range r.policy.BudgetScopes {
		spent := 0.0
		for _, row := range byWindow[sc.Window] {
			if r.scopeMatchesSpend(sc.Scope, row) {
				spent += row.costUSD
			}
		}
		out = append(out, routing.BudgetBurnState{
			Scope: sc.Scope, LimitUSD: sc.LimitUSD, SpentUSD: spent,
			Window: sc.Window, Bands: sc.Bands, Exhausted: sc.Exhausted,
		})
	}
	return out, nil
}

func budgetWindowDuration(window string) time.Duration {
	switch window {
	case "day":
		return 24 * time.Hour
	case "month":
		return 30 * 24 * time.Hour
	default: // week
		return 7 * 24 * time.Hour
	}
}

// scopeMatchesSpend resolves a scope key against one spend row.
// Project scopes match the project root's base name OR the full root.
func (r *RoutingRefresher) scopeMatchesSpend(scope string, row routingSpendRow) bool {
	switch {
	case scope == "global":
		return true
	case strings.HasPrefix(scope, "project:"):
		name := scope[len("project:"):]
		return row.projectRoot == name || filepath.Base(row.projectRoot) == name
	case strings.HasPrefix(scope, "tool:"):
		return row.tool == scope[len("tool:"):]
	case strings.HasPrefix(scope, "tier:"):
		tier, _ := r.resolver.Lookup(row.model)
		return string(tier) == scope[len("tier:"):]
	default:
		return false
	}
}

type routingSpendRow struct {
	model       string
	tool        string
	projectRoot string
	costUSD     float64
}

func (s *Store) selectRoutingSpend(ctx context.Context, since time.Time) ([]routingSpendRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(at.model, ''), COALESCE(se.tool, ''), COALESCE(p.root_path, ''),
		       SUM(COALESCE(at.cost_usd, 0))
		FROM api_turns at
		LEFT JOIN sessions se ON se.id = at.session_id
		LEFT JOIN projects p ON p.id = se.project_id
		WHERE at.timestamp >= ?
		GROUP BY 1, 2, 3`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.selectRoutingSpend: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []routingSpendRow
	for rows.Next() {
		var row routingSpendRow
		if err := rows.Scan(&row.model, &row.tool, &row.projectRoot, &row.costUSD); err != nil {
			return nil, fmt.Errorf("store.selectRoutingSpend: scan: %w", err)
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- health

// computeHealth turns the recent http_status stream into §R12.3
// breaker states. NULL/0 statuses (success turns predating status
// capture, streamed successes) count as OK.
func (r *RoutingRefresher) computeHealth(ctx context.Context, now time.Time) (map[string]routing.HealthState, error) {
	rows, err := r.store.selectRoutingHealth(ctx, now.Add(-breakerWindow))
	if err != nil {
		return nil, err
	}
	out := map[string]routing.HealthState{}
	seen := map[string]bool{}
	for _, row := range rows {
		seen[row.model] = true
		state := r.breakerStateFor(row, now)
		if state != routing.HealthHealthy {
			out[row.model] = state
		}
	}
	// A model with an open breaker but no traffic in the window stays
	// open until cooldown, then half-opens awaiting its probe request.
	for model, mem := range r.breakers {
		if seen[model] {
			continue
		}
		if now.Sub(mem.openedAt) >= breakerCooldown {
			out[model] = routing.HealthHalfOpen
		} else {
			out[model] = routing.HealthOpen
		}
	}
	return out, nil
}

// breakerStateFor advances one model's breaker (§R12.3): error-rate
// threshold opens it; cooldown half-opens it; the next natural
// request's outcome closes or re-opens it.
func (r *RoutingRefresher) breakerStateFor(row routingHealthRow, now time.Time) routing.HealthState {
	mem, isOpen := r.breakers[row.model]
	if isOpen {
		if now.Sub(mem.openedAt) < breakerCooldown {
			return routing.HealthOpen
		}
		// Half-open: judge by traffic after the breaker opened.
		switch {
		case row.lastOK.After(mem.openedAt):
			delete(r.breakers, row.model) // natural probe succeeded
			return routing.HealthHealthy
		case row.lastErr.After(mem.openedAt.Add(breakerCooldown)):
			mem.openedAt = now // probe failed: re-open
			return routing.HealthOpen
		default:
			return routing.HealthHalfOpen
		}
	}
	if row.turns >= breakerMinTurns {
		rate := float64(row.errors) / float64(row.turns)
		switch {
		case rate >= breakerOpenRate:
			r.breakers[row.model] = &breakerMemory{openedAt: now}
			return routing.HealthOpen
		case rate >= breakerDegradeRate:
			return routing.HealthDegraded
		}
	}
	return routing.HealthHealthy
}

type routingHealthRow struct {
	model   string
	turns   int64
	errors  int64
	lastErr time.Time
	lastOK  time.Time
}

func (s *Store) selectRoutingHealth(ctx context.Context, since time.Time) ([]routingHealthRow, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT COALESCE(model, ''), COUNT(*),
		       SUM(CASE WHEN http_status >= 500 OR http_status = 429 THEN 1 ELSE 0 END),
		       MAX(CASE WHEN http_status >= 500 OR http_status = 429 THEN timestamp ELSE '' END),
		       MAX(CASE WHEN http_status IS NULL OR http_status < 400 THEN timestamp ELSE '' END)
		FROM api_turns
		WHERE timestamp >= ?
		GROUP BY 1`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.selectRoutingHealth: %w", err)
	}
	defer func() { _ = rows.Close() }()
	var out []routingHealthRow
	for rows.Next() {
		var (
			row             routingHealthRow
			lastErr, lastOK string
		)
		if err := rows.Scan(&row.model, &row.turns, &row.errors, &lastErr, &lastOK); err != nil {
			return nil, fmt.Errorf("store.selectRoutingHealth: scan: %w", err)
		}
		row.lastErr = parseStamp(lastErr)
		row.lastOK = parseStamp(lastOK)
		out = append(out, row)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- latency

// computeLatencyP75 loads observed total latencies and computes p75
// per model Go-side (SQLite has no percentile; row volume over 7d is
// modest at the 60s cadence).
func (r *RoutingRefresher) computeLatencyP75(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT COALESCE(model, ''), total_response_ms
		FROM api_turns
		WHERE timestamp >= ? AND total_response_ms > 0`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.RoutingRefresher: latency query: %w", err)
	}
	defer func() { _ = rows.Close() }()
	byModel := map[string][]int64{}
	for rows.Next() {
		var (
			model string
			ms    int64
		)
		if err := rows.Scan(&model, &ms); err != nil {
			return nil, fmt.Errorf("store.RoutingRefresher: latency scan: %w", err)
		}
		byModel[model] = append(byModel[model], ms)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(byModel))
	for model, vals := range byModel {
		sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
		out[model] = vals[len(vals)*3/4]
	}
	return out, nil
}

// ---------------------------------------------------------------- session cache reads

// selectRecentSessionCacheReads returns each active session's most
// recent turn's cache_read volume — the warm-prefix size the §R13
// forfeit estimate prices on the live path (where ObservedUsage is
// nil). Sourced from api_turns (session-keyed, same semantic the P0
// replay used); the cachetrack cache_entries table is the future
// refinement hook for entry-level (model, scope, prefix_hash) state.
func (s *Store) selectRecentSessionCacheReads(ctx context.Context, since time.Time) (map[string]int64, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT at.session_id, COALESCE(at.cache_read_tokens, 0)
		FROM api_turns at
		JOIN (
			SELECT session_id, MAX(id) AS mid
			FROM api_turns
			WHERE timestamp >= ? AND session_id IS NOT NULL AND session_id != ''
			GROUP BY session_id
		) last ON last.mid = at.id`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.selectRecentSessionCacheReads: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]int64{}
	for rows.Next() {
		var (
			sid string
			cr  int64
		)
		if err := rows.Scan(&sid, &cr); err != nil {
			return nil, fmt.Errorf("store.selectRecentSessionCacheReads: scan: %w", err)
		}
		out[sid] = cr
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- window cadence

// computeWindowState is the §R15 heuristic v1, learned purely from
// observed traffic (no provider API):
//
//   - capacity     = the max request count over any complete 5-hour
//     block in the trailing 7 days (epoch-aligned blocks — an
//     approximation of the provider's rolling window).
//   - BurnFraction = current block's count / capacity (clamped to 1).
//   - ProjectedExhaustion = a 429 was observed in the last 30 minutes
//     (the window is under pressure NOW), or the burn fraction has
//     crossed the configured headroom line.
//
// Nil when the rate_limit_window feature is off in the policy.
func (r *RoutingRefresher) computeWindowState(ctx context.Context, now time.Time) (*routing.WindowState, error) {
	if !r.policy.RateLimit.Enabled {
		return nil, nil
	}
	const blockSeconds = 5 * 60 * 60
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT CAST(strftime('%s', timestamp) AS INTEGER) / ?, COUNT(*)
		FROM api_turns
		WHERE timestamp >= ?
		GROUP BY 1`, blockSeconds, timestamp(now.AddDate(0, 0, -7)))
	if err != nil {
		return nil, fmt.Errorf("store.RoutingRefresher: window blocks: %w", err)
	}
	defer func() { _ = rows.Close() }()
	currentBlock := now.Unix() / blockSeconds
	var capacity, current int64
	for rows.Next() {
		var block, count int64
		if err := rows.Scan(&block, &count); err != nil {
			return nil, fmt.Errorf("store.RoutingRefresher: window scan: %w", err)
		}
		if block == currentBlock {
			current = count
		} else if count > capacity {
			capacity = count
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var last429 string
	err = r.store.db.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(timestamp), '')
		FROM api_turns
		WHERE http_status = 429 AND timestamp >= ?`,
		timestamp(now.Add(-6*time.Hour))).Scan(&last429)
	if err != nil {
		return nil, fmt.Errorf("store.RoutingRefresher: last 429: %w", err)
	}

	st := &routing.WindowState{}
	if capacity > 0 {
		st.BurnFraction = float64(current) / float64(capacity)
		if st.BurnFraction > 1 {
			st.BurnFraction = 1
		}
	}
	headroom := float64(r.policy.RateLimit.HeadroomPct) / 100
	recent429 := !parseStamp(last429).IsZero() && now.Sub(parseStamp(last429)) <= 30*time.Minute
	st.ProjectedExhaustion = recent429 || (capacity > 0 && st.BurnFraction >= 1-headroom)
	return st, nil
}

// ---------------------------------------------------------------- session activity

// sessionActivityWindow bounds the recent-action load; a session quiet
// longer than this gets an empty window (classifier → unknown → no
// routing, the conservative direction).
const sessionActivityWindow = 30 * time.Minute

// sessionActivityActions caps the per-session window length.
const sessionActivityActions = 12

// actionLagTolerance is the §R8.3 freshness bound: a session whose
// newest api_turn is this much newer than its newest action is marked
// lagged — the classifier degrades to unknown.
const actionLagTolerance = 3 * time.Minute

// computeSessionActivity assembles each active session's classifier
// inputs (§R8.1). EVERY content resolution happens here, store-side:
// command text → CommandClass, permission-mode targets → phase, file
// targets → path-class hit flags + hash. No target leaves this
// function as anything but a flag or a hash (§24.3, §R16).
func (r *RoutingRefresher) computeSessionActivity(ctx context.Context, now time.Time) (map[string]routing.SessionActivity, error) {
	rows, err := r.store.db.QueryContext(ctx, `
		SELECT a.session_id, a.timestamp, a.action_type,
		       COALESCE(a.success, 1), COALESCE(a.is_sidechain, 0), COALESCE(a.target, '')
		FROM actions a
		WHERE a.timestamp >= ?
		ORDER BY a.session_id, a.timestamp, a.id`, timestamp(now.Add(-sessionActivityWindow)))
	if err != nil {
		return nil, fmt.Errorf("recent actions: %w", err)
	}
	defer func() { _ = rows.Close() }()

	type sessAccum struct {
		acts        []routing.ActionSignal
		lastAction  time.Time
		phase       string
		hits        map[string]bool
		hitTargets  []string
		sidechainAt bool
	}
	accums := map[string]*sessAccum{}
	for rows.Next() {
		var (
			sid, ts, actionType, target string
			success, sidechain          int64
		)
		if err := rows.Scan(&sid, &ts, &actionType, &success, &sidechain, &target); err != nil {
			return nil, fmt.Errorf("recent actions scan: %w", err)
		}
		acc, ok := accums[sid]
		if !ok {
			acc = &sessAccum{hits: map[string]bool{}}
			accums[sid] = acc
		}
		sig := routing.ActionSignal{
			Type:        actionType,
			Success:     success != 0,
			IsSidechain: sidechain != 0,
		}
		if actionType == models.ActionRunCommand {
			sig.CommandClass = routing.ResolveCommandClass(target)
		}
		if actionType == models.ActionPermissionMode {
			acc.phase = phaseFromPermissionMode(target)
		}
		if target != "" {
			for class, globs := range r.policy.PathClasses {
				if !acc.hits[class] && pathClassMatch(target, globs) {
					acc.hits[class] = true
					acc.hitTargets = append(acc.hitTargets, target)
				}
			}
		}
		acc.acts = append(acc.acts, sig)
		if len(acc.acts) > sessionActivityActions {
			acc.acts = acc.acts[len(acc.acts)-sessionActivityActions:]
		}
		if t := parseStamp(ts); t.After(acc.lastAction) {
			acc.lastAction = t
		}
		acc.sidechainAt = sig.IsSidechain
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	meta, err := r.store.selectRoutingSessionMeta(ctx, now.Add(-2*time.Hour))
	if err != nil {
		return nil, err
	}

	out := make(map[string]routing.SessionActivity, len(accums))
	for sid, acc := range accums {
		hits := make([]string, 0, len(acc.hits))
		for class := range acc.hits {
			hits = append(hits, class)
		}
		sort.Strings(hits)
		act := routing.SessionActivity{
			RecentActions:     acc.acts,
			ClientPhase:       acc.phase,
			PathClassHits:     hits,
			PathClassHitsHash: hashTargets(acc.hitTargets),
			LastSidechain:     acc.sidechainAt,
			ScopeKeys:         []string{"global"},
		}
		if m, ok := meta[sid]; ok {
			act.Project = filepath.Base(m.projectRoot)
			if m.projectRoot == "" {
				act.Project = ""
			}
			act.TurnCount = m.turnCount
			if act.Project != "" {
				act.ScopeKeys = append(act.ScopeKeys, "project:"+act.Project)
			}
			if m.tool != "" {
				act.ScopeKeys = append(act.ScopeKeys, "tool:"+m.tool)
			}
			// §R8.3 freshness: actions trailing the turn stream by more
			// than the tolerance mark the window lagged.
			if !m.lastTurn.IsZero() && m.lastTurn.Sub(acc.lastAction) > actionLagTolerance {
				act.ActionsLagged = true
			}
		}
		out[sid] = act
	}
	return out, nil
}

// phaseFromPermissionMode maps a permission-mode marker to the
// client-declared phase vocabulary: only "plan" carries routing
// meaning (§R8.1).
func phaseFromPermissionMode(target string) string {
	if strings.EqualFold(strings.TrimSpace(target), "plan") {
		return "plan"
	}
	return ""
}

// hashTargets hashes the matched targets for the decision row (§R16:
// hash only, never the path).
func hashTargets(targets []string) string {
	if len(targets) == 0 {
		return ""
	}
	sort.Strings(targets)
	sum := sha256.Sum256([]byte(strings.Join(targets, "\n")))
	return hex.EncodeToString(sum[:8])
}

// pathClassMatch matches one target path against a path-class's globs
// using the same conservative subset as internal/mcp/pathsafety.go
// (`*`, `?`, `<dir>/**` containment) plus the `**/<pat>` prefix form
// the §R21 examples use (matches the basename or any suffix segment).
func pathClassMatch(target string, globs []string) bool {
	rel := filepath.ToSlash(target)
	base := path.Base(rel)
	for _, pat := range globs {
		if pat == "" {
			continue
		}
		pat = filepath.ToSlash(pat)
		if strings.HasPrefix(pat, "**/") {
			pat = strings.TrimPrefix(pat, "**/")
		}
		if strings.HasSuffix(pat, "/**") {
			prefix := strings.TrimSuffix(pat, "/**")
			if rel == prefix || strings.HasPrefix(rel, prefix+"/") || strings.Contains(rel, "/"+prefix+"/") {
				return true
			}
			continue
		}
		if ok, _ := path.Match(pat, rel); ok {
			return true
		}
		if ok, _ := path.Match(pat, base); ok {
			return true
		}
	}
	return false
}

type routingSessionMeta struct {
	projectRoot string
	tool        string
	turnCount   int
	lastTurn    time.Time
}

// selectRoutingSessionMeta loads project/tool/turn-recency context for
// sessions with recent proxied turns.
func (s *Store) selectRoutingSessionMeta(ctx context.Context, since time.Time) (map[string]routingSessionMeta, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT se.id, COALESCE(p.root_path, ''), COALESCE(se.tool, ''),
		       COALESCE(t.n, 0), COALESCE(t.last_ts, '')
		FROM sessions se
		LEFT JOIN projects p ON p.id = se.project_id
		JOIN (
			SELECT session_id, COUNT(*) AS n, MAX(timestamp) AS last_ts
			FROM api_turns
			WHERE timestamp >= ? AND session_id IS NOT NULL AND session_id != ''
			GROUP BY session_id
		) t ON t.session_id = se.id`, timestamp(since))
	if err != nil {
		return nil, fmt.Errorf("store.selectRoutingSessionMeta: %w", err)
	}
	defer func() { _ = rows.Close() }()
	out := map[string]routingSessionMeta{}
	for rows.Next() {
		var (
			sid, root, tool, lastTS string
			n                       int
		)
		if err := rows.Scan(&sid, &root, &tool, &n, &lastTS); err != nil {
			return nil, fmt.Errorf("store.selectRoutingSessionMeta: scan: %w", err)
		}
		out[sid] = routingSessionMeta{
			projectRoot: root, tool: tool, turnCount: n, lastTurn: parseStamp(lastTS),
		}
	}
	return out, rows.Err()
}

// logWarn writes a refresher warning through the observer log; best
// effort, never fails the caller.
func (s *Store) logWarn(ctx context.Context, msg string, err error) {
	_ = s.InsertObserverLog(ctx, "warn", "routing", msg, err.Error())
}
