package guard

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// engineSet is the immutable-per-swap org-derived engine snapshot
// (P0-7 hot-reload). The Guard holds exactly one behind an
// atomic.Pointer; ReloadOrgLayer publishes a fresh one. Everything an
// Evaluate needs — the base engine, the org+user layers, the
// builtin/org/user layer states + rule categories, and the lazy
// per-project engine cache — lives here, so a single atomic Load gives
// a hot path a fully consistent view. A swapped-in set starts with an
// EMPTY project cache: project engines rebuild lazily against the new
// org layer, and in-flight Evaluate calls that already Loaded the old
// set keep using it (a consistent snapshot).
//
// The base slice/map fields (states, ruleCategories) are IMMUTABLE for
// the life of the snapshot. The project cache (projectEngines,
// projectStates, projectCats) is the ONLY mutable part and is guarded
// by pmu — the B1 per-snapshot cache object, bounded by
// maxProjectEngines exactly as the old single-map cache was.
type engineSet struct {
	revision  uint64
	base      *policy.Engine
	orgLayer  *policyFile // retained so per-project engines re-merge it
	userLayer *policyFile // unchanged across an org reload
	// budgetBinding is sealed with base so a native intervention decision
	// cannot pair one enrollment epoch with another epoch's numeric engine.
	budgetBinding   string
	budgetCalendars BudgetCalendars
	budgetWitness   BudgetDocumentWitness

	// orgNamedRules is the set of rule IDs the ORG layer actually
	// NAMES: every [[override]] row's target plus every rule the org
	// bundle itself defines. It is the blast radius of the org lock on
	// an INDIVIDUAL node (override.go: an individual node keeps local
	// approvals for every rule the org never mentioned), sealed with
	// the snapshot so a reload cannot tear it from orgLayer. nil when
	// no org bundle applies.
	orgNamedRules map[string]bool

	// states are the org+user layer descriptors (builtins carry no
	// state entry), in New's insertion order (org, then user).
	states []PolicyState
	// ruleCategories maps rule ID → category for audit attribution,
	// seeded from the built-in catalog and the org+user layers.
	ruleCategories map[string]policy.Category

	pmu            sync.Mutex
	projectEngines map[string]*policy.Engine
	projectStates  []PolicyState
	projectCats    map[string]policy.Category
}

var engineRevision atomic.Uint64

func (es *engineSet) accountingContext(managed bool) BudgetAccountingContext {
	return BudgetAccountingContext{Managed: managed, Calendars: BudgetCalendars{
		DailyTimezone: es.budgetCalendars.DailyTimezone, MonthlyTimezone: es.budgetCalendars.MonthlyTimezone,
	}, BudgetBinding: es.budgetBinding}
}

// newEngineSet seals a base engine + layers + immutable states/categories
// into a snapshot with an empty project cache.
func newEngineSet(base *policy.Engine, org, user *policyFile, states []PolicyState, ruleCats map[string]policy.Category, budgetBinding string, calendars ...BudgetCalendars) *engineSet {
	return &engineSet{
		revision:        engineRevision.Add(1),
		base:            base,
		orgLayer:        org,
		orgNamedRules:   namedRuleIDs(org),
		userLayer:       user,
		budgetBinding:   budgetBinding,
		budgetCalendars: normalizedBudgetCalendars(calendars),
		budgetWitness:   normalizedBudgetCalendars(calendars).documentWitness,
		states:          states,
		ruleCategories:  ruleCats,
		projectEngines:  make(map[string]*policy.Engine),
		projectCats:     make(map[string]policy.Category),
	}
}

// engineFor returns the engine for a project root within THIS snapshot,
// lazily building + caching it against the snapshot's org+user layers.
// A missing project policy (the overwhelmingly common case) caches the
// base engine. The maxProjectEngines bound is preserved: on overflow a
// new root evaluates with the base engine (correct, minus any
// project-layer escalations for that root).
func (es *engineSet) engineFor(g *Guard, projectRoot string) *policy.Engine {
	if projectRoot == "" || g.cfg.Rules.ProjectPolicy == "" {
		return es.base
	}
	es.pmu.Lock()
	if eng, ok := es.projectEngines[projectRoot]; ok {
		es.pmu.Unlock()
		return eng
	}
	if len(es.projectEngines) >= maxProjectEngines {
		es.pmu.Unlock()
		return es.base
	}
	es.pmu.Unlock()

	// Build outside the lock (file read + parse + engine construction).
	eng, st, cats, loaded := g.buildProjectEngine(es, projectRoot)

	var fire *PolicyState
	es.pmu.Lock()
	if existing, ok := es.projectEngines[projectRoot]; ok {
		eng = existing // another goroutine won the race; keep its engine
	} else if len(es.projectEngines) < maxProjectEngines {
		es.projectEngines[projectRoot] = eng
		if loaded {
			es.projectStates = append(es.projectStates, st)
			for id, c := range cats {
				es.projectCats[id] = c
			}
			s := st
			fire = &s
		}
	} else {
		// Capacity filled between the two locks: match the first-check
		// overflow behavior (evaluate with base — no project categories
		// installed for this root). Returning the freshly-built eng
		// would tear Evaluate vs categoryFor (project rule fires, but
		// categoryFor returns "" because cats were never installed).
		eng = es.base
	}
	es.pmu.Unlock()
	if fire != nil && g.onPolicyState != nil {
		g.onPolicyState(*fire)
	}
	return eng
}

// policyStates returns the snapshot's layer descriptors: the immutable
// builtin/org/user set first (New's order), then the lazily-loaded
// project states — all off ONE consistent snapshot.
func (es *engineSet) policyStates() []PolicyState {
	es.pmu.Lock()
	out := make([]PolicyState, 0, len(es.states)+len(es.projectStates))
	out = append(out, es.states...)
	out = append(out, es.projectStates...)
	es.pmu.Unlock()
	return out
}

// categoryFor resolves a rule ID's category off this snapshot: the
// immutable builtin/org/user map first, then the lazy project cats.
// Missing → "" (an unknown ID has no category).
func (es *engineSet) categoryFor(ruleID string) string {
	if c, ok := es.ruleCategories[ruleID]; ok {
		return string(c)
	}
	es.pmu.Lock()
	c := es.projectCats[ruleID]
	es.pmu.Unlock()
	return string(c)
}

// orgApplies reports whether an org policy bundle is part of THIS
// snapshot. With no bundle the node is an individual, un-enrolled node
// and the whole Track B mechanism is inert (byte-identical pre-wave
// behaviour).
//
// It is NOT on its own the org-lock predicate — that is orgLocksRule,
// which additionally asks how far the bundle's authority reaches on
// THIS node (P2-8: an individual node's bundle is a floor over the
// rules it names, not a lock over the whole catalog).
func (es *engineSet) orgApplies() bool { return es.orgLayer != nil }

// orgLocksRule reports whether the org layer LOCKS ruleID on this node
// — the question "may a local approval ever apply here", asked before
// the per-rule `overridable` grant is consulted.
//
// lockAll is the tenancy half, resolved by the Guard (Guard.orgLocksEveryRule):
//
//   - managed node (or a process that could not resolve its tenancy,
//     which keeps the conservative pre-fix answer): the organization is
//     authoritative over the whole catalog, so every rule is locked.
//   - individual node: the org bundle is a FLOOR. It locks exactly the
//     rules it names; a built-in or user-layer rule the bundle never
//     mentions keeps the node's own approvals, per CLAUDE.md's
//     lowering-only posture for the individual plane.
func (es *engineSet) orgLocksRule(ruleID string, lockAll bool) bool {
	if !es.orgApplies() {
		return false
	}
	if lockAll {
		return true
	}
	return es.orgNamedRules[ruleID]
}

// namedRuleIDs collects every rule ID an org policy layer names: the
// target of each [[override]] row and the ID of each rule the layer
// defines itself. nil in, nil out.
func namedRuleIDs(pf *policyFile) map[string]bool {
	if pf == nil {
		return nil
	}
	out := make(map[string]bool, len(pf.overrides)+len(pf.rules))
	for _, ov := range pf.overrides {
		if ov.RuleID != "" {
			out[ov.RuleID] = true
		}
	}
	for i := range pf.rules {
		if pf.rules[i].ID != "" {
			out[pf.rules[i].ID] = true
		}
	}
	return out
}

// orgState returns the snapshot's org-layer state (ok=false when the
// snapshot has no org layer).
func (es *engineSet) orgState() (PolicyState, bool) {
	for _, s := range es.states {
		if s.Layer == layerOrg {
			return s, true
		}
	}
	return PolicyState{}, false
}

// buildProjectEngine reads + parses + merges one project's policy file
// against the SNAPSHOT's org+user layers WITHOUT mutating the snapshot
// — the caller caches the result under pmu. loaded=false (with the
// snapshot's base engine) covers every degrade path (no file, read
// error, parse error, engine-build error), each recording an issue.
func (g *Guard) buildProjectEngine(es *engineSet, projectRoot string) (eng *policy.Engine, st PolicyState, cats map[string]policy.Category, loaded bool) {
	path := ProjectPolicyPath(g.cfg, projectRoot)
	raw, err := g.readFile(path)
	switch {
	case os.IsNotExist(err):
		return es.base, PolicyState{}, nil, false
	case err != nil:
		g.recordIssues([]string{fmt.Sprintf("project policy %s: %v", path, err)})
		return es.base, PolicyState{}, nil, false
	}
	pf, perr := parsePolicyFile(raw, layerProject)
	if perr != nil {
		g.recordIssues([]string{fmt.Sprintf("project policy %s: %v", path, perr)})
		return es.base, PolicyState{}, nil, false
	}
	built, err := g.buildEngine(es.base.Mode(), es.orgLayer, es.userLayer, pf)
	if err != nil {
		g.recordIssues([]string{fmt.Sprintf("project policy %s dropped: %v", path, err)})
		return es.base, PolicyState{}, nil, false
	}
	st = PolicyState{Layer: layerProject, Path: path, ContentHash: sha256hex(raw)}
	cats = make(map[string]policy.Category, len(pf.rules))
	for i := range pf.rules {
		cats[pf.rules[i].ID] = pf.rules[i].Category
	}
	return built, st, cats, true
}

// buildRuleCategories seeds the audit-attribution category map from the
// built-in catalog and the org+user layer rules (user last so a reused
// ID last-writes, matching New). Project cats are added lazily per
// snapshot.
func buildRuleCategories(org, user *policyFile) map[string]policy.Category {
	m := make(map[string]policy.Category)
	for _, info := range policy.Catalog() {
		m[info.ID] = info.Category
	}
	if org != nil {
		for i := range org.rules {
			m[org.rules[i].ID] = org.rules[i].Category
		}
	}
	if user != nil {
		for i := range user.rules {
			m[user.rules[i].ID] = user.rules[i].Category
		}
	}
	return m
}

// dropLayerState removes every state of the given layer (used by New's
// engine-build-failure fallback so a dropped layer is never reported as
// loaded).
func dropLayerState(states []PolicyState, layer string) []PolicyState {
	out := states[:0]
	for _, s := range states {
		if s.Layer != layer {
			out = append(out, s)
		}
	}
	return out
}

// ReloadOrgLayer re-reads + re-verifies the org bundle at the
// configured path (same verification as guard.New: signature + optional
// key pin) and, on success, atomically swaps the org-derived engine set
// so the next Evaluate enforces it. On ANY failure (missing/corrupt/
// verification/engine-build) it is a NO-OP that returns an error and
// leaves the running engine unchanged (fail-safe: never downgrade the
// live policy on a bad reload). Safe to call concurrently with Evaluate
// on the proxy/watcher/hook hot paths. Idempotent: reloading an
// already-effective version (identical content hash AND version) is a
// cheap no-op that keeps the warm project cache. A version-only bump
// (identical content, higher version — the server assigns monotonic
// versions independent of content) MUST fall through and publish so
// the running version converges; short-circuiting on hash alone would
// leave running=v1 / cached=v2 → pending_restart forever.
//
// After a nil-error return, Guard.PolicyStates()' org entry
// {Version, ContentHash} equals the just-accepted bundle's Version +
// sha256hex(BundleTOML) — the exact pair guardRunningFromGuard reads,
// so the P0-6 resolver flips the guard point from pending_restart to
// effective without a daemon restart.
func (g *Guard) ReloadOrgLayer(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("guard.ReloadOrgLayer: %w", err)
	}
	if g.orgBundlePath == "" {
		return fmt.Errorf("guard.ReloadOrgLayer: no org bundle path configured")
	}

	// Re-verify the cached bundle through the SAME parse/verify path New
	// uses (signature + optional pin). A failure here is fail-safe: the
	// live engine is left untouched.
	pf, st, issue, loaded := g.parseOrgBundle(g.orgBundlePath, g.orgKeyPinHash)
	if !loaded {
		if issue != "" {
			g.recordIssues([]string{issue})
			return fmt.Errorf("guard.ReloadOrgLayer: %s", issue)
		}
		return fmt.Errorf("guard.ReloadOrgLayer: no org bundle present at %s", g.orgBundlePath)
	}

	// Serialize construct+publish so a concurrent reload can never
	// publish an older snapshot over a newer one (B3).
	g.reloadMu.Lock()
	defer g.reloadMu.Unlock()

	cur := g.set.Load()
	if curOrg, ok := cur.orgState(); ok {
		// Idempotent short-circuit: identical org content AND version →
		// keep the warm project cache. Hash-only equality is NOT enough
		// (a version-only bump must publish so running converges).
		if curOrg.ContentHash == st.ContentHash && curOrg.Version == st.Version {
			return nil
		}
		// Non-regressing publish: refuse a candidate OLDER than the
		// currently-published org version (defensive — the production
		// caller is single-threaded, but this makes the concurrency
		// test honest and blocks a stale in-flight reload).
		if regressesOrg(curOrg.Version, st.Version) {
			return fmt.Errorf("guard.ReloadOrgLayer: refusing to publish org version %q over %q (non-regressing)", st.Version, curOrg.Version)
		}
	}

	// Build a FRESH base against the new org layer + the existing user
	// layer. A build failure is fail-safe: return the error, no swap.
	base, err := g.buildEngine(cur.base.Mode(), pf, cur.userLayer, nil)
	if err != nil {
		return fmt.Errorf("guard.ReloadOrgLayer: build engine: %w", err)
	}

	// Recompute the immutable layer state: replace the org entry, keep
	// the user entry; the project cache resets (rebuilds lazily against
	// the new org layer).
	states := replaceOrgState(cur.states, st)
	newES := newEngineSet(base, pf, cur.userLayer, states, buildRuleCategories(pf, cur.userLayer), g.budgetBinding(), g.budgetCalendars())
	g.set.Store(newES)

	// Keep the state-log owner single + idempotent (FetchPolicyBundle
	// already wrote the row; this fire updates the daemon's live record).
	if g.onPolicyState != nil {
		g.onPolicyState(st)
	}
	return nil
}

// replaceOrgState returns curStates with the org entry replaced by
// newOrg (org first, matching New's insertion order); non-org entries
// (the user layer) are preserved. Project states are NOT in curStates
// (they live in the per-snapshot cache), so they correctly reset.
func replaceOrgState(curStates []PolicyState, newOrg PolicyState) []PolicyState {
	out := make([]PolicyState, 0, len(curStates)+1)
	out = append(out, newOrg)
	for _, s := range curStates {
		if s.Layer == layerOrg {
			continue
		}
		out = append(out, s)
	}
	return out
}

// regressesOrg reports whether candidate is a strictly-older org
// version than current. Both are the decimal version strings the org
// bundle carries; an unparseable side degrades open (never blocks a
// reload on a malformed version string — the acceptance gate already
// validated it).
func regressesOrg(current, candidate string) bool {
	cur, ok1 := parseOrgVersion(current)
	cand, ok2 := parseOrgVersion(candidate)
	if !ok1 || !ok2 {
		return false
	}
	return cand < cur
}

// parseOrgVersion parses an org bundle version string into an int64.
// ok=false when the string is empty or unparseable (the caller degrades
// open).
func parseOrgVersion(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return 0, false
	}
	return v, true
}
