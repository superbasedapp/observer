package guard

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
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
	revision uint64
	// eager is the base engine (org + user layers, no project layer). On a
	// snapshot New builds for a v3 (project audience) org layer it is built
	// LAZILY, on first need, by baseBuild (lane sec-p2a, P-052 finding 5): a
	// hook in a project root whose org project sections load needs only the
	// folded project engine, so it builds one engine instead of two. Read it
	// through base(), never directly.
	eager     *policy.Engine
	baseOnce  sync.Once
	baseBuild func() (*policy.Engine, []string)
	// baseDropped names the layers (layerOrg, layerUser) the lazy base
	// build's ladder dropped. Written once inside baseOnce, read only after
	// base() returned, so a status surface never reports a layer the base
	// engine does not hold (plans decision log P-058).
	baseDropped []string
	// mode is the engines' mode, known without building one.
	mode      policy.Mode
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

	// orgProject is the org layer's composed envelope when it carries the
	// project audience (a v3 bundle), decoded once with the snapshot; nil
	// otherwise (orgproject.go).
	orgProject    *orgcontract.PolicyBundle
	orgProjectKey ed25519.PublicKey

	// projectNamed is, per project root whose engine folded org project
	// envelopes in, the rule IDs that folded org layer NAMES (namedRuleIDs
	// over it): the org lock's blast radius INSIDE that root on an
	// individual node, so a local approval cannot pass a rule only a
	// project section names (audit finding 3). Guarded by pmu and filled
	// with projectEngines; a root with no project layer has no entry.
	projectNamed map[string]map[string]bool

	// states are the org+user layer descriptors (builtins carry no
	// state entry), in New's insertion order (org, then user).
	states []PolicyState
	// ruleCategories maps rule ID → category for audit attribution,
	// seeded from the built-in catalog and the org+user layers.
	ruleCategories map[string]policy.Category

	// projectMatchKey and projectCheckedAt are, per project root whose
	// engine was built while the org project layer was in force, the match
	// it was built for (orgProjectMatch.key) and when that was last checked
	// (projectMatchStale). projectUnknown is, per such root, why its org
	// project layer is unknown ("" absent: known), the input of the
	// project_unknown floor (projectfloor.go). All three guarded by pmu.
	projectMatchKey  map[string]string
	projectCheckedAt map[string]time.Time
	projectUnknown   map[string]string

	pmu            sync.Mutex
	projectEngines map[string]*policy.Engine
	// projectStates are the loaded project layers' states per root, listed
	// in projectStateOrder (first build first), so a root whose cached
	// engine is rebuilt replaces its states rather than adding to them
	// (lane sec-p2a audit finding 7).
	projectStates     map[string][]PolicyState
	projectStateOrder []string
	projectCats       map[string]policy.Category

	// localBudgetOnly marks a derived snapshot built by localBudgetSet: its
	// base carries ONLY the node's own [guard.budget] numbers. It never
	// builds a project engine (that funnel reads the published, org-composed
	// budget) and its verdicts take no organization label.
	localBudgetOnly bool
	// localOnce / local cache that derived snapshot (REVIEW-4 P4-02), built
	// lazily the first time an admission needs it, so a node whose
	// enrolment is live never pays for a second engine.
	localOnce sync.Once
	local     *engineSet
}

var engineRevision atomic.Uint64

// localBudgetSet returns a snapshot that evaluates the node's OWN
// [guard.budget] block over the same org and user rule layers, with nothing an
// organization composed (no per-subject caps, no protection, no soft-window
// set, no B-625, no enrolment binding, UTC calendars). The proxy admission
// uses it when the enrolment this snapshot was composed for is confirmed gone
// or replaced and the org did not opt into fail-closed (D-502: fail open on
// the node's own numbers). nil when the engine cannot be built; the caller
// then admits, the guard's usual fail-safe.
func (es *engineSet) localBudgetSet(g *Guard) *engineSet {
	if es == nil || es.base() == nil {
		return nil
	}
	if es.localBudgetOnly {
		return es
	}
	es.localOnce.Do(func() {
		base, err := g.buildEngineWith(es.mode, es.orgLayer, es.userLayer, nil, nil, g.localBudgetInputs())
		if err != nil {
			g.recordIssues([]string{fmt.Sprintf("local-only budget engine: %v", err)})
			return
		}
		local := newEngineSet(base, es.orgLayer, es.userLayer, es.states, es.ruleCategories, "")
		local.revision = es.revision
		local.localBudgetOnly = true
		es.local = local
	})
	return es.local
}

func (es *engineSet) accountingContext(managed bool) BudgetAccountingContext {
	return BudgetAccountingContext{Managed: managed, Calendars: BudgetCalendars{
		DailyTimezone: es.budgetCalendars.DailyTimezone, MonthlyTimezone: es.budgetCalendars.MonthlyTimezone,
	}, BudgetBinding: es.budgetBinding}
}

// base returns the snapshot's base engine, building it on first use when the
// snapshot was sealed lazily (newLazyEngineSet). Safe for concurrent use.
func (es *engineSet) base() *policy.Engine {
	if es.baseBuild != nil {
		es.baseOnce.Do(func() { es.eager, es.baseDropped = es.baseBuild() })
	}
	return es.eager
}

// newLazyEngineSet is newEngineSet for a snapshot whose base engine is built
// on first use by build (New, for a v3 org layer whose layers are known to
// build). Everything else is sealed now, exactly as newEngineSet seals it.
// build also returns the layers its ladder dropped (baseDropped).
func newLazyEngineSet(mode policy.Mode, build func() (*policy.Engine, []string), org, user *policyFile, states []PolicyState, ruleCats map[string]policy.Category, budgetBinding string, calendars ...BudgetCalendars) *engineSet {
	es := newEngineSet(nil, org, user, states, ruleCats, budgetBinding, calendars...)
	es.mode, es.baseBuild = mode, build
	return es
}

// newEngineSet seals a base engine + layers + immutable states/categories
// into a snapshot with an empty project cache.
func newEngineSet(base *policy.Engine, org, user *policyFile, states []PolicyState, ruleCats map[string]policy.Category, budgetBinding string, calendars ...BudgetCalendars) *engineSet {
	es := newEngineSetBase(base, org, user, states, ruleCats, budgetBinding, calendars...)
	if env, key, ok := decodeOrgProjectEnvelope(org); ok {
		es.orgProject, es.orgProjectKey = &env, key
	}
	return es
}

// newEngineSetBase is newEngineSet without the org project decode.
func newEngineSetBase(base *policy.Engine, org, user *policyFile, states []PolicyState, ruleCats map[string]policy.Category, budgetBinding string, calendars ...BudgetCalendars) *engineSet {
	es := &engineSet{
		revision:         engineRevision.Add(1),
		eager:            base,
		orgLayer:         org,
		orgNamedRules:    namedRuleIDs(org),
		userLayer:        user,
		budgetBinding:    budgetBinding,
		budgetCalendars:  normalizedBudgetCalendars(calendars),
		budgetWitness:    normalizedBudgetCalendars(calendars).documentWitness,
		states:           states,
		ruleCategories:   ruleCats,
		projectEngines:   make(map[string]*policy.Engine),
		projectStates:    make(map[string][]PolicyState),
		projectCats:      make(map[string]policy.Category),
		projectNamed:     make(map[string]map[string]bool),
		projectMatchKey:  make(map[string]string),
		projectCheckedAt: make(map[string]time.Time),
		projectUnknown:   make(map[string]string),
	}
	if base != nil {
		es.mode = base.Mode()
	}
	return es
}

// engineFor returns the engine for a project root within THIS snapshot,
// lazily building + caching it against the snapshot's org+user layers.
// A missing project policy (the overwhelmingly common case) caches the
// base engine. The maxProjectEngines bound is preserved: on overflow a
// new root evaluates with an engine built uncached (overflowEngine), never
// with the bare base engine, so its project layers still apply.
func (es *engineSet) engineFor(g *Guard, projectRoot string) *policy.Engine {
	return es.engineForCheckout(g, projectRoot, "")
}

// engineForEvent is engineFor for one event: the engine of the checkout the
// event's working directory sits in (checkoutOf), so a linked worktree's own
// in-repo policy file applies in that worktree and not in the main checkout
// or a sibling worktree (lane LEFT-SHARED, SHR-8 residual). An event whose
// checkout is not known evaluates with the project engine that folds every
// checkout's file, the strictest, as before.
func (es *engineSet) engineForEvent(g *Guard, projectRoot, cwd string) *policy.Engine {
	return es.engineForCheckout(g, projectRoot, sharedCheckout(g, projectRoot, checkoutOf(projectRoot, cwd)))
}

// sharedCheckout maps a checkout whose engine would read exactly the files
// the every-checkout engine reads to "" (lane LEFT-SHARED audit finding 1):
// the main checkout of a project with no linked worktree, a project with no
// in-repo policy key, and the only linked worktree of a project. Such a
// checkout shares the root's one cache entry instead of taking a second
// entry for the same engine.
func sharedCheckout(g *Guard, projectRoot, checkout string) string {
	if checkout == "" || samePathSet(checkoutPolicyPaths(g.cfg, projectRoot, checkout), ProjectPolicyPaths(g.cfg, projectRoot)) {
		return ""
	}
	return checkout
}

// samePathSet reports whether a and b hold the same cleaned paths, in any
// order.
func samePathSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := make(map[string]int, len(a))
	for _, p := range a {
		seen[filepath.Clean(p)]++
	}
	for _, p := range b {
		k := filepath.Clean(p)
		if seen[k] == 0 {
			return false
		}
		seen[k]--
	}
	return true
}

// engineForCheckout returns the engine for one checkout of a project root:
// checkout "" (not known) folds the in-repo files of every checkout of the
// project (ProjectPolicyPaths), any other value folds the main checkout's
// file and that checkout's own (checkoutPolicyPaths). The trusted layer and
// the org project sections are the project's either way. Each checkout has
// its own cache entry (engineKey); the org match state stays per root. When
// the cache is full a new checkout never falls back to the base engine (lane
// LEFT-SHARED audit finding 1): it takes the root's cached every-checkout
// engine, or an engine built uncached (overflowEngine), so the in-repo, the
// trusted and the org project layers always apply.
func (es *engineSet) engineForCheckout(g *Guard, projectRoot, checkout string) *policy.Engine {
	// The two per-project layers are INDEPENDENT switches: the in-repo,
	// agent-writable file ([guard.rules].project_policy) and the
	// dashboard-authored trusted file ([guard.rules].trusted_project_dir).
	// Clearing project_policy is exactly the hardening that motivates the
	// trusted layer, so it must not also switch that layer off — gate on
	// both resolvers, not on the in-repo key alone.
	//
	// The org project layer (orgproject.go) is a third, ORG-signed source,
	// consulted only when the org layer in force carries the project
	// audience (a v3 bundle); a node with no project-scoped bundle never
	// reaches it.
	if es.localBudgetOnly || projectRoot == "" || (ProjectPolicyPath(g.cfg, projectRoot) == "" &&
		TrustedProjectPolicyPath(g.cfg, g.home, projectRoot) == "" && !es.orgProjectsInForce()) {
		return es.base()
	}
	ek := engineKey(projectRoot, checkout)
	var stale []PolicyState
	es.pmu.Lock()
	if eng, ok := es.projectEngines[ek]; ok {
		key, due := es.projectRecheckDue(ek)
		es.pmu.Unlock()
		if !due {
			return eng
		}
		// The re-check reads the record, the mapping and the envelope files,
		// outside the lock (lane sec-p2a audit finding 7).
		if g.orgProjectMatchKey(es, projectRoot) == key {
			return eng
		}
		es.pmu.Lock()
		if es.projectEngines[ek] == eng {
			// The root's org project match changed under this snapshot (the
			// daemon matcher or the resolve call wrote a new record, or a
			// missing envelope arrived): drop the cached engine and its
			// states and rebuild it now rather than at the next org reload.
			stale = es.dropProjectRoot(ek, projectRoot)
		} else if cur, ok := es.projectEngines[ek]; ok {
			// Another goroutine already rebuilt it.
			es.pmu.Unlock()
			return cur
		}
	}
	if len(es.projectEngines) >= maxProjectEngines {
		_, foldCached := es.projectEngines[engineKey(projectRoot, "")]
		es.pmu.Unlock()
		if checkout != "" && foldCached {
			// The every-checkout fold reads this checkout's file too: the
			// strictest engine of the root, already built.
			return es.engineForCheckout(g, projectRoot, "")
		}
		return es.overflowEngine(g, projectRoot, checkout)
	}
	es.pmu.Unlock()

	// Build outside the lock (file read + parse + engine construction).
	// A project root can carry TWO layers now — the in-repo file and the
	// trusted daemon-local file — so buildProjectEngine returns a state
	// slice (one entry per successfully-loaded layer).
	pb := g.buildProjectEngine(es, projectRoot, checkout)
	eng, states, cats, named, loaded := pb.eng, pb.states, pb.cats, pb.named, pb.loaded

	var fire []PolicyState
	es.pmu.Lock()
	if existing, ok := es.projectEngines[ek]; ok {
		eng = existing // another goroutine won the race; keep its engine
	} else if len(es.projectEngines) < maxProjectEngines {
		es.projectEngines[ek] = eng
		if pb.org.inForce {
			es.projectMatchKey[ek] = pb.org.key
			es.projectCheckedAt[ek] = time.Now()
			if pb.org.unknown != "" {
				es.projectUnknown[projectRoot] = pb.org.unknown
			}
		}
		if loaded {
			if _, seen := es.projectStates[ek]; !seen {
				es.projectStateOrder = append(es.projectStateOrder, ek)
			}
			es.projectStates[ek] = states
			for id, c := range cats {
				es.projectCats[id] = c
			}
			if len(named) > 0 {
				es.projectNamed[projectRoot] = named
			}
			// A rebuild reports only the layers that changed: a state the
			// dropped engine already reported is not fired again.
			for i := range states {
				if !hasPolicyState(stale, states[i]) {
					fire = append(fire, states[i])
				}
			}
		}
	} else {
		// Capacity filled between the two locks: use the engine just built,
		// uncached, exactly as overflowEngine does (its categories, the
		// root's lock radius and unknown state installed so Evaluate and
		// categoryFor agree), never the bare base engine.
		es.installUncached(projectRoot, pb)
	}
	es.pmu.Unlock()
	if g.onPolicyState != nil {
		for i := range fire {
			g.onPolicyState(fire[i])
		}
	}
	return eng
}

// overflowEngine is the engine of one checkout when the project cache is
// full: built now and not cached (lane LEFT-SHARED audit finding 1). Its rule
// categories, the root's org lock radius and its unknown org project state
// are installed (installUncached) so categoryFor, orgLocksRule and the
// project_unknown floor agree with the verdict; those three are keyed by rule
// ID or by root and are rewritten by every such build. The cost is one build
// per evaluation for a project past the cap, the price of never evaluating
// without its layers.
func (es *engineSet) overflowEngine(g *Guard, projectRoot, checkout string) *policy.Engine {
	pb := g.buildProjectEngine(es, projectRoot, checkout)
	es.pmu.Lock()
	es.installUncached(projectRoot, pb)
	es.pmu.Unlock()
	return pb.eng
}

// installUncached records, under pmu, what an uncached project build needs
// beside its engine: the root's unknown org project state, and when it
// loaded, its rule categories and the root's org lock radius.
func (es *engineSet) installUncached(projectRoot string, pb projectBuild) {
	if pb.org.inForce && pb.org.unknown != "" {
		es.projectUnknown[projectRoot] = pb.org.unknown
	}
	if !pb.loaded {
		return
	}
	for id, c := range pb.cats {
		es.projectCats[id] = c
	}
	if len(pb.named) > 0 {
		es.projectNamed[projectRoot] = pb.named
	}
}

// policyStates returns the snapshot's layer descriptors: the immutable
// builtin/org/user set first (New's order), then the lazily-loaded
// project states — all off ONE consistent snapshot.
func (es *engineSet) policyStates() []PolicyState {
	// A lazy snapshot settles which layers its base engine kept first: a
	// layer its ladder dropped is never reported as loaded (P-058). Status
	// surfaces only; the hook never reads the states.
	es.base()
	es.pmu.Lock()
	out := make([]PolicyState, 0, len(es.states)+len(es.projectStateOrder))
	for _, s := range es.states {
		if !es.baseDroppedLayer(s.Layer) {
			out = append(out, s)
		}
	}
	// Every checkout of a root reports the main checkout's file and the
	// root's trusted and org project layers again: list each state once
	// (lane LEFT-SHARED audit finding 7).
	for _, root := range es.projectStateOrder {
		for _, st := range es.projectStates[root] {
			if !hasPolicyState(out, st) {
				out = append(out, st)
			}
		}
	}
	es.pmu.Unlock()
	return out
}

// dropProjectRoot forgets a cached engine under pmu (its engine, states and
// match key under ek, the root's lock radius and unknown state, which every
// checkout of the root shares and the rebuild writes again) and returns the
// states it reported.
func (es *engineSet) dropProjectRoot(ek, projectRoot string) []PolicyState {
	stale := es.projectStates[ek]
	delete(es.projectEngines, ek)
	delete(es.projectNamed, projectRoot)
	delete(es.projectUnknown, projectRoot)
	delete(es.projectMatchKey, ek)
	if _, ok := es.projectStates[ek]; ok {
		delete(es.projectStates, ek)
		for i, r := range es.projectStateOrder {
			if r == ek {
				es.projectStateOrder = append(es.projectStateOrder[:i:i], es.projectStateOrder[i+1:]...)
				break
			}
		}
	}
	return stale
}

// hasPolicyState reports whether states holds a layer state equal to s
// (layer, path, version and content).
func hasPolicyState(states []PolicyState, s PolicyState) bool {
	for i := range states {
		if states[i].Layer == s.Layer && states[i].Path == s.Path && states[i].Version == s.Version && states[i].ContentHash == s.ContentHash {
			return true
		}
	}
	return false
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

// orgProjectsInForce reports whether the org layer in force carries the
// project audience (a v3 bundle), so a project root may have org project
// envelopes to load (orgproject.go).
func (es *engineSet) orgProjectsInForce() bool { return es.orgProject != nil }

// baseDroppedLayer reports whether the lazy base build dropped layer (after
// base() returned; false on an eagerly built snapshot, whose dropped layers
// were never sealed in).
func (es *engineSet) baseDroppedLayer(layer string) bool {
	for _, d := range es.baseDropped {
		if d == layer {
			return true
		}
	}
	return false
}

// orgLayerReported is the status surfaces' "the org layer is in force":
// the snapshot holds one and, for a lazy snapshot, its base build kept it.
// It builds a lazy base, so the hook path never calls it.
func (es *engineSet) orgLayerReported() bool {
	if es == nil || es.orgLayer == nil {
		return false
	}
	es.base()
	return !es.baseDroppedLayer(layerOrg)
}

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
//     lowering-only posture for the individual plane. Inside a project
//     root whose org project sections loaded, the rules those sections
//     name are named by the org too (projectNamed); in any other root
//     they are not.
func (es *engineSet) orgLocksRule(ruleID, projectRoot string, lockAll bool) bool {
	if !es.orgApplies() {
		return false
	}
	if lockAll || es.orgNamedRules[ruleID] {
		return true
	}
	if projectRoot == "" {
		return false
	}
	es.pmu.Lock()
	named := es.projectNamed[projectRoot]
	es.pmu.Unlock()
	return named[ruleID]
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

// promptRuleFlagOnly reports whether the snapshot's base engine (org +
// user layers) caps ruleID at flag through an explicit `enforce = false`.
// It is for seams that have a rule ID but no evaluated verdict; a seam
// holding a verdict reads Verdict.EnforceCappedBy, which also reflects
// the per-project layers.
func (es *engineSet) promptRuleFlagOnly(ruleID string) bool {
	return es.base().RuleEnforceCapped(ruleID)
}

// orgPromptFloorStops reports whether some prompt rule carries an org-pinned
// decision whose floor can stop a prompt (block or ask-once) and is not
// capped at flag.
func (es *engineSet) orgPromptFloorStops() bool {
	for _, id := range promptRuleIDs {
		if es.promptRuleFlagOnly(id) {
			continue
		}
		for _, v := range es.base().RuleStances(id) {
			if promptModeStops(promptModeFloor(v)) {
				return true
			}
		}
	}
	return false
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

// buildProjectEngine reads + parses + merges a project root's TWO
// per-project layers against the SNAPSHOT's org+user layers WITHOUT
// mutating the snapshot — the caller caches the result under pmu. The
// layers, in fold order:
//
//   - the in-repo <root>/.observer/guard-policy.toml (layerProject) —
//     agent-writable, escalate-only, git-shareable (unchanged);
//   - the trusted <trusted_project_dir>/<hash>.toml (layerTrustedProject)
//     — dashboard-authored, R-160-protected, weaken/disable-allowed but
//     never below the org floor. Its `disable` list unions into the
//     per-project engine's Config.Disabled inside buildEngine.
//
// It returns one PolicyState per successfully-loaded layer (0, 1 or 2).
// loaded=false (with the snapshot's base engine, states=nil) covers every
// degrade path (no files, read error, parse error, engine-build error),
// each recording an issue. A parse error on ONE layer drops that layer's
// contribution but the other layer still loads; only an engine-build
// failure of the merged result drops both.
//
// named is the rule-ID set the folded org layer names when org project
// envelopes loaded (nil otherwise): the root's org lock blast radius.
func (g *Guard) buildProjectEngine(es *engineSet, projectRoot, checkout string) projectBuild {
	// In-repo project layer (escalate-only): the main checkout's file and,
	// for a known checkout, that checkout's own (checkoutPolicyPaths, lane
	// LEFT-SHARED), else each linked worktree's own (ProjectPolicyPaths,
	// lane shr-worktree2); a copy identical to one already read counts once.
	inRepoFiles, inRepoStates := g.readInRepoPolicyFiles(checkoutPolicyPaths(g.cfg, projectRoot, checkout))

	// Trusted daemon-local project layer (weaken/disable-allowed,
	// org-floor-respected).
	trustedPath := TrustedProjectPolicyPath(g.cfg, g.home, projectRoot)
	var trusted *policyFile
	var trustedStates []PolicyState
	if trustedPath != "" {
		raw, err := g.readFile(trustedPath)
		switch {
		case os.IsNotExist(err):
			// no trusted project policy — the common case
		case err != nil:
			g.recordIssues([]string{fmt.Sprintf("trusted project policy %s: %v", trustedPath, err)})
		default:
			pf, perr := parsePolicyFile(raw, layerTrustedProject)
			if perr != nil {
				g.recordIssues([]string{fmt.Sprintf("trusted project policy %s: %v", trustedPath, perr)})
			} else {
				trusted = pf
				trustedStates = append(trustedStates, PolicyState{Layer: layerTrustedProject, Path: trustedPath, ContentHash: sha256hex(raw)})
			}
		}
	}

	// The org project layer: the envelopes of the projects this root matched
	// in the org-signed mapping, folded into the org layer escalate-only.
	om := g.orgProjectLayers(es, projectRoot)
	projectLayers, projectStates := om.layers, om.states
	org := es.orgLayer
	if len(projectLayers) > 0 {
		var issues []string
		org, issues = withOrgProjectLayers(es.orgLayer, projectLayers)
		g.recordIssues(issues)
	}

	// An in-repo file may only tune a rule this engine loads: an override
	// naming any other id (an old branch, a typo, or an agent writing a
	// worktree's file) is dropped with an issue naming the file and the
	// rule, so it can never fail the whole build (audit finding 1, lane
	// shr-worktree2).
	targets := inRepoOverrideTargets(g.packRules, effectiveConfigDisable(org, g.cfg.Rules.Disable), org, es.userLayer, trusted, inRepoFiles)
	for i := range inRepoFiles {
		var issues []string
		inRepoFiles[i], issues = dropUnloadedInRepoOverrides(inRepoFiles[i], inRepoStates[i].Path, targets)
		g.recordIssues(issues)
	}
	inRepo := foldInRepoPolicyFiles(inRepoFiles)

	if inRepo == nil && trusted == nil && len(projectLayers) == 0 {
		return projectBuild{eng: es.base(), org: om}
	}

	built, err := g.buildEngine(es.mode, org, es.userLayer, inRepo, trusted)
	if err != nil {
		// A linked worktree's file must never cost the project its own
		// policy: rebuild with the main checkout's file, the trusted layer
		// and the org project sections before any fallback to the bare
		// base engine.
		mainPath := ProjectPolicyPath(g.cfg, projectRoot)
		var mainFiles []*policyFile
		var mainStates []PolicyState
		for i := range inRepoFiles {
			if inRepoStates[i].Path == mainPath {
				mainFiles = append(mainFiles, inRepoFiles[i])
				mainStates = append(mainStates, inRepoStates[i])
			}
		}
		if len(mainFiles) < len(inRepoFiles) {
			g.recordIssues([]string{fmt.Sprintf("linked worktree policy files for %s dropped: %v", projectRoot, err)})
			inRepo, inRepoStates = foldInRepoPolicyFiles(mainFiles), mainStates
			if inRepo == nil && trusted == nil && len(projectLayers) == 0 {
				return projectBuild{eng: es.base(), org: om}
			}
			built, err = g.buildEngine(es.mode, org, es.userLayer, inRepo, trusted)
		}
	}
	states := make([]PolicyState, 0, len(inRepoStates)+len(trustedStates)+len(projectStates))
	states = append(states, inRepoStates...)
	states = append(states, trustedStates...)
	if len(projectLayers) > 0 {
		states = append(states, projectStates...)
	}
	if err != nil {
		g.recordIssues([]string{fmt.Sprintf("project policy for %s dropped: %v", projectRoot, err)})
		if len(projectLayers) > 0 && om.unknown == "" {
			// The matched project's sections could not be applied: its
			// layer is unknown here, never "nothing to load" (PR14).
			om.unknown = projectUnknownUnloadable
		}
		return projectBuild{eng: es.base(), org: om}
	}
	var named map[string]bool
	if len(projectLayers) > 0 {
		named = namedRuleIDs(org)
	}
	cats := make(map[string]policy.Category)
	for _, pl := range projectLayers {
		for i := range pl.rules {
			cats[pl.rules[i].ID] = pl.rules[i].Category
		}
	}
	if inRepo != nil {
		for i := range inRepo.rules {
			cats[inRepo.rules[i].ID] = inRepo.rules[i].Category
		}
	}
	if trusted != nil {
		for i := range trusted.rules {
			cats[trusted.rules[i].ID] = trusted.rules[i].Category
		}
	}
	return projectBuild{eng: built, states: states, cats: cats, named: named, loaded: true, org: om}
}

// readInRepoPolicyFiles reads and parses the in-repo policy files at paths,
// in order, with one state per file loaded; a missing file is the common
// case, a read or parse error records an issue and skips the file, and a
// copy identical to one already read counts once.
func (g *Guard) readInRepoPolicyFiles(paths []string) ([]*policyFile, []PolicyState) {
	var files []*policyFile
	var states []PolicyState
	seen := map[string]bool{}
	for _, path := range paths {
		raw, err := g.readFile(path)
		switch {
		case os.IsNotExist(err):
			// no in-repo project policy, the common case
		case err != nil:
			g.recordIssues([]string{fmt.Sprintf("project policy %s: %v", path, err)})
		case seen[sha256hex(raw)]:
			// the same file as another checkout's
		default:
			pf, perr := parsePolicyFile(raw, layerProject)
			if perr != nil {
				g.recordIssues([]string{fmt.Sprintf("project policy %s: %v", path, perr)})
			} else {
				seen[sha256hex(raw)] = true
				files = append(files, pf)
				states = append(states, PolicyState{Layer: layerProject, Path: path, ContentHash: sha256hex(raw)})
			}
		}
	}
	return files, states
}

// projectBuild is buildProjectEngine's result: the engine, the layer states
// and rule categories it loaded (loaded=false on every degrade path, with
// the base engine), the org lock's blast radius inside the root (named), and
// the root's org project match (org).
type projectBuild struct {
	eng    *policy.Engine
	states []PolicyState
	cats   map[string]policy.Category
	named  map[string]bool
	loaded bool
	org    orgProjectMatch
}

// projectRecheckEvery bounds how often a long-lived guard re-reads a cached
// root's match record (and its envelopes) to notice a match change without a
// new bundle. A hook process evaluates once and never re-checks. A variable
// so tests can set it to zero.
var projectRecheckEvery = 2 * time.Second

// projectRecheckDue reports, under pmu, whether a cached root's org project
// match is due its re-check (at most once per projectRecheckEvery; claiming
// it stamps the check time) and the key its engine was built for. The caller
// recomputes the key from the record, the mapping and the envelope files
// OUTSIDE the lock. A root built while the org project layer was not in
// force has no key and is never due.
func (es *engineSet) projectRecheckDue(ek string) (string, bool) {
	key, ok := es.projectMatchKey[ek]
	if !ok {
		return "", false
	}
	now := time.Now()
	if now.Sub(es.projectCheckedAt[ek]) < projectRecheckEvery {
		return "", false
	}
	es.projectCheckedAt[ek] = now
	return key, true
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
	pf, st, issue, cause, loaded := g.parseOrgBundleCause(g.orgBundlePath, g.orgKeyPinHash)
	if !loaded {
		if issue == "" && g.missingBundleIsTamper(g.set.Load()) {
			// A deleted bundle on a node that accepted one (T-864 gap 1):
			// the same fail-safe as an edited one. The running org layer
			// (or the last verified copy it came from) stays in force;
			// nothing is downgraded, and the tamper is recorded.
			issue, cause = orgBundleMissingIssue(g.orgBundlePath), bundleCauseMissing
		}
		if issue != "" {
			// The live engine is untouched, so the issue says it keeps the
			// org layer it holds (T-877).
			issue += " - " + g.orgLayerOutcome(liveOrgVersion(g.set.Load()))
			g.recordIssues([]string{issue})
			g.orgBundleRejected.Store(true)
			g.orgBundleTampered.Store(true)
			g.orgBundleCause.Store(int32(cause))
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
			g.clearOrgBundleTamper()
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
	base, err := g.buildEngine(cur.mode, pf, cur.userLayer, nil, nil)
	if err != nil {
		return fmt.Errorf("guard.ReloadOrgLayer: build engine: %w", err)
	}

	// Recompute the immutable layer state: replace the org entry, keep
	// the user entry; the project cache resets (rebuilds lazily against
	// the new org layer).
	g.clearOrgBundleTamper()
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
