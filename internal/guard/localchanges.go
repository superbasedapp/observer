package guard

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guardrecipe"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
)

// LocalRuleChanges lists every rule change this machine makes for itself, as
// the organization sees it on the guard policy-state row (gen9,
// orgcontract.LocalRuleChange): the `[guard.rules] disable` list of cfg (the
// config as the hook path loads it now, so an edit made after the daemon
// started is what gets reported), the user policy file, and per project root
// in roots the repository's project policy file and the trusted per-project
// layer, plus every root the trusted per-project layer itself holds a file
// for (trustedProjectEntries), so a trusted change for a project the store
// has no session for yet is reported too. hashRoot names each project the way
// the push wire does (store.ProjectIdentityHash); a root it maps to "" is
// skipped.
//
// Each change says whether it loosens the rule and whether this machine
// applies it. Both come from the merge itself (mergeOutcomes, review finding
// 2, 2026-11-12): the report runs the same fold the engine build runs, over
// the live org layer (and, per project, the org project sections that match
// the root) and the managed-node lock, and reads what the fold did. A
// change loosens when it sits below the reference the merge judges it
// against at that point (the built-in decision raised by the org layer and
// by the layers folded before it), or writes `enforce = false`; a disable
// always loosens. A [[rule]] row is applied only when claimRuleIDs kept it
// (its id is not a built-in, pack or org id). A refused loosening is still a
// loosening, which is what raises the organization's local_weakening
// finding (orgcontract.LocalRuleLoosenings). It reads only ids, decisions
// and enforcement flags out of the files: no matcher, doc line or path
// leaves this function.
//
// The list is in a stable order (layer, project, rule id, kind) and capped
// at orgcontract.MaxLocalRuleChanges; truncated reports a cut list or a
// change left out because its rule id is not reportable.
func (g *Guard) LocalRuleChanges(cfg config.GuardConfig, roots []string, hashRoot func(string) string) (changes []orgcontract.LocalRuleChange, truncated bool) {
	es := g.set.Load()
	var org *policyFile
	if es != nil && es.orgApplies() {
		org = es.orgLayer
	}
	lock := g.managedLock()
	cfgDisable, _ := splitConfigDisable(lock, cfg.Rules.Disable)
	named := orgLayerIDs(org)
	var out []orgcontract.LocalRuleChange
	seen := map[string]bool{}
	for _, raw := range cfg.Rules.Disable {
		id := strings.TrimSpace(raw)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		// The config list never passes through the merge: policy.New keeps
		// an org-named and an integrity rule (OSH-R-014), and the
		// managed-node lock leaves its ids out of the list (configDisable).
		refused := named[id] || policy.IsIntegrityRuleID(id) || lock.locks(id)
		out = append(out, orgcontract.LocalRuleChange{
			RuleID: id, Layer: orgcontract.LocalRuleLayerMachine, Kind: orgcontract.LocalRuleKindDisable,
			Loosens: true, Applied: !refused,
		})
	}
	var user *policyFile
	if p := UserPolicyPath(cfg, g.home); p != "" {
		user, _, _ = g.readLayerWithRecipe(p, layerUser)
	}
	if user != nil {
		out = append(out, changesFromOutcomes(mergeOutcomes(g.packRules, cfgDisable, lock, org, user, nil, nil), layerUser, "")...)
	}
	trustedRoots, unmapped := g.trustedProjectEntries(cfg)
	doneRoot := map[string]bool{}
	doneTrusted := map[string]bool{}
	for _, root := range append(append([]string(nil), roots...), trustedRoots...) {
		h := ""
		if hashRoot != nil {
			h = hashRoot(root)
		}
		if root == "" || h == "" || doneRoot[h] {
			continue
		}
		doneRoot[h] = true
		doneTrusted[trustedRootHash(root)] = true
		var project, trusted *policyFile
		if p := ProjectPolicyPath(cfg, root); p != "" {
			project = g.readLocalPolicyFile(p, layerProject)
		}
		if p := TrustedProjectPolicyPath(cfg, g.home, root); p != "" {
			trusted, _, _ = g.readLayerWithRecipe(p, layerTrustedProject)
		}
		if project == nil && trusted == nil {
			continue
		}
		orgR := org
		if es != nil && es.orgProjectsInForce() {
			if layers := g.orgProjectLayers(es, root).layers; len(layers) > 0 {
				orgR, _ = withOrgProjectLayers(org, layers)
			}
		}
		outcomes := mergeOutcomes(g.packRules, cfgDisable, lock, orgR, user, project, trusted)
		out = append(out, changesFromOutcomes(outcomes, layerTrustedProject, h)...)
		out = append(out, changesFromOutcomes(outcomes, layerProject, h)...)
	}
	changes, truncated = capLocalRuleChanges(out)
	// A trusted file whose root nothing names (no root record, no recipe
	// header, no known project) is a change the report cannot place.
	for _, h := range unmapped {
		if !doneTrusted[h] {
			truncated = true
			break
		}
	}
	return changes, truncated
}

// localRuleLayerOf maps a merge layer to the wire's LocalRuleLayer.
var localRuleLayerOf = map[string]string{
	layerUser:           orgcontract.LocalRuleLayerUserFile,
	layerProject:        orgcontract.LocalRuleLayerProjectFile,
	layerTrustedProject: orgcontract.LocalRuleLayerTrustedProject,
}

// changesFromOutcomes turns the merge outcomes of one layer into wire rows.
// A trusted disable listed twice is reported once.
func changesFromOutcomes(outcomes []mergeOutcome, layer, projectHash string) []orgcontract.LocalRuleChange {
	wireLayer := localRuleLayerOf[layer]
	var out []orgcontract.LocalRuleChange
	seenDisable := map[string]bool{}
	for _, o := range outcomes {
		if o.layer != layer {
			continue
		}
		c := orgcontract.LocalRuleChange{
			RuleID: strings.TrimSpace(o.ruleID), Layer: wireLayer, Kind: o.kind,
			Loosens: o.loosens, Applied: o.applied, ProjectRootHash: projectHash,
		}
		switch o.kind {
		case mergeKindDisable:
			if c.RuleID == "" || seenDisable[c.RuleID] {
				continue
			}
			seenDisable[c.RuleID] = true
		case mergeKindRule:
			c.Observe, c.Enforce, c.Enforced = o.rule.Observe.String(), o.rule.Enforce.String(), o.rule.Enforced
		case mergeKindOverride:
			ov := o.override
			c.Enforced, c.EnforceOff = ov.Enforced, ov.EnforceOff
			if ov.HasDec {
				c.Observe, c.Enforce = ov.Decision.String(), ov.Decision.String()
			}
		}
		out = append(out, c)
	}
	return out
}

// TrustedProjectRootRecordPath is the root record beside one project's
// trusted policy file (<trusted_project_dir>/<hash>.root): the project root
// the hashed file name stands for, one line. The dashboard writes it with
// the trusted file so the trusted layer can name its own roots (the file
// name is a one-way hash); an applied project recipe records its root in its
// header instead. Empty when the trusted layer is off or the root is empty.
func TrustedProjectRootRecordPath(cfg config.GuardConfig, home, projectRoot string) string {
	p := TrustedProjectPolicyPath(cfg, home, projectRoot)
	if p == "" {
		return ""
	}
	return strings.TrimSuffix(p, ".toml") + trustedRootSuffix
}

// trustedRootSuffix marks a trusted-layer root record.
const trustedRootSuffix = ".root"

// trustedRootHash is the file-name hash of a trusted per-project file for
// root (TrustedProjectPolicyPath's own derivation).
func trustedRootHash(root string) string {
	return sha256hex([]byte(filepath.ToSlash(filepath.Clean(root))))
}

// trustedProjectEntries enumerates the trusted per-project layer's own
// files (review finding 10, 2026-11-12): roots are the project roots its
// files stand for, read from each file's root record or from its applied
// recipe's header and checked against the file name's hash; unmapped are
// the hashes of the files whose root neither names. Empty when the layer is
// not configured or the directory cannot be listed.
func (g *Guard) trustedProjectEntries(cfg config.GuardConfig) (roots, unmapped []string) {
	dir := expandUserPath(cfg.Rules.TrustedProjectDir, g.home)
	if dir == "" {
		return nil, nil
	}
	entries, err := g.readDir(dir)
	if err != nil {
		return nil, nil
	}
	hashes := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		base, ok := strings.CutSuffix(name, RecipeFileSuffix)
		if !ok {
			base, ok = strings.CutSuffix(name, ".toml")
		}
		if ok && trustedHashRe.MatchString(base) {
			hashes[base] = true
		}
	}
	keys := make([]string, 0, len(hashes))
	for h := range hashes {
		keys = append(keys, h)
	}
	sort.Strings(keys)
	for _, h := range keys {
		root := ""
		if raw, err := g.readFile(filepath.Join(dir, h+trustedRootSuffix)); err == nil {
			if r := strings.TrimSpace(string(raw)); r != "" && trustedRootHash(r) == h {
				root = r
			}
		}
		if root == "" {
			if raw, err := g.readFile(filepath.Join(dir, h+RecipeFileSuffix)); err == nil {
				if m, ok := guardrecipe.ParseMeta(raw); ok && m.ProjectRoot != "" && trustedRootHash(m.ProjectRoot) == h {
					root = m.ProjectRoot
				}
			}
		}
		if root == "" {
			unmapped = append(unmapped, h)
			continue
		}
		roots = append(roots, root)
	}
	return roots, unmapped
}

// trustedHashRe is the shape of a trusted per-project file name's hash.
var trustedHashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// readLocalPolicyFile reads and parses one policy file for the report; a
// missing or unparsable file contributes nothing (`observer guard status`
// reports a broken file, and a file the guard cannot parse changes no rule).
func (g *Guard) readLocalPolicyFile(path, layer string) *policyFile {
	raw, err := g.readFile(path)
	if err != nil {
		return nil
	}
	pf, err := parsePolicyFile(raw, layer)
	if err != nil {
		return nil
	}
	return pf
}

// capLocalRuleChanges drops the changes the wire refuses (a rule id outside
// the reportable shape), sorts the rest stably and cuts the list at the
// wire bound.
func capLocalRuleChanges(in []orgcontract.LocalRuleChange) ([]orgcontract.LocalRuleChange, bool) {
	truncated := false
	out := make([]orgcontract.LocalRuleChange, 0, len(in))
	for _, c := range in {
		if !c.Valid() {
			truncated = true
			continue
		}
		out = append(out, c)
	}
	sort.SliceStable(out, func(a, b int) bool {
		x, y := out[a], out[b]
		if localLayerRank[x.Layer] != localLayerRank[y.Layer] {
			return localLayerRank[x.Layer] < localLayerRank[y.Layer]
		}
		if x.ProjectRootHash != y.ProjectRootHash {
			return x.ProjectRootHash < y.ProjectRootHash
		}
		if x.RuleID != y.RuleID {
			return x.RuleID < y.RuleID
		}
		return x.Kind < y.Kind
	})
	if len(out) > orgcontract.MaxLocalRuleChanges {
		out, truncated = out[:orgcontract.MaxLocalRuleChanges], true
	}
	if len(out) == 0 {
		out = nil
	}
	return out, truncated
}

// localLayerRank orders the layers machine-wide first, then per project.
var localLayerRank = map[string]int{
	orgcontract.LocalRuleLayerMachine:        0,
	orgcontract.LocalRuleLayerUserFile:       1,
	orgcontract.LocalRuleLayerTrustedProject: 2,
	orgcontract.LocalRuleLayerProjectFile:    3,
}
