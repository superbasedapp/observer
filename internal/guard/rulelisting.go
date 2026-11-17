package guard

import (
	"encoding/json"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/projectmatch"
)

// RuleListing is THE rule list every listing surface reads (`observer guard
// rules`, GET /api/guard/rules, the dashboard's Security > Rules tab): the
// effective rules in force on every project (EffectiveRules: built-ins with
// overrides applied, disabled rules removed, the user and org layers' own
// rules with their source), then the rules the organization's project
// sections add, each with Source "org" and Project set to the org project id
// it is scoped to.
//
// A project rule is listed once per project that defines it, in the signed
// mapping's order; a project rule whose id the org-wide layer already defines
// is left out, as the project fold drops it (withOrgProjectLayers). An
// envelope that is missing or does not verify against the composed bundle in
// force contributes nothing here (`observer guard status` reports it as a
// load issue). Reading the listing records no load issue and builds no
// per-project engine.
func (g *Guard) RuleListing() []policy.RuleInfo {
	es := g.set.Load()
	out := es.base().RuleInfos()
	defined := make(map[string]bool, len(out))
	for _, r := range out {
		defined[r.ID] = true
	}
	return append(out, g.orgProjectRuleInfos(es, defined)...)
}

// orgProjectRuleInfos lists the rules of every org project section this node
// holds (one per project in the signed mapping), skipping ids in defined.
func (g *Guard) orgProjectRuleInfos(es *engineSet, defined map[string]bool) []policy.RuleInfo {
	composed, key, ok := es.orgProjectEnvelope()
	if !ok {
		return nil
	}
	layout := projectmatch.LayoutFor(g.orgBundlePath)
	raw, err := g.readFile(layout.MappingPath())
	if err != nil {
		return nil
	}
	mf, err := projectmatch.DecodeMappingFile(raw)
	if err != nil {
		return nil
	}
	var out []policy.RuleInfo
	for _, e := range mf.Mapping.Projects {
		_, envRaw, err := g.readOrgProjectEnvelope(e.OrgProjectID)
		if err != nil {
			continue
		}
		var env orgcontract.PolicyBundle
		if err := json.Unmarshal(envRaw, &env); err != nil {
			continue
		}
		if err := projectmatch.CheckEnvelope(env, composed, e.OrgProjectID, key); err != nil {
			continue
		}
		pf, err := parsePolicyFile([]byte(env.BundleTOML), layerOrg)
		if err != nil {
			continue
		}
		for _, info := range policy.RuleInfosOf(pf.rules) {
			if defined[info.ID] {
				continue
			}
			info.Source = policy.SourceOrg
			info.Project = e.OrgProjectID
			out = append(out, info)
		}
	}
	return out
}
