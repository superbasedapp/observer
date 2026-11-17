package guard

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// OrgLayerRuleListing is the rule list an org bundle yields over the whole
// catalog a node can evaluate, before any local layer: the built-in rules and
// every row of the full security pillar pack (OrgRuleCatalog), with the
// bundle's overrides applied and its own [[rule]] definitions added. A row's
// Source says where its decision comes from: "org" when the bundle defines or
// overrides it, otherwise the catalog's own source ("builtin", or
// "pack:security" for a Code security row).
//
// It is the org server's answer to "what does this developer's machine run
// from the organization's side" (the effective preview), built by the same
// merge and engine construction the org lint runs (lintParsed, layer org), so
// the preview cannot name a decision the node's org layer would not produce.
// What it cannot know is the node's own layers (the local [guard.rules]
// disable list, the user and project policy files, the trusted per-project
// layer): none of them reach the org server. An empty bundle yields the
// catalog alone.
//
// A bundle that does not parse or does not build an engine returns the
// error; the caller reports it rather than showing a catalog the node would
// not run.
func OrgLayerRuleListing(bundleTOML string) ([]policy.RuleInfo, error) {
	return OrgLayerRuleListingWithProjects(bundleTOML, nil)
}

// OrgLayerRuleListingWithProjects is OrgLayerRuleListing inside one project:
// the org project envelopes a node loads there (projectTOMLs, each an
// envelope's bundle body) fold into the org layer escalate-only, the way the
// node folds them (withOrgProjectLayers), before the listing. A rule a
// project section names reads Source "org" like one the org bundle names.
// An empty projectTOMLs is OrgLayerRuleListing.
func OrgLayerRuleListingWithProjects(bundleTOML string, projectTOMLs []string) ([]policy.RuleInfo, error) {
	var org *policyFile
	if strings.TrimSpace(bundleTOML) != "" {
		pf, err := parsePolicyFile([]byte(bundleTOML), layerOrg)
		if err != nil {
			return nil, err
		}
		org = pf
	}
	var projects []*policyFile
	for _, p := range projectTOMLs {
		if strings.TrimSpace(p) == "" {
			continue
		}
		pf, err := parsePolicyFile([]byte(p), layerOrg)
		if err != nil {
			return nil, err
		}
		projects = append(projects, pf)
	}
	if len(projects) > 0 {
		org, _ = withOrgProjectLayers(org, projects)
	}
	extra, overrides, _, _ := mergeLayersWithPack(orgLintPack(), org, nil, nil, nil)
	eng, err := policy.New(policy.Config{ExtraRules: extra, Overrides: overrides})
	if err != nil {
		return nil, err
	}
	return eng.RuleInfos(), nil
}
