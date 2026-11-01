package main

import (
	"bytes"
	"slices"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/devcontainer"
)

// trust_conditions.go is the one seam through which the repository trust
// check reads its conditional rows (agentconfig TrustPathsWith; lane
// SBX-P3B, N2), for EVERY trust surface: the launch gate (launch_trust.go),
// the dashboard trust review (repoTrustDashboardPaths, dashapi
// Options.RepoTrustPaths) and `observer security trust check` / `accept`
// (security_trust_cmd.go). A hook registered from init says whether its
// condition holds; repoTrustConditional turns the holding conditions into
// the path table and the devcontainer parser filtered to the fields
// agentconfig's devcontainerFields table reports under them.
//
// N2 ruling (P-108, lane SBX-P3D): initializeCommand runs on the host
// whenever any devcontainer tool opens the folder, so its row
// (TrustCondDevcontainerHost) holds wherever the trust check runs. Its hook
// lives in this always-built file and reads the file through the shared
// reader (internal/devcontainer), so a build without the container sandbox
// driver has the row too. The rest of the file's ignored fields stay
// container-active only (the oci driver's own hook,
// terminal_sandbox_oci_trust.go). Both rows add the `.devcontainer/`
// config-directory row (agentconfig compileTrustPaths), which therefore
// follows the same rule: a symlinked `.devcontainer/` decides which file a
// devcontainer tool reads initializeCommand from.

// repoTrustCondition is what a holding hook contributes.
type repoTrustCondition struct {
	cond agentconfig.TrustCondition
}

// repoTrustConditionHooks are the registered hooks, appended from init.
var repoTrustConditionHooks []func(cfg config.Config, snap componentstate.Snapshot) (repoTrustCondition, bool)

func init() {
	repoTrustConditionHooks = append(repoTrustConditionHooks, devcontainerHostTrustCondition)
}

// devcontainerHostTrustCondition holds while a devcontainerFields row names
// the host condition (the N2 ruling; reversing it is that one row).
func devcontainerHostTrustCondition(config.Config, componentstate.Snapshot) (repoTrustCondition, bool) {
	c := agentconfig.TrustCondDevcontainerHost
	return repoTrustCondition{cond: c}, agentconfig.DevcontainerConditionUsed(c)
}

// repoTrustConditional is the trust path table every trust surface reads
// and the devcontainer parser for its conditional rows: nil and nil (the
// default table) unless a registered condition holds.
func repoTrustConditional(cfg config.Config, snap componentstate.Snapshot) ([]agentconfig.TrustPath, func([]byte) ([]string, map[string]string, error)) {
	var conds []agentconfig.TrustCondition
	for _, h := range repoTrustConditionHooks {
		if c, ok := h(cfg, snap); ok && !slices.Contains(conds, c.cond) {
			conds = append(conds, c.cond)
		}
	}
	if len(conds) == 0 {
		return nil, nil
	}
	return agentconfig.TrustPathsWith(conds...), devcontainerFieldsFor(conds...)
}

// repoTrustDashboardPaths is the dashboard trust review's seam onto
// repoTrustConditional (dashapi Options.RepoTrustPaths): the config and
// component state are read on each call, so the review lists the rows a
// launch would decide on now.
func repoTrustDashboardPaths(configPath string) func() ([]agentconfig.TrustPath, func([]byte) ([]string, map[string]string, error)) {
	return func() ([]agentconfig.TrustPath, func([]byte) ([]string, map[string]string, error)) {
		cfg, err := config.Load(config.LoadOptions{GlobalPath: configPath})
		if err != nil {
			cfg = config.Default()
		}
		return repoTrustConditional(cfg, componentSnapshotForConfig(cfg))
	}
}

// devcontainerFields is the shared reader (internal/devcontainer, the one
// devcontainer.json reader the container driver adopts from too) in the
// trust check's shape.
func devcontainerFields(data []byte) ([]string, map[string]string, error) {
	f, err := devcontainer.ParseDevcontainer(data)
	return f.Ignored, f.IgnoredRaw, err
}

// devcontainerFieldsFor is the shared reader filtered to the fields the
// table reports under conds. A file the reader cannot read is reported (as
// one reason for the file) when every field is reported, or when its text
// names a field the conditions report; otherwise a file the devcontainer
// tools could not read either runs nothing worth a reason.
func devcontainerFieldsFor(conds ...agentconfig.TrustCondition) func([]byte) ([]string, map[string]string, error) {
	return func(data []byte) ([]string, map[string]string, error) {
		ignored, raw, err := devcontainerFields(data)
		if err != nil {
			named := agentconfig.DevcontainerFieldsNamed(conds...)
			if slices.Contains(named, "*") || slices.ContainsFunc(named, func(f string) bool { return bytes.Contains(data, []byte(f)) }) {
				return nil, nil, err
			}
			return nil, nil, nil
		}
		var out []string
		vals := map[string]string{}
		for _, f := range ignored {
			if agentconfig.DevcontainerFieldReported(f, conds...) {
				out = append(out, f)
				vals[f] = raw[f]
			}
		}
		return out, vals, nil
	}
}
