package main

import (
	"context"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// arenaBudgetAdmissionSeam binds Agent Arena process starts to the same cold
// managed-budget admission used by command launchers. Arena's active backend
// is not proven at this boundary, so managed hard budgets conservatively
// refuse the process before it starts.
//
// NO PROCESS EVIDENCE IS AVAILABLE HERE, and that is structural rather than an
// omission: the seam it is installed behind (internal/arena.Driver.Admission)
// carries a tool name and a proxy URL only, so this boundary stays the
// conservative outer check.
//
// Arena runs inside the daemon, so the walk is the daemon-started one
// (enforceDaemonStartedLaunch): the repository trust row checks the
// candidate's own worktree (the arena.LaunchTarget on the context,
// arenaAdmissionTarget), honours
// the accepts of the repository the worktree was made from, never asks on
// the daemon's stdin, and hands the checked marker to the process's own
// environment. The judge runs in the Arena engine's one stable scratch
// directory, emptied for every drive (arena.judgeInScratch), which is its
// launch target, with no source repository: never the daemon's working
// directory.
//
// Before the walk, the launch policy a dashboard terminal launch answers
// to (OSH-R-004, arenaLaunchPolicyAdmission): the org's tools.disallow and
// the [terminal.launch] keys this node set (ruling P-203). The walk itself
// carries the org's terminals decision (row terminals.feature) and the
// managed hard budget, so an Arena process meets every org mandate on every
// node. The dashboard asks the same checks before a run makes its worktrees
// (arenaPreflightSeam).
func arenaBudgetAdmissionSeam(configPath string) func(context.Context, string, string) error {
	return func(ctx context.Context, tool, _ string) error {
		if err := arenaLaunchPolicyAdmission(configPath, tool, arenaAdmissionProjectRoot(ctx), true); err != nil {
			return err
		}
		at := daemonLaunch{}
		dir, source, addEnv, ok := arenaAdmissionTarget(ctx)
		if ok {
			at.dir = dir
			if dir != "" {
				at.acceptDir = source
			}
		}
		env, err := enforceDaemonStartedLaunch(ctx, configPath, tool,
			budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}, at)
		if err != nil {
			return err
		}
		if ok {
			addEnv(env)
		}
		return nil
	}
}

// arenaLoadConfig loads the daemon config an Arena admission reads (a
// variable for tests).
var arenaLoadConfig = func(path string) (config.Config, error) {
	return config.Load(config.LoadOptions{GlobalPath: path})
}

// arenaLaunchPolicyAdmission is the launch policy of a dashboard terminal
// launch, asked for one Arena process (candidate, judge or merge judge) of
// tool in projectRoot: the org's node.features tools.disallow, then the
// [terminal.launch] keys this node set (authorizeArenaAgent). claim counts
// one use of a covering tool grant, for the process that starts the vendor
// binary (M3-10); the preflight only peeks. A config that cannot be loaded
// refuses (fail closed: the policy could deny).
func arenaLaunchPolicyAdmission(configPath, tool, projectRoot string, claim bool) error {
	cfg, err := arenaLoadConfig(configPath)
	if err != nil {
		return fmt.Errorf("arena: cannot read the launch policy: %w", err)
	}
	disallowed := refuseIfToolDisallowedPeekCfg
	if claim {
		disallowed = refuseIfToolDisallowedCfg
	}
	if err := disallowed(cfg, tool, nil); err != nil {
		return err
	}
	return authorizeArenaAgent(cfg, tool, projectRoot)
}

// arenaPreflightSeam is the dashboard's check of one Arena tool before a
// run makes its worktrees (ruling P-203): the launch policy above (peeking
// at a tool grant, never counting it) and the daemon-started gate walk in
// the project root (the terminals decision, repository trust, the managed
// hard budget), so a refusal names its setting before anything is created.
func arenaPreflightSeam(configPath string) func(context.Context, string, string) error {
	return func(ctx context.Context, tool, projectRoot string) error {
		if err := arenaLaunchPolicyAdmission(configPath, tool, projectRoot, false); err != nil {
			return err
		}
		_, err := enforceDaemonStartedLaunch(ctx, configPath, tool,
			budgetLaunchEvidence{Route: budgetLaunchRouteUnknown}, daemonLaunch{dir: projectRoot})
		return err
	}
}
