package main

import (
	"errors"
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/termcore"
)

// terminal_launch_policy.go is the agent half of the [terminal.launch]
// policy in a file with no build tag, so a launch outside the terminals
// module (Agent Arena's admission, OSH-R-004) applies it in every build
// without linking the terminals packages (termcore is core).

// terminalAllowFreshAgent is the fresh-agent switch: [terminal].enabled
// gates the terminal-wide surface, so it needs both it and
// [terminal.launch].allow_fresh_agent (terminalLaunchPolicy reads it too).
func terminalAllowFreshAgent(tc config.TerminalConfig) bool {
	return tc.Enabled && tc.Launch.AllowFreshAgent
}

// arenaAgentPolicy is the [terminal.launch] policy an Arena process answers
// to (ruling P-203): only the agent keys this node actually set (a file, an
// env override or a verified governance pin; config.TerminalLaunchKeys).
// The shipped defaults (allow_fresh_agent false, empty lists) would refuse
// every Arena run on a node that never configured terminals, so an unset
// key is not checked and such a node runs Arena as before.
func arenaAgentPolicy(cfg config.Config) termcore.AgentPolicy {
	set, tc := cfg.TerminalLaunchSet, cfg.Terminal
	return termcore.AgentPolicy{
		CheckFresh: set.AllowFreshAgent, AllowFresh: terminalAllowFreshAgent(tc),
		CheckTools: set.AllowedTools, Tools: tc.Launch.AllowedTools,
		CheckRoots: set.AllowedProjectRoots, Roots: tc.Launch.AllowedProjectRoots,
	}
}

// arenaPolicyKeys names the setting behind each refusal of the agent
// authorization, so an Arena refusal says which key to change.
var arenaPolicyKeys = []struct {
	err error
	key string
}{
	{termcore.ErrFreshLaunchDisabled, "[terminal.launch].allow_fresh_agent"},
	{termcore.ErrToolNotAllowed, "[terminal.launch].allowed_tools"},
	{termcore.ErrProjectRootDenied, "[terminal.launch].allowed_project_roots"},
}

// authorizeArenaAgent applies arenaAgentPolicy to one Arena process of tool
// in projectRoot; a refusal names the setting.
func authorizeArenaAgent(cfg config.Config, tool, projectRoot string) error {
	_, err := arenaAgentPolicy(cfg).Authorize(tool, projectRoot)
	if err == nil {
		return nil
	}
	for _, row := range arenaPolicyKeys {
		if errors.Is(err, row.err) {
			return fmt.Errorf("arena: %w (refused by your %s setting, which Agent Arena follows like a New Terminal launch)", err, row.key)
		}
	}
	return fmt.Errorf("arena: %w", err)
}
