package termcore

import (
	"errors"
	"fmt"
)

// ErrFreshLaunchDisabled is the [terminal.launch].allow_fresh_agent refusal
// (re-exported by termsvc).
var ErrFreshLaunchDisabled = errors.New("termsvc: fresh-agent launch is disabled (set [terminal.launch].allow_fresh_agent)")

// ErrToolNotAllowed is the [terminal.launch].allowed_tools refusal
// (re-exported by termsvc).
var ErrToolNotAllowed = errors.New("termsvc: tool is not in the fresh-launch allow-list")

// AgentPolicy is the [terminal.launch] authorization of an AI agent launch
// with each check optional: a check whose Check flag is false is skipped.
// A dashboard agent launch checks all three (AuthorizeAgent); Agent Arena
// checks only the keys the node actually set (ruling P-203).
type AgentPolicy struct {
	CheckFresh bool
	AllowFresh bool
	CheckTools bool
	Tools      []string
	CheckRoots bool
	Roots      []string
}

// Authorize applies the checks p carries to one launch of tool in
// projectRoot, in the order fresh agents, tool allow-list, project root. It
// returns the canonical project root ("" when the root is not checked).
func (p AgentPolicy) Authorize(tool, projectRoot string) (string, error) {
	if p.CheckFresh && !p.AllowFresh {
		return "", ErrFreshLaunchDisabled
	}
	if p.CheckTools {
		allowed := false
		for _, t := range p.Tools {
			if t == tool {
				allowed = true
				break
			}
		}
		if !allowed {
			return "", fmt.Errorf("%w: %q", ErrToolNotAllowed, tool)
		}
	}
	if !p.CheckRoots {
		return "", nil
	}
	return ValidateProjectRoot(projectRoot, p.Roots)
}

// AuthorizeAgent is the full [terminal.launch] authorization of an AI agent
// launch a dashboard feature starts: fresh agents allowed, the tool on the
// allow-list, and projectRoot under an allowed root. It returns the
// canonical project root. termsvc's Policy.AuthorizeAgent (native resume)
// calls it.
func AuthorizeAgent(allowFresh bool, allowedTools, allowedRoots []string, tool, projectRoot string) (string, error) {
	return AgentPolicy{
		CheckFresh: true, AllowFresh: allowFresh,
		CheckTools: true, Tools: allowedTools,
		CheckRoots: true, Roots: allowedRoots,
	}.Authorize(tool, projectRoot)
}
