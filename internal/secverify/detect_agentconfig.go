package secverify

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// agentConfigClass is how verify treats a changed agent configuration
// file of one kind.
type agentConfigClass struct {
	Severity   Severity
	Confidence Confidence
	Action     Action
	// What names the kind in the message ("hook configuration").
	What string
}

// agentConfigKinds maps internal/agentconfig's file kinds to a CI
// judgement. A file a coding agent loads from the repository and that can
// make it run commands or reach servers (hooks, MCP servers, settings,
// permissions) denies when a PR adds or changes it: this is the "planted
// agent config" of security plan 11.1 F1. Instruction-like files (rules,
// skills, agents, commands, instructions) can steer an agent but cannot run
// anything on their own, so they flag. Repository trust proper (risky keys,
// the digest rule, the two roots) is phase B's `repo_trust` detector.
var agentConfigKinds = map[agentconfig.FileKind]agentConfigClass{
	agentconfig.KindHooks:        {SeverityHigh, ConfidenceHigh, ActionDeny, "hook configuration"},
	agentconfig.KindMCP:          {SeverityHigh, ConfidenceHigh, ActionDeny, "MCP server configuration"},
	agentconfig.KindPermissions:  {SeverityHigh, ConfidenceHigh, ActionDeny, "permission configuration"},
	agentconfig.KindSettings:     {SeverityHigh, ConfidenceMedium, ActionDeny, "settings file"},
	agentconfig.KindInstructions: {SeverityLow, ConfidenceMedium, ActionFlag, "instruction file"},
	agentconfig.KindRule:         {SeverityLow, ConfidenceMedium, ActionFlag, "rule file"},
	agentconfig.KindSkill:        {SeverityMedium, ConfidenceMedium, ActionFlag, "skill file"},
	agentconfig.KindAgent:        {SeverityMedium, ConfidenceMedium, ActionFlag, "agent definition"},
	agentconfig.KindCommand:      {SeverityLow, ConfidenceMedium, ActionFlag, "command file"},
}

// agentConfigFlagOnly lists project paths that sit in the agent-config
// table but are routinely edited for reasons that have nothing to do with
// an agent, so a change there flags instead of denying. Each row carries
// its reason.
var agentConfigFlagOnly = map[string]string{
	// Editor settings; the terminal-profile rule was dropped by JSP-7, and
	// what an agent reads here is phase B's key-level check.
	".vscode/settings.json": "editor settings shared with every developer",
}

// projectGlob is one project-scope path of the agent-config table.
type projectGlob struct {
	glob  string
	kind  agentconfig.FileKind
	tools []string
}

var (
	projectGlobsOnce sync.Once
	projectGlobsList []projectGlob
)

// projectGlobs derives the project-relative globs from the agent-config
// file table (the one owner of which files a tool loads from a project):
// every project-scope row whose path starts with the <project> token.
func projectGlobs() []projectGlob {
	projectGlobsOnce.Do(func() {
		idx := map[string]int{}
		for _, f := range agentconfig.Files() {
			if f.Scope != agentconfig.ScopeProjectShared && f.Scope != agentconfig.ScopeProjectLocal {
				continue
			}
			if _, ok := agentConfigKinds[f.Kind]; !ok {
				continue
			}
			for _, p := range f.Paths.All() {
				rest, ok := strings.CutPrefix(p, "<project>/")
				if !ok {
					continue
				}
				rest = strings.TrimSuffix(rest, "/")
				if strings.HasSuffix(p, "/") {
					rest += "/**"
				}
				key := string(f.Kind) + "\x00" + rest
				if i, seen := idx[key]; seen {
					projectGlobsList[i].tools = appendUnique(projectGlobsList[i].tools, f.Tool)
					continue
				}
				idx[key] = len(projectGlobsList)
				projectGlobsList = append(projectGlobsList, projectGlob{glob: rest, kind: f.Kind, tools: []string{f.Tool}})
			}
		}
		// Execution-bearing kinds first, so a path two rows claim takes the
		// stricter class.
		sort.SliceStable(projectGlobsList, func(i, j int) bool {
			return kindRank(projectGlobsList[i].kind) < kindRank(projectGlobsList[j].kind)
		})
	})
	return projectGlobsList
}

func kindRank(k agentconfig.FileKind) int {
	if agentConfigKinds[k].Action == ActionDeny {
		return 0
	}
	return 1
}

func appendUnique(xs []string, x string) []string {
	for _, v := range xs {
		if v == x {
			return xs
		}
	}
	return append(xs, x)
}

// detectAgentConfig reports every added or changed file the agent-config
// table says a coding agent loads from the repository.
func detectAgentConfig(ctx context.Context, in Input) Result {
	cov := Coverage{Detector: "agent_config", Status: CoverageComplete}
	var out []Finding
	globs := projectGlobs()
	for _, f := range in.Files {
		if ctx.Err() != nil {
			cov.Status = CoverageFailed
			cov.Note = "cancelled before every file was read"
			break
		}
		cov.Files++
		if f.Status == StatusDeleted {
			continue
		}
		for _, g := range globs {
			if !matchGlob(g.glob, f.Path) {
				continue
			}
			c := agentConfigKinds[g.kind]
			act := c.Action
			if _, flagOnly := agentConfigFlagOnly[f.Path]; flagOnly && act == ActionDeny {
				act = ActionFlag
			}
			verb := "changes"
			if f.Status == StatusAdded {
				verb = "adds"
			}
			rule := "agent-config/" + string(g.kind)
			out = append(out, Finding{
				RuleID:        rule,
				Detector:      "agent_config",
				Category:      CategoryAgentConfig,
				Severity:      c.Severity,
				Confidence:    c.Confidence,
				Path:          f.Path,
				Message:       "This change " + verb + " a " + c.What + " that " + toolList(g.tools) + " loads from the repository. Review it before merge: it can change what a coding agent runs or reads.",
				Fingerprint:   fingerprint(rule, f.Path, 0),
				DefaultAction: act,
			})
			break
		}
	}
	return Result{Findings: out, Coverage: cov}
}

// toolList names up to three tools from the registry ids, then "and N
// more". The ids come from the agent-config table, never the repository.
func toolList(tools []string) string {
	ts := append([]string(nil), tools...)
	sort.Strings(ts)
	if len(ts) > 3 {
		return strings.Join(ts[:3], ", ") + " and " + strconv.Itoa(len(ts)-3) + " more"
	}
	return strings.Join(ts, ", ")
}
