package main

import (
	"context"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launch_dotenv.go: a route the launcher sets in the environment that the
// tool itself overrides (surface-gap review CLI-7, lane w4-layers). A tool
// with the DotenvOverride capability (aider) loads .env files with override
// on, so an OPENAI_API_BASE in ~/.env, the project's .env or an --env-file
// replaces the launcher's value; its own config file's openai-api-base does
// the same. The launcher used to print "routing via" for such a launch.
//
// The decision is the effective-layer evaluator's (agentconfigsvc
// EffectiveLayers over the tool's families, with the launch environment the
// child gets): a route finding whose winner is not the launch environment
// means the turns bypass the proxy. An --env-file on argv is one more
// dotenv layer, read by key name only. No value is read into a message.
// Dispatches on the capability, never the tool name.

// launchRouteShadows returns the sources that outrank the launcher's route
// for this launch ("<file>: <key>"), empty when the route holds or the
// tool's capability declares no override. env is the child's environment;
// dir the launch directory ("" is the current one).
func launchRouteShadows(tool string, args []string, dir string, env []string) []string {
	c, ok := integration.For(tool)
	if !ok || c.Proxy == nil || c.Proxy.DotenvOverride == nil {
		return nil
	}
	d := *c.Proxy.DotenvOverride
	home, cwd := launchDirs()
	project := dir
	if project == "" {
		project = cwd
	}
	getenv := func(k string) string { v, _ := lookupEnvValue(env, k); return v }
	var out []string
	if project != "" {
		svc := agentconfigsvc.New(agentconfigsvc.Options{Home: home, GOOS: launchFiles.goos, Getenv: getenv, SystemRoot: launchFiles.systemRoot})
		rep, err := svc.EffectiveLayers(context.Background(), agentconfigsvc.LayerOptions{Projects: []string{project}, Tools: []string{tool}})
		if err == nil {
			for _, f := range rep.Findings {
				if f.Concern != agentconfig.ConcernRoute || f.Winning.Runtime == agentconfig.RuntimeLaunchEnv {
					continue
				}
				if f.Winning.Runtime == agentconfig.RuntimeDotenv {
					out = append(out, dotenvKeysIn(d.Files, d.Keys, home, project)...)
					continue
				}
				src := rep.Path(f)
				if src == "" {
					src = f.Winning.String()
				}
				out = append(out, src+": "+f.Key.String())
			}
		}
	}
	for _, p := range d.EnvFileArguments(args) {
		if !filepath.IsAbs(p) && project != "" {
			p = filepath.Join(project, p)
		}
		out = append(out, dotenvKeysIn([]string{p}, d.Keys, home, project)...)
	}
	return uniqueSorted(out)
}

func uniqueSorted(xs []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, x := range xs {
		if x != "" && !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	sort.Strings(out)
	return out
}

// routeShadowNotice is the launch line that replaces "routing via" when the
// tool's own files outrank the route (names and files only).
func routeShadowNotice(label string, shadows []string) string {
	return "observer " + label + ": not routed through the proxy unless these point at it: the tool loads its own base URL over the launcher's (" +
		strings.Join(shadows, "; ") + "); remove the key or point it at the proxy to route this launch"
}
