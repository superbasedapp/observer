package proxyroute

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/cfgfmt"
	"github.com/marmutapp/superbased-observer/internal/credfile"
	"github.com/marmutapp/superbased-observer/internal/hostfile"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/platform/jetbrainshost"
)

// # Zed per-agent routes (surface-gap S-1, decision D8; live check LC27)
//
// Zed runs a registry-installed ACP agent (Claude Agent, Codex, OpenCode,
// ...) from its own download cache, so no Observer launcher, shim or shell
// env reaches it. Zed does pass per-agent environment from its settings:
// agent_servers.<agent id> is a tagged entry ({"type": "registry", "env":
// {...}} for a registry agent, {"type": "custom", "command": ..., "env":
// {...}} for a custom one; crates/settings_content/src/agent.rs
// CustomAgentServerSettings), and its env is applied last
// (crates/project/src/agent_server_store.rs, the audit's S-1 reading).
//
// RegisterZedAgent(agent) writes agent_servers.<agent>.env.<VAR> = the
// proxy URL in Zed's settings.json, where VAR is the env route of the
// Observer tool the ACP agent id maps to (jetbrainshost's grounded agent
// table, shared ACP registry ids, crossed with the tool's registry
// ProxyRoute EnvVar / Suffix) when that route is one unconditional env
// variable (singleEnvRoute): capability data, never a tool name. An
// absent entry is created as a registry entry, so the "type" tag Zed
// requires is always there. The edit is one member through
// internal/hostfile (JSONC kept, Zed's directory must exist, no link
// followed, a backup ring, an atomic write); a value already there that
// points somewhere other than a loopback proxy is refused without Force.
//
// BUILT AND SWITCHED OFF behind LC27 (the integration WriterKindHostRoute
// row for zed): whether an agent_servers env value reaches a
// registry-installed agent is exactly what LC27 checks. Unregister is never
// gated. Provenance recording and route maintenance join in the switch-on
// commit.

// ZedAgentRoute is one ACP agent Zed can host whose Observer tool has an
// env route.
type ZedAgentRoute struct {
	// Agent is the ACP registry agent id (the agent_servers key).
	Agent string
	// Tool is the Observer registry tool the agent runs.
	Tool string
	// EnvVar and Suffix are the tool's env route.
	EnvVar, Suffix string
}

// zedSettingsArtifact is Zed's user settings file.
const zedSettingsArtifact = "zed/user-settings"

// zedRouteGateTool is the integration rowless gate's tool for these routes.
const zedRouteGateTool = "zed"

// runLiveGatedHostRoutes lets this package's tests run the gated writer.
// Production code never sets it: switching it on is deleting the
// integration row.
var runLiveGatedHostRoutes = false

// zedRouteGOOS is the OS whose catalogue path Zed's settings resolve for
// (the running OS; tests pin it).
var zedRouteGOOS = func() string { return runtime.GOOS }

// ZedAgentRoutes lists the ACP agents with an env route, sorted by agent.
func ZedAgentRoutes() []ZedAgentRoute {
	var out []ZedAgentRoute
	for agent, tool := range jetbrainshost.ACPAgents() {
		c, ok := integration.For(tool)
		if !ok || !singleEnvRoute(c.Proxy) {
			continue
		}
		out = append(out, ZedAgentRoute{Agent: agent, Tool: tool, EnvVar: c.Proxy.EnvVar, Suffix: c.Proxy.Suffix})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Agent < out[j].Agent })
	return out
}

// singleEnvRoute reports whether a tool's route is one unconditional env
// variable, the only shape a host's per-agent env can carry: a route with a
// RouteGate (Copilot CLI's BYOK lane, which needs a key and a model and
// would break a signed-in session) or a config-content variable beside it
// (OpenCode's OPENCODE_CONFIG_CONTENT) is never written there.
func singleEnvRoute(p *integration.ProxyRoute) bool {
	return p != nil && strings.TrimSpace(p.EnvVar) != "" && p.Gate == nil && p.ConfigContentEnv == ""
}

// ZedAgentRouteGate returns the live checks the Zed agent routes wait on.
func ZedAgentRouteGate() integration.LiveGates {
	return integration.RowlessWriterGates(zedRouteGateTool, integration.WriterKindHostRoute)
}

// zedAgentRoute finds agent's route row.
func zedAgentRoute(agent string) (ZedAgentRoute, bool) {
	for _, r := range ZedAgentRoutes() {
		if r.Agent == agent {
			return r, true
		}
	}
	return ZedAgentRoute{}, false
}

// zedSettingsPath resolves Zed's settings.json on this machine.
func (r *Registrar) zedSettingsPath() (string, error) {
	got, err := agentconfig.ResolveArtifact(zedSettingsArtifact, agentconfig.PathEnv{GOOS: zedRouteGOOS(), Home: r.opts.HomeDir, Getenv: r.opts.Getenv})
	if err != nil {
		return "", fmt.Errorf("proxyroute: %w", err)
	}
	switch got.Status {
	case agentconfig.PathResolved:
		return filepath.Clean(filepath.FromSlash(strings.ReplaceAll(got.Path, `\`, "/"))), nil
	case agentconfig.PathRelocationUnresolved:
		return "", credfile.SafeErrorf("proxyroute: %s is set to a relative path, which Zed reads against its own working directory; nothing was written (set an absolute path)", got.RelocatedBy)
	}
	return "", nil
}

// zedRouteURL is the proxy URL for a route row.
func zedRouteURL(port int, row ZedAgentRoute) string {
	return fmt.Sprintf("http://127.0.0.1:%d%s", port, row.Suffix)
}

// RegisterZedAgent writes agent's env route into Zed's settings.json.
func (r *Registrar) RegisterZedAgent(agent string) RegistrationResult {
	tool := "zed-acp/" + agent
	row, ok := zedAgentRoute(agent)
	if !ok {
		return RegistrationResult{Tool: tool, DryRun: r.opts.DryRun, Error: fmt.Errorf("proxyroute.RegisterZedAgent: %q is not an ACP agent with an env route", agent)}
	}
	want := zedRouteURL(r.opts.ProxyPort, row)
	res := RegistrationResult{Tool: tool, BaseURL: want, DryRun: r.opts.DryRun}
	if g := ZedAgentRouteGate(); g.Waiting() && !runLiveGatedHostRoutes {
		res.ConfigMissing = true
		res.SkipReason = LiveGateSkipPrefix + g.Text()
		return res
	}
	path, err := r.zedSettingsPath()
	if err != nil || path == "" {
		res.Error = err
		res.ConfigMissing = err == nil
		return res
	}
	res.ConfigPath = path
	entryKey := []string{"agent_servers", agent}
	entry, found, err := hostfile.Value(path, cfgfmt.FormatJSONC, entryKey)
	switch {
	case isNoHostDir(err):
		res.ConfigMissing = true
		return res
	case errors.Is(err, hostfile.ErrLink):
		// The hostfile error names the linked component (FU-198).
		res.ConfigMissing = true
		res.SkipReason = "not written: " + err.Error()
		return res
	case err != nil:
		res.Error = err
		return res
	}
	edit := hostfile.Edit{Path: path, Format: cfgfmt.FormatJSONC, DryRun: r.opts.DryRun, NoBackup: true}
	if !found {
		edit.Member = entryKey
		edit.Value = map[string]any{"type": "registry", "env": map[string]any{row.EnvVar: want}}
	} else {
		m, isMap := entry.(map[string]any)
		if !isMap {
			res.Error = credfile.SafeErrorf("proxyroute: agent_servers.%s in %s is not an object; nothing was written", agent, path)
			return res
		}
		env, _ := m["env"].(map[string]any)
		// The same three rules as RegisterClaudeCode: exactly ours is
		// AlreadySet, another loopback proxy (another observer install, or
		// this one before a port move) is kept unless --force repoints it,
		// anything else needs --force.
		if have, ok := env[row.EnvVar].(string); ok && have != "" {
			switch {
			case have == want:
				res.AlreadySet = true
				return res
			case IsObserverBaseURL(have) && !r.opts.Force:
				res.AlreadySet = true
				res.BaseURL = have
				return res
			case !r.opts.Force:
				res.Error = credfile.SafeErrorf("proxyroute: agent_servers.%s.env.%s in %s points somewhere else; pass --force to overwrite", agent, row.EnvVar, path)
				return res
			}
		}
		edit.Member = append(append([]string(nil), entryKey...), "env", row.EnvVar)
		edit.Value = want
	}
	out, err := hostfile.Apply(edit)
	if err != nil {
		res.Error = err
		return res
	}
	res.Added = out.Changed
	res.AlreadySet = !out.Changed
	return res
}

// UnregisterZedAgent removes agent's env route when it is this install's
// own value (a loopback URL on this registrar's proxy port, the rule of
// isOwnClaudeBaseURL), leaving a user's own local gateway on another port
// alone. Only the env member goes: the agent_servers entry stays even when
// Observer created it, because nothing records that it did. Never gated.
func (r *Registrar) UnregisterZedAgent(agent string) RegistrationResult {
	tool := "zed-acp/" + agent
	res := RegistrationResult{Tool: tool, DryRun: r.opts.DryRun}
	row, ok := zedAgentRoute(agent)
	if !ok {
		res.Error = fmt.Errorf("proxyroute.UnregisterZedAgent: %q is not an ACP agent with an env route", agent)
		return res
	}
	path, err := r.zedSettingsPath()
	if err != nil || path == "" {
		res.Error = err
		res.ConfigMissing = err == nil
		return res
	}
	res.ConfigPath = path
	member := []string{"agent_servers", agent, "env", row.EnvVar}
	have, found, err := hostfile.Value(path, cfgfmt.FormatJSONC, member)
	if err != nil {
		res.ConfigMissing = isNoHostDir(err) || errors.Is(err, hostfile.ErrLink)
		if errors.Is(err, hostfile.ErrLink) {
			// Say why nothing was removed, naming the linked component.
			res.SkipReason = "nothing removed: " + err.Error()
		}
		if !res.ConfigMissing {
			res.Error = err
		}
		return res
	}
	if s, _ := have.(string); !found || !isOwnClaudeBaseURL(strings.TrimSuffix(s, row.Suffix), r.opts.ProxyPort) {
		res.ConfigMissing = true
		return res
	}
	out, err := hostfile.Apply(hostfile.Edit{Path: path, Format: cfgfmt.FormatJSONC, Member: member, Remove: true, DryRun: r.opts.DryRun, NoBackup: true})
	if err != nil {
		res.Error = err
		return res
	}
	res.Added = out.Changed
	return res
}

// isNoHostDir reports the hostfile refusal of a missing host directory.
func isNoHostDir(err error) bool {
	return errors.Is(err, hostfile.ErrNoHostDir)
}
