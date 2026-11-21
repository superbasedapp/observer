//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
	"github.com/marmutapp/superbased-observer/internal/sandboxenv"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
)

// terminal_sandbox_env.go is every backend's one way to build a box's
// environment (WINFIX2 audit finding 1, ledger
// SBX-WIN-ENV-1): the launching environment through the allow-list of
// internal/sandboxenv, never the parent's minus a deny-list. A driver's
// env function (mxcBoxEnv, ociContainerEnv, vmRunEnv, landlockEnv,
// seatbeltAgentEnv, appleRunEnv, sandboxHostChildEnv) runs its input through
// sandboxBoxEnv first and then sets its own run variables;
// tests/invariant/sandbox_env_test.go fails when a driver hands
// os.Environ() to anything else.

// sandboxObserverEnv are Observer's own variables the daemon or the host
// helper set for a run that the launcher inside the box reads: the
// daemon-child marker, the trusted launcher channel (a driver whose box
// cannot hold the descriptor drops it again), the sandbox marker and tier,
// the allow-list names themselves, the repository trust handoff, the
// capture relay's descriptor and redial switch, and the run's inner log.
var sandboxObserverEnv = []string{
	envDaemonChild, envOOBFD, envOOBAuth, envOOBCorr, envOOBTool, envOOBRun,
	sandboxEnvMarker, sandbox.EnvEgress, sandboxenv.EnvAllow, sandboxenv.EnvPassed, sandboxenv.EnvSignInShared,
	repoTrustSourceEnv, repoTrustBenchmarkSourceEnv, repoTrustBenchmarkMarkerEnv, repoTrustCheckedEnv,
	relayEnvFD, hostedRelayRedialEnv, sandboxInnerLogEnv,
}

// sandboxBoxEnv is environ through the box allow-list for a box running
// goos ("windows", or "linux"/"darwin"): the OS table, the names the launch
// carried in sandboxenv.EnvAllow (the tool's provider variables and the
// user's pass_env) and Observer's own run variables, less any name in drop
// (sandboxenv.Spec.Drop). Nothing is added.
func sandboxBoxEnv(goos string, environ []string, drop ...string) []string {
	allow, _ := sandboxenv.Lookup(environ, goos, sandboxenv.EnvAllow)
	return sandboxenv.Filter(environ, sandboxenv.Spec{GOOS: goos, Extra: sandboxenv.Decode(allow), Observer: sandboxObserverEnv, Drop: drop})
}

// sandboxEnvAllowNames is what a launch of tool hands its box beyond the OS
// table: the tool row's ProviderEnv (a capability of the row, never the
// tool's name) and the user's [terminal.sandbox].pass_env.
func sandboxEnvAllowNames(tool string, pass []string) []string {
	var out []string
	if c, ok := integration.For(tool); ok {
		out = append(out, c.Sandbox.ProviderEnv...)
	}
	return append(out, pass...)
}

// withSandboxEnvAllow returns env with sandboxenv.EnvAllow naming allow and
// sandboxenv.EnvPassed naming pass, every inherited value of either removed
// first, so the developer's own environment can never widen a box through
// them. An empty list sets no variable.
func withSandboxEnvAllow(env, allow, pass []string) []string {
	out := make([]string, 0, len(env)+2)
	for _, kv := range env {
		if k := sandboxEnvKey(kv); k == sandboxenv.EnvAllow || k == sandboxenv.EnvPassed {
			continue
		}
		out = append(out, kv)
	}
	if v := sandboxenv.Encode(allow); v != "" {
		out = append(out, sandboxenv.EnvAllow+"="+v)
	}
	if v := sandboxenv.Encode(pass); v != "" {
		out = append(out, sandboxenv.EnvPassed+"="+v)
	}
	return out
}

// sandboxEnvKey is an entry's name (the text before the first '=').
func sandboxEnvKey(kv string) string {
	for i := 0; i < len(kv); i++ {
		if kv[i] == '=' {
			return kv[:i]
		}
	}
	return kv
}

// sandboxEnvNames are the names of env's entries.
func sandboxEnvNames(env []string) []string {
	out := make([]string, 0, len(env))
	for _, kv := range env {
		if k := sandboxEnvKey(kv); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// sandboxHostChildEnv is what the host helper of the bubblewrap and
// process_lite rows hands the layer it starts: the allow-list, then the tier
// from its own flags (withSandboxTier). bwrap is not given --clearenv; this
// filtered environment is the one it passes on, which is the same.
func sandboxHostChildEnv(environ []string, h sandbox.HostArgs) []string {
	return withSandboxTier(sandboxBoxEnv("linux", environ), h)
}

// sandboxLaunchEnv sets the allow-list names a dashboard launch's box gets:
// the Sandboxer's names (the tool's provider variables and pass_env), plus
// the names of the variables the daemon itself chose for this launch (a
// model selection's), which are Observer's, never inherited.
func sandboxLaunchEnv(env []string, req termsvc.LaunchRequest) []string {
	allow := append(append([]string(nil), req.SandboxEnvAllow...), sandboxEnvNames(req.ExtraEnv)...)
	return withSandboxSignInShared(withSandboxEnvAllow(env, allow, req.SandboxEnvPassed), req.SandboxSignInShared)
}

// withSandboxSignInShared returns env with sandboxenv.EnvSignInShared naming
// tool (operator ruling P-183), every inherited value removed first; an
// empty tool sets nothing.
func withSandboxSignInShared(env []string, tool string) []string {
	out := make([]string, 0, len(env)+1)
	for _, kv := range env {
		if sandboxEnvKey(kv) != sandboxenv.EnvSignInShared {
			out = append(out, kv)
		}
	}
	if tool != "" {
		out = append(out, sandboxenv.EnvSignInShared+"="+tool)
	}
	return out
}

// sandboxCLIPassEnvLabel is the CLI posture line's pass_env part: "" for
// none, else ", pass_env A,B".
func sandboxCLIPassEnvLabel(pass []string) string {
	if len(pass) == 0 {
		return ""
	}
	return ", pass_env " + strings.Join(pass, ",")
}
