package sandboxcred

import (
	"slices"
	"strings"
)

// boxenv.go decides a local run's box environment while its credential
// lane is open (tracker rows F-005 and F-010 A7, finding N3-A7): only the
// key variable of each provider the lane binds may enter the box, holding
// that provider's run sentinel; every other variable the credential table
// (each provider's CredEnv) classes as a credential is dropped, whether the
// tool row or the user's pass_env let it in, so the box never holds a real
// model key beside a sentinel. A variable the table does not class is kept
// as before.

// EnvAction is what happens to one box variable.
type EnvAction string

// The closed EnvAction vocabulary.
const (
	EnvKeep     EnvAction = "keep"
	EnvSentinel EnvAction = "sentinel"
	EnvDrop     EnvAction = "drop"
)

// IsCredentialEnv reports whether the credential table classes name as a
// variable carrying a model provider's credential.
func IsCredentialEnv(name string) bool { return CredEnvProvider(name) != "" }

// boxEnvRule is one row: when matches holds, the variable gets action.
type boxEnvRule struct {
	name    string
	matches func(bound []string, name string) bool
	action  EnvAction
}

// keyEnvOwner is the bound provider whose key variable name is ("" none).
func keyEnvOwner(bound []string, name string) string {
	for _, id := range bound {
		if p, ok := ProviderFor(id); ok && p.KeyEnv != "" && p.KeyEnv == name {
			return p.ID
		}
	}
	return ""
}

// boxEnvRules are walked top-down for each variable of the box env.
var boxEnvRules = []boxEnvRule{
	{"a bound provider's key variable", func(b []string, n string) bool { return keyEnvOwner(b, n) != "" }, EnvSentinel},
	{"another credential variable", func(_ []string, n string) bool { return IsCredentialEnv(n) }, EnvDrop},
}

// boxEnvActionSet is the action for variable name under the bound set.
func boxEnvActionSet(bound []string, name string) EnvAction {
	for _, r := range boxEnvRules {
		if r.matches(bound, name) {
			return r.action
		}
	}
	return EnvKeep
}

// BoxEnvAction is the action for variable name in the box env of a run
// whose lane injects for provider (an unknown provider injects nothing, so
// every classed variable is dropped).
func BoxEnvAction(provider, name string) EnvAction {
	return boxEnvActionSet([]string{provider}, name)
}

// BoxEnv applies BoxEnvAction to env (KEY=VALUE entries): the lane's key
// variable carries sentinel, every other classed variable is removed. It
// returns the new env and the names it dropped (names only, in env order,
// each once).
func BoxEnv(provider, sentinel string, env []string) ([]string, []string) {
	return BoxEnvSet(map[string]string{provider: sentinel}, env)
}

// BoxEnvSet is BoxEnv for a lane that binds several providers: sentinels
// maps each bound provider to its own run sentinel, and each bound
// provider's key variable carries that provider's sentinel only.
func BoxEnvSet(sentinels map[string]string, env []string) ([]string, []string) {
	bound := make([]string, 0, len(sentinels))
	for id, s := range sentinels {
		if s != "" {
			bound = append(bound, id)
		}
	}
	slices.Sort(bound)
	out := make([]string, 0, len(env))
	var dropped []string
	seen := map[string]bool{}
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		switch boxEnvActionSet(bound, name) {
		case EnvSentinel:
			out = append(out, name+"="+sentinels[keyEnvOwner(bound, name)])
		case EnvDrop:
			if !seen[name] {
				seen[name] = true
				dropped = append(dropped, name)
			}
		default:
			out = append(out, kv)
		}
	}
	return out, dropped
}
