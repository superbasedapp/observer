package intervention

import "github.com/marmutapp/superbased-observer/internal/integration"

// ClassifyInvocation classifies the first argument after an installed target
// against the registry's leading-argument declaration. Callers must pass
// present=false when there is no argument after the executable or interpreted
// entrypoint.
//
// The caller has already matched the exact installed executable or script
// identity, so classification is inverted for an ordinary dedicated surface:
// an argument the registry does not declare non-billable is that product's
// billable CLI. A prompt, an arbitrary flag, and an undeclared subcommand are
// therefore governed invocations; only a declared server/daemon or maintenance
// argument is InvocationNonCLI.
//
// Two shapes still abstain. A surface that declares RequireDeclaredCLI keeps
// the fail-closed contract, so an argument in neither declared set is
// unclassified. A contradictory declaration — the same argument named as both
// CLI and non-CLI — is unclassified rather than resolved by precedence.
func ClassifyInvocation(spec integration.InvocationSpec, leading string, present bool) InvocationClass {
	if !present {
		if spec.AllowNoArguments {
			return InvocationCLI
		}
		return InvocationUnclassified
	}
	cli := invocationStringIn(leading, spec.CLILeadingArguments)
	nonCLI := invocationStringIn(leading, spec.NonCLILeadingArguments)
	switch {
	case cli && nonCLI:
		return InvocationUnclassified
	case cli:
		return InvocationCLI
	case nonCLI:
		return InvocationNonCLI
	case spec.RequireDeclaredCLI:
		return InvocationUnclassified
	default:
		return InvocationCLI
	}
}

func invocationStringIn(value string, set []string) bool {
	for _, candidate := range set {
		if value == candidate {
			return true
		}
	}
	return false
}
