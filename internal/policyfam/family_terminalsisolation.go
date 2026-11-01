//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package policyfam

import "github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"

// family_terminalsisolation.go links the sandbox module's terminals.isolation
// compiler (internal/policyfam/terminalsisolation, sandbox plan v2 section
// 8.2, D-752 Q41) through the linked-family seam (linked.go). It is owned by
// terminals.sandbox: a build with -tags sbo_omit_terminals_sandbox (or one
// omitting what the module requires, isolation or terminals) leaves it out,
// and every terminals.isolation body then NACKs with ErrFamilyNotLinked. The
// build line matches the node's floor holder
// (cmd/observer/sandbox_posture_wire.go), so no build links the compiler
// without the code that applies the floors.
//
// Enforces is true: a floor changes what the node may launch the moment it
// is accepted, so it needs the node's preauthorize_enforce consent exactly
// like node.features' sandbox_required. There is no CheckPosture leg: every
// floor only removes candidates (the compiler refuses every widening value),
// and a floor no backend here meets refuses the launch rather than running
// it weaker, so a floor cannot loosen a node's posture.

func init() {
	RegisterLinkedFamily(terminalsisolation.Family, LinkedFamily{
		Compile: func(raw []byte, maxBytes int64) (any, []byte, error) {
			s, canon, err := terminalsisolation.CompileBody(raw, maxBytes)
			if err != nil {
				return nil, nil, err
			}
			return s, canon, nil
		},
		Enforces: func(any) bool { return true },
		RequiredCapabilities: func(spec any) []string {
			return terminalsisolation.RequiredCapabilities(spec.(terminalsisolation.PolicySpec)) //nolint:forcetypeassert // caller contract: spec came from CompileFamilyBody(family, ...)
		},
		LiveCapabilities: terminalsisolation.LiveCapabilities,
		// The sandbox module owns the family: a node whose [components]
		// leaves it inactive advertises none of these tokens.
		Owner: "terminals.sandbox",
		LintWarnings: func(spec any) []string {
			s := spec.(terminalsisolation.PolicySpec) //nolint:forcetypeassert // caller contract
			rows := terminalsisolation.RegistryRows()
			out := terminalsisolation.RemoteOnlyWarnings(s, rows)
			// Plan 11.5: each OS against the rows this release offers.
			out = append(out, terminalsisolation.UnmetLocallyWarnings(s, rows)...)
			if s.InForce() {
				// D-753 Q43: the delivery projects sandbox_required onto
				// node.features for every managed member while a floor is in
				// force (internal/orgserver/policyresource_isolation.go).
				out = append(out, "managed nodes also receive \"Require a sandboxed terminal\" while any floor is in force; a managed node without the sandbox module then refuses new terminals")
			}
			return out
		},
	})
}
