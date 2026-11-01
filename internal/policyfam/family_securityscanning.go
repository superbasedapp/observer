//go:build !sbo_omit_security && !sbo_omit_org_security

package policyfam

import (
	"errors"

	"github.com/marmutapp/superbased-observer/internal/policyfam/securityscanning"
)

var errNotSecurityScanningSpec = errors.New("policyfam: not a security.scanning spec")

// family_securityscanning.go links the security.scanning compiler (the
// security module's scanner floors, internal/policyfam/securityscanning;
// security plan 4.9, lane SEC-E) through the linked-family seam (linked.go),
// the second user of the seam after family_mcpaccess.go. It is owned by the
// node component `security` and the server component `org.security`: a build
// with -tags sbo_omit_security or sbo_omit_org_security leaves it out, and
// every body of the family then answers ErrFamilyNotLinked (a publish is
// refused, an accepting node NACKs with a named reason).
//
// It registers exactly once; a second registration anywhere makes the family
// a conflict (LinkedConflicts), pinned by securityscanning_inbuild_test.go.

func init() {
	RegisterLinkedFamily(securityscanning.Family, LinkedFamily{
		Compile: func(raw []byte, maxBytes int64) (any, []byte, error) {
			s, canon, err := securityscanning.CompileBody(raw, maxBytes)
			if err != nil {
				return nil, nil, err
			}
			return s, canon, nil
		},
		// A spec of another type is a caller bug; every leg answers it the
		// conservative way (needs consent, refused) rather than panicking.
		Enforces: func(spec any) bool {
			s, ok := spec.(securityscanning.PolicySpec)
			return !ok || securityscanning.Enforces(s)
		},
		RequiredCapabilities: func(spec any) []string {
			s, ok := spec.(securityscanning.PolicySpec)
			if !ok {
				return nil
			}
			return securityscanning.RequiredCapabilities(s)
		},
		LiveCapabilities: securityscanning.LiveCapabilities,
		// The D-753 leg (lane SEC-E3): the children require.components
		// names, which the org server projects as node.components require
		// for a managed member.
		RequiredComponents: func(spec any) []string {
			s, ok := spec.(securityscanning.PolicySpec)
			if !ok {
				return nil
			}
			return securityscanning.RequiredComponents(s)
		},
		CheckPosture: func(spec any) (string, error) {
			s, ok := spec.(securityscanning.PolicySpec)
			if !ok {
				return "spec", errNotSecurityScanningSpec
			}
			return securityscanning.CheckPosture(s)
		},
	})
}
