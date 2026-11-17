//go:build sbo_omit_security

package guard

import "github.com/marmutapp/superbased-observer/internal/policy"

// orgLintPack (see orgpack.go) in a build without the security component:
// no security pillar rows exist in this binary, so the org layer is linted
// against the built-ins only and OrgRuleCatalog is the built-in catalog.
// An S-7xx override is then refused as an unknown rule, the pre-CG-1
// behaviour, because no node built this way can evaluate one.
func orgLintPack() []policy.Rule { return nil }
