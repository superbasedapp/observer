//go:build !sbo_omit_security

package guard

import (
	"sync"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// orgLintPack (see orgpack.go) in a build that carries the security
// component: the full security pillar pack, composed once with every
// component on. A composition error is a build defect (secrules' own tests
// pin it); lint then runs without the pack, which refuses the S- overrides
// loudly rather than accepting them unchecked.
var orgLintPack = sync.OnceValue(func() []policy.Rule {
	c, err := secrules.Compose(func(string) bool { return true })
	if err != nil {
		return nil
	}
	return c.Rules
})
