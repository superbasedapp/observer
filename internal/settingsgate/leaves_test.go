package settingsgate

import (
	"strings"

	"github.com/marmutapp/superbased-observer/internal/configschema"
)

func prefixHasLeaf(p string) bool {
	for _, l := range configschema.Leaves() {
		if l.Path == p || strings.HasPrefix(l.Path, p+".") {
			return true
		}
	}
	return false
}
