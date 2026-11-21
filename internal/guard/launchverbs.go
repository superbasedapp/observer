package guard

import (
	"slices"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// launchVerbsOnce caches the registry's launcher verbs: the registry is
// compiled in, so the list never changes while the process runs.
var launchVerbsOnce = sync.OnceValue(func() []string {
	var out []string
	for _, tool := range integration.Tools() {
		c, ok := integration.For(tool)
		if !ok || c.Handoff.Launch == nil || c.Handoff.Launch.Subcommand == "" {
			continue
		}
		out = append(out, c.Handoff.Launch.Subcommand)
	}
	slices.Sort(out)
	return slices.Compact(out)
})

// launchVerbsForPolicy is the R-168 launcher verb list (lane cli-2): every
// `observer <verb>` the integration registry declares a terminal launch
// for, its one owner. Rows that are no longer advertised keep their verb
// here, since the CLI may still run it.
func launchVerbsForPolicy() []string { return slices.Clone(launchVerbsOnce()) }
