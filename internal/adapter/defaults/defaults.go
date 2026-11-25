package defaults

import (
	"sort"

	"github.com/marmutapp/superbased-observer/internal/adapter"
)

// slot is one adapter's place in the canonical order.
type slot struct {
	order int
	build func() adapter.Adapter
}

// registered holds the slots the per-adapter files add from init().
var registered []slot

// register adds one adapter constructor at its canonical position. It is
// called only from init() of an adapter_<pkg>.go file.
func register(order int, build func() adapter.Adapter) {
	registered = append(registered, slot{order: order, build: build})
}

// Adapters returns the canonical set of session-file adapters compiled
// into this binary, with zero-value defaults, in canonical order. Callers
// that need runtime config apply it after this returns, through the
// optional capability interfaces in internal/adapter (HookDedupConfigurer,
// CaptureStartupPreparer, NativeToolClassifier) or, in an adapter-owned
// build-tagged file, by type-asserting them.
//
// Used by:
//   - cmd/observer/main.go::buildWatcher  (registers each into the
//     watcher Registry)
//   - cmd/observer/main.go::recognizesSessionFile  (composes a single
//     IsSessionFile predicate for the dashboard's health endpoint
//     orphan filter)
//   - internal/adapter/defaults/defaults_test.go  (invariants — every
//     adapter must require under-WatchPaths in its IsSessionFile, and
//     no two adapters' watch roots share a prefix)
func Adapters() []adapter.Adapter {
	slots := append([]slot(nil), registered...)
	sort.SliceStable(slots, func(i, j int) bool { return slots[i].order < slots[j].order })
	out := make([]adapter.Adapter, 0, len(slots))
	for _, s := range slots {
		out = append(out, s.build())
	}
	return out
}

// ByTool returns a fresh adapter for one registry tool id, and false when
// this binary was built without it (an omitted adapter package) or no
// adapter reports that name. Callers that need one adapter's parser (a
// backfill correction pass) use this instead of importing the adapter's
// package, so the package can leave the binary.
func ByTool(tool string) (adapter.Adapter, bool) {
	for _, a := range Adapters() {
		if a.Name() == tool {
			return a, true
		}
	}
	return nil, false
}
