//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation

package hook

import (
	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/sandbox"
)

// sandboxedChild reports whether THIS hook process is running inside a B9
// sandbox, read from the OBSERVER_SANDBOX marker its parent (the sandboxed
// `observer <verb>` child, itself inside the bwrap boundary) exported. Hooks
// are spawned by the AI tool ITSELF, inside the boundary, so they inherit the
// marker and this self-report is truthful; the proxy lane (the daemon,
// outside any boundary) never sets it, so proxy-sourced events stay
// unstamped (Sandboxed=false, an honest zero — spec §6 observability
// posture). sandbox.EnvMarker is the single owner of the wire constant.
// The marker is read through the hook context seam's host default
// (internal/hookctx): the pure event builders that ask take no context.
func sandboxedChild() bool {
	return hookctx.Process().Getenv(sandbox.EnvMarker) == "1"
}
