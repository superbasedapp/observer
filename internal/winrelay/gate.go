package winrelay

import "github.com/marmutapp/superbased-observer/internal/integration"

// Gate is the relay's live-check gates (surface-gap DEC-12): live checks LC6
// (pending tracker row WSL-2) and LC14, each a row of the integration
// registry's rowless gated writers (integration.WriterKindRelay), so the
// doctor's writers.live_gate list names them with every other gated
// writer. While any waits, `observer relay serve` refuses to start and the
// Windows route writer keeps pointing at the WSL proxy. Switching the relay
// on is deleting those rows once both checks pass.
func Gate() integration.LiveGates {
	return integration.RowlessWriterGates("claude-code", integration.WriterKindRelay)
}
