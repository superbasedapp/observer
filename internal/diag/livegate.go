package diag

import (
	"fmt"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// checkLiveGatedWriters names every writer that is built but switched off
// until a live check passes (surface-gap decision DEC-12,
// integration.LiveGate), one line each in the shared wording "built,
// waiting on live check <id>". Informational: nothing is wrong on this
// node, the writers are simply not on yet.
func checkLiveGatedWriters() Check {
	gated := integration.LiveGatedWriters()
	if len(gated) == 0 {
		return Check{Name: "writers.live_gate", Status: StatusOK, Message: "no writer is waiting on a live check"}
	}
	details := make([]string, 0, len(gated))
	for _, g := range gated {
		line := fmt.Sprintf("%s %s writer: %s", g.Tool, g.Kind, g.Gate.Text())
		if g.Note != "" {
			line += " (" + g.Note + ")"
		}
		details = append(details, line)
	}
	return Check{
		Name: "writers.live_gate", Status: StatusOK,
		Message: fmt.Sprintf("%d writer(s) built, waiting on a live check; Observer does not run them yet", len(gated)),
		Details: details,
	}
}
