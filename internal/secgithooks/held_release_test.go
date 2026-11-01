package secgithooks

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// TestHeldRefusalLineGivesReleaseStep (SEC-GATE5 follow-up): the pre-push
// refusal no longer says that amending, rebasing or resetting and retrying
// releases the hold (the hold follows the reflog); it gives S-792's
// release step from the one constant.
func TestHeldRefusalLineGivesReleaseStep(t *testing.T) {
	for _, line := range []string{
		HeldRefusalLine(strings.Repeat("a", 40), "origin"),
		HeldRefusalLine("", "origin"),
	} {
		if !strings.Contains(line, secrules.PushReleaseStep) {
			t.Errorf("refusal %q does not give the release step", line)
		}
		if strings.Contains(line, "retry") {
			t.Errorf("refusal %q still says retry", line)
		}
	}
}
