package autohand

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// TestPrivateActionMapIsSubsetOfTooltax is the CLASSIFIER to TABLE direction
// over the private actionMap (records.go).
func TestPrivateActionMapIsSubsetOfTooltax(t *testing.T) {
	conformtest.MapIsSubset(t, models.ToolAutohand, actionMap)
}

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction:
// every autohand row in internal/tooltax resolves the same through
// classifyTool, including its git_ / browser_ prefix rules.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	conformtest.AgreesWithTable(t, []string{models.ToolAutohand}, func(native string) string {
		if a := classifyTool(native); a != models.ActionUnknown {
			return a
		}
		return ""
	})
}
