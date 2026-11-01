package cortexcode

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	conformtest.AgreesWithTable(t, []string{models.ToolCortexCode}, func(native string) string {
		return actionMap[normalizeToolKey(native)]
	})
}

// TestPrivateActionMapIsSubsetOfTooltax is the CLASSIFIER to TABLE direction.
func TestPrivateActionMapIsSubsetOfTooltax(t *testing.T) {
	conformtest.MapIsSubset(t, models.ToolCortexCode, actionMap)
}
