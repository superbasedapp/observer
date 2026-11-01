package dirac

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// classifierMap is the full enumerable private classifier: the native
// tool table plus the synthesized `respond.<operation>` names.
func classifierMap() map[string]string {
	m := make(map[string]string, len(actionMap)+len(respondActions))
	for k, v := range actionMap {
		m[k] = v
	}
	for k, v := range respondActions {
		m[k] = v
	}
	return m
}

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	m := classifierMap()
	conformtest.AgreesWithTable(t, []string{models.ToolDirac}, func(native string) string {
		return m[native]
	})
}

// TestPrivateActionMapIsSubsetOfTooltax is the CLASSIFIER to TABLE direction.
func TestPrivateActionMapIsSubsetOfTooltax(t *testing.T) {
	conformtest.MapIsSubset(t, models.ToolDirac, classifierMap())
}
