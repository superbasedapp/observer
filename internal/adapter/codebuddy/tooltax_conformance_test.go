package codebuddy

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	conformtest.AgreesWithTable(t, []string{models.ToolCodeBuddy}, func(native string) string {
		a, _ := mapToolName(native)
		return a
	})
}

// TestPrivateActionMapIsSubsetOfTooltax is the CLASSIFIER to TABLE
// direction: every name the map classifies must exist in tooltax with the
// SAME action type.
func TestPrivateActionMapIsSubsetOfTooltax(t *testing.T) {
	conformtest.MapIsSubset(t, models.ToolCodeBuddy, actionMap)
}
