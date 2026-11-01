package deepagents

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// classifyForTooltax runs the adapter's REAL private classifier over one
// native tool name (mapTool, parse.go: a switch on the lower-cased name).
func classifyForTooltax(native string) string {
	a, _ := mapTool(native, nil)
	return a
}

var tooltaxTools = []string{models.ToolDeepAgentsCode}

var (
	unclassifiedDomain = map[string]string{}
	missingTooltaxRows = map[string]string{}
)

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	conformtest.AgreesWithTable(t, tooltaxTools, classifyForTooltax)
}

// TestClassifierDomainIsSubsetOfTooltax is the CLASSIFIER to TABLE direction
// over the case labels of mapTool, extracted from source.
func TestClassifierDomainIsSubsetOfTooltax(t *testing.T) {
	conformtest.DomainIsSubset(t, conformtest.Domain{
		Dir: ".", Func: "mapTool", Tools: tooltaxTools, Classify: classifyForTooltax,
		Unclassified: unclassifiedDomain, Missing: missingTooltaxRows,
	})
}
