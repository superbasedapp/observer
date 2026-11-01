package ibmbob

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// classifyForTooltax runs the adapter's REAL private classifier over one
// native tool name. The classifier is mapTool (parse.go), a
// `switch strings.ToLower(strings.TrimSpace(name))`.
func classifyForTooltax(native string) string {
	a, _ := mapTool(native, nil)
	return a
}

// tooltaxTools lists the tool ids this adapter's classifier feeds.
var tooltaxTools = []string{models.ToolIBMBob}

// unclassifiedDomain freezes case labels that resolve to ActionUnknown, each
// labelled "deliberate: <why>" or "dead: <why>" (see conformtest.Domain).
var unclassifiedDomain = map[string]string{}

// missingTooltaxRows freezes case labels the classifier maps but tooltax has
// no tool-specific row for yet (see conformtest.Domain).
var missingTooltaxRows = map[string]string{}

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	conformtest.AgreesWithTable(t, tooltaxTools, classifyForTooltax)
}

// TestClassifierDomainIsSubsetOfTooltax is the CLASSIFIER to TABLE direction
// over the case labels of mapTool, extracted from source.
func TestClassifierDomainIsSubsetOfTooltax(t *testing.T) {
	conformtest.DomainIsSubset(t, conformtest.Domain{
		Dir:          ".",
		Func:         "mapTool",
		Tools:        tooltaxTools,
		Classify:     classifyForTooltax,
		Unclassified: unclassifiedDomain,
		Missing:      missingTooltaxRows,
	})
}
