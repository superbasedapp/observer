package vtcode

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// classifyForTooltax runs the adapter's REAL private classifier over one
// native tool name. It is the single place the WP-T3 conformance pins below
// reach into the shipping code (the shared algorithm lives in
// internal/tooltax/conformtest).
//
// The classifier is mapVTCodeTool (tools.go).
func classifyForTooltax(native string) string {
	return mapVTCodeTool(native)
}

// tooltaxTools lists the tool ids this adapter's classifier feeds.
var tooltaxTools = []string{models.ToolVTCode}

// unclassifiedDomain freezes case labels that resolve to ActionUnknown, each
// labelled "deliberate: <why>" or "dead: <why>" (see conformtest.Domain).
var unclassifiedDomain = map[string]string{}

// missingTooltaxRows freezes case labels the classifier maps but tooltax has
// no tool-specific row for yet (see conformtest.Domain). Empty since the
// vtcode rows landed in internal/tooltax/table.go (conformtest fails on a
// stale freeze).
var missingTooltaxRows = map[string]string{}

// TestPrivateMappingAgreesWithTooltax is the TABLE to CLASSIFIER direction.
func TestPrivateMappingAgreesWithTooltax(t *testing.T) {
	conformtest.AgreesWithTable(t, tooltaxTools, classifyForTooltax)
}

// TestClassifierDomainIsSubsetOfTooltax is the CLASSIFIER to TABLE direction
// over the case labels of mapVTCodeTool, extracted from source.
func TestClassifierDomainIsSubsetOfTooltax(t *testing.T) {
	conformtest.DomainIsSubset(t, conformtest.Domain{
		Dir:          ".",
		Func:         "mapVTCodeTool",
		Tools:        tooltaxTools,
		Classify:     classifyForTooltax,
		Unclassified: unclassifiedDomain,
		Missing:      missingTooltaxRows,
	})
}
