package dimcode

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformast"
	"github.com/marmutapp/superbased-observer/internal/tooltax/conformtest"
)

// classifyForTooltax runs the adapter's REAL private classifier over one
// native tool name (the shared algorithm lives in internal/tooltax/conformtest).
// The classifier is mapTool (parse.go), a
// `switch strings.ToLower(strings.TrimSpace(name))`.
func classifyForTooltax(native string) string {
	a, _ := mapTool(native, nil)
	return a
}

// tooltaxTools lists the tool ids this adapter's classifier feeds.
var tooltaxTools = []string{models.ToolDimCode}

// unclassifiedDomain freezes case labels that resolve to ActionUnknown. None:
// every label of mapTool classifies.
var unclassifiedDomain = map[string]string{}

// missingTooltaxRows freezes case labels the classifier maps but tooltax has
// no tool-specific row for yet. None once the dimcode rows (docs/dimcode-
// adapter.md "tooltax rows") are in internal/tooltax/table.go.
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

// TestClassifierDomainIsTheGroundedToolSet pins the native names mapTool
// recognises independently of the shared table, so the list the wiring spec
// hands the orchestrator cannot silently drift from the code.
func TestClassifierDomainIsTheGroundedToolSet(t *testing.T) {
	got, err := conformast.SwitchCaseStrings(".", "mapTool")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"agent", "askuserquestion", "chrome", "edit", "exec", "find", "glob",
		"goal", "grep", "read", "rg", "search", "skill", "todowrite", "wait",
		"webfetch", "websearch", "workflow", "workflow_result", "write",
	}
	set := map[string]bool{}
	for _, n := range got {
		set[n] = true
	}
	for _, n := range want {
		if !set[n] {
			t.Errorf("mapTool no longer recognises %q", n)
		}
		delete(set, n)
	}
	for n := range set {
		t.Errorf("mapTool recognises %q, which the grounded set (and the tooltax wiring spec) does not list", n)
	}
}
