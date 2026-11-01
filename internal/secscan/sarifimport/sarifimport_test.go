package sarifimport

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secscan"
)

const root = "/home/u/proj"

// doc renders one SARIF document with the given results JSON.
func doc(results string) []byte {
	return []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x","version":"1.2","rules":[{"id":"G101","defaultConfiguration":{"level":"error"}}]}},"results":[` + results + `]}]}`)
}

// one renders one result.
func one(uri, base, level string) string {
	b := ""
	if base != "" {
		b = `,"uriBaseId":` + jsonString(base)
	}
	return fmt.Sprintf(`{"ruleId":"G101","level":%s,"message":{"text":"password hunter2 found"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":%s%s},"region":{"startLine":3,"snippet":{"text":"hunter2"}}}}]}`, jsonString(level), jsonString(uri), b)
}

// jsonString is s as a JSON string literal.
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// TestHostileSARIF is the D3 (JSP-12) hostile SARIF suite against the
// import's strict location rule: the same rows the custom driver refuses.
func TestHostileSARIF(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		uri  string
		base string
		ok   bool
	}{
		{"plain relative path", "src/a.go", "", true},
		{"file:/// under the root", "file:///home/u/proj/src/a.py", "", true},
		{"file://localhost under the root", "file://localhost/home/u/proj/a.py", "", true},
		{"%SRCROOT% base id", "src/a.go", "%SRCROOT%", true},
		{"traversal", "../../etc/passwd", "", false},
		{"percent-encoded traversal", "%2e%2e/%2e%2e/etc/passwd", "", false},
		{"absolute path without a scheme", "/etc/passwd", "", false},
		{"file:// outside the root", "file:///etc/passwd", "", false},
		{"file:// on a sibling prefix", "file:///home/u/proj2/a.go", "", false},
		{"file:// with a remote host", "file://evil.example/home/u/proj/a.go", "", false},
		{"https", "https://evil.example/a.go", "", false},
		{"javascript", "javascript:alert(1)", "", false},
		{"data", "data:text/plain,hi", "", false},
		{"a drive letter", "C:/Windows/win.ini", "", false},
		{"backslashes", `src\a.go`, "", false},
		{"a foreign uriBaseId", "passwd", "EVIL", false},
		{"file uri with a base id", "file:///home/u/proj/a.go", "%SRCROOT%", false},
		{"a query", "src/a.go?x=1", "", false},
		{"a fragment", "src/a.go#L1", "", false},
		{"a control character", "src/a\u0007.go", "", false},
		{"too long", strings.Repeat("a/", 600) + "x.go", "", false},
	}
	for _, tc := range cases {
		res, err := Import(Input{Data: doc(one(tc.uri, tc.base, "warning")), Tool: "gosec", ProjectRoot: root, ProjectRootHash: "h"})
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got := len(res.Findings) == 1; got != tc.ok {
			t.Errorf("%s: imported=%v, want %v (coverage %+v)", tc.name, got, tc.ok, res.Coverage)
		}
		if !tc.ok && (len(res.Coverage.Skipped) != 1 || res.Coverage.Outcome == secscan.OutcomeClean) {
			t.Errorf("%s: refused row not counted, or clean: %+v", tc.name, res.Coverage)
		}
	}
}

// TestWindowsFileURI: a gosec or Bandit file:///C:/ URI under a Windows
// project root imports as a relative path.
func TestWindowsFileURI(t *testing.T) {
	t.Parallel()
	res, err := Import(Input{Data: doc(one("file:///C:/Work/Proj/cmd/main.go", "", "error")), Tool: "gosec", ProjectRoot: `C:\Work\Proj`, ProjectRootHash: "h"})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Location.RelPath != "cmd/main.go" {
		t.Fatalf("got %+v, %v", res, err)
	}
}

// TestImportIsFlagOnlyAndTextFree: severities never above medium, low
// confidence, unknown baseline, the tool's id prefixed to the rule, and
// none of the engine's message or snippet text kept.
func TestImportIsFlagOnlyAndTextFree(t *testing.T) {
	t.Parallel()
	res, err := Import(Input{Data: doc(one("src/a.go", "", "error")), Tool: "gosec", ProjectRoot: root, ProjectRootHash: "h"})
	if err != nil || len(res.Findings) != 1 {
		t.Fatalf("got %+v, %v", res, err)
	}
	f := res.Findings[0]
	if f.Severity != policy.FindingSeverityMedium || f.Confidence != policy.FindingConfidenceLow || f.Baseline != policy.FindingBaselineUnknown {
		t.Errorf("not flag-only: %+v", f)
	}
	if f.Rule.ID != "gosec/G101" || f.Rule.Pack != DriverID || f.Engine.Driver != DriverID || f.Location.StartLine != 3 {
		t.Errorf("identity: %+v", f)
	}
	if strings.Contains(f.Message+f.FixHint+f.EvidenceRedacted, "hunter2") {
		t.Errorf("engine text leaked: %q", f.Message)
	}
	if res.Coverage.Outcome != secscan.OutcomeFindings {
		t.Errorf("outcome %s", res.Coverage.Outcome)
	}
}

// TestEmptySARIFIsNeverClean: an empty file, a file with no runs and a file
// whose every result was refused are unknown, never clean.
func TestEmptySARIFIsNeverClean(t *testing.T) {
	t.Parallel()
	for name, data := range map[string][]byte{
		"no results":  doc(""),
		"no runs":     []byte(`{"version":"2.1.0","runs":[]}`),
		"all refused": doc(one("https://evil.example/a.go", "", "error")),
	} {
		res, err := Import(Input{Data: data, Tool: "bandit", ProjectRoot: root, ProjectRootHash: "h"})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if res.Coverage.Outcome != secscan.OutcomeUnknown {
			t.Errorf("%s: outcome %s, want unknown", name, res.Coverage.Outcome)
		}
	}
}

// TestImportRefuses: an unknown tool, a non-SARIF document and an
// oversized one are refused before any finding.
func TestImportRefuses(t *testing.T) {
	t.Parallel()
	if _, err := Import(Input{Data: doc(""), Tool: "nmap", ProjectRoot: root, ProjectRootHash: "h"}); err == nil {
		t.Error("unknown tool accepted")
	}
	if _, err := Import(Input{Data: []byte(`{"version":"1.0"}`), Tool: "gosec", ProjectRoot: root, ProjectRootHash: "h"}); err == nil {
		t.Error("not SARIF 2.1.0 accepted")
	}
	deep := strings.Repeat("[", 200) + strings.Repeat("]", 200)
	if _, err := Import(Input{Data: []byte(deep), Tool: "gosec", ProjectRoot: root, ProjectRootHash: "h"}); err == nil {
		t.Error("too deep accepted")
	}
}

// TestLineageIsAnInference: a matched path carries the edit's lineage (a
// file-level match, method and low confidence) but its attribution class
// stays unknown, never ai, so the org rollup never counts an imported
// finding as agent-introduced (audit finding 3); an unmatched one carries no
// lineage.
func TestLineageIsAnInference(t *testing.T) {
	t.Parallel()
	lin := func(rel string) (secfinding.Lineage, bool) {
		if rel == "src/a.go" {
			return secfinding.Lineage{SessionID: "s1", ActionID: "7", PromptActionID: "6", Tool: "claude-code"}, true
		}
		return secfinding.Lineage{}, false
	}
	data := doc(one("src/a.go", "", "error") + "," + one("src/b.go", "", "error"))
	res, err := Import(Input{Data: data, Tool: "codeql", ProjectRoot: root, ProjectRootHash: "h", Lineage: lin})
	if err != nil || len(res.Findings) != 2 {
		t.Fatalf("got %+v, %v", res, err)
	}
	for _, f := range res.Findings {
		if f.Attribution.Method != LineageMethod || f.Attribution.Confidence != policy.FindingConfidenceLow {
			t.Errorf("%s: attribution %+v", f.Location.RelPath, f.Attribution)
		}
		switch f.Location.RelPath {
		case "src/a.go":
			if f.Attribution.Class != policy.FindingAttributionUnknown || f.Lineage.SessionID != "s1" || f.Lineage.PromptActionID != "6" {
				t.Errorf("matched: %+v", f)
			}
		case "src/b.go":
			if f.Attribution.Class != policy.FindingAttributionUnknown || f.Lineage.SessionID != "" {
				t.Errorf("unmatched: %+v", f)
			}
		}
	}
}

// TestDriverRowRegisters: the row passes the registry's validation.
func TestDriverRowRegisters(t *testing.T) {
	t.Parallel()
	d := Driver{Tool: "gosec", RootHash: func(string) string { return "h" }, Source: func(context.Context) ([]byte, error) { return doc(one("a.go", "", "note")), nil }}
	if _, err := secscan.NewRegistry(d); err != nil {
		t.Fatal(err)
	}
	res, err := d.Scan(context.Background(), secscan.Target{ProjectRoot: root})
	if err != nil || len(res.Findings) != 1 || res.Findings[0].Severity != policy.FindingSeverityInfo {
		t.Fatalf("scan: %+v %v", res, err)
	}
}
