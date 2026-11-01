package sarif

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/testsupport/importpin"
)

func TestPureImports(t *testing.T) {
	t.Parallel()
	importpin.Check(t, importpin.Spec{
		Forbidden: []string{"os", "os/exec", "net", "net/http", "database/sql", "path/filepath", "github.com/fsnotify/fsnotify"},
		Reason:    "security pillar plan section 4.5.3: a pure decoder",
	})
}

func TestDecodeCaps(t *testing.T) {
	t.Parallel()
	if _, err := Decode([]byte(`{"version":"2.0.0","runs":[]}`)); !errors.Is(err, ErrBadVersion) {
		t.Errorf("version: %v", err)
	}
	deep := `{"version":"2.1.0","runs":[{"x":` + strings.Repeat("[", MaxDepth) + strings.Repeat("]", MaxDepth) + `}]}`
	if _, err := Decode([]byte(deep)); !errors.Is(err, ErrTooDeep) {
		t.Errorf("depth: %v", err)
	}
	// Brackets inside strings do not count toward depth.
	quoted := `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"` + strings.Repeat("[", 200) + `"}},"results":[]}]}`
	if _, err := Decode([]byte(quoted)); err != nil {
		t.Errorf("quoted brackets: %v", err)
	}
	if _, err := Decode(make([]byte, MaxBytes+1)); !errors.Is(err, ErrTooLarge) {
		t.Errorf("size: %v", err)
	}
	var b strings.Builder
	b.WriteString(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[`)
	for i := 0; i < MaxResults+5; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"ruleId":"r","message":{"text":"m"}}`)
	}
	b.WriteString(`]}]}`)
	lg, err := Decode([]byte(b.String()))
	if err != nil || len(lg.Runs[0].Results) != MaxResults || lg.Runs[0].Dropped != 5 {
		t.Fatalf("result cap: %v %d %d", err, len(lg.Runs[0].Results), lg.Runs[0].Dropped)
	}
}

func TestSnippetIsNeverDecoded(t *testing.T) {
	t.Parallel()
	lg, err := Decode([]byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"x"}},"results":[{"ruleId":"r","locations":[{"physicalLocation":{"artifactLocation":{"uri":"a"},"region":{"startLine":2,"snippet":{"text":"TOPSECRET"}}}}]}]}]}`))
	if err != nil {
		t.Fatal(err)
	}
	r := lg.Runs[0].Results[0]
	if r.Locations[0].StartLine != 2 || strings.Contains(strings.Join([]string{r.Message, r.Locations[0].URI}, ""), "TOPSECRET") {
		t.Fatalf("snippet decoded: %+v", r)
	}
}

// TestEncodeRoundTrip: an export decodes back with its rule ids,
// locations, levels and lineage, and carries no evidence.
func TestEncodeRoundTrip(t *testing.T) {
	t.Parallel()
	in := []secfinding.Finding{
		{
			Rule: secfinding.Rule{ID: "S-721"}, Category: policy.FindingSecret, Severity: policy.FindingSeverityHigh,
			Location: secfinding.Location{RelPath: "a/b.go", StartLine: 3, EndLine: 3}, Message: "secret in code",
			EvidenceRedacted: "token=[aws]", Lineage: secfinding.Lineage{SessionID: "s1", Tool: "claude-code", Model: "m"},
		},
		{Rule: secfinding.Rule{ID: "S-761"}, Category: policy.FindingCodeVuln, Severity: policy.FindingSeverityLow, Message: "x"},
		{Message: "no rule id is skipped"},
	}
	data, err := Encode(in, ToolInfo{Name: "SuperBased Observer", Version: "1.0.0"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "token=") {
		t.Fatal("evidence must never be exported")
	}
	lg, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	run := lg.Runs[0]
	// S-761 names no file: code scanning would drop the whole upload over
	// it, so it is left out (and counted, TestEncodeEveryResultIsLocated).
	if run.Tool.Name != "SuperBased Observer" || len(run.Results) != 1 || len(run.Tool.Rules) != 1 {
		t.Fatalf("run = %+v", run)
	}
	r := run.Results[0]
	if r.RuleID != "S-721" || r.Level != "error" || r.Locations[0].URI != "a/b.go" || r.Locations[0].StartLine != 3 {
		t.Fatalf("result = %+v", r)
	}
	if r.Properties[PropSession] != "s1" || r.Properties[PropTool] != "claude-code" || r.Properties[PropTaint] != "false" {
		t.Fatalf("lineage = %+v", r.Properties)
	}
	if run.Tool.Rules[0].SecuritySeverity != "8.0" {
		t.Fatalf("levels: %+v", run.Tool.Rules[0])
	}
}

// TestEncodeEveryResultIsLocated: every exported result has a physical
// location with a uri and a region (line 1 for a file-level finding), the
// shape GitHub code scanning accepts; a finding with no file is left out
// and counted in the run's PropUnlocated property.
func TestEncodeEveryResultIsLocated(t *testing.T) {
	t.Parallel()
	in := []secfinding.Finding{
		{Rule: secfinding.Rule{ID: "S-721"}, Severity: policy.FindingSeverityHigh, Location: secfinding.Location{RelPath: "a.go", StartLine: 4, EndLine: 5}, Message: "m"},
		{Rule: secfinding.Rule{ID: "S-740"}, Severity: policy.FindingSeverityMedium, Location: secfinding.Location{RelPath: "go.mod"}, Message: "file level"},
		{Rule: secfinding.Rule{ID: "S-761"}, Severity: policy.FindingSeverityLow, Message: "no file"},
	}
	data, err := Encode(in, ToolInfo{Name: "SuperBased Observer"})
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				RuleID    string `json:"ruleId"`
				Locations []struct {
					PhysicalLocation *struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
			Properties map[string]any `json:"properties"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	run := log.Runs[0]
	if len(run.Results) != 2 || run.Properties[PropUnlocated] != float64(1) {
		t.Fatalf("results %+v properties %v", run.Results, run.Properties)
	}
	lines := map[string]int{"S-721": 4, "S-740": 1}
	for _, r := range run.Results {
		if len(r.Locations) != 1 {
			t.Fatalf("%s: locations %+v", r.RuleID, r.Locations)
		}
		pl := r.Locations[0].PhysicalLocation
		if pl == nil || pl.ArtifactLocation.URI == "" || strings.HasPrefix(pl.ArtifactLocation.URI, "/") || pl.Region == nil || pl.Region.StartLine != lines[r.RuleID] {
			t.Fatalf("%s: physical location %+v", r.RuleID, pl)
		}
	}
}
