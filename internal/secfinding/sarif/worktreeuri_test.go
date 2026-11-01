package sarif

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
)

// TestArtifactURIWorktree (lane LEFT-SEC audit F3): an out-of-tree worktree
// sighting exports as a valid relative URI reference under
// WorktreeURIPrefix, percent-encoded, with its key in the result
// properties; the location rule passes it and rejects the raw sighting.
func TestArtifactURIWorktree(t *testing.T) {
	sighting := "[worktree:0123456789abcdef]/pkg/a b:c.go"
	f := secfinding.Finding{
		LocalKey: "k1", Rule: secfinding.Rule{ID: "secret.aws_access_key"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Confidence: policy.FindingConfidenceHigh, Baseline: policy.FindingBaselineNew,
		Message: "AWS key", Location: secfinding.Location{RelPath: sighting, StartLine: 3, EndLine: 3},
	}
	data, err := Encode([]secfinding.Finding{f, {
		LocalKey: "k2", Rule: secfinding.Rule{ID: "secret.aws_access_key"}, Category: policy.FindingSecret,
		Severity: policy.FindingSeverityHigh, Message: "AWS key", Location: secfinding.Location{RelPath: "cfg.py", StartLine: 1},
	}}, ToolInfo{Name: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if p := LocationProblems(data); len(p) != 0 {
		t.Fatalf("location problems: %v", p)
	}
	var lg outLog
	if err := json.Unmarshal(data, &lg); err != nil {
		t.Fatal(err)
	}
	rs := lg.Runs[0].Results
	if got, want := rs[0].Locations[0].Physical.Artifact.URI, ".observer-worktree/0123456789abcdef/pkg/a%20b%3Ac.go"; got != want {
		t.Errorf("worktree URI %q, want %q", got, want)
	}
	if rs[0].Properties[PropWorktree] != "[worktree:0123456789abcdef]" {
		t.Errorf("worktree key property %v", rs[0].Properties)
	}
	if got := rs[1].Locations[0].Physical.Artifact.URI; got != "cfg.py" {
		t.Errorf("in-tree URI %q", got)
	}
	if _, ok := rs[1].Properties[PropWorktree]; ok {
		t.Error("an in-tree result carries a worktree key")
	}
	raw := strings.Replace(string(data), ".observer-worktree/0123456789abcdef/pkg/a%20b%3Ac.go", "[worktree:0123456789abcdef]/pkg/a.go", 1)
	if p := LocationProblems([]byte(raw)); len(p) != 1 {
		t.Errorf("the raw sighting URI passed the location rule: %v", p)
	}
}

// TestValidArtifactURI pins the URI reference check.
func TestValidArtifactURI(t *testing.T) {
	for u, want := range map[string]bool{
		"cfg.py": true, "src/a%20b.go": true, ".observer-worktree/0123456789abcdef/x": true,
		"file:///repo/a.go": true, "https://example.com/a": true,
		"": false, "[worktree:0123456789abcdef]/x": false, "1a:b/c": false, "a:b/c": true, "a b.go": false,
		"bad%zz": false, "trail%2": false, "a/[x]": false,
	} {
		if got := validArtifactURI(u); got != want {
			t.Errorf("validArtifactURI(%q) = %v, want %v", u, got, want)
		}
	}
}
