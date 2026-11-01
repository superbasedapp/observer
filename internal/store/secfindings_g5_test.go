//go:build !sbo_omit_security

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secfinding/sarif"
)

// TestListSecFindingsCarriesExportLineage: the finding load the SARIF
// export uses returns the whole lineage the encoder writes (lane sec-g5,
// plan 4.5.3 "Out"), so the export's superbased/prompt_action, attribution
// and taint properties are filled, not empty.
func TestListSecFindingsCarriesExportLineage(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	f := secFinding("p1", "k1")
	f.Lineage = secfinding.Lineage{SessionID: "s1", ActionID: "9", PromptActionID: "8", Tool: "claude-code", ToolVersion: "2.1", Model: "m", Surface: "cli"}
	f.Attribution = secfinding.InferredAttribution{Class: policy.FindingAttributionAI, Method: "sarifimport.lineage.v1", Confidence: policy.FindingConfidenceLow}
	f.TaintAtWrite = secfinding.TaintAtWrite{Tainted: true, OriginClass: "web"}
	if _, _, err := s.UpsertSecFinding(ctx, f, time.Now()); err != nil {
		t.Fatal(err)
	}
	got, err := s.ListSecFindings(ctx, SecFindingFilter{ProjectRootHash: "p1"})
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	g := got[0]
	if g.Lineage != f.Lineage || g.Attribution != f.Attribution || !g.TaintAtWrite.Tainted {
		t.Fatalf("lineage not loaded: %+v %+v %+v", g.Lineage, g.Attribution, g.TaintAtWrite)
	}
	data, err := sarif.Encode(got, sarif.ToolInfo{Name: "t"})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Properties map[string]string `json:"properties"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	p := doc.Runs[0].Results[0].Properties
	if p[sarif.PropPrompt] != "8" || p[sarif.PropSession] != "s1" || p[sarif.PropAttribution] != "ai" || p[sarif.PropTaint] != "true" {
		t.Fatalf("export properties: %v", p)
	}
}

// TestMarkSecFindingFixedVerifiedMovesOnlyNotReproduced: the move takes a
// not_reproduced finding to fixed_verified with a closed event carrying the
// evidence; an open finding is never closed by it.
func TestMarkSecFindingFixedVerifiedMovesOnlyNotReproduced(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	open, _, err := s.UpsertSecFinding(ctx, secFinding("p1", "k-open"), now)
	if err != nil {
		t.Fatal(err)
	}
	obs := secfinding.FixObservations{RuleNoLongerFires: true, TestCommandObserved: true}
	if moved, err := s.MarkSecFindingFixedVerified(ctx, open, "observed test command", obs, now); err != nil || moved {
		t.Fatalf("an open finding moved: %v %v", moved, err)
	}
	gone, _, _ := s.UpsertSecFinding(ctx, secFinding("p1", "k-gone"), now)
	if ok, err := s.CloseSecFindingNotReproduced(ctx, gone, now); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if moved, err := s.MarkSecFindingFixedVerified(ctx, gone, "observed test command: class go_test", obs, now); err != nil || !moved {
		t.Fatalf("not moved: %v %v", moved, err)
	}
	var status, detail string
	if err := database.QueryRowContext(ctx, `SELECT status FROM sec_findings WHERE id = ?`, gone).Scan(&status); err != nil || status != string(policy.FindingStatusFixedVerified) {
		t.Fatalf("status %q %v", status, err)
	}
	if err := database.QueryRowContext(ctx, `SELECT detail FROM sec_finding_events WHERE finding_id = ? ORDER BY id DESC LIMIT 1`, gone).Scan(&detail); err != nil || detail != "fixed_verified:observed test command: class go_test" {
		t.Fatalf("event %q %v", detail, err)
	}
	if moved, _ := s.MarkSecFindingFixedVerified(ctx, gone, "again", obs, now); moved {
		t.Fatal("moved twice")
	}
	// The org row carries the observations written with the move (audit
	// finding 4), not the empty fix_json of a bare status update.
	rows, err := s.SelectSecurityFindingRows(ctx, 100, SecurityScope{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.Status != string(policy.FindingStatusFixedVerified) {
			continue
		}
		found = true
		if !r.FixTestCommandObserved || !r.FixRuleNoLongerFires || r.FixTestFilesEdited || r.FixTestExitCode != 0 {
			t.Fatalf("org row fix fields: %+v", r)
		}
	}
	if !found {
		t.Fatal("no fixed_verified org row")
	}
}

// TestPackChangeCloseIsNotFixEvidence: a run with another rule pack version
// closes a finding recorded under the old one with SecClosedPackChanged,
// and that finding never moves to fixed_verified; a close under the same
// version stays eligible (audit finding 5).
func TestPackChangeCloseIsNotFixEvidence(t *testing.T) {
	t.Parallel()
	s, database := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	obs := secfinding.FixObservations{RuleNoLongerFires: true, TestCommandObserved: true}
	for _, tc := range []struct {
		key, runVersion string
		eligible        bool
	}{
		{"k-pack-changed", "1.3.0", false},
		{"k-same-pack", "1.2.0", true},
	} {
		f := secFinding("p-pack", tc.key)
		f.Rule.Pack, f.Rule.PackVersion = "observer-code", "1.2.0"
		f.Engine.Driver = "opengrep"
		f.Location.RelPath = tc.key + ".py"
		id, _, err := s.UpsertSecFinding(ctx, f, now.Add(-time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		if n, err := s.CloseGoneSecFindings(ctx, SecGoneQuery{
			ProjectRootHash: "p-pack", Driver: "opengrep", RulePack: "observer-code",
			Paths: []string{tc.key + ".py"}, PackVersion: tc.runVersion,
		}, now); err != nil || n != 1 {
			t.Fatalf("%s: close %d %v", tc.key, n, err)
		}
		var detail string
		if err := database.QueryRowContext(ctx, `SELECT detail FROM sec_finding_events WHERE finding_id = ? ORDER BY id DESC LIMIT 1`, id).Scan(&detail); err != nil {
			t.Fatal(err)
		}
		if (detail == SecClosedPackChanged) == tc.eligible {
			t.Errorf("%s: close detail %q", tc.key, detail)
		}
		moved, err := s.MarkSecFindingFixedVerified(ctx, id, "observed test command", obs, now)
		if err != nil || moved != tc.eligible {
			t.Errorf("%s: moved %v (%v), want %v", tc.key, moved, err, tc.eligible)
		}
	}
}
