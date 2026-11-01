//go:build !sbo_omit_security && !sbo_omit_security_scan_sarif_import

package main

import (
	"context"
	"strconv"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/componentstate"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedAIEdit records one session with a prompt and an AI edit of rel in
// root, and returns the edit's and the prompt's action ids.
func seedAIEdit(t *testing.T, st *store.Store, root, sid, rel string, at time.Time) (editID, promptID int64) {
	t.Helper()
	ctx := context.Background()
	pid, err := st.UpsertProject(ctx, root, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpsertSession(ctx, models.Session{ID: sid, ProjectID: pid, Tool: models.ToolClaudeCode, StartedAt: at.Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	for _, a := range []models.Action{
		{SessionID: sid, ProjectID: pid, Timestamp: at.Add(-time.Minute), ActionType: models.ActionUserPrompt, Target: "fix the login handler", Success: true, Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: sid + "p"},
		{SessionID: sid, ProjectID: pid, Timestamp: at, ActionType: models.ActionEditFile, Target: rel, Success: true, Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: sid + "e"},
	} {
		if _, err := st.InsertActions(ctx, []models.Action{a}); err != nil {
			t.Fatal(err)
		}
	}
	prompts, _, err := st.LoadProjectPrompts(ctx, pid, at.Add(-24*time.Hour), at.Add(time.Hour), 10)
	if err != nil || len(prompts) != 1 {
		t.Fatalf("prompts %v %v", prompts, err)
	}
	promptID = prompts[0].ActionID
	editID = promptID + 1
	if _, err := st.InsertFileChanges(ctx, []store.FileChangeRow{{
		SessionID: sid, ProjectID: pid, ActionID: editID, FilePathHash: loc.PathHash(root, rel),
		Category: string(loc.CategoryCode), Actor: store.LOCActorAI, Confidence: string(loc.ConfidenceHigh),
		Source: store.LOCSourceEdit, Stats: loc.Stats{AddedCode: 2}, Version: loc.Version, SavedAt: at,
	}}); err != nil {
		t.Fatal(err)
	}
	return editID, promptID
}

const testSARIF = `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec","rules":[{"id":"G101"}]}},"results":[
{"ruleId":"G101","level":"error","message":{"text":"hunter2"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/a.go"},"region":{"startLine":4}}}]},
{"ruleId":"G101","level":"warning","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"src/b.go"},"region":{"startLine":1}}}]},
{"ruleId":"G101","level":"error","message":{"text":"x"},"locations":[{"physicalLocation":{"artifactLocation":{"uri":"file:///etc/passwd"}}}]}]}]}`

// TestImportSARIFFileRecordsWithLineage: one import records flag-only
// findings, attaches the inferred lineage of the latest AI edit where the
// path matches, refuses the out-of-root row, and closes nothing.
func TestImportSARIFFileRecordsWithLineage(t *testing.T) {
	st, _ := openTestStore(t)
	ctx := context.Background()
	root := t.TempDir()
	editID, promptID := seedAIEdit(t, st, root, "s-g5", "src/a.go", time.Now().Add(-time.Hour))
	rep, err := importSARIFFile(ctx, st, root, "gosec", []byte(testSARIF))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Findings != 2 || rep.New != 2 || rep.WithLineage != 1 || rep.Refused["outside_project_root"] != 1 || rep.Outcome != "findings" {
		t.Fatalf("report %+v", rep)
	}
	got, err := st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen})
	if err != nil || len(got) != 2 {
		t.Fatalf("%v %v", got, err)
	}
	for _, f := range got {
		if f.Confidence != policy.FindingConfidenceLow || f.Engine.Driver != "sarif-import" {
			t.Errorf("not flag-only: %+v", f)
		}
		if f.Location.RelPath == "src/a.go" {
			if f.Lineage.SessionID != "s-g5" || f.Lineage.ActionID != strconv.FormatInt(editID, 10) || f.Lineage.PromptActionID != strconv.FormatInt(promptID, 10) || f.Attribution.Class != policy.FindingAttributionUnknown {
				t.Errorf("lineage %+v %+v", f.Lineage, f.Attribution)
			}
		} else if f.Lineage.SessionID != "" {
			t.Errorf("unmatched path got lineage %+v", f.Lineage)
		}
	}
	// An empty import closes nothing and reports unknown.
	rep, err = importSARIFFile(ctx, st, root, "gosec", []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"gosec"}},"results":[]}]}`))
	if err != nil || rep.Outcome != "unknown" {
		t.Fatalf("empty: %+v %v", rep, err)
	}
	if got, _ := st.ListSecFindings(ctx, store.SecFindingFilter{Status: policy.FindingStatusOpen}); len(got) != 2 {
		t.Fatalf("an empty import closed findings: %d open", len(got))
	}
}

// TestSARIFImportIsOptIn: with no [components] block the component is not
// selected; selecting it (with security.code) turns it on.
func TestSARIFImportIsOptIn(t *testing.T) {
	if sarifImportSelected(componentstate.Legacy()) {
		t.Fatal("selected with no [components] block")
	}
	snap := componentstate.Resolve(config.ComponentsConfig{Add: []string{sarifImportComponent, "security.code"}}, nil)
	if !sarifImportSelected(snap) {
		t.Fatal("not selected although added")
	}
}
