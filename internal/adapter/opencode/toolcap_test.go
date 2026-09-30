package opencode

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/contentcap"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// TestParseSessionFile_CapsHugeToolOutputAndNeverIngestsSummaryDiffs pins the
// two halves of post-Agent-Access backlog item 9 for the OpenCode store:
//
//  1. a tool part whose output is megabytes (a build log, a whole-bundle
//     diff) leaves the adapter capped at the 1 MiB ToolOutput contract;
//  2. a user message carrying OpenCode's summary.diffs[] (full before/after
//     patches of every changed file - 41 MB for one message in the operator
//     report) contributes nothing but the prompt text: no emitted field
//     carries a patch body.
func TestParseSessionFile_CapsHugeToolOutputAndNeverIngestsSummaryDiffs(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "opencode.db")
	setupOpenCodeDB(t, path)

	huge := strings.Repeat("z", 3*contentcap.DefaultMaxBytes)
	const patchMarker = "PATCH-BODY-SENTINEL"
	patch := "@@ -1 +1 @@\n-" + patchMarker + strings.Repeat("a", 64<<10) + "\n+" + patchMarker + "\n"

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE part SET data = json_set(data, '$.state.output', ?, '$.state.metadata.output', ?) WHERE id = 'prt_tool'`, huge, huge); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE message SET data = json_set(data, '$.summary', json(?)) WHERE id = 'msg_user'`,
		`{"diffs":[{"file":"internal/intelligence/dashboard/webapp/dist/assets/index-AAAA.js","patch":`+jsonString(patch)+`,"additions":1,"deletions":1,"status":"modified"}]}`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()

	a := NewWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	var tool *models.ToolEvent
	for i := range res.ToolEvents {
		ev := &res.ToolEvents[i]
		if ev.MessageID == "msg_tool" && ev.RawToolName == "bash" {
			tool = ev
		}
		for name, v := range map[string]string{
			"Target": ev.Target, "RawToolInput": ev.RawToolInput, "ToolOutput": ev.ToolOutput,
			"PrecedingReasoning": ev.PrecedingReasoning, "ErrorMessage": ev.ErrorMessage,
		} {
			if strings.Contains(v, patchMarker) {
				t.Errorf("event %s: %s carries a summary.diffs patch body", ev.SourceEventID, name)
			}
		}
	}
	if tool == nil {
		t.Fatal("bash tool event not emitted")
	}
	if want := contentcap.Cap(huge, contentcap.DefaultMaxBytes); tool.ToolOutput != want {
		t.Errorf("ToolOutput = %d bytes, want the %d-byte capped body", len(tool.ToolOutput), len(want))
	}
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
