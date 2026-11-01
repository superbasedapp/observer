package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// TestPrintToolViewNotesOnlyTheRelocation (FU-140 audit follow-up 3): the
// inspect NOTES column carries the relocation note of a moved file, never a
// file's other reasons (never-read text, a link refusal, a read error).
func TestPrintToolViewNotesOnlyTheRelocation(t *testing.T) {
	v := agentconfig.ToolView{Files: []agentconfig.FileView{
		{ID: "claude-code/user-settings", State: agentconfig.FilePresent, Path: "/cfg/settings.json", Reason: "Moved by CLAUDE_CONFIG_DIR: claude-code reads this file here, not at its default location."},
		{ID: "claude-code/global-config", State: agentconfig.FileNeverRead, Reason: "Never read by Observer (the catalogue marks this file off-limits)."},
		{ID: "claude-code/project-settings", State: agentconfig.FileUnreadable, Reason: "open /work/x: permission denied"},
	}}
	var out bytes.Buffer
	printToolView(&out, v, map[string]string{"claude-code/user-settings": "Moved by CLAUDE_CONFIG_DIR: claude-code reads this file here, not at its default location."}, false)
	got := out.String()
	if !strings.Contains(got, "Moved by CLAUDE_CONFIG_DIR") {
		t.Errorf("the relocation note is missing:\n%s", got)
	}
	for _, not := range []string{"Never read by Observer", "permission denied"} {
		if strings.Contains(got, not) {
			t.Errorf("NOTES carries %q:\n%s", not, got)
		}
	}
}
