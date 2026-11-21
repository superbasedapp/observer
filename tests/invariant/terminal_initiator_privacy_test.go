package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestTerminalRunInitiatorIsNodeLocal pins migration 220 (lane cli-2,
// tracker PT-61) NODE-LOCAL: terminal_run.initiator and
// terminal_run.parent_session_id (who started a run, and the agent session
// it was traced to) never reach the org wire. The terminal wire row is
// built from an explicit column list in internal/store/terminaldevorgrows.go
// and the push envelope in internal/store/orgpush*.go; the wire shapes live
// in internal/orgcontract. None of them may name either column or carry an
// initiator field. Shipping them would be a separate opt-in aggregate wire
// shape with a server pair and a share key, never these raw columns.
func TestTerminalRunInitiatorIsNodeLocal(t *testing.T) {
	root := repoRoot(t)
	forbidden := regexp.MustCompile(`(?i)\binitiator\b|parent_session_id|ParentSessionID`)
	var files []string
	for _, glob := range []string{
		"internal/store/orgpush*.go",
		"internal/store/terminaldevorgrows.go",
		"internal/orgcontract/*.go",
	} {
		m, err := filepath.Glob(filepath.Join(root, glob))
		if err != nil {
			t.Fatalf("glob %s: %v", glob, err)
		}
		files = append(files, m...)
	}
	if len(files) == 0 {
		t.Fatal("no wire files found; the sentinel would pass vacuously")
	}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		if loc := forbidden.FindIndex(b); loc != nil {
			rel, _ := filepath.Rel(root, f)
			t.Errorf("%s names the node-local terminal_run origin (%q): migration 220's columns must stay off the org wire", rel, b[loc[0]:loc[1]])
		}
	}
}
