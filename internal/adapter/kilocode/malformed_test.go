package kilocode

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// TestParseSessionFile_CLIMalformedRowsAreCounted pins the visible half of
// CAPTURE-02 for the kilo-code CLI store. Its queries already carry the
// json_valid guard, so a malformed data column is skipped and the pass
// succeeds (TestParseSessionFile_CLIMalformedJSONDoesNotCrash); this test
// pins that the skip is no longer silent: the watermark moves past the bad
// rows and one warning names how many were skipped.
func TestParseSessionFile_CLIMalformedRowsAreCounted(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "kilo.db")
	setupKiloDBWithMalformed(t, path)
	a := NewCLIWithOptions(nil, []string{root})
	res, err := a.ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if res.NewOffset != 3000 {
		t.Fatalf("NewOffset = %d, want 3000 (the watermark must move past the bad rows)", res.NewOffset)
	}
	if len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "skipped 2 row(s)") {
		t.Fatalf("warnings = %q, want one warning naming 2 skipped rows", res.Warnings)
	}
	again, err := a.ParseSessionFile(context.Background(), path, res.NewOffset)
	if err != nil {
		t.Fatalf("ParseSessionFile (resume): %v", err)
	}
	if len(again.Warnings) != 0 {
		t.Fatalf("resume pass warnings = %q, want none", again.Warnings)
	}
}
