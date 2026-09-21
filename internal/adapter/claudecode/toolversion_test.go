package claudecode

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// userLineWithVersion builds a minimal `type:"user"` JSONL line carrying
// the transcript top-level `version` (and an entrypoint), for tool-
// version-capture tests. Observer's committed fixtures strip `version`,
// so the field is supplied inline here — its presence in real Claude
// Code transcripts is proven by the qoder adapter, which decodes the
// same field from the identical Claude-Code JSONL.
func userLineWithVersion(sessionID, uuid, version string) string {
	line := `{"type":"user","sessionId":"` + sessionID + `","cwd":"/tmp/w","uuid":"` + uuid +
		`","timestamp":"2026-09-02T10:00:00Z","entrypoint":"cli"`
	if version != "" {
		line += `,"version":"` + version + `"`
	}
	line += `,"message":{"role":"user","content":[{"type":"text","text":"hi"}]}}`
	return line
}

// TestParseSessionFile_ToolVersion pins Issue 2 (migration 125): the
// transcript top-level `version` becomes exactly one SessionToolVersion,
// latched from the first version-bearing line; a transcript with no
// version emits none (honest unknown).
func TestParseSessionFile_ToolVersion(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		version string
		want    string // "" = expect no stamp
	}{
		{"version present", "1.0.40", "1.0.40"},
		{"version absent", "", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "session-tv-"+tc.name+".jsonl")
			body := userLineWithVersion("sess-tv", "msg-1", tc.version) + "\n"
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := New().ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if tc.want == "" {
				if len(res.SessionToolVersions) != 0 {
					t.Fatalf("tool versions = %+v; want none", res.SessionToolVersions)
				}
				return
			}
			if len(res.SessionToolVersions) != 1 {
				t.Fatalf("tool versions: got %d want 1", len(res.SessionToolVersions))
			}
			got := res.SessionToolVersions[0]
			if got.SessionID != "sess-tv" || got.Version != tc.want {
				t.Errorf("tool version = %+v; want {sess-tv %s}", got, tc.want)
			}
		})
	}
}

// TestParseSessionFile_ToolVersionFirstLineOnly pins that a later line
// with a different version does not override the first-latched value.
func TestParseSessionFile_ToolVersionFirstLineOnly(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "session-tv-first.jsonl")
	body := userLineWithVersion("sess-first", "msg-1", "1.0.40") + "\n" +
		userLineWithVersion("sess-first", "msg-2", "1.0.41") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := New().ParseSessionFile(context.Background(), path, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionToolVersions) != 1 {
		t.Fatalf("tool versions: got %d want 1", len(res.SessionToolVersions))
	}
	if res.SessionToolVersions[0].Version != "1.0.40" {
		t.Errorf("version = %q; want the FIRST line's 1.0.40", res.SessionToolVersions[0].Version)
	}
}
