package codex

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestParseSessionFile_ToolVersion pins Issue 2 (migration 125): the
// owning session_meta's `cli_version` becomes a SessionToolVersion, and
// a rollout with no cli_version emits none (honest unknown).
func TestParseSessionFile_ToolVersion(t *testing.T) {
	t.Parallel()

	withVersion := `{"timestamp":"2026-09-02T10:00:00.000Z","type":"session_meta","payload":{"id":"sess-ver","session_id":"sess-ver","cwd":"/w","model":"gpt-5.6","originator":"codex_cli_rs","source":"cli","cli_version":"0.150.0"}}`
	noVersion := `{"timestamp":"2026-09-02T10:00:00.000Z","type":"session_meta","payload":{"id":"sess-nov","session_id":"sess-nov","cwd":"/w","model":"gpt-5.6","originator":"codex_cli_rs","source":"cli"}}`

	cases := []struct {
		name        string
		body        string
		wantVersion string // "" = expect no stamp
	}{
		{"cli_version present", withVersion, "0.150.0"},
		{"cli_version absent", noVersion, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			path := filepath.Join(dir, "rollout-"+tc.name+".jsonl")
			if err := os.WriteFile(path, []byte(tc.body+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			res, err := NewWithOptions(nil, dir).ParseSessionFile(context.Background(), path, 0)
			if err != nil {
				t.Fatalf("ParseSessionFile: %v", err)
			}
			if tc.wantVersion == "" {
				if len(res.SessionToolVersions) != 0 {
					t.Fatalf("tool versions = %+v; want none", res.SessionToolVersions)
				}
				return
			}
			if len(res.SessionToolVersions) != 1 {
				t.Fatalf("tool versions: got %d want 1", len(res.SessionToolVersions))
			}
			got := res.SessionToolVersions[0]
			if got.Version != tc.wantVersion {
				t.Errorf("version = %q; want %q", got.Version, tc.wantVersion)
			}
		})
	}
}
