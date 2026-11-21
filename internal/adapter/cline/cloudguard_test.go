package cline

import (
	"context"
	"path/filepath"
	"testing"
)

// TestProjectedCloudTaskDoesNotLandLocally is the lane CA-V6 adapter guard:
// a Cline Cloud session projected into the VS Code task history (its id is
// "ses-..." or the "cloud-provisioning-..." placeholder, the extension's own
// isCloudSessionId) must not land as a local session, even when a task
// folder carrying that id holds a full transcript. The same fixture under a
// local task id still parses, so the guard removes nothing else.
func TestProjectedCloudTaskDoesNotLandLocally(t *testing.T) {
	t.Parallel()
	for _, id := range []string{"ses-01JSYNTH0000CLOUD0001", "cloud-provisioning-1793351400123"} {
		path := copyFixture(t, id)
		root := filepath.Dir(filepath.Dir(path))
		a := NewWithOptions(nil, []string{root})
		if a.IsSessionFile(path) {
			t.Errorf("%s: IsSessionFile claimed a projected cloud task", id)
		}
		res, err := a.ParseSessionFile(context.Background(), path, 0)
		if err != nil {
			t.Fatalf("%s: ParseSessionFile: %v", id, err)
		}
		if len(res.ToolEvents) != 0 || len(res.TokenEvents) != 0 || len(res.SessionSurfaces) != 0 ||
			len(res.SessionToolVersions) != 0 {
			t.Errorf("%s: a projected cloud task landed rows: %d tool, %d token, %d surface", id,
				len(res.ToolEvents), len(res.TokenEvents), len(res.SessionSurfaces))
		}
		if res.NewOffset == 0 {
			t.Errorf("%s: the offset must advance so the file is not re-read", id)
		}
	}
	local := copyFixture(t, "1793351400123")
	a := NewWithOptions(nil, []string{filepath.Dir(filepath.Dir(local))})
	if !a.IsSessionFile(local) {
		t.Fatal("a local task id is no longer claimed")
	}
	res, err := a.ParseSessionFile(context.Background(), local, 0)
	if err != nil || len(res.ToolEvents) == 0 {
		t.Fatalf("a local task no longer parses: %d events, %v", len(res.ToolEvents), err)
	}
}

func TestProjectedCloudTaskIDs(t *testing.T) {
	t.Parallel()
	for id, want := range map[string]bool{
		"ses-abc": true, " ses-abc": true, "cloud-provisioning-x": true, //nolint:gocritic // the padded key is the case under test: projectedCloudTask trims
		"1793351400123": false, "01JSYNTH": false, "session-ses-1": false, "": false, "sess": false,
	} {
		if got := projectedCloudTask(id); got != want {
			t.Errorf("projectedCloudTask(%q) = %v, want %v", id, got, want)
		}
	}
}
