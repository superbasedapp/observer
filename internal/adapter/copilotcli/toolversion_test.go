package copilotcli

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestToolVersionFromSessionStart pins Issue 2 (migration 125): the
// `copilotVersion` on the session.start event becomes a
// SessionToolVersion. The jetbrains fixture carries copilotVersion
// "1.0.79".
func TestToolVersionFromSessionStart(t *testing.T) {
	root, err := filepath.Abs(jetbrainsFixtureDir)
	if err != nil {
		t.Fatal(err)
	}
	ssRoot := filepath.Join(t.TempDir(), "session-state")
	sessDir := filepath.Join(ssRoot, jetbrainsFixtureSession)
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events.jsonl", "workspace.yaml"} {
		b, rerr := os.ReadFile(filepath.Join(root, jetbrainsFixtureSession, name))
		if rerr != nil {
			t.Fatalf("read fixture %s: %v", name, rerr)
		}
		if werr := os.WriteFile(filepath.Join(sessDir, name), b, 0o644); werr != nil {
			t.Fatal(werr)
		}
	}

	evt := filepath.Join(sessDir, "events.jsonl")
	res, err := NewWithOptions(nil, ssRoot).ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionToolVersions) != 1 {
		t.Fatalf("SessionToolVersions = %+v, want exactly one", res.SessionToolVersions)
	}
	tv := res.SessionToolVersions[0]
	if tv.SessionID != jetbrainsFixtureSession {
		t.Errorf("tool-version session = %q, want %q", tv.SessionID, jetbrainsFixtureSession)
	}
	if tv.Version != "1.0.79" {
		t.Errorf("version = %q, want 1.0.79", tv.Version)
	}
}

// TestNoToolVersionWithoutSessionStart pins the honest-unknown path: an
// events.jsonl with no session.start (thus no copilotVersion) emits no
// tool-version stamp.
func TestNoToolVersionWithoutSessionStart(t *testing.T) {
	ssRoot := filepath.Join(t.TempDir(), "session-state")
	sessDir := filepath.Join(ssRoot, "no-start-0000-0000-0000-000000000000")
	if err := os.MkdirAll(sessDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A lone non-start event carries no copilotVersion.
	body := `{"type": "assistant.message", "data": {"content": "hi"}}` + "\n"
	evt := filepath.Join(sessDir, "events.jsonl")
	if err := os.WriteFile(evt, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := NewWithOptions(nil, ssRoot).ParseSessionFile(context.Background(), evt, 0)
	if err != nil {
		t.Fatalf("ParseSessionFile: %v", err)
	}
	if len(res.SessionToolVersions) != 0 {
		t.Fatalf("SessionToolVersions = %+v, want none", res.SessionToolVersions)
	}
}
