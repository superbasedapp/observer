package oteldirect

import (
	"crypto/sha256"
	"encoding/hex"
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/oteldirect/ccfixture"
	"github.com/marmutapp/superbased-observer/internal/shiptoken"
)

// ingestHash is internal/orgserver/ingest/ingest.go hashOrComputed for an
// absent shipped hash: lowercase hex SHA-256 of the raw bytes, "" for "".
func ingestHash(raw string) string {
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func TestHashMatchesIngest(t *testing.T) {
	for _, s := range []string{"", "/home/dev/src/app", "https://github.com/acme/x", "ünïcode ✓"} {
		if got, want := hashRaw(s), ingestHash(s); got != want {
			t.Errorf("hashRaw(%q) = %q, ingest computes %q", s, got, want)
		}
	}
}

// loaded returns the four admitted families with EVERY string field set, so
// a raw content column the posture table misses stays visible to
// shiptoken.RawContent.
func loaded() orgcontract.PushEnvelope {
	env := orgcontract.PushEnvelope{
		Sessions: make([]orgcontract.SessionRow, 1), Actions: make([]orgcontract.ActionRow, 1),
		APITurns: make([]orgcontract.APITurnRow, 1), OTelContent: make([]orgcontract.OTelContentRow, 1),
	}
	fill := func(v reflect.Value) {
		for i := 0; i < v.NumField(); i++ {
			if f := v.Field(i); f.Kind() == reflect.String {
				f.SetString("raw-" + v.Type().Field(i).Name)
			}
		}
	}
	fill(reflect.ValueOf(&env.Sessions[0]).Elem())
	fill(reflect.ValueOf(&env.Actions[0]).Elem())
	fill(reflect.ValueOf(&env.APITurns[0]).Elem())
	fill(reflect.ValueOf(&env.OTelContent[0]).Elem())
	// Hash columns start empty so the posture must compute them.
	env.Sessions[0].ProjectRootHash, env.Sessions[0].GitRemoteHash = "", ""
	env.Sessions[0].GitUpstreamRemoteHash, env.Sessions[0].WorkspaceHash = "", ""
	env.Actions[0].TargetHash, env.Actions[0].SourceFileHash = "", ""
	env.APITurns[0].ProjectRootHash = ""
	env.OTelContent[0].ContentHash = ""
	return env
}

// TestPostureClearsEveryRawColumn: after the metadata-only posture,
// shiptoken's raw-content table (the node seam's mirror) finds nothing.
func TestPostureClearsEveryRawColumn(t *testing.T) {
	env := loaded()
	if raw := shiptoken.RawContent(env); len(raw) != 4 {
		t.Fatalf("fixture not fully loaded: %v", raw)
	}
	ApplyPosture(&env, false)
	if raw := shiptoken.RawContent(env); len(raw) != 0 {
		t.Fatalf("raw content left after metadata-only posture: %v", raw)
	}
	cases := []struct {
		name, got, raw string
	}{
		{"sessions.project_root_hash", env.Sessions[0].ProjectRootHash, "raw-ProjectRoot"},
		{"sessions.git_remote_hash", env.Sessions[0].GitRemoteHash, "raw-GitRemote"},
		{"sessions.git_upstream_remote_hash", env.Sessions[0].GitUpstreamRemoteHash, "raw-GitUpstreamRemote"},
		{"sessions.workspace_hash", env.Sessions[0].WorkspaceHash, "raw-Workspace"},
		{"actions.target_hash", env.Actions[0].TargetHash, "raw-Target"},
		{"actions.source_file_hash", env.Actions[0].SourceFileHash, "raw-SourceFile"},
		{"api_turns.project_root_hash", env.APITurns[0].ProjectRootHash, "raw-ProjectRoot"},
		{"otel_content.content_hash", env.OTelContent[0].ContentHash, "raw-Content"},
	}
	for _, c := range cases {
		if c.got != ingestHash(c.raw) {
			t.Errorf("%s = %q, want ingest hash of %q", c.name, c.got, c.raw)
		}
	}
	// Non-content metadata survives.
	if env.Sessions[0].ID != "raw-ID" || env.Actions[0].ActionType != "raw-ActionType" || env.APITurns[0].Model != "raw-Model" {
		t.Fatal("posture cleared a metadata column")
	}
}

func TestPostureOnMappedExport(t *testing.T) {
	s := ccfixture.Default(fixtureStart)
	s.Prompt, s.ToolDetail, s.Repo = true, true, true
	cases := []struct {
		name    string
		full    bool
		wantRaw bool
	}{
		{"full content keeps raw", true, true},
		{"metadata only hashes", false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := MapLogs(whole(s), Options{})
			before := m.Envelope
			before.Sessions = append([]orgcontract.SessionRow(nil), m.Envelope.Sessions...)
			before.Actions = append([]orgcontract.ActionRow(nil), m.Envelope.Actions...)
			before.OTelContent = append([]orgcontract.OTelContentRow(nil), m.Envelope.OTelContent...)
			ApplyPosture(&m.Envelope, c.full)
			raw := shiptoken.RawContent(m.Envelope)
			if (len(raw) > 0) != c.wantRaw {
				t.Fatalf("raw content = %v", raw)
			}
			if c.full {
				return
			}
			// The hashes the mapper stamped equal what ingest computes from
			// the raw values that were cleared.
			for i, a := range m.Envelope.Actions {
				if a.TargetHash != ingestHash(before.Actions[i].Target) || a.SourceFileHash != ingestHash(before.Actions[i].SourceFile) {
					t.Fatalf("action %d hashes do not match ingest", i)
				}
			}
			sr := m.Envelope.Sessions[0]
			if sr.ProjectRootHash != ingestHash(ccfixture.HostPath) || sr.GitRemoteHash != ingestHash(ccfixture.RepositoryURL) || sr.GitBranch != "" {
				t.Fatalf("session = %+v", sr)
			}
			for _, oc := range m.Envelope.OTelContent {
				if oc.Content != "" || oc.ContentHash != ingestHash(ccfixture.PromptText) {
					t.Fatalf("content row = %+v", oc)
				}
			}
		})
	}
	ApplyPosture(nil, false) // no panic
}
