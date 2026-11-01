package store

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/hookliveness"
)

// TestSelectSessionHookActivity pins the wire read: the trailing window, the
// primary key order, and the second gate on content-level env classes (the
// CLAUDE_CONFIG_DIR hash ships only when shipsContent; the coarse classes
// always do).
func TestSelectSessionHookActivity(t *testing.T) {
	t.Parallel()
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()
	hash := hookliveness.PathHashClass("/home/dev/.claude-work")
	env := map[string]string{"ANTHROPIC_BASE_URL": "loopback", "CLAUDE_CONFIG_DIR": hash}
	if err := s.UpsertHookActivity(ctx, []HookActivityRow{
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "s2", Count: 2, FirstAt: now.Add(-time.Hour), LastAt: now, EnvClasses: env},
		{Tool: "claude-code", Event: "SessionStart", SessionID: "s1", FirstAt: now, LastAt: now},
		{Tool: "claude-code", Event: "PreToolUse", SessionID: "old", FirstAt: now.AddDate(0, 0, -9), LastAt: now.AddDate(0, 0, -8)},
	}); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name         string
		shipsContent bool
		wantEnv      map[string]string
	}{
		{"metadata tier drops the path hash", false, map[string]string{"ANTHROPIC_BASE_URL": "loopback"}},
		{"raw content keeps it", true, env},
	}
	for _, tc := range cases {
		got, err := s.SelectSessionHookActivity(ctx, tc.shipsContent)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if len(got) != 2 || got[0].SessionID != "s1" || got[1].SessionID != "s2" {
			t.Fatalf("%s: rows = %+v, want s1 then s2 (the 8-day-old row is outside the window)", tc.name, got)
		}
		if got[1].Count != 2 || got[1].Event != "PreToolUse" || got[1].FirstAt == "" || got[1].LastAt == "" {
			t.Errorf("%s: row = %+v, want the stored count and times", tc.name, got[1])
		}
		if !reflect.DeepEqual(got[1].EnvClasses, tc.wantEnv) {
			t.Errorf("%s: env = %v, want %v", tc.name, got[1].EnvClasses, tc.wantEnv)
		}
		if got[0].EnvClasses != nil {
			t.Errorf("%s: a row with no env classes ships %v, want nil", tc.name, got[0].EnvClasses)
		}
	}
}

// TestWireEnvClasses covers the decode edge cases: empty, undecodable, and a
// map left empty by the filter all ship nothing.
func TestWireEnvClasses(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		stored  string
		content bool
		want    map[string]string
	}{
		{"", true, nil},
		{"{not json", true, nil},
		{`{"CLAUDE_CONFIG_DIR":"hash:0123456789abcdef"}`, false, nil},
		{`{"CLAUDE_CONFIG_DIR":"hash:0123456789abcdef"}`, true, map[string]string{"CLAUDE_CONFIG_DIR": "hash:0123456789abcdef"}},
		{`{"CLAUDE_CODE_USE_BEDROCK":"on"}`, false, map[string]string{"CLAUDE_CODE_USE_BEDROCK": "on"}},
	} {
		if got := wireEnvClasses(tc.stored, tc.content); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("wireEnvClasses(%q, %v) = %v, want %v", tc.stored, tc.content, got, tc.want)
		}
	}
}
