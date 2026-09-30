package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSetConfigKey pins the dotted-key walk over toml tags, one case
// per supported leaf type plus the failure modes.
func TestSetConfigKey(t *testing.T) {
	cases := []struct {
		name    string
		key     string
		value   string
		check   func(c Config) bool
		wantErr string
	}{
		{
			name: "float leaf", key: "compression.conversation.target_ratio", value: "0.7",
			check: func(c Config) bool { return c.Compression.Conversation.TargetRatio == 0.7 },
		},
		{
			name: "bool leaf", key: "compression.shell.enabled", value: "false",
			check: func(c Config) bool { return !c.Compression.Shell.Enabled },
		},
		{
			name: "int leaf", key: "compression.conversation.preserve_last_n", value: "25",
			check: func(c Config) bool { return c.Compression.Conversation.PreserveLastN == 25 },
		},
		{
			name: "string leaf", key: "profiles.default", value: "codex-safe",
			check: func(c Config) bool { return c.Profiles.Default == "codex-safe" },
		},
		{
			name: "string-slice leaf", key: "compression.conversation.compress_types", value: "logs, code",
			check: func(c Config) bool {
				ct := c.Compression.Conversation.CompressTypes
				return len(ct) == 2 && ct[0] == "logs" && ct[1] == "code"
			},
		},
		{
			name: "empty slice", key: "compression.conversation.compress_types", value: "",
			check: func(c Config) bool { return len(c.Compression.Conversation.CompressTypes) == 0 },
		},
		{
			name: "map entry", key: "profiles.by_tool.cline", value: "codex-variant",
			check: func(c Config) bool { return c.Profiles.ByTool["cline"] == "codex-variant" },
		},
		{
			name: "existing map entry overwrite", key: "profiles.by_provider.anthropic", value: "codex-safe",
			check: func(c Config) bool { return c.Profiles.ByProvider["anthropic"] == "codex-safe" },
		},
		{name: "unknown segment", key: "compression.nope.x", value: "1", wantErr: `unknown key segment "nope"`},
		{name: "type mismatch", key: "compression.conversation.target_ratio", value: "abc", wantErr: "wants a number"},
		{name: "table not leaf", key: "profiles.by_tool", value: "x", wantErr: "set one entry"},
		{name: "past leaf", key: "profiles.default.deeper", value: "x", wantErr: "descends past a leaf"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg := Default()
			err := SetConfigKey(&cfg, c.key, c.value)
			if c.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, c.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !c.check(cfg) {
				t.Errorf("key %s=%s did not land", c.key, c.value)
			}
		})
	}
}

// TestUpdateProjectOverlay pins the project-file front door: creates
// the file, round-trips keys, preserves existing keys, enforces the
// allow-list, and refuses to clobber a corrupt file.
func TestUpdateProjectOverlay(t *testing.T) {
	root := t.TempDir()

	if err := UpdateProjectOverlay(root, "compression.conversation.target_ratio", "0.5"); err != nil {
		t.Fatal(err)
	}
	if err := UpdateProjectOverlay(root, "profiles.default", "codex-variant"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ProjectOverlayFilename))
	if err != nil {
		t.Fatal(err)
	}
	base := Default().Compression
	base.Conversation.Enabled = true
	got, err := ProjectCompression(base, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Conversation.TargetRatio != 0.5 {
		t.Errorf("first key lost after second write: ratio=%v", got.Conversation.TargetRatio)
	}
	if pp := ProjectProfiles(defaultProfiles(), raw); pp.Default != "codex-variant" {
		t.Errorf("profiles.default: got %q", pp.Default)
	}

	// Allow-list: daemon-level keys refused.
	if err := UpdateProjectOverlay(root, "observer.db_path", "/evil"); err == nil {
		t.Error("daemon-level key must be refused in a project file")
	}

	// Corrupt existing file: refuse rather than clobber.
	if err := os.WriteFile(filepath.Join(root, ProjectOverlayFilename), []byte("not [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := UpdateProjectOverlay(root, "profiles.default", "default"); err == nil {
		t.Error("corrupt project file must refuse the write")
	}
}
