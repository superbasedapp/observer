package config

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeProjectFile(t *testing.T, root, body string) string {
	t.Helper()
	dir := filepath.Join(root, ".observer")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestFindProjectRoot walks up from a nested cwd to the directory
// holding .observer/config.toml; misses return "".
func TestFindProjectRoot(t *testing.T) {
	root := t.TempDir()
	writeProjectFile(t, root, "")
	nested := filepath.Join(root, "src", "internal", "deep")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}
	if got := FindProjectRoot(nested, ""); got != root {
		t.Errorf("FindProjectRoot: got %q want %q", got, root)
	}
	if got := FindProjectRoot(t.TempDir(), ""); got != "" {
		t.Errorf("no-file walk: got %q want empty", got)
	}

	// The master config's own location is never a project root: a hit
	// equal to excludeFile is skipped and the walk continues upward.
	if got := FindProjectRoot(nested, filepath.Join(root, ProjectOverlayFilename)); got != "" {
		t.Errorf("excluded master path treated as project root: %q", got)
	}

	// And the home directory is skipped unconditionally — the walk
	// from anywhere under home must not adopt ~/.observer/config.toml
	// (the daemon master config) as a project overlay. Probed
	// indirectly: the no-file TempDir walk above climbs THROUGH the
	// real home on dev boxes where ~/.observer/config.toml exists and
	// still returns "".
}

// TestProjectProfiles pins assignment override semantics: project
// keys win, unset keys inherit, and the GLOBAL value is never mutated
// (maps cloned).
func TestProjectProfiles(t *testing.T) {
	global := defaultProfiles()
	raw := []byte("[profiles]\ndefault = \"codex-variant\"\n[profiles.by_provider]\nanthropic = \"codex-safe\"\n")

	got := ProjectProfiles(global, raw)
	if got.Default != "codex-variant" {
		t.Errorf("default: got %q", got.Default)
	}
	if got.ByProvider["anthropic"] != "codex-safe" {
		t.Errorf("anthropic: got %q", got.ByProvider["anthropic"])
	}
	if got.ByProvider["openai"] != "codex-safe" {
		t.Errorf("openai must inherit the global assignment: got %q", got.ByProvider["openai"])
	}
	if global.ByProvider["anthropic"] != "claude-code" || global.Default != DefaultProfileName {
		t.Error("global ProfilesConfig was mutated by the project overlay")
	}
}

// TestProjectCompression pins the param overlay + the guard:
// conversation.enabled can only be turned OFF by a project, never on.
func TestProjectCompression(t *testing.T) {
	base := Default().Compression
	base.Conversation.Enabled = true
	base.Conversation.TargetRatio = 0.85

	raw := []byte("[compression.conversation]\ntarget_ratio = 0.5\n")
	got, err := ProjectCompression(base, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Conversation.TargetRatio != 0.5 {
		t.Errorf("target_ratio: got %v want 0.5 (project param overlay)", got.Conversation.TargetRatio)
	}
	if !got.Conversation.Enabled {
		t.Error("enabled untouched by file must stay base value")
	}

	// Off-direction honored…
	off, err := ProjectCompression(base, []byte("[compression.conversation]\nenabled = false\n"))
	if err != nil {
		t.Fatal(err)
	}
	if off.Conversation.Enabled {
		t.Error("project must be able to turn compression OFF for its traffic")
	}
	// …on-direction refused.
	baseOff := base
	baseOff.Conversation.Enabled = false
	on, err := ProjectCompression(baseOff, []byte("[compression.conversation]\nenabled = true\n"))
	if err != nil {
		t.Fatal(err)
	}
	if on.Conversation.Enabled {
		t.Error("project must NOT be able to turn compression ON (master owns the switch)")
	}
}

// TestProjectOverlay_AllowListByConstruction: daemon-level keys in a
// world-authored project file have no parse target and cannot take
// effect.
func TestProjectOverlay_AllowListByConstruction(t *testing.T) {
	base := Default().Compression
	raw := []byte("[observer]\ndb_path = \"/tmp/evil.db\"\n[proxy]\nanthropic_upstream = \"http://evil\"\n[compression.conversation]\npreserve_last_n = 3\n")
	got, err := ProjectCompression(base, raw)
	if err != nil {
		t.Fatal(err)
	}
	if got.Conversation.PreserveLastN != 3 {
		t.Errorf("allow-listed key must apply: got %d", got.Conversation.PreserveLastN)
	}
	// Nothing else to assert — db_path/upstreams have no field in the
	// parse target; this test documents the posture and guards against
	// someone widening projectOverlayDoc to config.Config.
}

// TestProjectOverlays_Cache pins the mtime cache: same generation
// serves from cache, an edit changes the stamp, a corrupt file warns
// once and reads as absent.
func TestProjectOverlays_Cache(t *testing.T) {
	root := t.TempDir()
	path := writeProjectFile(t, root, "[profiles]\ndefault = \"codex-safe\"\n")

	var warns []string
	c := NewProjectOverlays()
	c.Warnf = func(f string, a ...any) { warns = append(warns, fmt.Sprintf(f, a...)) }

	raw1, stamp1, ok := c.Lookup(root)
	if !ok || len(raw1) == 0 || stamp1 == "" {
		t.Fatalf("first lookup: ok=%v raw=%d stamp=%q", ok, len(raw1), stamp1)
	}
	_, stamp2, ok := c.Lookup(root)
	if !ok || stamp2 != stamp1 {
		t.Errorf("unchanged file must serve the same stamp: %q vs %q", stamp2, stamp1)
	}

	// Edit → new stamp. Backdate-proof by bumping mtime explicitly.
	if err := os.WriteFile(path, []byte("[profiles]\ndefault = \"codex-variant\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	raw3, stamp3, ok := c.Lookup(root)
	if !ok || stamp3 == stamp1 {
		t.Errorf("edited file must change the stamp: %q vs %q", stamp3, stamp1)
	}
	if string(raw3) == string(raw1) {
		t.Error("edited file must re-read")
	}

	// Corrupt file: absent + warn.
	if err := os.WriteFile(path, []byte("not [valid"), 0o644); err != nil {
		t.Fatal(err)
	}
	future = future.Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := c.Lookup(root); ok {
		t.Error("corrupt file must read as absent")
	}
	if len(warns) != 1 {
		t.Errorf("corrupt file warns once at cache fill: got %d (%v)", len(warns), warns)
	}
	// Re-lookup same generation: no re-warn.
	if _, _, ok := c.Lookup(root); ok {
		t.Error("still absent")
	}
	if len(warns) != 1 {
		t.Errorf("no re-warn on cached invalid generation: got %d", len(warns))
	}

	if _, _, ok := c.Lookup(""); ok {
		t.Error("empty root must miss")
	}
}
