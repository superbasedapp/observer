package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/adapter/cursor"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

func TestCursorThoughtCaptureWithoutDatabase(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("USERPROFILE", dir)
	configPath := filepath.Join(dir, "invalid.toml")
	if err := os.WriteFile(configPath, []byte("[invalid"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := os.CreateTemp(dir, "input")
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	output, err := os.CreateTemp(dir, "output")
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	preview := strings.Repeat("thought ", 40)
	if _, err := input.WriteString(`{"conversation_id":"thought-fast-path","text":"` + preview + `"}`); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	oldInput, oldOutput := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = input, output
	defer func() { os.Stdin, os.Stdout = oldInput, oldOutput }()
	handleCursorHook(context.Background(), cursor.EventAfterAgentThought, configPath)
	reply, err := os.ReadFile(output.Name())
	if err != nil || !strings.Contains(string(reply), `"continue":true`) {
		t.Fatalf("thought reply %q: %v", reply, err)
	}
	// Even unusable config/DB must not prevent the next action from claiming
	// its preview. The observation itself must never need a storage sink.
	event, ok, err := cursor.BuildEvent(cursor.EventPreToolUse, []byte(`{"conversation_id":"thought-fast-path","generation_id":"next","tool_name":"Grep","tool_input":{"pattern":"x"}}`), scrub.New())
	if err != nil || !ok || event.PrecedingReasoning != preview[:200] {
		t.Fatalf("successor reasoning %q, ok=%v err=%v", event.PrecedingReasoning, ok, err)
	}
}
