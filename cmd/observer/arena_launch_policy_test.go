package main

import (
	"os"
	"strings"
	"testing"
)

// allowArenaLaunches opts a test config into the [terminal.launch] policy an
// Arena process now answers to (OSH-R-004), so a test of the walk behind it
// reaches the walk.
func allowArenaLaunches(t *testing.T, cfgPath string) {
	t.Helper()
	b, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "[terminal") {
		t.Fatalf("%s already has a [terminal] block", cfgPath)
	}
	b = append(b, []byte("\n[terminal]\nenabled = true\n[terminal.launch]\nallow_fresh_agent = true\nallowed_tools = [\"claude-code\"]\n")...)
	if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
		t.Fatal(err)
	}
}
