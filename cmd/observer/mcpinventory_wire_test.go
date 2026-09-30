// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcp/locate"
)

// TestMCPInventoryWireReadsAndProbes: the binding parses every client config
// through mcpsec and tags each server with its config path; a missing or
// malformed config is skipped, never fatal; the stat probe moves on an edit
// and not otherwise.
func TestMCPInventoryWireReadsAndProbes(t *testing.T) {
	dir := t.TempDir()
	claude := filepath.Join(dir, ".claude.json")
	cursor := filepath.Join(dir, "cursor-mcp.json")
	if err := os.WriteFile(claude, []byte(`{"mcpServers":{"files":{"command":"npx","args":["-y","@acme/files"],"env":{"API_KEY":"secret-value"}}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cursor, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	locs := []locate.Location{
		{Client: "claude-code", Path: claude, Format: locate.FormatMCPServersJSON},
		{Client: "cursor", Path: cursor, Format: locate.FormatMCPServersJSON},
		{Client: "codex", Path: filepath.Join(dir, "missing.toml"), Format: locate.FormatCodexTOML},
	}
	got := readMCPInventory(locs, os.ReadFile)
	if len(got) != 1 {
		t.Fatalf("entries = %+v, want the one parsable server", got)
	}
	e := got[0]
	if e.Client != "claude-code" || e.Name != "files" || e.Command != "npx" || e.ConfigPath != claude || len(e.EnvKeys) != 1 || e.EnvKeys[0] != "API_KEY" {
		t.Fatalf("entry = %+v", e)
	}
	a := statMCPConfigs(locs, os.Stat)
	if b := statMCPConfigs(locs, os.Stat); a != b {
		t.Fatal("the probe is not stable on an unchanged tree")
	}
	later := time.Now().Add(time.Hour)
	if err := os.Chtimes(claude, later, later); err != nil {
		t.Fatal(err)
	}
	if c := statMCPConfigs(locs, os.Stat); c == a {
		t.Fatal("the probe did not move on a config edit")
	}
}
