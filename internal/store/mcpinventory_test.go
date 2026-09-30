// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/mcpintel/discover"
)

// mcpInvSecret is a GitHub-token-shaped value the node scrubber redacts.
const mcpInvSecret = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"

func mcpInvFixture() []MCPInventoryEntry {
	return []MCPInventoryEntry{
		{
			Server: mcpsec.Server{
				Client: "claude-code", Name: "files", Transport: "stdio", Command: "npx",
				Args: []string{"-y", "@acme/files", "--token=" + mcpInvSecret}, EnvKeys: []string{"ZED", "API_KEY"},
			},
			ConfigPath: "/home/dev/.claude.json",
		},
		// The same remote in two clients folds into ONE row; the lexically-first
		// client ("claude-code") wins.
		{
			Server:     mcpsec.Server{Client: "cursor", Name: "linear", Transport: "http", Command: "https://user:pw@mcp.linear.app/sse"},
			ConfigPath: "/home/dev/.cursor/mcp.json",
		},
		{
			Server:     mcpsec.Server{Client: "claude-code", Name: "linear", Transport: "http", Command: "https://mcp.linear.app/sse/"},
			ConfigPath: "/home/dev/.claude.json",
		},
		{Server: mcpsec.Server{Client: "codex", Name: "  ", Transport: "stdio", Command: "x"}}, // nameless: skipped
	}
}

func wireMCPInv(s *Store, entries []MCPInventoryEntry, now time.Time) {
	s.SetMCPInventoryProviders(MCPInventoryProviders{
		Inventory: func(context.Context) ([]MCPInventoryEntry, error) { return entries, nil },
		Now:       func() time.Time { return now },
	})
}

// TestSelectMCPInventoryFullShape: the FULL shape carries the raw locator -
// scrubbed args, userinfo-free URL, env KEY names only (sorted), the config
// path HASHED - with the identity computed by internal/mcpintel/discover.
func TestSelectMCPInventoryFullShape(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	wireMCPInv(s, mcpInvFixture(), now)
	pinFirst := now.Add(-72 * time.Hour)
	if err := s.UpsertGuardPin(ctx, GuardPinRow{
		Kind: "mcp_server", Name: "files", Client: "claude-code",
		PinHash: "v1 cfg:aa tools:-", FirstSeen: pinFirst, LastVerified: now, Status: "pinned",
	}); err != nil {
		t.Fatal(err)
	}
	rows, err := s.SelectMCPInventory(ctx, "org-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2 (nameless skipped, remote folded): %+v", len(rows), rows)
	}
	byName := map[string]int{}
	for i, r := range rows {
		byName[r.ServerName] = i
	}
	files := rows[byName["files"]]
	if files.Command != "npx" || files.Client != "claude-code" || files.Transport != "stdio" {
		t.Fatalf("files row = %+v", files)
	}
	for _, a := range files.Args {
		if strings.Contains(a, mcpInvSecret) {
			t.Fatalf("arg %q leaked the secret - args must be scrubbed", a)
		}
	}
	if strings.Join(files.EnvKeys, ",") != "API_KEY,ZED" {
		t.Fatalf("env keys = %v, want sorted names", files.EnvKeys)
	}
	if files.ConfigPathHash != discover.ConfigPathHash("/home/dev/.claude.json") {
		t.Fatalf("config path hash = %q", files.ConfigPathHash)
	}
	if files.FirstSeen != pinFirst.Unix() || files.LastSeen != now.Unix() || files.ObservedAt != now.Unix() {
		t.Fatalf("seen = %d/%d/%d", files.FirstSeen, files.LastSeen, files.ObservedAt)
	}
	wantFP := discover.LocatorFingerprint(discover.Locator{Transport: "stdio", Command: "npx", Args: files.Args, ConfigPathHash: files.ConfigPathHash})
	if files.LocatorFingerprint != wantFP || files.ServerNameHash != discover.ServerNameHash("org-1", "files") {
		t.Fatal("identity not computed by discover")
	}
	linear := rows[byName["linear"]]
	if linear.Client != "claude-code" || strings.Contains(linear.URL, "pw") || strings.Contains(linear.URL, "user") {
		t.Fatalf("linear row = %+v (lexically-first client, userinfo stripped)", linear)
	}
	raw, _ := json.Marshal(rows)
	for _, needle := range []string{mcpInvSecret, "/home/dev", "user:pw"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("full shape leaks %q", needle)
		}
	}
}

// TestSelectMCPInventoryReducedShape: raw=false carries the identity +
// metadata only - the SAME fingerprint / name hash as the full shape - and no
// raw locator key at all.
func TestSelectMCPInventoryReducedShape(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	wireMCPInv(s, mcpInvFixture(), now)
	full, err := s.SelectMCPInventory(ctx, "org-1", true)
	if err != nil {
		t.Fatal(err)
	}
	red, err := s.SelectMCPInventory(ctx, "org-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(red) != len(full) {
		t.Fatalf("reduced %d rows vs full %d", len(red), len(full))
	}
	for i := range red {
		if red[i].LocatorFingerprint != full[i].LocatorFingerprint || red[i].ServerNameHash != full[i].ServerNameHash ||
			red[i].Transport != full[i].Transport {
			t.Fatalf("reduced identity differs from full at %d", i)
		}
		b, _ := json.Marshal(red[i])
		var keys map[string]any
		_ = json.Unmarshal(b, &keys)
		for _, k := range []string{"client", "server_name", "url", "command", "args", "env_keys", "config_path_hash"} {
			if _, ok := keys[k]; ok {
				t.Errorf("reduced row carries raw key %q: %s", k, b)
			}
		}
	}
}

// TestSelectMCPInventoryUnwiredAndErrors: an unwired seam composes nothing; a
// provider error surfaces.
func TestSelectMCPInventoryUnwiredAndErrors(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	if rows, err := s.SelectMCPInventory(ctx, "org-1", true); err != nil || rows != nil {
		t.Fatalf("unwired = %v, %v", rows, err)
	}
	if tok, err := s.probeMCPInventory(ctx); err != nil || tok != "mi-unwired" {
		t.Fatalf("unwired probe = %q, %v", tok, err)
	}
	boom := errors.New("boom")
	s.SetMCPInventoryProviders(MCPInventoryProviders{Inventory: func(context.Context) ([]MCPInventoryEntry, error) { return nil, boom }})
	if _, err := s.SelectMCPInventory(ctx, "org-1", true); !errors.Is(err, boom) {
		t.Fatalf("err = %v", err)
	}
}

// TestProbeMCPInventory: the provider's own probe wins; the fallback hash
// moves on a config change and NOT on the clock.
func TestProbeMCPInventory(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	entries := mcpInvFixture()
	wireMCPInv(s, entries, time.Unix(100, 0))
	a, _ := s.probeMCPInventory(ctx)
	wireMCPInv(s, entries, time.Unix(999, 0))
	b, _ := s.probeMCPInventory(ctx)
	if a != b {
		t.Fatal("the fallback probe moved with the clock")
	}
	changed := append([]MCPInventoryEntry(nil), entries...)
	changed[0].Args = append([]string(nil), "--other")
	wireMCPInv(s, changed, time.Unix(999, 0))
	if c, _ := s.probeMCPInventory(ctx); c == a {
		t.Fatal("the fallback probe did not move on a config change")
	}
	s.SetMCPInventoryProviders(MCPInventoryProviders{
		Inventory: func(context.Context) ([]MCPInventoryEntry, error) { return entries, nil },
		Probe:     func(context.Context) (string, error) { return "tok", nil },
	})
	if p, _ := s.probeMCPInventory(ctx); p != "mi-ptok" {
		t.Fatalf("provider probe = %q", p)
	}
}

// TestMCPInventoryComposedByShareGate: the ONE composition site in
// SelectUnpushedSince - nothing by default, REDUCED under the individual
// mcp_activity opt-in, FULL under every shipsRawContent() disjunct.
func TestMCPInventoryComposedByShareGate(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name  string
		share ShareOptions
		rows  int
		raw   bool
	}{
		{"default ships nothing", ShareOptions{}, 0, false},
		{"individual mcp_activity ships reduced", ShareOptions{MCPActivity: true}, 2, false},
		{"full_content ships full", ShareOptions{FullContent: true}, 2, true},
		{"admin_managed ships full", ShareOptions{AdminManaged: true}, 2, true},
		{"enterprise grant ships full", ShareOptions{EnterpriseGranted: true}, 2, true},
		{"mcp_activity on a managed node ships full", ShareOptions{MCPActivity: true, FullContent: true}, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newTestStore(t)
			wireMCPInv(s, mcpInvFixture(), time.Unix(1790000000, 0))
			batch, err := s.SelectUnpushedSince(ctx, PushCursor{}, 1<<20, "org-1", "dev@x", tc.share, ScopeOptions{})
			if err != nil {
				t.Fatal(err)
			}
			if len(batch.MCPInventory) != tc.rows {
				t.Fatalf("rows = %d, want %d", len(batch.MCPInventory), tc.rows)
			}
			for _, r := range batch.MCPInventory {
				if r.OrgID != "org-1" || r.UserEmail != "dev@x" {
					t.Fatalf("attribution = %q/%q", r.OrgID, r.UserEmail)
				}
				if (r.ServerName != "") != tc.raw {
					t.Fatalf("raw=%v but row = %+v", tc.raw, r)
				}
			}
			if tc.rows > 0 && !batch.hasAggregates() {
				t.Fatal("an inventory-only batch must still push (hasAggregates)")
			}
		})
	}
}
