// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package invariant

import (
	"context"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/guard/mcpsec"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// This file is the privacy sentinel for the Agent Access P11 (c) shadow-MCP
// discovery inventory wire (orgcontract.MCPInventoryRow;
// docs/plans/agent-access-implementation-plan-2026-09-23.md §2.2 sentinel
// bullet + §11.12b (c); rulings R12.10, R13.8, R14.6):
//
//   - orgpush.go never reaches the inventory SOURCES itself (no mcpsec /
//     locate import, no client-config file name in a literal) - the rows come
//     only through the store.MCPInventoryProviders function seam;
//   - an INDIVIDUAL node ships NOTHING by default;
//   - with [org_client.share].mcp_activity it ships the REDUCED shape: the
//     identity + metadata an ingest needs (source_scope, locator_fingerprint,
//     server_name_hash, transport, observed_at, first/last seen) and NO raw
//     locator field (the SHARE-OFF NEGATIVE test);
//   - an ENROLLED teams/enterprise node (every shipsRawContent() disjunct)
//     ships the FULL shape - still with args scrubbed, env KEY names only and
//     the config path hashed, never an env value or a raw path.

// invReducedKeys is the complete key set a reduced row may carry.
var invReducedKeys = map[string]bool{
	"org_id": true, "user_email": true, "source_scope": true, "locator_fingerprint": true,
	"server_name_hash": true, "transport": true, "observed_at": true, "first_seen": true, "last_seen": true,
}

// invSecretToken / invEnvValue must never reach the wire in ANY shape.
const (
	invSecretToken = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	invEnvValue    = "ENV-VALUE-NEVER-READ"
	invConfigPath  = "/home/dev-private/.claude.json"
)

// seedInventoryStore opens a migrated agent DB with the inventory seam bound
// to a fixed two-server inventory (a stdio server with a secret in its args
// and a remote server with userinfo in its URL).
func seedInventoryStore(t *testing.T) *store.Store {
	t.Helper()
	s, _ := newRelayInvariantStore(t)
	entries := []store.MCPInventoryEntry{
		{
			Server: mcpsec.Server{
				Client: "claude-code", Name: "private-files", Transport: "stdio", Command: "npx",
				Args: []string{"-y", "@acme/private-files", "--token=" + invSecretToken}, EnvKeys: []string{"FILES_API_KEY"},
			},
			ConfigPath: invConfigPath,
		},
		{Server: mcpsec.Server{
			Client: "cursor", Name: "private-remote", Transport: "http",
			Command: "https://svc-user:svc-pass@mcp.private.example/mcp",
		}, ConfigPath: invConfigPath},
	}
	s.SetMCPInventoryProviders(store.MCPInventoryProviders{
		Inventory: func(context.Context) ([]store.MCPInventoryEntry, error) { return entries, nil },
		Now:       func() time.Time { return time.Unix(1790000000, 0) },
	})
	return s
}

// TestOrgpushNeverReadsMCPInventorySources: the inventory's sources stay off
// orgpush.go - no import of the extraction packages and no client-config
// file name in any string literal.
func TestOrgpushNeverReadsMCPInventorySources(t *testing.T) {
	t.Parallel()
	path := filepath.Join("..", "..", "internal", "store", "orgpush.go")
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, src, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	for _, imp := range file.Imports {
		p := strings.Trim(imp.Path.Value, `"`)
		for _, bad := range []string{
			"github.com/marmutapp/superbased-observer/internal/guard/mcpsec",
			"github.com/marmutapp/superbased-observer/internal/mcp/locate",
		} {
			if p == bad {
				t.Errorf("orgpush.go imports %q - the inventory must reach the wire ONLY through store.MCPInventoryProviders (mcpinventory.go)", bad)
			}
		}
	}
	for _, name := range []string{".claude.json", "mcp.json", "config.toml", "mcpServers", "mcp_servers", "opencode.json", "cline_mcp_settings"} {
		if strings.Contains(string(src), `"`+name) || strings.Contains(string(src), name+`"`) {
			t.Errorf("orgpush.go names the client MCP config source %q in a literal", name)
		}
	}
}

// TestMCPInventoryIndividualNodeShipsNothingByDefault: the zero ShareOptions
// attaches no inventory row even with the seam bound.
func TestMCPInventoryIndividualNodeShipsNothingByDefault(t *testing.T) {
	t.Parallel()
	batch := selectRelay(t, seedInventoryStore(t), store.ShareOptions{})
	if len(batch.MCPInventory) != 0 {
		t.Fatalf("default share shipped %d inventory rows - an individual node ships nothing without mcp_activity (R13.8)", len(batch.MCPInventory))
	}
	raw, _ := json.Marshal(batch)
	for _, needle := range []string{"private-files", "private-remote", "locator_fingerprint"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("default batch leaks %q", needle)
		}
	}
}

// TestMCPInventoryShareOffShipsReducedShapeOnly is the SHARE-OFF NEGATIVE
// test: under mcp_activity alone (shipsRawContent()==false) every row carries
// the full identity - so it still ingests - and not one raw locator key.
func TestMCPInventoryShareOffShipsReducedShapeOnly(t *testing.T) {
	t.Parallel()
	batch := selectRelay(t, seedInventoryStore(t), store.ShareOptions{MCPActivity: true})
	if len(batch.MCPInventory) != 2 {
		t.Fatalf("mcp_activity shipped %d inventory rows, want 2", len(batch.MCPInventory))
	}
	for _, r := range batch.MCPInventory {
		if r.LocatorFingerprint == "" || r.ServerNameHash == "" || r.Transport == "" || r.ObservedAt == 0 || r.FirstSeen == 0 || r.LastSeen == 0 {
			t.Fatalf("reduced row is not ingestible (identity missing): %+v", r)
		}
		b, _ := json.Marshal(r)
		var keys map[string]any
		if err := json.Unmarshal(b, &keys); err != nil {
			t.Fatal(err)
		}
		for k := range keys {
			if !invReducedKeys[k] {
				t.Errorf("reduced row carries non-identity key %q: %s", k, b)
			}
		}
	}
	raw, _ := json.Marshal(batch)
	for _, needle := range []string{
		"private-files", "private-remote", "npx", "mcp.private.example", invSecretToken, invEnvValue,
		"FILES_API_KEY", "dev-private", "svc-pass", "claude-code", "cursor",
	} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("share-off batch leaks %q", needle)
		}
	}
}

// TestMCPInventoryManagedNodeShipsFullShape: every shipsRawContent() disjunct
// ships the raw locator - with the secret scrubbed out of the args, the URL
// userinfo stripped, env KEY names only, and the config path hashed.
func TestMCPInventoryManagedNodeShipsFullShape(t *testing.T) {
	t.Parallel()
	for name, share := range map[string]store.ShareOptions{
		"full_content":       {FullContent: true},
		"admin_managed":      {AdminManaged: true},
		"enterprise_granted": {EnterpriseGranted: true},
	} {
		t.Run(name, func(t *testing.T) {
			batch := selectRelay(t, seedInventoryStore(t), share)
			if len(batch.MCPInventory) != 2 {
				t.Fatalf("managed posture shipped %d rows, want 2", len(batch.MCPInventory))
			}
			names := map[string]bool{}
			for _, r := range batch.MCPInventory {
				names[r.ServerName] = true
				if r.Client == "" || r.LocatorFingerprint == "" || r.ServerNameHash == "" {
					t.Fatalf("full row missing fields: %+v", r)
				}
			}
			if !names["private-files"] || !names["private-remote"] {
				t.Fatalf("full shape lacks the raw names: %v", names)
			}
			raw, _ := json.Marshal(batch)
			for _, needle := range []string{invSecretToken, invEnvValue, "svc-pass", "svc-user", "dev-private"} {
				if strings.Contains(string(raw), needle) {
					t.Errorf("full shape leaks %q (scrub / userinfo strip / path hash)", needle)
				}
			}
			if !strings.Contains(string(raw), "FILES_API_KEY") {
				t.Error("full shape should carry env KEY names")
			}
		})
	}
}
