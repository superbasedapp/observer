// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgcontract

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// mcpInventoryIdentityKeys are the MCPInventoryRow keys the REDUCED
// (share-off) shape carries - everything ingest + replay need (R14.6).
var mcpInventoryIdentityKeys = map[string]bool{
	"org_id": true, "user_email": true, // envelope attribution (server re-pins both)
	"source_scope": true, "locator_fingerprint": true, "server_name_hash": true,
	"transport": true, "observed_at": true, "first_seen": true, "last_seen": true,
}

// mcpInventoryRawKeys are the RAW locator keys that ship ONLY under
// shipsRawContent(). Each must be omitempty so the reduced shape is
// structurally free of it.
var mcpInventoryRawKeys = map[string]bool{
	"client": true, "server_name": true, "url": true, "command": true,
	"args": true, "env_keys": true, "config_path_hash": true,
}

// TestMCPInventoryRowFieldClassification is the classification sentinel: every
// json key of MCPInventoryRow is either an identity/metadata key or a raw
// locator key, never both and never neither, and every raw key is omitempty.
// A new field fails here until it is classified.
func TestMCPInventoryRowFieldClassification(t *testing.T) {
	rt := reflect.TypeOf(MCPInventoryRow{})
	seen := map[string]bool{}
	for i := 0; i < rt.NumField(); i++ {
		tag := rt.Field(i).Tag.Get("json")
		parts := strings.Split(tag, ",")
		key := parts[0]
		seen[key] = true
		omit := len(parts) > 1 && parts[1] == "omitempty"
		switch {
		case mcpInventoryIdentityKeys[key] && mcpInventoryRawKeys[key]:
			t.Errorf("key %q classified twice", key)
		case mcpInventoryRawKeys[key] && !omit:
			t.Errorf("raw key %q must be omitempty so the reduced shape never carries it", key)
		case !mcpInventoryIdentityKeys[key] && !mcpInventoryRawKeys[key]:
			t.Errorf("key %q (field %s) is unclassified - decide identity vs raw locator before it ships", key, rt.Field(i).Name)
		}
	}
	for k := range mcpInventoryIdentityKeys {
		if !seen[k] {
			t.Errorf("identity key %q vanished from the row", k)
		}
	}
	for k := range mcpInventoryRawKeys {
		if !seen[k] {
			t.Errorf("raw key %q vanished from the row", k)
		}
	}
}

// TestMCPInventoryWireCompatBothDirections: an old agent's envelope has no
// mcp_inventory key and decodes to a nil slice; a new envelope with nothing to
// send is byte-identical to the old shape (omitempty); an old server ignores
// the key (ordinary encoding/json behaviour, stated explicitly).
func TestMCPInventoryWireCompatBothDirections(t *testing.T) {
	var old PushEnvelope
	if err := json.Unmarshal([]byte(`{"agent_version":"1.30.0","cursor_from":1,"cursor_to":2}`), &old); err != nil {
		t.Fatal(err)
	}
	if old.MCPInventory != nil {
		t.Fatalf("old envelope decoded MCPInventory = %v, want nil", old.MCPInventory)
	}
	b, _ := json.Marshal(PushEnvelope{AgentVersion: "1.36.0"})
	if strings.Contains(string(b), "mcp_inventory") {
		t.Fatalf("an empty inventory must not appear on the wire: %s", b)
	}
	type oldServerEnvelope struct {
		AgentVersion string `json:"agent_version"`
	}
	withInv, _ := json.Marshal(PushEnvelope{AgentVersion: "1.36.0", MCPInventory: []MCPInventoryRow{{LocatorFingerprint: "fp", ServerNameHash: "h", SourceScope: "n"}}})
	var oldEnv oldServerEnvelope
	if err := json.Unmarshal(withInv, &oldEnv); err != nil || oldEnv.AgentVersion != "1.36.0" {
		t.Fatalf("an old server must ignore mcp_inventory: %v %+v", err, oldEnv)
	}
}
