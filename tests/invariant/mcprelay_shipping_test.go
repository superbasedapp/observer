//go:build !sbo_omit_agentaccess_relay

// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package invariant

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// mcprelay_shipping_test.go holds the relay privacy tests that need the
// relay's push composition, which a build without agentaccess.relay (the
// minimal edition, -tags sbo_omit_agentaccess_relay) leaves out: there no
// relay row ever ships, which mcprelay_privacy_test.go's default test
// still pins in every build (lane RBFIX, the edition omit-tag sets).

// TestMCPRelayActivityOptInShipsAggregateOnly: mcp_activity on an individual
// node ships the HMAC-only aggregate and NO per-record row.
func TestMCPRelayActivityOptInShipsAggregateOnly(t *testing.T) {
	t.Parallel()
	s, database := newRelayInvariantStore(t)
	seedRelayChain(t, database)
	batch := selectRelay(t, s, store.ShareOptions{MCPActivity: true})
	if len(batch.MCPRelayActivity) != 1 {
		t.Fatalf("mcp_activity shipped %d aggregate rows, want 1", len(batch.MCPRelayActivity))
	}
	row := batch.MCPRelayActivity[0]
	if row.OrgID != "org-1" || row.ToolRefHMAC != "h-tool" || row.Decision != "allow" || row.ClientAttestation != "process_attested" || row.N != 1 {
		t.Fatalf("aggregate row = %+v", row)
	}
	if len(batch.MCPRelayEvents) != 0 {
		t.Fatalf("mcp_activity shipped %d per-record events: the opt-in buys the aggregate ONLY (R8.30.b)", len(batch.MCPRelayEvents))
	}
	raw, _ := json.Marshal(batch)
	for _, needle := range []string{"PRIVATE", "create_issue", `"github"`, "args_full", "result_full"} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("aggregate-only batch leaks %q", needle)
		}
	}
}

// TestMCPRelayManagedPostureShipsAggregateAndEvents: each of the three
// shipsRawContent() paths ships the aggregate AND the per-record L2 events
// with mcp_activity OFF, and the cursor advances to the last shipped seq.
func TestMCPRelayManagedPostureShipsAggregateAndEvents(t *testing.T) {
	t.Parallel()
	for name, share := range map[string]store.ShareOptions{
		"full_content":       {FullContent: true},
		"admin_managed":      {AdminManaged: true},
		"enterprise_granted": {EnterpriseGranted: true},
	} {
		t.Run(name, func(t *testing.T) {
			s, database := newRelayInvariantStore(t)
			seq := seedRelayChain(t, database)
			batch := selectRelay(t, s, share)
			if len(batch.MCPRelayActivity) != 1 {
				t.Fatalf("aggregate rows = %d, want 1 (posture ships it regardless of mcp_activity)", len(batch.MCPRelayActivity))
			}
			if len(batch.MCPRelayEvents) != 2 {
				t.Fatalf("events = %d, want decision + completion", len(batch.MCPRelayEvents))
			}
			d, c := batch.MCPRelayEvents[0], batch.MCPRelayEvents[1]
			if d.RecordKind != "decision" || d.LocalRecordSeq != seq || d.Server != "github" || d.Tool != "create_issue" ||
				d.ArgsFull != `{"title":"PRIVATE"}` || d.CaptureLevel != "L2" || d.OrgID != "org-1" || d.UserEmail != "dev@x" {
				t.Fatalf("decision event = %+v", d)
			}
			if c.RecordKind != "completion" || c.ResultFull != `{"number":1}` || c.LatencyMS == nil || *c.LatencyMS != 80 || c.ResultSizeBytes == nil {
				t.Fatalf("completion event = %+v", c)
			}
			if batch.Cursor.MCPRelay != seq+1 {
				t.Fatalf("cursor = %d, want %d (the last shipped seq)", batch.Cursor.MCPRelay, seq+1)
			}
		})
	}
}
