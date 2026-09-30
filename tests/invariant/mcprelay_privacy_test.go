// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package invariant

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// This file is the privacy sentinel for the Agent Access P4 MCP relay wires
// (docs/plans/agent-access-implementation-plan-2026-09-23.md §9.5 / §11.7
// W4e; rulings R8.30.a/b, R9.5, R10.6, R11.10, R14.5). The table-name half
// lives in privacy_test.go's forbiddenCacheTables (the three mcp_relay_*
// names); the DATA posture is pinned here:
//
//   - an INDIVIDUAL node ships NOTHING relay-shaped by default; with
//     mcp_activity it ships the HMAC-only aggregate and STILL no per-record
//     row (no plain name, no payload);
//   - an ENROLLED teams/enterprise node (shipsRawContent() - full_content,
//     admin_managed, or the org-signed EnterpriseGranted raise) ships the
//     aggregate AND the per-record L2 events regardless of mcp_activity;
//   - the aggregate wire shape is a fixed HMAC/enum/count set;
//   - mcp_activity is NOT an org-raisable share tier;
//   - SourceNodeKey is envelope-level and omitempty.

// TestForbiddenCacheTablesExpectedRelaySet is the non-gameable membership pin
// for the three relay tables (mirrors TestForbiddenOrgControlPlaneTablesExpectedSet).
func TestForbiddenCacheTablesExpectedRelaySet(t *testing.T) {
	t.Parallel()
	have := map[string]bool{}
	for _, n := range forbiddenCacheTables {
		have[n] = true
	}
	for _, w := range []string{"mcp_relay_state", "mcp_relay_launch_spec", "mcp_relay_record"} {
		if !have[w] {
			t.Errorf("node-local relay table %q is missing from forbiddenCacheTables — orgpush.go would no longer be guarded against naming it", w)
		}
	}
}

// newRelayInvariantStore opens a migrated agent DB and returns the store AND
// the handle (the relay seam is fed through the record package, not the
// store, exactly as the relay itself writes it).
func newRelayInvariantStore(t *testing.T) (*store.Store, *sql.DB) {
	t.Helper()
	database, err := db.Open(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "agent.db")})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	return store.New(database), database
}

// seedRelayChain appends one L2 decision + its completion, dated now (inside
// the aggregate window), and returns the decision's seq.
func seedRelayChain(t *testing.T, database *sql.DB) int64 {
	t.Helper()
	ctx := context.Background()
	relay := record.NewSQLStore(database, "invariant-node")
	now := time.Now().UTC().Unix()
	res, err := relay.Append(ctx, record.Record{
		Kind: record.KindDecision, TS: now, VServer: "vs-github", ServerRefHMAC: "h-server", ToolRefHMAC: "h-tool",
		Server: "github", Tool: "create_issue", CallID: "c1", TraceID: "tr1", CorrConfidence: record.CorrExact,
		Method: "tools/call", EventKind: record.EventCall, Decision: record.DecisionAllow, ReasonCode: "grant:1",
		ClientAttestation: record.AttestProcess, CredentialAssurance: "node_enrolled",
		CaptureLevel: record.CaptureL2, ArgsFull: `{"title":"PRIVATE"}`, ArgsScrubStatus: record.ScrubStructured,
	})
	if err != nil {
		t.Fatalf("seed decision: %v", err)
	}
	if _, err := relay.Append(ctx, record.Record{
		Kind: record.KindCompletion, TS: now + 1, CallID: "c1", DecisionSeq: record.Int(res.Record.Seq),
		CaptureLevel: record.CaptureL2, ResultStatus: "ok", ResultFull: `{"number":1}`, ResultScrubStatus: record.ScrubStructured,
		ResultSizeBytes: record.Int(12), LatencyMS: record.Int(80),
	}); err != nil {
		t.Fatalf("seed completion: %v", err)
	}
	return res.Record.Seq
}

func selectRelay(t *testing.T, s *store.Store, share store.ShareOptions) store.PushBatch {
	t.Helper()
	batch, err := s.SelectUnpushedSince(context.Background(), store.PushCursor{}, 1<<20, "org-1", "dev@x", share, store.ScopeOptions{})
	if err != nil {
		t.Fatalf("SelectUnpushedSince: %v", err)
	}
	return batch
}

// TestMCPRelayIndividualNodeShipsNothingByDefault: the zero ShareOptions
// attaches neither relay family even when the chain has records.
func TestMCPRelayIndividualNodeShipsNothingByDefault(t *testing.T) {
	t.Parallel()
	s, database := newRelayInvariantStore(t)
	seedRelayChain(t, database)
	batch := selectRelay(t, s, store.ShareOptions{})
	if len(batch.MCPRelayActivity) != 0 || len(batch.MCPRelayEvents) != 0 {
		t.Fatalf("default share shipped activity=%d events=%d — the individual posture is L0 / nothing (R9.5)", len(batch.MCPRelayActivity), len(batch.MCPRelayEvents))
	}
	if batch.Cursor.MCPRelay != 0 {
		t.Fatalf("cursor advanced to %d without shipping", batch.Cursor.MCPRelay)
	}
	raw, _ := json.Marshal(batch)
	for _, needle := range []string{"PRIVATE", "create_issue", `"github"`} {
		if strings.Contains(string(raw), needle) {
			t.Errorf("default batch leaks %q", needle)
		}
	}
}

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
		t.Fatalf("mcp_activity shipped %d per-record events — the opt-in buys the aggregate ONLY (R8.30.b)", len(batch.MCPRelayEvents))
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

// TestMCPRelayActivityRowWireShapeIsHMACOnly pins the aggregate's field SET
// (the exact-count assertion of the UpdatePosture precedent): attribution,
// a date, a policy-object name, one keyed HMAC, two closed enums and a
// count. No plain tool/server name, no payload, no user_id / machine_fp.
func TestMCPRelayActivityRowWireShapeIsHMACOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"OrgID": true, "UserEmail": true,
		"Day": true, "VirtualServer": true, "ToolRefHMAC": true,
		"Decision": true, "ClientAttestation": true,
		"N": true,
	}
	typ := reflect.TypeOf(orgcontract.MCPRelayActivityRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("MCPRelayActivityRow has %d fields, want exactly %d — a field cannot be added without a deliberate edit here", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("MCPRelayActivityRow gained field %q — the aggregate is HMAC/enum/count ONLY (R8.23.f)", name)
		}
	}
	for _, bad := range []string{"Server", "Tool", "Args", "Result", "UserID", "MachineFP", "CallID"} {
		if _, ok := typ.FieldByName(bad); ok {
			t.Errorf("MCPRelayActivityRow carries %s", bad)
		}
	}
}

// TestMCPActivityTierIsIndividualOnlyAndDefaultOff pins R8.30.b: the tier
// exists as a node-side bool (ShareOptions + config + the one mapping),
// defaults OFF, and is NOT part of the org-raisable share vocabulary.
func TestMCPActivityTierIsIndividualOnlyAndDefaultOff(t *testing.T) {
	t.Parallel()
	f, ok := reflect.TypeOf(store.ShareOptions{}).FieldByName("MCPActivity")
	if !ok || f.Type.Kind() != reflect.Bool {
		t.Fatal("store.ShareOptions.MCPActivity must exist and be a bool")
	}
	if (store.ShareOptions{}).MCPActivity {
		t.Fatal("ShareOptions zero value has MCPActivity=true — the tier must default OFF")
	}
	cf, ok := reflect.TypeOf(config.OrgClientShareConfig{}).FieldByName("MCPActivity")
	if !ok || cf.Tag.Get("toml") != "mcp_activity" {
		t.Fatal("config.OrgClientShareConfig.MCPActivity must exist with toml:\"mcp_activity\"")
	}
	if config.Default().OrgClient.Share.MCPActivity {
		t.Fatal("config.Default() turns mcp_activity on")
	}
	if !orgclient.ShareOptionsFromConfig(config.OrgClientConfig{Share: config.OrgClientShareConfig{MCPActivity: true}}).MCPActivity {
		t.Fatal("ShareOptionsFromConfig does not map mcp_activity")
	}
	for _, k := range nodegov.ShareKeys {
		if k.Key == "mcp_activity" {
			t.Fatal("mcp_activity is in nodegov.ShareKeys — it is an INDIVIDUAL-only opt-in (R8.30.b) and must never be an org-raisable share directive")
		}
	}
}

// TestSourceNodeKeyIsEnvelopeLevelAndOmitempty pins the compat invariant: a
// node without the key produces the pre-P4 bytes.
func TestSourceNodeKeyIsEnvelopeLevelAndOmitempty(t *testing.T) {
	t.Parallel()
	raw, _ := json.Marshal(orgcontract.PushEnvelope{})
	if strings.Contains(string(raw), "source_node_key") || strings.Contains(string(raw), "mcp_relay") {
		t.Fatalf("empty envelope carries relay keys: %s", raw)
	}
	raw, _ = json.Marshal(orgcontract.PushEnvelope{SourceNodeKey: "abc"})
	if !strings.Contains(string(raw), `"source_node_key":"abc"`) {
		t.Fatalf("source_node_key not encoded: %s", raw)
	}
	if got := orgcontract.SourceNodeKeyFromThumbprint("jkt"); len(got) != 64 || got == orgcontract.SourceNodeKeyFromThumbprint("jkt2") {
		t.Fatalf("SourceNodeKeyFromThumbprint = %q", got)
	}
	if !strings.HasPrefix(orgcontract.MemberSourceNodeKey("u1"), orgcontract.MemberSourceNodeKeyPrefix) {
		t.Fatal("MemberSourceNodeKey lost its prefix")
	}
}
