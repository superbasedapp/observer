// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package orgclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"regexp"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/db/dbtemplate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// seedFreshAction inserts ONE action with a unique source event id so the
// next push has a non-empty batch (seedActivity's fixed ids dedup on re-seed,
// which would silently skip the push and leave the captured envelope stale).
func seedFreshAction(t *testing.T, s *store.Store, id string) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "git@example.com:acme/app.git")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.UpsertSession(ctx, models.Session{ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.InsertActions(ctx, []models.Action{{
		SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(), ActionType: models.ActionReadFile, Target: "a.go", Success: true,
		Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: id,
	}}); err != nil {
		t.Fatal(err)
	}
}

// capturePushServer is an org server stub that records the last envelope.
func capturePushServer(t *testing.T) (*httptest.Server, *orgcontract.PushEnvelope) {
	t.Helper()
	env := &orgcontract.PushEnvelope{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		wire, _ := io.ReadAll(r.Body)
		*env = decodeEnvelope(t, wire)
		writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{
			AcceptedRows: int64(len(env.Sessions) + len(env.Actions)), NextCursor: env.CursorTo,
		})
	}))
	t.Cleanup(srv.Close)
	return srv, env
}

// TestPushOnce_SourceNodeKeyFromKeySlot: with the agent-access key slot wired
// the envelope carries SHA-256(thumbprint); without it the key is absent and
// the envelope is pre-P4-shaped (W4e, R8.30.a).
func TestPushOnce_SourceNodeKeyFromKeySlot(t *testing.T) {
	s := newAgentStore(t)
	bs := &memBearerStore{}
	srv, env := capturePushServer(t)
	bindPub(srv, enrolFixture(t, s, bs, srv.URL))
	seedActivity(t, s, 2)

	keys := &memAgentAccessKeys{}
	k, created, err := EnsureAgentAccessKey(keys)
	if err != nil || !created {
		t.Fatalf("EnsureAgentAccessKey: created=%v err=%v", created, err)
	}
	want, err := SourceNodeKeyForKey(k)
	if err != nil || !hex64.MatchString(want) {
		t.Fatalf("SourceNodeKeyForKey = %q err=%v", want, err)
	}
	c := newTestClient(t, s, bs)
	c.SetAgentAccessKeyStore(keys)
	if _, err := c.PushOnce(context.Background()); err != nil {
		t.Fatalf("PushOnce: %v", err)
	}
	if env.SourceNodeKey != want {
		t.Fatalf("source_node_key = %q, want %q", env.SourceNodeKey, want)
	}

	// The same node with an EMPTY slot ships no key at all - and never fails
	// the push over it.
	seedFreshAction(t, s, "fresh-1")
	*env = orgcontract.PushEnvelope{SourceNodeKey: "stale"}
	c2 := newTestClient(t, s, bs)
	c2.SetAgentAccessKeyStore(&memAgentAccessKeys{})
	if r, err := c2.PushOnce(context.Background()); err != nil || r.Empty {
		t.Fatalf("PushOnce (empty slot): res=%+v err=%v", r, err)
	}
	if env.SourceNodeKey != "" {
		t.Fatalf("empty slot shipped source_node_key %q", env.SourceNodeKey)
	}
	if _, err := SourceNodeKeyForKey(AgentAccessKey{}); err == nil {
		t.Fatal("SourceNodeKeyForKey accepted a key with no signer")
	}
}

// TestShareOptionsFromConfig_MCPActivity pins the [org_client.share].
// mcp_activity -> ShareOptions.MCPActivity mapping and its default.
func TestShareOptionsFromConfig_MCPActivity(t *testing.T) {
	if ShareOptionsFromConfig(config.OrgClientConfig{}).MCPActivity {
		t.Fatal("mcp_activity defaults ON - it must be an explicit individual-node opt-in")
	}
	cfg := config.OrgClientConfig{Share: config.OrgClientShareConfig{MCPActivity: true}}
	if !ShareOptionsFromConfig(cfg).MCPActivity {
		t.Fatal("mcp_activity = true did not map onto ShareOptions.MCPActivity")
	}
}

// TestPushOnce_IndividualMCPActivityShipsAggregateOnly is the end-to-end W4e
// consent proof through the real push loop: an individual node opted into
// mcp_activity ships the HMAC-only aggregate and NO per-record events; the
// managed posture (full_content) ships both.
func TestPushOnce_IndividualMCPActivityShipsAggregateOnly(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.db")
	database, err := dbtemplate.Open(context.Background(), db.Options{Path: path})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	s := store.New(database)
	bs := &memBearerStore{}
	srv, env := capturePushServer(t)
	bindPub(srv, enrolFixture(t, s, bs, srv.URL))

	relay := record.NewSQLStore(database, "node-a")
	ctx := context.Background()
	res, err := relay.Append(ctx, record.Record{
		Kind: record.KindDecision, TS: 1790000000, VServer: "vs-github", ToolRefHMAC: "h-tool", Server: "github", Tool: "create_issue",
		CallID: "c1", CorrConfidence: record.CorrExact, EventKind: record.EventCall, Decision: record.DecisionAllow,
		ClientAttestation: record.AttestProcess, CredentialAssurance: "node_enrolled",
		CaptureLevel: record.CaptureL2, ArgsFull: `{"title":"secret plan"}`, ArgsScrubStatus: record.ScrubStructured,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := relay.Append(ctx, record.Record{
		Kind: record.KindCompletion, TS: 1790000001, CallID: "c1", DecisionSeq: record.Int(res.Record.Seq),
		CaptureLevel: record.CaptureL2, ResultStatus: "ok", ResultFull: `{"n":1}`, ResultScrubStatus: record.ScrubStructured,
	}); err != nil {
		t.Fatal(err)
	}
	// The relay rows are dated 2026-09-21; the aggregate windows on "now",
	// so widen nothing - they are inside the 7-day window at test time only
	// if now is close. Use the events (cursor wire, unwindowed) as the
	// managed-posture proof and the aggregate's presence as the opt-in proof.
	base := config.OrgClientConfig{
		Enabled: true, PushIntervalSeconds: config.DefaultPushIntervalSeconds,
		MaxPushBytes: config.DefaultMaxPushBytes, KeychainID: config.DefaultKeychainID,
	}

	individual := base
	individual.Share = config.OrgClientShareConfig{MCPActivity: true}
	seedFreshAction(t, s, "fresh-a")
	if r, err := New(individual, s, bs, "test-version", http.DefaultClient, quietLogger()).PushOnce(ctx); err != nil || r.Empty {
		t.Fatalf("individual PushOnce: res=%+v err=%v", r, err)
	}
	if len(env.MCPRelayEvents) != 0 {
		t.Fatalf("individual node shipped %d per-record relay events", len(env.MCPRelayEvents))
	}
	for _, a := range env.MCPRelayActivity {
		if a.ToolRefHMAC != "h-tool" || a.Decision != "allow" {
			t.Fatalf("aggregate row = %+v", a)
		}
	}

	managed := base
	managed.Share = config.OrgClientShareConfig{FullContent: true}
	seedFreshAction(t, s, "fresh-b")
	*env = orgcontract.PushEnvelope{}
	if r, err := New(managed, s, bs, "test-version", http.DefaultClient, quietLogger()).PushOnce(ctx); err != nil || r.Empty {
		t.Fatalf("managed PushOnce: res=%+v err=%v", r, err)
	}
	if len(env.MCPRelayEvents) != 2 {
		t.Fatalf("managed node shipped %d relay events, want decision + completion", len(env.MCPRelayEvents))
	}
	d, c := env.MCPRelayEvents[0], env.MCPRelayEvents[1]
	if d.RecordKind != "decision" || d.Server != "github" || d.Tool != "create_issue" || d.ArgsFull != `{"title":"secret plan"}` {
		t.Fatalf("decision event = %+v", d)
	}
	if c.RecordKind != "completion" || c.ResultFull != `{"n":1}` || c.LocalRecordSeq != d.LocalRecordSeq+1 {
		t.Fatalf("completion event = %+v", c)
	}
	// Delivered exactly once: the cursor advanced, so the next push carries
	// no relay events.
	seedFreshAction(t, s, "fresh-c")
	*env = orgcontract.PushEnvelope{MCPRelayEvents: []orgcontract.MCPRelayEventRow{{RecordKind: "stale"}}}
	if r, err := New(managed, s, bs, "test-version", http.DefaultClient, quietLogger()).PushOnce(ctx); err != nil || r.Empty {
		t.Fatalf("managed PushOnce 2: res=%+v err=%v", r, err)
	}
	if len(env.MCPRelayEvents) != 0 {
		t.Fatalf("relay events re-shipped after the cursor advanced: %d", len(env.MCPRelayEvents))
	}
}
