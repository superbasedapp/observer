package orgclient

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// seedBodyActions seeds n actions whose tool bodies are bodyBytes each, the
// shape of the live 2026-11-10 managed node's backlog (~5 KiB per action).
func seedBodyActions(t *testing.T, s *store.Store, n, bodyBytes int) {
	t.Helper()
	ctx := context.Background()
	pid, err := s.UpsertProject(ctx, "/tmp/proj", "git@example.com:acme/app.git")
	if err != nil {
		t.Fatalf("UpsertProject: %v", err)
	}
	if err := s.UpsertSession(ctx, models.Session{
		ID: "s1", ProjectID: pid, Tool: models.ToolClaudeCode, Model: "claude", StartedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("UpsertSession: %v", err)
	}
	acts := make([]models.Action, n)
	for i := range acts {
		acts[i] = models.Action{
			SessionID: "s1", ProjectID: pid, Timestamp: time.Now().UTC(),
			ActionType: models.ActionRunCommand, Target: "go test ./...", Success: true,
			Tool: models.ToolClaudeCode, SourceFile: "f.jsonl", SourceEventID: "e" + strconv.Itoa(i),
			RawToolInput: strings.Repeat("i", bodyBytes/2), RawToolOutput: strings.Repeat("o", bodyBytes/2),
		}
	}
	if _, err := s.InsertActions(ctx, acts); err != nil {
		t.Fatalf("InsertActions: %v", err)
	}
}

// inventoryOf returns an AI tool configuration inventory of rows rows with
// valueBytes of observed text each.
func inventoryOf(rows, valueBytes int) orgcontract.AgentConfigInventoryReport {
	rep := orgcontract.AgentConfigInventoryReport{Digest: "inv-" + strconv.Itoa(rows) + "-" + strconv.Itoa(valueBytes)}
	for i := 0; i < rows; i++ {
		rep.Rows = append(rep.Rows, orgcontract.AgentConfigStateRow{
			Tool: "claude-code", Setting: "claude-code/@skills", FileID: "claude-code/skill:~/.claude/skills/s" + strconv.Itoa(i) + ".md",
			Scope: "user", State: orgcontract.AgentConfigInventoryState,
			ObservedValue: `"` + strings.Repeat("x", valueBytes) + `"`,
		})
	}
	return rep
}

// TestPushOnce_EnvelopeNeverExceedsLimit reproduces the 2026-11-10 managed
// node wedge ("push batch too large", every cycle, a constant ~200 KiB over
// whatever the row count): a backlog that fills the cursor lanes plus an AI
// tool configuration inventory that was attached after the budget check and
// never counted. Every push must now serialize at or under max_push_bytes,
// the backlog must drain, and the inventory must reach the server (cut, and
// flagged Truncated, when it is larger than its share of the envelope).
func TestPushOnce_EnvelopeNeverExceedsLimit(t *testing.T) {
	cases := []struct {
		name          string
		actions, body int
		invRows       int
		invValue      int
		wantCut       bool
	}{
		{name: "live shape: full backlog plus a 200 KiB inventory", actions: 600, body: 5 << 10, invRows: 100, invValue: 2 << 10},
		{name: "inventory larger than its share is cut", actions: 300, body: 5 << 10, invRows: 400, invValue: 2 << 10, wantCut: true},
		{name: "a lone action larger than the envelope", actions: 1, body: 3 << 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newAgentStore(t)
			bs := &memBearerStore{}
			var mu sync.Mutex
			var sizes []int
			var gotInv *orgcontract.AgentConfigInventoryReport
			var actions int
			var lastAction orgcontract.ActionRow
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				wire, _ := io.ReadAll(r.Body)
				raw := gunzip(t, wire)
				env := decodeEnvelope(t, wire)
				mu.Lock()
				sizes = append(sizes, len(raw))
				if env.AgentConfigInventory != nil {
					gotInv = env.AgentConfigInventory
				}
				actions += len(env.Actions)
				if len(env.Actions) > 0 {
					lastAction = env.Actions[len(env.Actions)-1]
				}
				mu.Unlock()
				writeTestJSON(w, http.StatusOK, orgcontract.PushResponse{AcceptedRows: int64(len(env.Actions))})
			}))
			defer srv.Close()
			pub := enrolFixture(t, s, bs, srv.URL)
			bindPub(srv, pub)
			seedBodyActions(t, s, tc.actions, tc.body)
			if tc.invRows > 0 {
				s.SetAgentConfigStateGate(func(context.Context) bool { return true })
				s.SetAgentConfigInventory(inventoryOf(tc.invRows, tc.invValue))
			}
			c := newTestClient(t, s, bs)
			c.cfg.Share.AdminManaged, c.cfg.Share.FullToolBodies = true, true
			limit := int(c.maxPushBytes())

			for i := 0; i < 50; i++ {
				res, err := c.PushOnce(context.Background())
				if err != nil {
					t.Fatalf("push %d: %v (sizes so far %v)", i, err, sizes)
				}
				if res.Empty {
					break
				}
			}
			for i, n := range sizes {
				if n > limit {
					t.Fatalf("push %d serialized %d bytes > limit %d", i, n, limit)
				}
			}
			if actions != tc.actions {
				t.Fatalf("server received %d actions, want the whole backlog %d", actions, tc.actions)
			}
			if tc.invRows > 0 {
				if gotInv == nil {
					t.Fatal("the inventory never reached the server")
				}
				if cut := len(gotInv.Rows) < tc.invRows; cut != tc.wantCut || gotInv.Truncated != tc.wantCut {
					t.Fatalf("inventory rows %d/%d truncated=%v, want cut=%v", len(gotInv.Rows), tc.invRows, gotInv.Truncated, tc.wantCut)
				}
			}
			if tc.body > limit {
				if !strings.Contains(lastAction.RawToolOutput+lastAction.RawToolInput, "cut to fit the org push limit") {
					t.Fatal("an action cut to fit must carry the cut marker")
				}
				ov, err := s.LoadOrgPushOversizedRows(context.Background())
				if err != nil || len(ov) == 0 || !ov[0].Cut {
					t.Fatalf("the cut must be recorded in the oversized-row report: %+v, %v", ov, err)
				}
			}
			if tc.wantCut {
				ov, _ := s.LoadOrgPushOversizedRows(context.Background())
				found := false
				for _, r := range ov {
					found = found || (r.Family == "envelope_agent_config_inventory" && r.Cut && r.Rows > 0)
				}
				if !found {
					t.Fatalf("the inventory cut must be recorded: %+v", ov)
				}
			}
		})
	}
}
