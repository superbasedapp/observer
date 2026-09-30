// SPDX-License-Identifier: BUSL-1.1
// Copyright (c) 2026 SuperBased

package store

import (
	"context"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/mcpintel/correlate"
	"github.com/marmutapp/superbased-observer/internal/mcprelay/record"
)

// TestLoadSessionMCPCalls pins the node seam of P11(a): relay records
// anchored to a session (by coding_session_id, or by an action_ref naming one
// of its tool-use ids with no session anchor - the loopback shape) join the
// session's actions through the shared derivation; another session's calls
// and an unanchored call never attach; completions join their decision.
func TestLoadSessionMCPCalls(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	base := time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339Nano) }
	mustExec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/home/dev/proj', ?)`, ts(0))
	mustExec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('sess-1', 1, 'claude-code', ?), ('sess-2', 1, 'claude-code', ?)`, ts(0), ts(0))
	act := func(sess, key, msg string, turn int, d time.Duration, typ, raw string) {
		mustExec(`INSERT INTO actions (session_id, project_id, timestamp, turn_index, action_type, raw_tool_name, tool, source_file, source_event_id, message_id)
			VALUES (?, 1, ?, ?, ?, ?, 'claude-code', '/t/s.jsonl', ?, ?)`, sess, ts(d), turn, typ, raw, key, msg)
	}
	act("sess-1", "u1", "", 1, 0, "user_prompt", "")
	act("sess-1", "toolu_A", "msg_1", 1, 10*time.Second, "mcp_call", "mcp__github__search_issues")
	act("sess-1", "toolu_B", "msg_2", 1, 40*time.Second, "mcp_call", "mcp__github__get_issue")
	act("sess-1", "r1", "msg_2", 1, 41*time.Second, "read_file", "Read")
	act("sess-2", "toolu_Z", "msg_9", 1, 10*time.Second, "mcp_call", "mcp__github__search_issues")

	relay := record.NewSQLStore(database, "node-k")
	appendDec := func(callID, sessAnchor, actionRef, tool string, d time.Duration) int64 {
		t.Helper()
		conf := record.CorrNone
		if sessAnchor != "" || actionRef != "" {
			conf = record.CorrExact
		}
		res, err := relay.Append(ctx, record.Record{
			Kind: record.KindDecision, TS: base.Add(d).Unix(), VServer: "github", ServerRefHMAC: "hs", ToolRefHMAC: "ht",
			Server: "github", Tool: tool, CallID: callID, CodingSessionID: sessAnchor, ActionRef: actionRef, CorrConfidence: conf,
			Method: "tools/call", EventKind: record.EventCall, Decision: record.DecisionAllow,
			ClientAttestation: record.AttestProcess, CredentialAssurance: "node_enrolled", CaptureLevel: record.CaptureL2,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Record.Seq
	}
	seqA := appendDec("call-A", "sess-1", "toolu_A", "search_issues", 11*time.Second) // exact via tool-use id
	appendDec("call-B", "", "toolu_B", "get_issue", 41*time.Second)                   // loopback: action_ref only
	appendDec("call-S", "sess-1", "", "search_issues", time.Hour)                     // session only
	appendDec("call-Z", "sess-2", "toolu_Z", "search_issues", 11*time.Second)         // other session
	appendDec("call-N", "", "", "search_issues", 12*time.Second)                      // unanchored
	if _, err := relay.Append(ctx, record.Record{
		Kind: record.KindCompletion, TS: base.Add(12 * time.Second).Unix(), CallID: "call-A",
		DecisionSeq: record.Int(seqA), CaptureLevel: record.CaptureL2, ResultStatus: "ok", ResultSizeBytes: record.Int(321), LatencyMS: record.Int(9),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := s.LoadSessionMCPCalls(ctx, "sess-1")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]correlate.Call{}
	for _, c := range res.Calls {
		got[c.CallID] = c
	}
	if len(res.Calls) != 3 {
		t.Fatalf("calls %+v", res.Calls)
	}
	a := got["call-A"]
	if a.Correlation.Confidence != correlate.Exact || a.Correlation.ActionKey != "toolu_A" || a.Correlation.PromptKey != "u1" || !a.Completed ||
		a.ResultSizeBytes == nil || *a.ResultSizeBytes != 321 || a.Sources[0] != correlate.SourceNode {
		t.Fatalf("call-A %+v", a)
	}
	if b := got["call-B"]; b.Correlation.Confidence != correlate.Exact || b.Correlation.ActionKey != "toolu_B" {
		t.Fatalf("call-B (action_ref only) %+v", b.Correlation)
	}
	if sc := got["call-S"]; sc.Correlation.Level != correlate.LevelSession || sc.Correlation.Confidence != correlate.Exact {
		t.Fatalf("call-S %+v", sc.Correlation)
	}
	if _, leaked := got["call-Z"]; leaked {
		t.Fatal("another session's call attached")
	}
	if _, leaked := got["call-N"]; leaked {
		t.Fatal("an unanchored call attached")
	}
	empty, err := s.LoadSessionMCPCalls(ctx, "no-such-session")
	if err != nil || empty.Calls == nil || len(empty.Calls) != 0 {
		t.Fatalf("empty session %+v %v", empty, err)
	}
}

// TestLoadSessionMCPCallsUnanchored pins the node seam of the unanchored
// tier (backlog item 10): an OpenCode-shaped session (its relay tool
// captured as action_type unknown, target "<entry key>_<tool>") gets the
// relay call that carried no anchor, inferred at action level with its
// completion joined; the call shows on exactly that session; a call two
// sessions match too closely is shown on neither and counted ambiguous.
func TestLoadSessionMCPCallsUnanchored(t *testing.T) {
	s, database := newTestStore(t)
	ctx := context.Background()
	mustExec := func(q string, args ...any) {
		t.Helper()
		if _, err := database.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	base := time.Date(2026, 9, 27, 9, 56, 0, 0, time.UTC)
	ts := func(d time.Duration) string { return base.Add(d).Format(time.RFC3339Nano) }
	mustExec(`INSERT INTO projects (id, root_path, created_at) VALUES (1, '/home/dev/proj', ?)`, ts(0))
	mustExec(`INSERT INTO sessions (id, project_id, tool, started_at) VALUES ('ses_oc', 1, 'opencode', ?), ('ses_oc2', 1, 'opencode', ?)`, ts(0), ts(0))
	act := func(sess, key string, d time.Duration, typ, target string) {
		mustExec(`INSERT INTO actions (session_id, project_id, timestamp, turn_index, action_type, raw_tool_name, target, tool, source_file, source_event_id, message_id)
			VALUES (?, 1, ?, 0, ?, ?, ?, 'opencode', '/t/opencode.db', ?, ?)`, sess, ts(d), typ, target, target, key, "msg:"+key)
	}
	const name = "superbased-deepwiki_read_wiki_structure"
	act("ses_oc", "prompt:oc", 0, "user_prompt", "hello")
	act("ses_oc", "part:1", 10*time.Second, "unknown", name)
	act("ses_oc", "part:2", 10*time.Minute, "unknown", name)
	act("ses_oc2", "part:9", 10*time.Minute+2*time.Second, "unknown", name)

	relay := record.NewSQLStore(database, "node-k")
	appendDec := func(callID string, d time.Duration) int64 {
		t.Helper()
		res, err := relay.Append(ctx, record.Record{
			Kind: record.KindDecision, TS: base.Add(d).Unix(), VServer: "deepwiki", ServerRefHMAC: "hs", ToolRefHMAC: "ht",
			Tool: "read_wiki_structure", CallID: callID, CorrConfidence: record.CorrNone,
			Method: "tools/call", EventKind: record.EventCall, Decision: record.DecisionAllow,
			ClientAttestation: record.AttestConfigured, CredentialAssurance: "node_enrolled", CaptureLevel: record.CaptureL2,
		})
		if err != nil {
			t.Fatal(err)
		}
		return res.Record.Seq
	}
	seq := appendDec("call-oc", 11*time.Second)
	appendDec("call-amb", 10*time.Minute+3*time.Second)
	appendDec("call-curl", 2*time.Hour) // a curl proof: no captured action anywhere
	if _, err := relay.Append(ctx, record.Record{
		Kind: record.KindCompletion, TS: base.Add(12 * time.Second).Unix(), CallID: "call-oc",
		DecisionSeq: record.Int(seq), CaptureLevel: record.CaptureL2, ResultStatus: "ok", LatencyMS: record.Int(40),
	}); err != nil {
		t.Fatal(err)
	}

	res, err := s.LoadSessionMCPCalls(ctx, "ses_oc")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Calls) != 1 || res.Totals.Ambiguous != 1 || res.Totals.Inferred != 1 {
		t.Fatalf("ses_oc %+v", res)
	}
	c := res.Calls[0]
	if c.CallID != "call-oc" || c.Correlation.Confidence != correlate.Inferred || c.Correlation.Method != correlate.MethodUnanchoredToolTime ||
		c.Correlation.ActionKey != "part:1" || c.Correlation.PromptKey != "prompt:oc" || !c.Completed || c.LatencyMS == nil {
		t.Fatalf("call-oc %+v", c)
	}
	other, err := s.LoadSessionMCPCalls(ctx, "ses_oc2")
	if err != nil {
		t.Fatal(err)
	}
	if len(other.Calls) != 0 || other.Totals.Ambiguous != 1 {
		t.Fatalf("ses_oc2 %+v", other)
	}
}
