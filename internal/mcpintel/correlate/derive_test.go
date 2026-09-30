package correlate

import (
	"encoding/json"
	"testing"
	"time"
)

const sess = "0b7c9e4e-1111-4a2b-9c3d-000000000001"

var t0 = time.Date(2026, 9, 25, 12, 0, 0, 0, time.UTC)

func i64(v int64) *int64 { return &v }

// actions is a small Claude-Code-shaped session: two turns, each opened by a
// user prompt, with MCP calls named mcp__<server>__<tool>.
func actions() []Action {
	return []Action{
		{Key: "u1", ActionType: actionTypeUserPrompt, TurnIndex: i64(1), TS: t0},
		{Key: "toolu_A", MessageID: "msg_1", TurnIndex: i64(1), TS: t0.Add(10 * time.Second), ActionType: actionTypeMCPCall, RawToolName: "mcp__github__search_issues"},
		{Key: "toolu_B", MessageID: "msg_1", TurnIndex: i64(1), TS: t0.Add(11 * time.Second), ActionType: actionTypeMCPCall, RawToolName: "mcp__github__get_issue"},
		{Key: "u2", ActionType: actionTypeUserPrompt, TurnIndex: i64(2), TS: t0.Add(5 * time.Minute)},
		{Key: "toolu_C", MessageID: "msg_2", TurnIndex: i64(2), TurnID: "turn-2", TS: t0.Add(5*time.Minute + 20*time.Second), ActionType: actionTypeMCPCall, RawToolName: "mcp__linear__create_issue"},
		{Key: "read_1", MessageID: "msg_2", TurnIndex: i64(2), TS: t0.Add(5*time.Minute + 21*time.Second), ActionType: "read_file"},
	}
}

func dec(callID string, ts time.Time, mut func(*Record)) Record {
	r := Record{Source: SourceNode, Kind: KindDecision, CallID: callID, TS: ts.Unix(), Trusted: true, Decision: "allow", CaptureLevel: "L2"}
	if mut != nil {
		mut(&r)
	}
	return r
}

// TestRulesTable pins one case per row of the rules table (CLAUDE.md #5).
func TestRulesTable(t *testing.T) {
	cases := []struct {
		name       string
		rec        Record
		wantConf   Confidence
		wantLevel  Level
		wantMethod string
		wantAction string
		wantPrompt string
	}{
		{
			"1 untrusted carrier (direct OAuth / API-key client) is none even with anchors",
			dec("c1", t0.Add(10*time.Second), func(r *Record) { r.Trusted = false; r.CodingSessionID = sess; r.ActionRef = "toolu_A" }),
			None, LevelNone, MethodUntrusted, "", "",
		},
		{
			"2 action_ref = tool-use id is exact at action level",
			dec("c2", t0.Add(10*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "toolu_A"; r.Tool = "search_issues" }),
			Exact, LevelAction, MethodActionRef, "toolu_A", "u1",
		},
		{
			"2b action_ref outranks a stale session env",
			dec("c2b", t0.Add(10*time.Second), func(r *Record) { r.CodingSessionID = "stale-session"; r.ActionRef = "toolu_A" }),
			Exact, LevelAction, MethodActionRef, "toolu_A", "u1",
		},
		{
			"3 action_ref = message id narrowed by tool name is exact",
			dec("c3", t0.Add(11*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "msg_1"; r.Tool = "get_issue" }),
			Exact, LevelAction, MethodActionRefMessage, "toolu_B", "u1",
		},
		{
			"3b action_ref = message id with two MCP calls and no tool name pins the turn",
			dec("c3b", t0.Add(11*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "msg_1" }),
			Exact, LevelTurn, MethodActionRefMessage, "", "u1",
		},
		{
			"4 anchored to another session is none",
			dec("c4", t0.Add(10*time.Second), func(r *Record) { r.CodingSessionID = "other-session"; r.Tool = "search_issues" }),
			None, LevelNone, MethodSessionMismatch, "", "",
		},
		{
			"6 no session anchor (an action_ref naming no action here) is none",
			dec("c5", t0.Add(10*time.Second), func(r *Record) { r.Tool = "search_issues"; r.ActionRef = "toolu_elsewhere" }),
			None, LevelNone, MethodNoAnchor, "", "",
		},
		{
			"6 unresolved action_ref in an anchored session is inferred at session level",
			dec("c6", t0.Add(10*time.Second), func(r *Record) {
				r.CodingSessionID = sess
				r.ActionRef = "toolu_not_ingested"
				r.Tool = "search_issues"
			}),
			Inferred, LevelSession, MethodActionRefUnresolved, "", "",
		},
		{
			"7 turn_ref with a single tool match is an inferred action",
			dec("c7", t0.Add(5*time.Minute+20*time.Second), func(r *Record) { r.CodingSessionID = sess; r.TurnRef = "turn-2"; r.Tool = "create_issue" }),
			Inferred, LevelAction, MethodTurnRefTool, "toolu_C", "u2",
		},
		{
			"7b turn_ref (turn_index) without a tool match is exact at turn level",
			dec("c7b", t0.Add(15*time.Second), func(r *Record) { r.CodingSessionID = sess; r.TurnRef = "1"; r.Tool = "unknown_tool" }),
			Exact, LevelTurn, MethodTurnRef, "", "u1",
		},
		{
			"8 session + tool name + time window is an inferred action",
			dec("c8", t0.Add(12*time.Second), func(r *Record) { r.CodingSessionID = sess; r.Tool = "search_issues" }),
			Inferred, LevelAction, MethodSessionToolTime, "toolu_A", "u1",
		},
		{
			"9 session + time window without a name (a tools/call below L2) needs a single candidate",
			dec("c9", t0.Add(5*time.Minute+25*time.Second), func(r *Record) { r.CodingSessionID = sess; r.Method = "tools/call"; r.CaptureLevel = "L1" }),
			Inferred, LevelAction, MethodSessionTime, "toolu_C", "u2",
		},
		{
			"10 session-anchored call with nothing finer is exact at session level",
			dec("c10", t0.Add(time.Hour), func(r *Record) { r.CodingSessionID = sess; r.Tool = "search_issues" }),
			Exact, LevelSession, MethodSessionOnly, "", "",
		},
		{
			"9b two candidates in the window without a name falls back to the session",
			dec("c9b", t0.Add(12*time.Second), func(r *Record) { r.CodingSessionID = sess }),
			Exact, LevelSession, MethodSessionOnly, "", "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Derive(DeriveInput{SessionID: sess, Records: []Record{tc.rec}, Actions: actions()})
			if tc.wantConf == None {
				if len(res.Calls) != 0 || res.Totals.Unlinked != 1 {
					t.Fatalf("a none link must never attach: %+v", res)
				}
				p := groupsFor(t, tc.rec)
				if p.link.Method != tc.wantMethod {
					t.Fatalf("method %q want %q", p.link.Method, tc.wantMethod)
				}
				return
			}
			if len(res.Calls) != 1 {
				t.Fatalf("calls %+v", res)
			}
			l := res.Calls[0].Correlation
			if l.Confidence != tc.wantConf || l.Level != tc.wantLevel || l.Method != tc.wantMethod || l.ActionKey != tc.wantAction || l.PromptKey != tc.wantPrompt {
				t.Fatalf("link %+v, want %s/%s/%s action=%q prompt=%q", l, tc.wantConf, tc.wantLevel, tc.wantMethod, tc.wantAction, tc.wantPrompt)
			}
		})
	}
}

// groupsFor runs the rules for one record without the attach filter.
func groupsFor(t *testing.T, r Record) *pending {
	t.Helper()
	g, _ := groupRecords([]Record{r})
	idx := newSessionIndex(sess, actions())
	for ph := phaseAnchored; ph <= phaseUnanchored; ph++ {
		if g[0].resolve(idx, ph) {
			break
		}
	}
	return g[0]
}

// TestSpoofedAnchorsOnNonRelayIgnored: a gateway copy from a non-relay token
// carrying anchors contributes nothing; the trusted node copy's anchors win.
func TestSpoofedAnchorsOnNonRelayIgnored(t *testing.T) {
	spoof := dec("c1", t0.Add(10*time.Second), func(r *Record) {
		r.Source, r.Trusted, r.CodingSessionID, r.ActionRef, r.Decision, r.ArgsFull = SourceGateway, false, sess, "toolu_B", "deny", `{"spoof":1}`
	})
	spoofComp := Record{Source: SourceGateway, Kind: KindCompletion, CallID: "c1", ResultStatus: "error", ResultFull: "spoofed"}
	node := dec("c1", t0.Add(10*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "toolu_A" })
	res := Derive(DeriveInput{SessionID: sess, Records: []Record{spoof, spoofComp, node}, Actions: actions()})
	if len(res.Calls) != 1 || res.Calls[0].Correlation.ActionKey != "toolu_A" || res.Calls[0].ActionRef != "toolu_A" {
		t.Fatalf("spoofed anchor leaked: %+v", res.Calls)
	}
	// Reusing a relay call's id folds NOTHING of the untrusted copy in.
	if c := res.Calls[0]; c.Decision != "allow" || c.ArgsFull != "" || c.Completed || len(c.Sources) != 1 || res.Totals.Unlinked != 1 {
		t.Fatalf("untrusted copy folded into the relay call: %+v totals %+v", c, res.Totals)
	}
	// Alone, the spoofing copy never attaches.
	if res := Derive(DeriveInput{SessionID: sess, Records: []Record{spoof}, Actions: actions()}); len(res.Calls) != 0 {
		t.Fatalf("untrusted copy attached: %+v", res.Calls)
	}
}

// TestDedupeOnCallID: the gateway row, the node row and a re-pushed node row
// of ONE call fold into one call; completions join; the gateway copy wins
// the verdict, the node copy fills what the gateway lacks.
func TestDedupeOnCallID(t *testing.T) {
	gw := dec("call-1", t0.Add(10*time.Second), func(r *Record) {
		r.Source, r.Decision, r.CodingSessionID, r.ActionRef, r.Tool = SourceGateway, "pass", sess, "toolu_A", "search_issues"
	})
	node := dec("call-1", t0.Add(9*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "toolu_A"; r.VirtualServer = "github" })
	repush := node
	comp := Record{Source: SourceNode, Kind: KindCompletion, CallID: "call-1", Trusted: true, TS: t0.Add(11 * time.Second).Unix(), ResultStatus: "ok", LatencyMS: i64(42)}
	gwComp := Record{Source: SourceGateway, Kind: KindCompletion, CallID: "call-1", Trusted: true, TS: t0.Add(11 * time.Second).Unix(), ResultStatus: "ok", ResultTokensEst: i64(120)}
	other := dec("call-2", t0.Add(11*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "toolu_B" })
	res := Derive(DeriveInput{SessionID: sess, Records: []Record{repush, comp, gw, node, other, gwComp}, Actions: actions()})
	if len(res.Calls) != 2 || res.Totals.Exact != 2 {
		t.Fatalf("calls %+v", res)
	}
	c := res.Calls[0]
	if c.CallID != "call-1" || c.Decision != "pass" || c.VirtualServer != "github" || !c.Completed || c.LatencyMS == nil || *c.LatencyMS != 42 ||
		c.ResultTokensEst == nil || !c.TokensEstimated || c.TS != t0.Add(9*time.Second).Unix() {
		t.Fatalf("merged call %+v", c)
	}
	if len(c.Sources) != 2 || c.Sources[0] != SourceGateway || c.Sources[1] != SourceNode {
		t.Fatalf("sources %v", c.Sources)
	}
	if res.Totals.FoldedDuplicates != 3 || c.FoldedDuplicateRecords != 3 {
		t.Fatalf("folded %d / %d", res.Totals.FoldedDuplicates, c.FoldedDuplicateRecords)
	}
}

// TestExactClaimsBeforeHeuristics: an exactly anchored call claims its
// action before a heuristic call could take it, whatever the input order.
func TestExactClaimsBeforeHeuristics(t *testing.T) {
	heur := dec("h", t0.Add(10*time.Second), func(r *Record) { r.CodingSessionID = sess; r.Tool = "search_issues" })
	exact := dec("x", t0.Add(20*time.Second), func(r *Record) { r.CodingSessionID = sess; r.ActionRef = "toolu_A" })
	res := Derive(DeriveInput{SessionID: sess, Records: []Record{heur, exact}, Actions: actions()})
	got := map[string]Link{}
	for _, c := range res.Calls {
		got[c.CallID] = c.Correlation
	}
	if got["x"].ActionKey != "toolu_A" || got["x"].Confidence != Exact {
		t.Fatalf("exact %+v", got["x"])
	}
	if got["h"].Level != LevelSession || got["h"].ActionKey != "" {
		t.Fatalf("heuristic must not steal the claimed action: %+v", got["h"])
	}
}

// TestCompletionOnlyAndLimit: a completion without its decision never
// attaches; Limit truncates honestly.
func TestCompletionOnlyAndLimit(t *testing.T) {
	recs := []Record{{Source: SourceNode, Kind: KindCompletion, CallID: "orphan", ResultStatus: "ok"}}
	for i := 0; i < 5; i++ {
		recs = append(recs, dec(string(rune('a'+i)), t0.Add(time.Duration(i)*time.Hour), func(r *Record) { r.CodingSessionID = sess }))
	}
	res := Derive(DeriveInput{SessionID: sess, Records: recs, Actions: actions(), Limit: 3})
	if len(res.Calls) != 3 || !res.Truncated || res.Totals.Calls != 5 {
		t.Fatalf("limit %+v", res)
	}
	for _, c := range res.Calls {
		if c.CallID == "orphan" {
			t.Fatal("completion-only call attached")
		}
	}
}

// TestNameNormalization: registry names with characters an AI client folds
// still match the namespaced tool name.
func TestNameNormalization(t *testing.T) {
	acts := []Action{{Key: "k", ActionType: actionTypeMCPCall, RawToolName: "mcp__my_server__do_thing", TS: t0}}
	r := dec("n", t0.Add(time.Second), func(r *Record) { r.CodingSessionID = sess; r.Tool = "do-thing"; r.Server = "my.server" })
	res := Derive(DeriveInput{SessionID: sess, Records: []Record{r}, Actions: acts})
	if len(res.Calls) != 1 || res.Calls[0].Correlation.ActionKey != "k" {
		t.Fatalf("%+v", res.Calls)
	}
}

func TestParseTimestamp(t *testing.T) {
	want := time.Date(2026, 9, 25, 12, 0, 1, 0, time.UTC)
	for _, s := range []string{"2026-09-25T12:00:01Z", "2026-09-25T12:00:01.000Z", "2026-09-25 12:00:01", "2026-09-25T12:00:01", "1790337601", "1790337601000"} {
		got, ok := ParseTimestamp(s)
		if !ok || !got.Equal(want) {
			t.Errorf("%q -> %v %v", s, got, ok)
		}
	}
	if _, ok := ParseTimestamp("not a time"); ok {
		t.Error("garbage parsed")
	}
}

// TestWireShape pins the JSON field names the node panel and the org drawer
// render (the UI lane builds against these).
func TestWireShape(t *testing.T) {
	res := Derive(DeriveInput{SessionID: sess, Records: []Record{dec("c", t0.Add(10*time.Second), func(r *Record) {
		r.CodingSessionID = sess
		r.ActionRef = "toolu_A"
	})}, Actions: actions()})
	b, err := json.Marshal(res)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	for _, k := range []string{"session_id", "calls", "totals", "truncated"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing %q in %s", k, b)
		}
	}
	call := m["calls"].([]any)[0].(map[string]any)
	corr := call["correlation"].(map[string]any)
	for _, k := range []string{"confidence", "level", "method", "action_key", "turn_index", "prompt_key"} {
		if _, ok := corr[k]; !ok {
			t.Errorf("missing correlation.%q in %s", k, b)
		}
	}
	for _, k := range []string{"call_id", "sources", "ts", "completed"} {
		if _, ok := call[k]; !ok {
			t.Errorf("missing call.%q in %s", k, b)
		}
	}
}
