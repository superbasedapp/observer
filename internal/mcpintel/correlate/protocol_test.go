package correlate

import (
	"testing"
	"time"
)

// Protocol records (initialize, notifications/*, tools/list, ...) never
// claim an action (defect D1, found live on demo node-1 2026-09-28): the
// relay records every JSON-RPC message of an MCP session, and the nameless
// protocol messages are processed first (oldest first) - before the fix they
// claimed the one captured tool call the session's tools/call belongs to,
// which then fell back to session level.

// liveTS is the ses_f1b31faf3ffevJtLbO7uio9k5H relay timeline (unix s).
const liveTS = 1790545103

func liveAt(off int64) time.Time { return time.Unix(liveTS+off, 0).UTC() }

// liveRec is one node relay record of the live OpenCode session: loopback
// slug "deepwiki", L2 capture, no anchor. stripMethod models the org copy
// of a node-only record pushed before the method rode the wire.
func liveRec(callID, method, tool string, off int64, stripMethod bool) Record {
	r := dec(callID, liveAt(off), func(r *Record) {
		r.VirtualServer, r.Method, r.Tool = "deepwiki", method, tool
	})
	if stripMethod {
		r.Method = ""
	}
	return r
}

// liveGateway is the org front's copy of a relay-forwarded call (vserver /
// server ids, the method always captured).
func liveGateway(callID, method, tool string, off int64) Record {
	return dec(callID, liveAt(off), func(r *Record) {
		r.Source, r.VirtualServer, r.Server, r.Method, r.Tool = SourceGateway, "vs_cf944fb69cef79f2", "srv_303c8f9ab45f0015", method, tool
	})
}

// liveRecords is the session's five relay decisions (the order they were
// recorded in; Derive sorts by ts then call id, so the protocol records of
// the same second as the tools/call still run first).
func liveRecords(stripMethod bool) []Record {
	return []Record{
		liveRec("c6n-initialized", "notifications/initialized", "", 0, stripMethod),
		liveRec("a-initialize", "initialize", "", 0, stripMethod),
		liveRec("b-tools-list", "tools/list", "", 1, stripMethod),
		liveRec("a-cancelled", "notifications/cancelled", "", 4, stripMethod),
		liveRec("z-tools-call", "tools/call", "read_wiki_structure", 4, stripMethod),
	}
}

const livePart = "part:prt_0e4ce19e2001teXgMkNsXwRtWF"

func livePool(sid string) []PoolAction {
	return []PoolAction{poolAct(sid, livePart, liveAt(2), actionTypeUnknown, ocName)}
}

func TestProtocolRecordsNeverClaim(t *testing.T) {
	type want struct {
		level  Level
		method string
		action string
	}
	protocol := want{LevelSession, MethodUnanchoredProtocol, ""}
	toolCall := want{LevelAction, MethodUnanchoredToolTime, livePart}
	cases := []struct {
		name string
		recs []Record
		want map[string]want
	}{
		{
			name: "live ses_f1b31 shape (node panel): tools/call owns the action, protocol is session level",
			recs: liveRecords(false),
			want: map[string]want{
				"c6n-initialized": protocol, "a-initialize": protocol, "b-tools-list": protocol,
				"a-cancelled": protocol, "z-tools-call": toolCall,
			},
		},
		{
			name: "same records with the method stripped (org copy pushed before it shipped): same verdicts",
			recs: liveRecords(true),
			want: map[string]want{
				"c6n-initialized": protocol, "a-initialize": protocol, "b-tools-list": protocol,
				"a-cancelled": protocol, "z-tools-call": toolCall,
			},
		},
		{
			name: "org fold: gateway + node copies of initialize and tools/call fold and keep the verdicts",
			recs: append(liveRecords(true),
				liveGateway("a-initialize", "initialize", "", 0),
				liveGateway("z-tools-call", "tools/call", "read_wiki_structure", 4)),
			want: map[string]want{
				"c6n-initialized": protocol, "a-initialize": protocol, "b-tools-list": protocol,
				"a-cancelled": protocol, "z-tools-call": toolCall,
			},
		},
		{
			name: "live ses_f1db shape: tools/list recorded first at the same second as the initialized notification",
			recs: []Record{
				liveRec("-bdq-tools-list", "tools/list", "", 0, false),
				liveRec("fSc-initialized", "notifications/initialized", "", 0, false),
				liveRec("ssY-tools-call", "tools/call", "read_wiki_structure", 4, false),
				liveRec("x5r-cancelled", "notifications/cancelled", "", 4, false),
			},
			want: map[string]want{
				"-bdq-tools-list": protocol, "fSc-initialized": protocol, "x5r-cancelled": protocol, "ssY-tools-call": toolCall,
			},
		},
		{
			name: "a protocol record alone is session level and leaves the action unclaimed",
			recs: []Record{liveRec("init", "initialize", "", 0, false)},
			want: map[string]want{"init": protocol},
		},
		{
			name: "prompts/get names a prompt, not a tool call: session level, never claims",
			recs: []Record{
				liveRec("p", "prompts/get", "read_wiki_structure", 1, false),
				liveRec("z-tools-call", "tools/call", "read_wiki_structure", 4, false),
			},
			want: map[string]want{"p": protocol, "z-tools-call": toolCall},
		},
		{
			name: "a tools/call below L2 (no tool name) still claims the one server-named candidate",
			recs: []Record{
				liveRec("init", "initialize", "", 0, false),
				dec("l1-call", liveAt(4), func(r *Record) { r.VirtualServer, r.Method, r.CaptureLevel = "deepwiki", "tools/call", "L1" }),
			},
			want: map[string]want{"init": protocol, "l1-call": {LevelAction, MethodUnanchoredServerTime, livePart}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Derive(DeriveInput{
				SessionID: sessOC, Records: tc.recs, Pool: livePool(sessOC),
				Actions: []Action{ocPrompt(sessOC, liveAt(-30))},
			})
			if len(res.Calls) != len(tc.want) || res.Totals.Unlinked != 0 || res.Totals.Ambiguous != 0 {
				t.Fatalf("calls %d totals %+v, want %d attached", len(res.Calls), res.Totals, len(tc.want))
			}
			claimed := 0
			for _, c := range res.Calls {
				w, ok := tc.want[c.CallID]
				if !ok {
					t.Fatalf("unexpected call %q", c.CallID)
				}
				l := c.Correlation
				if l.Level != w.level || l.Method != w.method || l.ActionKey != w.action || l.Confidence != Inferred {
					t.Errorf("%s: link %+v, want %s/%s action=%q", c.CallID, l, w.level, w.method, w.action)
				}
				if l.ActionKey != "" {
					claimed++
				}
				if w.level == LevelSession && (l.PromptKey != "" || l.MessageID != "" || l.TurnIndex != nil) {
					t.Errorf("%s: a session-level link carries finer fields: %+v", c.CallID, l)
				}
			}
			if hasTool := tc.want["z-tools-call"].action != "" || tc.want["ssY-tools-call"].action != "" || tc.want["l1-call"].action != ""; hasTool && claimed != 1 {
				t.Errorf("the action was claimed %d times, want once (by the tool call)", claimed)
			}
		})
	}
}

// TestProtocolOwnerKeepsTheSeparationRule: a protocol record is owned by the
// same nearest-session rule (>= InferSessionSeparation, otherwise ambiguous
// and shown nowhere) - it only never claims.
func TestProtocolOwnerKeepsTheSeparationRule(t *testing.T) {
	cases := []struct {
		name       string
		pool       []PoolAction
		wantMethod string // "" = dropped (another session owns it / no match)
		wantAmbig  int
	}{
		{
			name:       "two sessions within 10 s: ambiguous, attached nowhere, counted",
			pool:       append(livePool(sessOC), poolAct(sessOC2, "b:1", liveAt(-2), actionTypeUnknown, ocName)),
			wantMethod: MethodUnanchoredAmbiguous, wantAmbig: 1,
		},
		{
			name: "another session clearly nearer: dropped here",
			pool: []PoolAction{
				poolAct(sessOC, "a:1", liveAt(-60), actionTypeUnknown, ocName),
				poolAct(sessOC2, "b:1", liveAt(2), actionTypeUnknown, ocName),
			},
		},
		{
			name: "this session clearly nearer than a second one: session level here",
			pool: []PoolAction{
				poolAct(sessOC, "a:1", liveAt(2), actionTypeUnknown, ocName),
				poolAct(sessOC2, "b:1", liveAt(-60), actionTypeUnknown, ocName),
			},
			wantMethod: MethodUnanchoredProtocol,
		},
		{
			name: "two tool calls of THIS session only: still one owner, session level (not ambiguous)",
			pool: []PoolAction{
				poolAct(sessOC, "a:1", liveAt(2), actionTypeUnknown, ocName),
				poolAct(sessOC, "a:2", liveAt(-5), actionTypeUnknown, "superbased-deepwiki_ask_question"),
			},
			wantMethod: MethodUnanchoredProtocol,
		},
		{
			name: "no action naming the server in the window: not shown",
			pool: []PoolAction{poolAct(sessOC, "a:1", liveAt(2), actionTypeUnknown, "otherserver_read_wiki_structure")},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Derive(DeriveInput{SessionID: sessOC, Records: []Record{liveRec("n", "notifications/initialized", "", 0, false)}, Pool: tc.pool})
			if res.Totals.Ambiguous != tc.wantAmbig {
				t.Fatalf("totals %+v", res.Totals)
			}
			switch tc.wantMethod {
			case "":
				if len(res.Calls) != 0 || res.Totals.Unlinked != 0 {
					t.Fatalf("attached or counted: %+v", res)
				}
			case MethodUnanchoredAmbiguous:
				if len(res.Calls) != 0 || res.Totals.Unlinked != 1 {
					t.Fatalf("an ambiguous call must attach nowhere: %+v", res)
				}
			default:
				if len(res.Calls) != 1 || res.Calls[0].Correlation.Method != tc.wantMethod || res.Calls[0].Correlation.Level != LevelSession {
					t.Fatalf("%+v", res.Calls)
				}
			}
		})
	}
}

// TestAnchoredProtocolRecordsNeverClaim: the anchored rows apply the same
// predicate - an anchored initialize / tools/list never takes the action
// its session's tools/call is matched to (rules 3, 8, 10).
func TestAnchoredProtocolRecordsNeverClaim(t *testing.T) {
	cases := []struct {
		name       string
		proto      Record
		call       Record
		wantProto  Link // Confidence / Level / Method compared
		wantAction string
		wantMethod string
	}{
		{
			name:       "rule 10: a nameless anchored notification does not take the only MCP action",
			proto:      dec("a-n", t0.Add(5*time.Minute+21*time.Second), func(r *Record) { r.CodingSessionID, r.Method = sess, "notifications/initialized" }),
			call:       dec("z-c", t0.Add(5*time.Minute+22*time.Second), func(r *Record) { r.CodingSessionID, r.Method, r.CaptureLevel = sess, "tools/call", "L1" }),
			wantProto:  Link{Confidence: Exact, Level: LevelSession, Method: MethodSessionOnly},
			wantAction: "toolu_C", wantMethod: MethodSessionTime,
		},
		{
			name:       "rule 10 with the method stripped at L2 (org legacy copy): same",
			proto:      dec("a-n", t0.Add(5*time.Minute+21*time.Second), func(r *Record) { r.CodingSessionID = sess }),
			call:       dec("z-c", t0.Add(5*time.Minute+22*time.Second), func(r *Record) { r.CodingSessionID, r.Tool = sess, "create_issue" }),
			wantProto:  Link{Confidence: Exact, Level: LevelSession, Method: MethodSessionOnly},
			wantAction: "toolu_C", wantMethod: MethodSessionToolTime,
		},
		{
			name:       "rule 8: an anchored tools/list naming the turn stays at the turn",
			proto:      dec("a-l", t0.Add(5*time.Minute+19*time.Second), func(r *Record) { r.CodingSessionID, r.TurnRef, r.Method = sess, "turn-2", "tools/list" }),
			call:       dec("z-c", t0.Add(5*time.Minute+22*time.Second), func(r *Record) { r.CodingSessionID, r.Method, r.Tool = sess, "tools/call", "create_issue" }),
			wantProto:  Link{Confidence: Exact, Level: LevelTurn, Method: MethodTurnRef},
			wantAction: "toolu_C", wantMethod: MethodSessionToolTime,
		},
		{
			name:       "rule 3: an initialize carrying a message id pins the turn, never the action",
			proto:      dec("a-i", t0.Add(5*time.Minute+19*time.Second), func(r *Record) { r.CodingSessionID, r.ActionRef, r.Method = sess, "msg_2", "initialize" }),
			call:       dec("z-c", t0.Add(5*time.Minute+22*time.Second), func(r *Record) { r.CodingSessionID, r.Method, r.Tool = sess, "tools/call", "create_issue" }),
			wantProto:  Link{Confidence: Exact, Level: LevelTurn, Method: MethodActionRefMessage},
			wantAction: "toolu_C", wantMethod: MethodSessionToolTime,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Derive(DeriveInput{SessionID: sess, Records: []Record{tc.proto, tc.call}, Actions: actions()})
			got := map[string]Link{}
			for _, c := range res.Calls {
				got[c.CallID] = c.Correlation
			}
			p, c := got[tc.proto.CallID], got[tc.call.CallID]
			if p.Confidence != tc.wantProto.Confidence || p.Level != tc.wantProto.Level || p.Method != tc.wantProto.Method || p.ActionKey != "" {
				t.Errorf("protocol link %+v, want %+v", p, tc.wantProto)
			}
			if c.ActionKey != tc.wantAction || c.Method != tc.wantMethod || c.Level != LevelAction {
				t.Errorf("tool call link %+v, want action %q via %s", c, tc.wantAction, tc.wantMethod)
			}
		})
	}
}

// TestInvokesTool pins the predicate, one row per case (CLAUDE.md #5).
func TestInvokesTool(t *testing.T) {
	cases := []struct {
		method, tool, level string
		want                bool
	}{
		{"tools/call", "read_wiki_structure", "L2", true},
		{"tools/call", "", "L1", true},
		{"tools/call", "", "L2", true},
		{"initialize", "", "L2", false},
		{"notifications/initialized", "", "L0", false},
		{"notifications/cancelled", "", "L2", false},
		{"tools/list", "", "L2", false},
		{"prompts/get", "a_prompt", "L2", false},
		{"resources/read", "file:///x", "L2", false},
		{"", "read_wiki_structure", "L2", true}, // legacy copy: a named call
		{"", "", "L2", false},                   // legacy copy: a nameless L2 record is protocol
		{"", "", "L1", true},                    // legacy copy below L2: benefit of the doubt
		{"", "", "", true},
	}
	for _, tc := range cases {
		c := &Call{Method: tc.method, Tool: tc.tool, CaptureLevel: tc.level}
		if got := c.invokesTool(); got != tc.want {
			t.Errorf("invokesTool(method=%q tool=%q level=%q) = %v, want %v", tc.method, tc.tool, tc.level, got, tc.want)
		}
	}
}
