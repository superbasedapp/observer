package correlate

import (
	"fmt"
	"testing"
	"time"
)

// The unanchored tier (rule 5): a trusted relay call with no session,
// action or turn ref, attributed through the node / owner-wide pool.

const (
	sessOC  = "ses_f1db4f1beffeLdDNuCoLQxsuvh" // OpenCode-shaped
	sessOC2 = "ses_second_opencode_session"
)

// ocName is OpenCode's projected name for the relay entry
// "superbased-deepwiki" + upstream tool "read_wiki_structure".
const ocName = "superbased-deepwiki_read_wiki_structure"

func ocPrompt(sid string, at time.Time) Action {
	return Action{Key: "prompt:" + sid, ActionType: actionTypeUserPrompt, TurnIndex: i64(0), TS: at}
}

func poolAct(sid, key string, at time.Time, typ, target string) PoolAction {
	return PoolAction{SessionID: sid, Action: Action{Key: key, MessageID: "msg:" + key, TurnIndex: i64(0), TS: at, ActionType: typ, Target: target}}
}

// unanchoredDec is the OpenCode relay decision: loopback slug, L2 tool name,
// no anchors.
func unanchoredDec(callID string, at time.Time, mut func(*Record)) Record {
	return dec(callID, at, func(r *Record) {
		r.VirtualServer, r.Tool = "deepwiki", "read_wiki_structure"
		if mut != nil {
			mut(r)
		}
	})
}

func TestUnanchoredTier(t *testing.T) {
	base := t0
	cases := []struct {
		name       string
		recs       []Record
		pool       []PoolAction
		anchored   []string
		wantConf   Confidence // "" = not attached
		wantLevel  Level
		wantMethod string
		wantAction string
		wantPrompt string
		wantAmbig  int
		wantUnlink int
	}{
		{
			name:     "OpenCode shape: projected name <entry>_<tool>, no anchor -> inferred action",
			recs:     []Record{unanchoredDec("oc1", base.Add(11*time.Second), nil)},
			pool:     []PoolAction{poolAct(sessOC, "part:1", base.Add(10*time.Second), actionTypeUnknown, ocName)},
			wantConf: Inferred, wantLevel: LevelAction, wantMethod: MethodUnanchoredToolTime, wantAction: "part:1", wantPrompt: "prompt:" + sessOC,
		},
		{
			name: "gateway copy (vserver id) + node copy (slug) fold and still match on the slug",
			recs: []Record{
				unanchoredDec("oc1", base.Add(11*time.Second), func(r *Record) { r.Source, r.VirtualServer = SourceGateway, "vs_cf944fb69cef79f2" }),
				unanchoredDec("oc1", base.Add(11*time.Second), nil),
			},
			pool:     []PoolAction{poolAct(sessOC, "part:1", base.Add(10*time.Second), actionTypeUnknown, ocName)},
			wantConf: Inferred, wantLevel: LevelAction, wantMethod: MethodUnanchoredToolTime, wantAction: "part:1", wantPrompt: "prompt:" + sessOC,
		},
		{
			name:     "codex colon target server:tool on an mcp_call",
			recs:     []Record{unanchoredDec("cx", base.Add(11*time.Second), nil)},
			pool:     []PoolAction{poolAct(sessOC, "cx:1", base.Add(10*time.Second), actionTypeMCPCall, "superbased-deepwiki:read_wiki_structure")},
			wantConf: Inferred, wantLevel: LevelAction, wantMethod: MethodUnanchoredToolTime, wantAction: "cx:1", wantPrompt: "prompt:" + sessOC,
		},
		{
			name:     "bare tool name on an adapter-classified mcp_call (cursor ':tool')",
			recs:     []Record{unanchoredDec("cu", base.Add(11*time.Second), nil)},
			pool:     []PoolAction{poolAct(sessOC, "cu:1", base.Add(10*time.Second), actionTypeMCPCall, ":read_wiki_structure")},
			wantConf: Inferred, wantLevel: LevelAction, wantMethod: MethodUnanchoredToolTime, wantAction: "cu:1", wantPrompt: "prompt:" + sessOC,
		},
		{
			name: "bare tool name on an unknown action never matches",
			recs: []Record{unanchoredDec("u", base.Add(11*time.Second), nil)},
			pool: []PoolAction{poolAct(sessOC, "u:1", base.Add(10*time.Second), actionTypeUnknown, "read_wiki_structure")},
		},
		{
			name: "tool suffix without the server segment never matches",
			recs: []Record{unanchoredDec("u", base.Add(11*time.Second), nil)},
			pool: []PoolAction{poolAct(sessOC, "u:1", base.Add(10*time.Second), actionTypeUnknown, "otherserver_read_wiki_structure")},
		},
		{
			name: "outside the window (action 3 minutes before) never matches",
			recs: []Record{unanchoredDec("u", base.Add(3*time.Minute), nil)},
			pool: []PoolAction{poolAct(sessOC, "u:1", base, actionTypeUnknown, ocName)},
		},
		{
			name:     "an action exactly claimed by another record's action_ref is no candidate",
			recs:     []Record{unanchoredDec("u", base.Add(11*time.Second), nil)},
			pool:     []PoolAction{poolAct(sessOC, "u:1", base.Add(10*time.Second), actionTypeUnknown, ocName)},
			anchored: []string{"u:1"},
		},
		{
			name: "two sessions within the separation: ambiguous, attached nowhere, counted",
			recs: []Record{unanchoredDec("amb", base.Add(11*time.Second), nil)},
			pool: []PoolAction{
				poolAct(sessOC, "a:1", base.Add(10*time.Second), actionTypeUnknown, ocName),
				poolAct(sessOC2, "b:1", base.Add(8*time.Second), actionTypeUnknown, ocName),
			},
			wantMethod: MethodUnanchoredAmbiguous, wantAmbig: 1, wantUnlink: 1,
		},
		{
			name: "another session clearly nearer owns the call: dropped here, not counted",
			recs: []Record{unanchoredDec("far", base.Add(71*time.Second), nil)},
			pool: []PoolAction{
				poolAct(sessOC, "a:1", base.Add(10*time.Second), actionTypeUnknown, ocName),
				poolAct(sessOC2, "b:1", base.Add(70*time.Second), actionTypeUnknown, ocName),
			},
		},
		{
			name: "this session clearly nearer owns the call over a second session",
			recs: []Record{unanchoredDec("near", base.Add(11*time.Second), nil)},
			pool: []PoolAction{
				poolAct(sessOC, "a:1", base.Add(10*time.Second), actionTypeUnknown, ocName),
				poolAct(sessOC2, "b:1", base.Add(-90*time.Second), actionTypeUnknown, ocName),
			},
			wantConf: Inferred, wantLevel: LevelAction, wantMethod: MethodUnanchoredToolTime, wantAction: "a:1", wantPrompt: "prompt:" + sessOC,
		},
		{
			name:     "below L2 (no tool name): the one server-named candidate",
			recs:     []Record{unanchoredDec("l1", base.Add(11*time.Second), func(r *Record) { r.Tool = ""; r.CaptureLevel = "L1" })},
			pool:     []PoolAction{poolAct(sessOC, "a:1", base.Add(10*time.Second), actionTypeUnknown, ocName)},
			wantConf: Inferred, wantLevel: LevelAction, wantMethod: MethodUnanchoredServerTime, wantAction: "a:1", wantPrompt: "prompt:" + sessOC,
		},
		{
			name: "below L2 with two server-named candidates: ambiguous",
			recs: []Record{unanchoredDec("l1", base.Add(11*time.Second), func(r *Record) { r.Tool = ""; r.CaptureLevel = "L1" })},
			pool: []PoolAction{
				poolAct(sessOC, "a:1", base.Add(10*time.Second), actionTypeUnknown, ocName),
				poolAct(sessOC, "a:2", base.Add(5*time.Second), actionTypeUnknown, "superbased-deepwiki_ask_question"),
			},
			wantMethod: MethodUnanchoredAmbiguous, wantAmbig: 1, wantUnlink: 1,
		},
		{
			name:       "an untrusted unanchored copy is rule 1, never the tier",
			recs:       []Record{unanchoredDec("x", base.Add(11*time.Second), func(r *Record) { r.Trusted = false })},
			pool:       []PoolAction{poolAct(sessOC, "a:1", base.Add(10*time.Second), actionTypeUnknown, ocName)},
			wantMethod: MethodUntrusted, wantUnlink: 1,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := Derive(DeriveInput{
				SessionID: sessOC, Records: tc.recs, Pool: tc.pool, AnchoredKeys: tc.anchored,
				Actions: []Action{ocPrompt(sessOC, base)},
			})
			if res.Totals.Ambiguous != tc.wantAmbig || res.Totals.Unlinked != tc.wantUnlink {
				t.Fatalf("totals %+v, want ambiguous=%d unlinked=%d", res.Totals, tc.wantAmbig, tc.wantUnlink)
			}
			if tc.wantConf == "" {
				if len(res.Calls) != 0 {
					t.Fatalf("attached %+v", res.Calls)
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
			if l.Confidence == Exact {
				t.Fatal("the unanchored tier must never claim exact")
			}
		})
	}
}

// TestUnanchoredTwoCallsOneAction: the second call of a session whose only
// matching action is claimed stays in the session, at session level.
func TestUnanchoredTwoCallsOneAction(t *testing.T) {
	res := Derive(DeriveInput{
		SessionID: sessOC,
		Records:   []Record{unanchoredDec("c1", t0.Add(11*time.Second), nil), unanchoredDec("c2", t0.Add(12*time.Second), nil)},
		Pool:      []PoolAction{poolAct(sessOC, "a:1", t0.Add(10*time.Second), actionTypeUnknown, ocName)},
	})
	if len(res.Calls) != 2 || res.Calls[0].Correlation.ActionKey != "a:1" ||
		res.Calls[1].Correlation.Method != MethodUnanchoredSession || res.Calls[1].Correlation.Level != LevelSession {
		t.Fatalf("%+v", res.Calls)
	}
}

// TestAnchoredClaimsBeforeUnanchored: an anchored-session heuristic call
// claims its action before the unanchored tier runs.
func TestAnchoredClaimsBeforeUnanchored(t *testing.T) {
	act := Action{Key: "a:1", ActionType: actionTypeMCPCall, TS: t0.Add(10 * time.Second), Target: "superbased-deepwiki:read_wiki_structure"}
	anch := unanchoredDec("anch", t0.Add(12*time.Second), func(r *Record) { r.CodingSessionID = sessOC })
	un := unanchoredDec("un", t0.Add(11*time.Second), nil)
	res := Derive(DeriveInput{
		SessionID: sessOC, Records: []Record{un, anch}, Actions: []Action{act},
		Pool: []PoolAction{{SessionID: sessOC, Action: act}},
	})
	got := map[string]Link{}
	for _, c := range res.Calls {
		got[c.CallID] = c.Correlation
	}
	if got["anch"].ActionKey != "a:1" || got["un"].Method != MethodUnanchoredSession {
		t.Fatalf("%+v", got)
	}
}

// TestUnanchoredNeverOnTwoSessions derives every session's panel over one
// shared pool and record set (what the node and the org both load) and
// checks each call attaches to at most one session, whatever the layout.
func TestUnanchoredNeverOnTwoSessions(t *testing.T) {
	sessions := []string{"s1", "s2", "s3"}
	for layout := 0; layout < 40; layout++ {
		var pool []PoolAction
		var recs []Record
		for i := 0; i < 6; i++ {
			sid := sessions[(layout+i)%len(sessions)]
			at := t0.Add(time.Duration((layout*7+i*13)%150) * time.Second)
			pool = append(pool, poolAct(sid, fmt.Sprintf("k%d", i), at, actionTypeUnknown, ocName))
			recs = append(recs, unanchoredDec(fmt.Sprintf("c%d", i), at.Add(time.Duration(i%3)*time.Second), nil))
		}
		owners := map[string]string{}
		for _, sid := range sessions {
			res := Derive(DeriveInput{SessionID: sid, Records: recs, Pool: pool})
			for _, c := range res.Calls {
				if prev, dup := owners[c.CallID]; dup {
					t.Fatalf("layout %d: call %s on %s and %s", layout, c.CallID, prev, sid)
				}
				owners[c.CallID] = sid
			}
		}
	}
}

func TestWindows(t *testing.T) {
	acts := []Action{
		{ActionType: actionTypeUnknown, Target: ocName, TS: t0},
		{ActionType: actionTypeUnknown, Target: ocName, TS: t0.Add(30 * time.Second)},
		{ActionType: actionTypeUnknown, Target: ocName, TS: t0.Add(time.Hour)},
		{ActionType: "read_file", Target: "x.go", TS: t0.Add(2 * time.Hour)},
		{ActionType: actionTypeMCPCall, Target: "", TS: t0.Add(3 * time.Hour)},
	}
	w := RecordWindows(acts)
	if len(w) != 2 || !w[0].From.Equal(t0.Add(-6*time.Second)) || !w[0].To.Equal(t0.Add(30*time.Second+121*time.Second)) {
		t.Fatalf("record windows %+v", w)
	}
	pw := PoolWindows([]Record{
		unanchoredDec("a", t0, nil),
		unanchoredDec("b", t0.Add(time.Hour), func(r *Record) { r.CodingSessionID = "s" }), // anchored: ignored
		{Kind: KindCompletion, TS: t0.Add(2 * time.Hour).Unix()},
	})
	if len(pw) != 1 || !pw[0].From.Equal(t0.Add(-121*time.Second)) || !pw[0].To.Equal(t0.Add(6*time.Second)) {
		t.Fatalf("pool windows %+v", pw)
	}
}
