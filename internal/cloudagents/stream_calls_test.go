package cloudagents

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// The run stream fixtures follow the live shape (2026-11-01): each tool call
// arrives as "running" events (the first without args) and one "completed"
// event with its result; event ids are <epoch ms>-<seq>. All values are
// invented.

const (
	childAgentID = "bc-5e1f0a2b-7c3d-4e5f-8a9b-0c1d2e3f4a09"
	// t0 is the first fixture event (1792264205000 ms).
	fixtureT0 = "2026-10-17T19:10:05Z"
)

// TestRunStreamOneActionPerCall reduces the live-shaped first window: three
// calls with arguments or a completion land once each; the argless fourth
// waits for the next window.
func TestRunStreamOneActionPerCall(t *testing.T) {
	r := &RunStream{RunID: "run-2"}
	var d SSEDecoder
	readSSE(t, "cursor-cloud/stream-live.sse", r, &d, ts("2026-10-17T19:20:00Z"))
	if r.Done || d.LastEventID() != "1792264210000-13" || r.Status != "running" {
		t.Fatalf("first window: done=%v id=%q status=%q", r.Done, d.LastEventID(), r.Status)
	}
	t0 := ts(fixtureT0)
	want := []struct {
		tool, target string
		at           time.Time
		known        bool
	}{
		{"read_file", "/workspace/src/loader.go", t0.Add(1 * time.Second), true},
		{"file_search", "**/*_test.go", t0.Add(2 * time.Second), true},
		{"edit_file", "/workspace/src/loader.go", t0.Add(4 * time.Second), false},
	}
	if len(r.Activity) != len(want) {
		t.Fatalf("activity = %+v", r.Activity)
	}
	for i, w := range want {
		a := r.Activity[i]
		if a.Tool != w.tool || a.Target != w.target || !a.At.Equal(w.at) || a.OutcomeKnown != w.known || a.Pending == w.known || a.Failed {
			t.Errorf("call %d = %+v, want %+v", i, a, w)
		}
		if !strings.HasPrefix(a.ID, "run:run-2:tool:h") {
			t.Errorf("call %d id %q: a call id with '|' is keyed by its digest", i, a.ID)
		}
	}
}

// TestRunStreamResumeKeepsOneAction reads the resume window: the call
// whose running events were read in the first window keeps its id, so its
// completion patches that action instead of adding one.
func TestRunStreamResumeKeepsOneAction(t *testing.T) {
	r1 := &RunStream{RunID: "run-2"}
	var d1 SSEDecoder
	readSSE(t, "cursor-cloud/stream-live.sse", r1, &d1, ts("2026-10-17T19:20:00Z"))
	r2 := &RunStream{RunID: "run-2"}
	var d2 SSEDecoder
	readSSE(t, "cursor-cloud/stream-resume.sse", r2, &d2, ts("2026-10-17T19:21:00Z"))
	if !r2.Done || r2.Status != "finished" || d2.LastEventID() != "1792264221100-24" {
		t.Fatalf("resumed: done=%v status=%q id=%q", r2.Done, r2.Status, d2.LastEventID())
	}
	if len(r2.Children) != 1 || r2.Children[0] != childAgentID {
		t.Fatalf("children = %v", r2.Children)
	}
	edit := r1.Activity[2]
	var patched *Activity
	for i := range r2.Activity {
		if r2.Activity[i].ID == edit.ID {
			patched = &r2.Activity[i]
		}
	}
	if patched == nil || !patched.OutcomeKnown || patched.Failed {
		t.Fatalf("edit_file completion in the second window = %+v (first window id %s)", patched, edit.ID)
	}

	cur := mustConn(t, ConnectorCursorCloud)
	all := append(append([]Activity{}, r1.Activity...), r2.Activity...)
	ev := MapActivity(cur, "bc-1", "/repo", all)
	byID := map[string]models.ToolEvent{}
	for _, e := range ev {
		if _, dup := byID[e.SourceEventID]; !dup {
			byID[e.SourceEventID] = e // the store keeps the first insert
		}
	}
	// Seven calls in the two windows, seven actions (the old reducer made
	// one per event).
	if len(byID) != 7 {
		t.Fatalf("distinct actions = %d: %+v", len(byID), ev)
	}
	wantType := map[string]string{
		"read_file": models.ActionReadFile, "file_search": models.ActionSearchFiles,
		"edit_file": models.ActionEditFile, "run_terminal_cmd": models.ActionRunCommand,
		"communicate_update": models.ActionHarnessCall, "create_agent": models.ActionSpawnSubagent,
		"send_message": models.ActionHarnessCall,
	}
	for _, e := range byID {
		if w := wantType[e.RawToolName]; e.ActionType != w {
			t.Errorf("%s = %s, want %s", e.RawToolName, e.ActionType, w)
		}
		switch e.RawToolName {
		case "run_terminal_cmd":
			if e.Target != "go test ./src/... -run TestLoader" || e.Success {
				t.Errorf("run_terminal_cmd = target %q success %v", e.Target, e.Success)
			}
		case "edit_file":
			if !e.OutcomePending || e.Target != "/workspace/src/loader.go" {
				t.Errorf("edit_file landed pending with its path first: %+v", e)
			}
		case "create_agent":
			if e.Target != childAgentID {
				t.Errorf("create_agent target = %q", e.Target)
			}
		case "communicate_update", "send_message":
			if e.Target != "" {
				t.Errorf("%s keeps no target (message text): %q", e.RawToolName, e.Target)
			}
		}
	}
	ups := MapOutcomes(cur, "bc-1", r2.Activity)
	var editUp *models.ActionOutcomeUpdate
	for i := range ups {
		if ups[i].SourceEventID == byID[cur.ID+":bc-1:"+edit.ID].SourceEventID {
			editUp = &ups[i]
		}
		if ups[i].ErrorMessage != "" || ups[i].ToolOutput != "" {
			t.Errorf("an outcome patch carries no text: %+v", ups[i])
		}
	}
	if editUp == nil || !editUp.SuccessKnown || !editUp.Success {
		t.Fatalf("edit_file outcome patch = %+v", editUp)
	}
	// No result content, no message text, no prompt survives the reduction.
	if s := fmt.Sprintf("%+v %+v", all, ev); strings.Contains(s, "SYNTHETIC") {
		t.Errorf("content leaked into activity: %s", s)
	}
}

// TestRunStreamCallTable pins the per-call reduction rules row by row.
func TestRunStreamCallTable(t *testing.T) {
	const at0 = 1792264205000
	ev := func(seq int, data string) SSEEvent {
		return SSEEvent{ID: fmt.Sprintf("%d-%d", at0+int64(seq)*1000, seq), Event: "tool_call", Data: data}
	}
	cases := []struct {
		name   string
		events []SSEEvent
		done   bool
		// want: one line per emitted activity, "tool|target|known|failed".
		want []string
	}{
		{"argless running only waits", []SSEEvent{
			ev(1, `{"callId":"c1","name":"read_file","status":"running"}`),
		}, false, nil},
		{"argless running flushed on done", []SSEEvent{
			ev(1, `{"callId":"c1","name":"read_file","status":"running"}`),
		}, true, []string{"read_file||false|false"}},
		{"args from the latest event that has them", []SSEEvent{
			ev(1, `{"callId":"c1","name":"read_file","status":"running","args":{"path":"/a.go"}}`),
			ev(2, `{"callId":"c1","name":"read_file","status":"running","args":{"path":"/b.go"}}`),
			ev(3, `{"callId":"c1","name":"read_file","status":"completed","result":{"success":{"content":"x"}}}`),
		}, false, []string{"read_file|/b.go|true|false"}},
		{"error result fails", []SSEEvent{
			ev(1, `{"callId":"c1","name":"run_terminal_cmd","status":"completed","args":{"command":"make"},"result":{"error":{"errorMessage":"boom"}}}`),
		}, false, []string{"run_terminal_cmd|make|true|true"}},
		{"failed status fails", []SSEEvent{
			ev(1, `{"callId":"c1","name":"edit_file","status":"failed","args":{"path":"/a.go"}}`),
		}, false, []string{"edit_file|/a.go|true|true"}},
		{"two calls two actions", []SSEEvent{
			ev(1, `{"callId":"c1","name":"read_file","status":"running","args":{"path":"/a.go"}}`),
			ev(2, `{"callId":"c2","name":"read_file","status":"running","args":{"path":"/a.go"}}`),
		}, false, []string{"read_file|/a.go|false|false", "read_file|/a.go|false|false"}},
		{"glob target", []SSEEvent{
			ev(1, `{"callId":"c1","name":"file_search","status":"running","args":{"globPattern":"*.md","targetDirectory":"/w"}}`),
		}, false, []string{"file_search|*.md|false|false"}},
		{"unknown tool keeps no target", []SSEEvent{
			ev(1, `{"callId":"c1","name":"web_lookup","status":"running","args":{"query":"private words"}}`),
		}, false, []string{"web_lookup||false|false"}},
		{"create_agent without an agent id links nothing", []SSEEvent{
			ev(1, `{"callId":"c1","name":"create_agent","status":"completed","args":{"prompt":"p"},"result":{"success":{"message":"m"}}}`),
		}, false, []string{"create_agent||true|false"}},
		{"failed create_agent links nothing", []SSEEvent{
			ev(1, `{"callId":"c1","name":"create_agent","status":"completed","args":{"prompt":"p"},"result":{"error":{"errorMessage":"no"}}}`),
		}, false, []string{"create_agent||true|true"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &RunStream{RunID: "r1"}
			for _, e := range tc.events {
				r.Add(e, time.Time{})
			}
			if tc.done {
				r.Add(SSEEvent{ID: "x", Event: "done", Data: "{}"}, time.Time{})
			}
			var got []string
			for _, a := range r.Activity {
				got = append(got, fmt.Sprintf("%s|%s|%v|%v", a.Tool, a.Target, a.OutcomeKnown, a.Failed))
			}
			if strings.Join(got, ";") != strings.Join(tc.want, ";") {
				t.Errorf("got %v, want %v", got, tc.want)
			}
			if len(r.Children) != 0 {
				t.Errorf("children = %v", r.Children)
			}
		})
	}
}

func TestRunStreamTargetIsScrubbedAndCapped(t *testing.T) {
	r := &RunStream{RunID: "r1"}
	secret := "sk-ant-api03-" + strings.Repeat("Q", 40)
	r.Add(SSEEvent{
		ID: "1792264205000-1", Event: "tool_call",
		Data: `{"callId":"c1","name":"run_terminal_cmd","status":"running","args":{"command":"ANTHROPIC_API_KEY=` + secret + ` make"}}`,
	}, time.Time{})
	long := strings.Repeat("a/", 3000)
	r.Add(SSEEvent{
		ID: "1792264205000-2", Event: "tool_call",
		Data: `{"callId":"c2","name":"read_file","status":"running","args":{"path":"/` + long + `"}}`,
	}, time.Time{})
	if len(r.Activity) != 2 {
		t.Fatalf("activity = %+v", r.Activity)
	}
	if strings.Contains(r.Activity[0].Target, secret) || r.Activity[0].Target == "" {
		t.Errorf("command target not scrubbed: %q", r.Activity[0].Target)
	}
	if n := len(r.Activity[1].Target); n == 0 || n > maxActivityTarget {
		t.Errorf("path target length %d, cap %d", n, maxActivityTarget)
	}
}

func TestCallKey(t *testing.T) {
	cases := []struct {
		in    string
		plain bool
	}{
		{"toolu_01", true},
		{"call-2.a", true},
		{"toolu_01|loader-read", false},
		{"a b", false},
		{strings.Repeat("x", 97), false},
	}
	for _, tc := range cases {
		got := callKey(tc.in)
		if (got == tc.in) != tc.plain {
			t.Errorf("callKey(%q) = %q, plain=%v", tc.in, got, tc.plain)
		}
		if got != callKey(tc.in) || !reCallID.MatchString(got) {
			t.Errorf("callKey(%q) = %q is not a stable token", tc.in, got)
		}
	}
	if callKey("a|b") == callKey("a|c") {
		t.Error("distinct call ids share a key")
	}
}

func TestEventTime(t *testing.T) {
	cases := []struct {
		id   string
		want string // "" = no time
	}{
		{"1792264205000-1", fixtureT0},
		{"1792264205123-44", "2026-10-17T19:10:05.123Z"},
		{"6", ""},
		{"12-3", ""},
		{"abc-1", ""},
		{"99999999999999-1", ""},
		{"", ""},
	}
	for _, tc := range cases {
		got, ok := eventTime(tc.id)
		if tc.want == "" {
			if ok {
				t.Errorf("eventTime(%q) = %v, want none", tc.id, got)
			}
			continue
		}
		if !ok || !got.Equal(ts(tc.want)) {
			t.Errorf("eventTime(%q) = %v %v, want %s", tc.id, got, ok, tc.want)
		}
	}
	// An id without a time leaves At zero for the caller to fill.
	r := &RunStream{RunID: "r1"}
	r.Add(SSEEvent{ID: "7", Event: "tool_call", Data: `{"callId":"c1","name":"read_file","status":"running","args":{"path":"/a"}}`}, ts(fixtureT0))
	if len(r.Activity) != 1 || !r.Activity[0].At.IsZero() {
		t.Errorf("activity = %+v", r.Activity)
	}
}

func TestChildLineage(t *testing.T) {
	cases := []struct {
		name          string
		parent, child string
		ok            bool
	}{
		{"valid", "bc-parent-1", childAgentID, true},
		{"no parent", "", childAgentID, false},
		{"no child", "bc-parent-1", "", false},
		{"self", childAgentID, childAgentID, false},
		{"bad child id", "bc-parent-1", "bc child", false},
	}
	for _, tc := range cases {
		lin, ok := ChildLineage(ChildLink{Parent: tc.parent, Child: tc.child})
		if ok != tc.ok {
			t.Errorf("%s: ok = %v", tc.name, ok)
			continue
		}
		if ok && (lin.SessionID != tc.child || lin.ParentThreadID != tc.parent || lin.ThreadSource != ThreadSourceSubagent || lin.ForkedFromID != "") {
			t.Errorf("%s: lineage = %+v", tc.name, lin)
		}
	}
}
