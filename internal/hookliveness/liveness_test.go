package hookliveness

import (
	"reflect"
	"strings"
	"testing"
	"time"
)

var (
	t0    = time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)
	now   = t0.Add(24 * time.Hour)
	opts  = Options{Epoch: t0, Now: now}
	specs = []EventSpec{
		{Native: "SessionStart", Registered: true, SessionKey: true},
		{Native: "PreToolUse", Registered: true, SessionKey: true},
		{Native: "Notification", Registered: false},
	}
)

func act(event, sid string, n int64) Activity {
	return Activity{Tool: "claude-code", Event: event, SessionID: sid, Count: n, FirstAt: t0.Add(time.Hour), LastAt: t0.Add(2 * time.Hour)}
}

func sess(id, surface string) Session {
	return Session{ID: id, Surface: surface, StartedAt: t0.Add(time.Hour)}
}

// TestClassifyToolRules holds one case per toolRules row, in table order.
func TestClassifyToolRules(t *testing.T) {
	cases := []struct {
		name string
		in   ToolInput
		opts Options
		want Rule
		sev  Severity
	}{
		{"no_hook_surface", ToolInput{Tool: "x", Events: []EventSpec{{Native: "E"}}}, opts, RuleNoHookSurface, SeverityNone},
		{"hooks_disabled_switch", ToolInput{Tool: "claude-code", Events: specs, DisabledSwitches: []string{"disableAllHooks"}, Sessions: []Session{sess("s1", "cli")}}, opts, RuleDisabledSwitch, SeverityWarn},
		{"not_yet_observed", ToolInput{Tool: "claude-code", Events: specs, Sessions: []Session{sess("s1", "cli")}}, Options{Now: now}, RuleNotYetObserved, SeverityInfo},
		{"idle", ToolInput{Tool: "claude-code", Events: specs}, opts, RuleIdle, SeverityNone},
		{"hooks_never_seen", ToolInput{Tool: "claude-code", Events: specs, Sessions: []Session{sess("s1", "cli")}}, opts, RuleNeverSeen, SeverityWarn},
		{"no_session_key", ToolInput{Tool: "t", Events: []EventSpec{{Native: "E", Registered: true}}, Activity: []Activity{act("E", "", 3)}}, opts, RuleNoSessionKey, SeverityInfo},
		{"unattributed_only", ToolInput{Tool: "claude-code", Events: specs, Activity: []Activity{act("PreToolUse", "", 3)}, Sessions: []Session{sess("s1", "cli")}}, opts, RuleUnattributedOnly, SeverityInfo},
		{"session_ids_unjoined", ToolInput{Tool: "claude-code", Events: specs, Activity: []Activity{act("PreToolUse", "hook-sid", 3)}, Sessions: []Session{sess("store-sid", "cli")}}, opts, RuleSessionIDsUnjoined, SeverityInfo},
		{"hooks_silent_on_surface", ToolInput{
			Tool: "claude-code", Events: specs,
			Activity: []Activity{act("PreToolUse", "s1", 3)},
			Sessions: []Session{sess("s1", "cli"), sess("s2", "desktop"), sess("s3", "desktop")},
		}, opts, RuleSilentOnSurface, SeverityWarn},
		{"hooks_silent_some_sessions", ToolInput{
			Tool: "claude-code", Events: specs,
			Activity: []Activity{act("PreToolUse", "s1", 3)},
			Sessions: []Session{sess("s1", "cli"), sess("s2", "cli")},
		}, opts, RuleSilentSomeSessions, SeverityInfo},
		{"ok", ToolInput{
			Tool: "claude-code", Events: specs,
			Activity: []Activity{act("SessionStart", "s1", 1), act("PreToolUse", "s1", 9)},
			Sessions: []Session{sess("s1", "cli")},
		}, opts, RuleOK, SeverityOK},
	}
	if len(cases) != len(toolRules) {
		t.Fatalf("%d cases for %d tool rules: add a case per row", len(cases), len(toolRules))
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if string(toolRules[i].rule) != tc.name {
				t.Fatalf("case %d is %q, table row is %q", i, tc.name, toolRules[i].rule)
			}
			v := Classify(tc.in, tc.opts)
			if v.Rule != tc.want || v.Severity != tc.sev {
				t.Fatalf("got %s/%d, want %s/%d (%+v)", v.Rule, v.Severity, tc.want, tc.sev, v)
			}
		})
	}
}

// TestEventRules holds one case per eventRules row, in table order.
func TestEventRules(t *testing.T) {
	cases := []struct {
		name string
		in   eventFacts
	}{
		{string(EventSeenUnregistered), eventFacts{attributed: 1}},
		{string(EventNotRegistered), eventFacts{}},
		{string(EventSeen), eventFacts{registered: true, attributed: 2, unattributed: 1}},
		{string(EventSeenUnattributed), eventFacts{registered: true, unattributed: 1}},
		{string(EventNeverSeen), eventFacts{registered: true}},
	}
	if len(cases) != len(eventRules) {
		t.Fatalf("%d cases for %d event rules", len(cases), len(eventRules))
	}
	for i, tc := range cases {
		if string(eventRules[i].rule) != tc.name {
			t.Fatalf("case %d is %q, table row is %q", i, tc.name, eventRules[i].rule)
		}
		if got := decideEvent(tc.in); string(got) != tc.name {
			t.Errorf("%s: got %s", tc.name, got)
		}
	}
}

// TestClassifyDetail pins the derived detail: per-event verdicts, silent
// surfaces, the unattributed count, env route truth and the out-of-file
// switch hint.
func TestClassifyDetail(t *testing.T) {
	a1 := act("PreToolUse", "s1", 4)
	a1.EnvClasses = map[string]string{"ANTHROPIC_BASE_URL": ClassLoopback}
	a2 := act("SessionStart", "s2", 1)
	a2.EnvClasses = map[string]string{"ANTHROPIC_BASE_URL": ClassProviderDirect, "CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST": ClassOn}
	in := ToolInput{
		Tool: "dimcode", Events: specs,
		Activity: []Activity{a1, a2, act("PreToolUse", "", 2), act("Leftover", "s1", 1)},
		Sessions: []Session{sess("s1", "cli"), sess("s2", "cli"), sess("s3", ""), sess("old", "cli")},
	}
	in.Sessions[3].StartedAt = t0.Add(-time.Hour) // before the epoch: not judged
	v := Classify(in, opts)
	if v.Rule != RuleSilentOnSurface || !reflect.DeepEqual(v.SilentSurfaces, []string{"unknown"}) || v.ExampleSilent != "s3" {
		t.Fatalf("verdict: %+v", v)
	}
	if v.JudgedSessions != 3 || v.SilentSessions != 1 || v.Unattributed != 2 {
		t.Fatalf("counts: %+v", v)
	}
	wantEvents := []EventVerdict{
		{Event: "SessionStart", Rule: EventSeen, Count: 1},
		{Event: "PreToolUse", Rule: EventSeen, Count: 6},
		{Event: "Leftover", Rule: EventSeenUnregistered, Count: 1},
	}
	if !reflect.DeepEqual(v.Events, wantEvents) {
		t.Fatalf("events: %+v", v.Events)
	}
	wantEnv := map[string]map[string]int{
		"ANTHROPIC_BASE_URL":                   {ClassLoopback: 1, ClassProviderDirect: 1},
		"CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST": {ClassOn: 1},
	}
	if !reflect.DeepEqual(v.EnvSessions, wantEnv) {
		t.Fatalf("env: %+v", v.EnvSessions)
	}
	if !reflect.DeepEqual(v.OutOfFileSwitches, OutOfFileSwitches["dimcode"]) {
		t.Fatalf("switch hint: %v", v.OutOfFileSwitches)
	}
}

// TestSettleSkipsFreshSessions: a session younger than Settle is not judged,
// so hooks still in the spool never read as silence.
func TestSettleSkipsFreshSessions(t *testing.T) {
	in := ToolInput{
		Tool: "claude-code", Events: specs, Activity: []Activity{act("PreToolUse", "s1", 1)},
		Sessions: []Session{sess("s1", "cli"), {ID: "fresh", Surface: "cli", StartedAt: now.Add(-time.Second)}},
	}
	if v := Classify(in, opts); v.Rule != RuleOK || v.JudgedSessions != 1 {
		t.Fatalf("got %+v", v)
	}
}

// TestEpochSessionWithActivityIsJudged: the session that set the epoch
// starts before its own first hook, so it starts before the epoch; its
// attributed activity still makes it an observed, judged session (found by
// lane w5-wire, the server rule's ordering).
func TestEpochSessionWithActivityIsJudged(t *testing.T) {
	first := sess("s1", "cli")
	first.StartedAt = t0.Add(-time.Second)
	in := ToolInput{Tool: "claude-code", Events: specs, Activity: []Activity{act("PreToolUse", "s1", 1)}, Sessions: []Session{first}}
	if v := Classify(in, opts); v.Rule != RuleOK || v.JudgedSessions != 1 {
		t.Fatalf("got %+v, want ok with one judged session", v)
	}
}

func TestClassifyAllOrdersWorstFirst(t *testing.T) {
	vs := ClassifyAll([]ToolInput{
		{Tool: "b", Events: specs, Activity: []Activity{act("PreToolUse", "s1", 1)}, Sessions: []Session{sess("s1", "cli")}},
		{Tool: "a", Events: specs, Sessions: []Session{sess("s9", "cli")}},
	}, opts)
	if vs[0].Tool != "a" || vs[0].Rule != RuleNeverSeen || vs[1].Rule != RuleOK {
		t.Fatalf("order: %+v", vs)
	}
}

func TestEnvClassesNeverCarryValues(t *testing.T) {
	env := map[string]string{
		"ANTHROPIC_BASE_URL":                   "http://127.0.0.1:8820/secret-path?k=v",
		"OPENAI_BASE_URL":                      "https://api.openai.com/v1",
		"CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST": "1",
		"CLAUDE_CONFIG_DIR":                    "/home/dev/.claude-work",
		"CLAUDE_CODE_USE_BEDROCK":              "0",
		"CLAUDE_CODE_USE_VERTEX":               "maybe",
		"UNRELATED":                            "x",
	}
	got := EnvClasses(func(k string) string { return env[k] })
	want := map[string]string{
		"ANTHROPIC_BASE_URL":                   ClassLoopback,
		"OPENAI_BASE_URL":                      ClassProviderDirect,
		"CLAUDE_CODE_PROVIDER_MANAGED_BY_HOST": ClassOn,
		"CLAUDE_CONFIG_DIR":                    PathHashClass("/home/dev/.claude-work"),
		"CLAUDE_CODE_USE_BEDROCK":              ClassOff,
		"CLAUDE_CODE_USE_VERTEX":               ClassSet,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
	for k, v := range got {
		if strings.Contains(v, "/") || strings.Contains(v, "8820") || strings.Contains(v, "claude-work") {
			t.Errorf("%s class %q carries part of the value", k, v)
		}
	}
	if !strings.HasPrefix(got["CLAUDE_CONFIG_DIR"], "hash:") || len(got["CLAUDE_CONFIG_DIR"]) != len("hash:")+16 {
		t.Errorf("config dir hash shape: %q", got["CLAUDE_CONFIG_DIR"])
	}
	if EnvClasses(func(string) string { return "" }) != nil {
		t.Error("no probe set: want nil")
	}
}

func TestURLClass(t *testing.T) {
	for in, want := range map[string]string{
		"http://localhost:8820":       ClassLoopback,
		"http://[::1]:8820":           ClassLoopback,
		"https://API.anthropic.com":   ClassProviderDirect,
		"https://gw.example.com/v1":   ClassOtherHost,
		"not a url":                   ClassInvalid,
		"   ":                         ClassEmpty,
		"https://127.0.0.2:9000/up/x": ClassLoopback,
	} {
		if got := URLClass(in); got != want {
			t.Errorf("URLClass(%q) = %s, want %s", in, got, want)
		}
	}
}

func TestPayloadSessionID(t *testing.T) {
	big := `"` + strings.Repeat("a", 1<<16) + `"`
	for in, want := range map[string]string{
		`{"session_id":"s1","tool_input":` + big + `}`:   "s1",
		"\xEF\xBB\xBF" + `{"sessionId":"s2"}`:            "s2",
		`{"hook_event_name":"x","conversation_id":"c3"}`: "c3",
		`{"tool_input":{"session_id":"nested"},"x":1}`:   "",
		`{"session_id":"","sessionId":"s4"}`:             "s4",
		`{"session_id":7,"conversation_id":"c5"}`:        "c5",
		`[1,2]`:                                            "",
		`not json`:                                         "",
		``:                                                 "",
		`{"session_id":"s6"` /* truncated after the id */ : "s6",
		// FU-127: Antigravity's camelCase conversationId and Cascade's
		// trajectory_id are id keys, and one precedence rule picks
		// between spellings whatever their document order.
		`{"conversationId":"agy1","transcriptPath":"/t"}`:               "agy1",
		`{"agent_action_name":"pre_run_command","trajectory_id":"tr1"}`: "tr1",
		`{"sessionId":"camel","session_id":"snake"}`:                    "snake",
		`{"conversationId":"c","sessionId":"s7"}`:                       "s7",
		`{"trajectory_id":"t","conversation_id":"c8"}`:                  "c8",
		`{"sessionId":"s9","tool_input":{"x":1}`:                        "s9",
	} {
		if got := PayloadSessionID([]byte(in)); got != want {
			t.Errorf("PayloadSessionID(%.40q) = %q, want %q", in, got, want)
		}
	}
}

// TestMetadataClass pins the closed metadata vocabulary: every coarse class
// ships, a path hash and an unknown string do not.
func TestMetadataClass(t *testing.T) {
	for _, c := range []string{ClassOn, ClassOff, ClassSet, ClassEmpty, ClassLoopback, ClassProviderDirect, ClassOtherHost, ClassInvalid} {
		if !MetadataClass(c) {
			t.Errorf("MetadataClass(%q) = false, want true", c)
		}
	}
	for _, c := range []string{PathHashClass("/home/u/.claude-work"), "hash:0123456789abcdef", "", "/a/path"} {
		if MetadataClass(c) {
			t.Errorf("MetadataClass(%q) = true, want false", c)
		}
	}
}
