package mcprelay

import (
	"strings"
	"testing"
)

func TestCorrelationFromEnv(t *testing.T) {
	env := map[string]string{"A": "", "B": "sess-b", "C": "sess-c", "BAD": "has space", "LONG": strings.Repeat("x", maxAnchorLen+1)}
	look := func(k string) string { return env[k] }
	cases := []struct {
		name string
		keys []string
		want string
	}{
		{"first non-empty key wins", []string{"A", "B", "C"}, "sess-b"},
		{"unusable values are skipped", []string{"BAD", "LONG", "C"}, "sess-c"},
		{"no key set", []string{"A", "MISSING"}, ""},
		{"no keys", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := CorrelationFromEnv(look, tc.keys); got.CodingSessionID != tc.want || got.TurnRef != "" || got.ActionRef != "" {
				t.Fatalf("got %+v want session %q", got, tc.want)
			}
		})
	}
	if got := CorrelationFromEnv(nil, []string{"B"}); got != (Correlation{}) {
		t.Fatalf("nil lookup %+v", got)
	}
}

// TestForCallToolUseMeta pins the per-call action_ref source: the client's
// params._meta tool-use id (live-grounded Claude Code key) overrides a
// stream-level action_ref; anything unusable is dropped, never carried.
func TestForCallToolUseMeta(t *testing.T) {
	stream := Correlation{CodingSessionID: "s1", TurnRef: "t1", ActionRef: "stream-action"}
	cases := []struct {
		name   string
		params string
		want   string
	}{
		{"claude code tool-use id", `{"name":"x","_meta":{"claudecode/toolUseId":"toolu_01ABC","progressToken":1}}`, "toolu_01ABC"},
		{"no _meta keeps the stream anchor", `{"name":"x"}`, "stream-action"},
		{"non-string meta value ignored", `{"name":"x","_meta":{"claudecode/toolUseId":42}}`, "stream-action"},
		{"over-long meta value dropped", `{"_meta":{"claudecode/toolUseId":"` + strings.Repeat("a", maxAnchorLen+1) + `"}}`, "stream-action"},
		{"control characters dropped", `{"_meta":{"claudecode/toolUseId":"a\nb"}}`, "stream-action"},
		{"array params", `[1,2]`, "stream-action"},
		{"unknown meta key", `{"_meta":{"other/toolUseId":"toolu_X"}}`, "stream-action"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stream.forCall(&Message{Method: "tools/call", Params: []byte(tc.params)})
			if got.ActionRef != tc.want || got.CodingSessionID != "s1" || got.TurnRef != "t1" {
				t.Fatalf("got %+v want action %q", got, tc.want)
			}
		})
	}
	bad := Correlation{CodingSessionID: strings.Repeat("s", maxAnchorLen+1), TurnRef: "t\x00"}
	if got := bad.forCall(nil); got != (Correlation{}) {
		t.Fatalf("unbounded stream anchors carried: %+v", got)
	}
}
