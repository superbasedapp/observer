package dashboard

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/db"
)

// launch_hold_fold_test.go pins lane cli-2 fixes-3, audit M2: the confirm
// card reads a held body's members the way the launch handlers' JSON
// decode does (case-insensitively), and a body that names a member twice
// under that folding, whose decode keeps the last one, is refused, never
// held.

// TestJSONFoldKeyMatchesTheDecode: two names fold equal exactly when
// encoding/json decodes them into the same struct field.
func TestJSONFoldKeyMatchesTheDecode(t *testing.T) {
	for _, name := range []string{"sandbox", "SANDBOX", "Sandbox", "sAnDbOx", "ſandbox", "sandbo", "sandboxx", "sand_box", "sandbox ", "Kind"} {
		var v struct {
			Sandbox bool `json:"sandbox"`
		}
		raw, _ := json.Marshal(map[string]bool{name: true})
		if err := json.Unmarshal(raw, &v); err != nil {
			t.Fatal(err)
		}
		if got := jsonFoldKey(name) == jsonFoldKey("sandbox"); got != v.Sandbox {
			t.Errorf("%q: folds equal to sandbox = %v, but the decode sets the field = %v", name, got, v.Sandbox)
		}
	}
	var k struct {
		Kind string `json:"kind"`
	}
	_ = json.Unmarshal([]byte(`{"KIND":"gui"}`), &k) // a Kelvin sign
	if (jsonFoldKey("KIND") == jsonFoldKey("kind")) != (k.Kind == "gui") {
		t.Errorf("the Kelvin sign folds unlike the decode (decoded %q)", k.Kind)
	}
}

// TestHeldDetailsReadMixedCaseMembers: each member the card reads for the
// human is read under every spelling the decode accepts.
func TestHeldDetailsReadMixedCaseMembers(t *testing.T) {
	row := func(pattern string) agentLaunchRoute {
		r, ok := launchRouteFor(pattern)
		if !ok {
			t.Fatalf("no row %s", pattern)
		}
		return r
	}
	find := func(ds []dashapi.PendingLaunchDetail, label string) (dashapi.PendingLaunchDetail, bool) {
		for _, d := range ds {
			if d.Label == label {
				return d, true
			}
		}
		return dashapi.PendingLaunchDetail{}, false
	}
	for _, tc := range []struct {
		name, pattern, body, label string
		check                      func(d dashapi.PendingLaunchDetail) bool
	}{
		{"sandbox upper", "/api/terminal/launch", `{"SANDBOX":true}`, "sandbox", func(d dashapi.PendingLaunchDetail) bool { return d.Value == "sandboxed" && !d.Warn }},
		{"sandbox long s", "/api/terminal/launch", `{"ſandbox":true}`, "sandbox", func(d dashapi.PendingLaunchDetail) bool { return d.Value == "sandboxed" }},
		{"sandbox mixed false", "/api/tools/launch", `{"Sandbox":false}`, "sandbox", func(d dashapi.PendingLaunchDetail) bool { return d.Warn && strings.Contains(d.Value, "unsandboxed") }},
		{"sign_in_seed", "/api/terminal/launch", `{"Sign_In_Seed":true}`, "Sign_In_Seed", func(d dashapi.PendingLaunchDetail) bool {
			return d.Warn && strings.Contains(d.Value, "copies your sign-in")
		}},
		{"kind", "/api/terminal/launch", `{"KIND":"gui"}`, "KIND", func(d dashapi.PendingLaunchDetail) bool { return strings.Contains(d.Value, "desktop app") }},
		{"workspace_remote", "/api/terminal/launch", `{"Workspace_Remote":"https://e.x/r.git"}`, "Workspace_Remote", func(d dashapi.PendingLaunchDetail) bool { return d.Warn }},
		{"confirm_spend", "/api/benchmarks/run", `{"Confirm_Spend":true}`, "Confirm_Spend", func(d dashapi.PendingLaunchDetail) bool { return d.Warn }},
		{"allow_unpriced", "/api/benchmarks/run", `{"ALLOW_UNPRICED":true}`, "ALLOW_UNPRICED", func(d dashapi.PendingLaunchDetail) bool { return d.Warn }},
	} {
		ds := heldDetails(row(tc.pattern), tc.pattern, []byte(tc.body))
		d, ok := find(ds, tc.label)
		if !ok || !tc.check(d) {
			t.Errorf("%s: card %+v does not read %s", tc.name, ds, tc.body)
		}
	}
	// A sandbox member under another spelling is said once, in words, and
	// not again as a raw member.
	ds := heldDetails(row("/api/terminal/launch"), "/api/terminal/launch", []byte(`{"SANDBOX":true}`))
	if len(ds) != 1 {
		t.Errorf("SANDBOX shown more than once: %+v", ds)
	}
}

// TestDuplicateMemberIsRefusedNotHeld: an agent's launch body that names a
// read member twice under the decode's folding (mixed case, the same
// spelling twice, or nested) is refused with duplicate_member; nothing is
// held and the handler never runs. A body without one is held as before.
func TestDuplicateMemberIsRefusedNotHeld(t *testing.T) {
	database, err := openTestDB(context.Background(), db.Options{Path: filepath.Join(t.TempDir(), "d.db")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	pending := newFakePending()
	s, err := New(Options{
		DB: database, LaunchManager: &fakeLaunchManager{}, PendingLaunches: pending,
		LaunchCaller: func(context.Context, netip.AddrPort, netip.AddrPort) (string, string) {
			return dashapi.InitiatorAgent, "sess-parent"
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ran := 0
	inner := func(http.ResponseWriter, *http.Request) { ran++ }
	post := func(pattern, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		s.holdAgentLaunch(pattern, inner)(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return rec
	}
	for _, tc := range []struct{ name, pattern, path, body, dup string }{
		{"sandbox case", "/api/terminal/launch", "/api/terminal/launch", `{"sandbox":true,"SANDBOX":false}`, "SANDBOX"},
		{"sandbox twice", "/api/terminal/launch", "/api/terminal/launch", `{"sandbox":true,"sandbox":false}`, "sandbox"},
		{"sandbox long s", "/api/session/", "/api/session/abc/launch", `{"sandbox":true,"ſandbox":false}`, "ſandbox"},
		{"sign_in_seed", "/api/terminal/launch", "/api/terminal/launch", `{"sign_in_seed":false,"Sign_In_Seed":true}`, "Sign_In_Seed"},
		{"kind", "/api/terminal/launch", "/api/terminal/launch", `{"kind":"pty","KIND":"gui"}`, "KIND"},
		{"workspace_remote", "/api/terminal/launch", "/api/terminal/launch", `{"workspace_remote":"https://a.x/r.git","WORKSPACE_REMOTE":"https://b.x/r.git"}`, "WORKSPACE_REMOTE"},
		{"confirm_spend", "/api/benchmarks/run", "/api/benchmarks/run", `{"confirm_spend":true,"Confirm_Spend":true,"spec":"x"}`, "Confirm_Spend"},
		{"allow_unpriced", "/api/benchmarks/run", "/api/benchmarks/run", `{"confirm_spend":true,"allow_unpriced":false,"Allow_Unpriced":true}`, "Allow_Unpriced"},
		{"nested candidate", "/api/arena/runs", "/api/arena/runs", `{"candidates":[{"tool":"codex","TOOL":"claude-code"}]}`, "TOOL"},
	} {
		rec := post(tc.pattern, tc.path, tc.body)
		var resp struct{ Code, Error string }
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		if rec.Code != http.StatusBadRequest || resp.Code != dashapi.PendingCodeDuplicateMember || !strings.Contains(resp.Error, `"`+tc.dup+`"`) {
			t.Errorf("%s: = %d %s, want 400 %s naming %q", tc.name, rec.Code, rec.Body.String(), dashapi.PendingCodeDuplicateMember, tc.dup)
		}
	}
	if ran != 0 || len(pending.List()) != 0 {
		t.Fatalf("a duplicate-member body ran (%d) or was held (%d)", ran, len(pending.List()))
	}
	// The same members once each: held as before.
	if rec := post("/api/terminal/launch", "/api/terminal/launch", `{"sandbox":true,"tool":"codex","candidates":[{"tool":"a"},{"tool":"b"}]}`); rec.Code != http.StatusAccepted || len(pending.List()) != 1 {
		t.Fatalf("a body naming each member once = %d %s", rec.Code, rec.Body.String())
	}
}

// TestFoldedDuplicateMemberWalk covers the walk itself.
func TestFoldedDuplicateMemberWalk(t *testing.T) {
	for _, tc := range []struct {
		body string
		dup  string
	}{
		{`{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}`, ""},
		{`{"a":{"x":1,"X":2}}`, "X"},
		{`{"a":[1,"a",{"b":1}],"A":2}`, "A"},
		{`{"a":"b","b":"a"}`, ""},
		{`[{"a":1},{"a":1}]`, ""},
		{`not json`, ""},
		{`{"a":1,"b"`, ""},
	} {
		got, ok := foldedDuplicateMember([]byte(tc.body))
		if ok != (tc.dup != "") || got != tc.dup {
			t.Errorf("%s: = %q %v, want %q", tc.body, got, ok, tc.dup)
		}
	}
}
