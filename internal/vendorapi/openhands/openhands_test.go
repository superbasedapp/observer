package openhands

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/testsupport/vendormock"
	"github.com/marmutapp/superbased-observer/internal/vendorapi"
	vs "github.com/marmutapp/superbased-observer/internal/vendorsurface"
)

const testConversation = "5b8f0c3e-0000-4000-8000-000000000001"

var testParams = vendorapi.Params{ParamConversationID: testConversation}

func fixture(t *testing.T, surface vs.SurfaceID, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "vendorapi", "openhands", string(surface), name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func resp(body []byte, cursor string) vendorapi.Response {
	return vendorapi.Response{
		Status: 200, Origin: "https://app.all-hands.dev:443", Body: body, Cursor: cursor, Params: testParams,
	}
}

func isDrift(err error) bool { return err != nil && errors.Is(err, vendorapi.ErrSchemaDrift) }

// TestAppConversationsParseCorpus: one snapshot per conversation, one usage
// row where metrics exist (native tokens plus USD), the session_api_key and
// conversation_url never decoded.
func TestAppConversationsParseCorpus(t *testing.T) {
	raw := fixture(t, SurfaceAppConversations, "normal_page.json")
	p, err := parseAppConversations(resp(raw, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Snapshots) != 2 || len(p.Usage) != 1 || p.SourceRecords != 2 || p.NextCursor != "synthpage0002" {
		t.Fatalf("snapshots %d usage %d records %d next %q", len(p.Snapshots), len(p.Usage), p.SourceRecords, p.NextCursor)
	}
	s := p.Snapshots[0]
	want := map[string]string{
		"created_at": "2026-10-30T09:12:00Z", "updated_at": "2026-10-30T09:40:12Z", "title": "Summarize this repository",
		"created_by_user_id": "user-synth-0001", "selected_repository": "acme/widget", "selected_branch": "main",
		"git_provider": "github", "trigger": "openhands_api", "llm_model": "litellm_proxy/claude-sonnet-4-5",
		"sandbox_status": "PAUSED", "execution_status": "finished", "sub_conversation_count": "1", "pr_count": "1",
		"pr_number": "42",
	}
	if s.Class != ConversationClass || s.Subject != testConversation || len(s.Body) != len(want) {
		t.Fatalf("snapshot %+v", s)
	}
	for k, v := range want {
		if s.Body[k] != v {
			t.Errorf("body[%s] = %q, want %q", k, s.Body[k], v)
		}
	}
	for _, sn := range p.Snapshots {
		for k, v := range sn.Body {
			if strings.Contains(v, "synthetic-session-placeholder") || strings.Contains(v, "runtime-synth") || strings.Contains(k, "session_api") {
				t.Fatalf("a runtime credential leaked into %s=%s", k, v)
			}
		}
	}
	u := p.Usage[0]
	updated := time.Date(2026, 10, 30, 9, 40, 12, 0, time.UTC)
	if u.JoinValue != testConversation || u.InputTokens != 182340 || u.OutputTokens != 6120 ||
		u.CacheReadTokens != 150200 || u.CacheWriteTokens != 21400 || u.ReasoningTokens != 0 ||
		u.ChargedUnit != ChargedUnitUSD || u.ChargedMicros != 421_500 || u.IdentityKind != "user_id" ||
		u.Identity != "user-synth-0001" || !u.At.Equal(updated) || u.Revision != updated.Unix() ||
		u.Model != "litellm_proxy/claude-sonnet-4-5" || u.Flags[InputBasisFlag] != InputBasisValue {
		t.Fatalf("usage %+v", u)
	}
	if s2 := p.Snapshots[1]; s2.Body["parent_conversation_id"] != testConversation || s2.Body["pr_count"] != "0" {
		t.Fatalf("child snapshot %+v", s2)
	}
	last, err := parseAppConversations(resp(fixture(t, SurfaceAppConversations, "last_page.json"), "synthpage0002"))
	if err != nil || last.NextCursor != "" || len(last.Usage) != 1 {
		t.Fatalf("last page %+v %v", last, err)
	}
	// No creator: the caller owns it; absent cache counts stay zero-valued
	// fields of a row whose basis flag says what the counts are.
	if lu := last.Usage[0]; lu.IdentityKind != IdentityCaller || lu.Identity != IdentityCallerValue ||
		lu.InputTokens != 2100 || lu.ChargedMicros != 12_500 {
		t.Fatalf("last usage %+v", lu)
	}
}

// TestEventsParseCorpus: messages land as content, every other kind as a
// metadata row naming the tool, never the action or observation body.
func TestEventsParseCorpus(t *testing.T) {
	p, err := parseEvents(resp(fixture(t, SurfaceEvents, "normal_page.json"), ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := vendorapi.Validate(p); err != nil {
		t.Fatalf("page does not validate: %v", err)
	}
	if len(p.Content) != 1 || len(p.Audit) != 2 || p.SourceRecords != 3 || p.NextCursor != "syntheventpage0002" ||
		len(canaryEvents(p)) != 0 {
		t.Fatalf("content %d audit %d next %q", len(p.Content), len(p.Audit), p.NextCursor)
	}
	c := p.Content[0]
	if c.Role != "prompt" || c.Text != "Summarize this repository" || c.SessionRef != testConversation ||
		!c.At.Equal(time.Date(2026, 10, 30, 9, 12, 1, 120_000_000, time.UTC)) {
		t.Fatalf("content %+v", c)
	}
	a, o := p.Audit[0], p.Audit[1]
	if a.Action != "tool_call" || a.Target != "terminal" || !a.ActorIsAgent || a.AgentSessionID != testConversation ||
		a.Detail["tool_call_id"] != "toolu_synth_0001" || a.Namespace != EventNamespace {
		t.Fatalf("action %+v", a)
	}
	if o.Action != "tool_result" || o.ActorIsAgent || o.Detail["source"] != "environment" {
		t.Fatalf("observation %+v", o)
	}
	for _, e := range p.Audit {
		for k, v := range e.Detail {
			if strings.Contains(v, "ls -la") || k == "command" {
				t.Fatalf("an action body leaked: %s=%s", k, v)
			}
		}
	}
	last, err := parseEvents(resp(fixture(t, SurfaceEvents, "last_page.json"), "syntheventpage0002"))
	if err != nil || last.NextCursor != "" || len(last.Content) != 1 || last.Content[0].Role != "response" ||
		len(last.Audit) != 1 || last.Audit[0].Action != "state_update" {
		t.Fatalf("last page %+v %v", last, err)
	}
	odd, err := parseEvents(resp([]byte(`{"items":[{"id":"e1","timestamp":"2026-10-30T09:00:00Z","source":"agent",
		"kind":"BrandNewEvent","secret":"never-read"}],"next_page_id":null}`), ""))
	if err != nil || odd.Audit[0].Action != ActionOther || len(canaryEvents(odd)) != 1 || len(odd.Audit[0].Detail) != 1 {
		t.Fatalf("unknown kind %+v %v", odd, err)
	}
	long := `{"items":[{"id":"e1","timestamp":"2026-10-30T09:00:00Z","source":"agent","kind":"MessageEvent",
		"llm_message":{"role":"assistant","content":[{"type":"text","text":"` + strings.Repeat("é", vendorapi.MaxContentBytes) +
		`"},{"type":"image","image_urls":["x"]}]}}],"next_page_id":null}`
	cut, err := parseEvents(resp([]byte(long), ""))
	if err != nil || !cut.Content[0].Truncated || vendorapi.Validate(cut) != nil {
		t.Fatalf("long message %v", err)
	}
}

func TestBuildContract(t *testing.T) {
	from := time.Date(2026, 10, 29, 0, 0, 0, 0, time.UTC)
	w := vendorapi.Window{From: from, To: from.Add(48 * time.Hour)}
	req, err := buildAppConversations(nil, w, "")
	if err != nil || req.Method != "GET" || req.Path != "/api/v1/app-conversations/search" ||
		req.Query["limit"][0] != "100" || req.Query["include_sub_conversations"][0] != "true" ||
		req.Query["updated_at__gte"][0] != "2026-10-29T00:00:00Z" || req.Query["updated_at__lt"][0] != "2026-10-31T00:00:00Z" ||
		req.Query["page_id"] != nil {
		t.Fatalf("search request %+v %v", req, err)
	}
	all, err := buildAppConversations(nil, vendorapi.Window{}, "synthpage0002")
	if err != nil || all.Query["updated_at__gte"] != nil || all.Query["page_id"][0] != "synthpage0002" {
		t.Fatalf("unwindowed request %+v %v", all, err)
	}
	ev, err := buildEvents(testParams, vendorapi.Window{}, "")
	if err != nil || ev.Path != "/api/v1/conversation/"+testConversation+"/events/search" ||
		ev.Query["sort_order"][0] != "TIMESTAMP" || ev.Query["limit"][0] != "100" || ev.Query["timestamp__gte"] != nil {
		t.Fatalf("events request %+v %v", ev, err)
	}
	evw, err := buildEvents(testParams, w, "p2")
	if err != nil || evw.Query["timestamp__gte"][0] != "2026-10-29T00:00:00Z" || evw.Query["page_id"][0] != "p2" {
		t.Fatalf("windowed events request %+v %v", evw, err)
	}
	for name, err := range map[string]error{
		"search half window": errOf(buildAppConversations(nil, vendorapi.Window{From: from}, "")),
		"search bad cursor":  errOf(buildAppConversations(nil, vendorapi.Window{}, "bad cursor!")),
		"events no id":       errOf(buildEvents(nil, vendorapi.Window{}, "")),
		"events traversal":   errOf(buildEvents(vendorapi.Params{ParamConversationID: "../x"}, vendorapi.Window{}, "")),
		"events inverted":    errOf(buildEvents(testParams, vendorapi.Window{From: from, To: from}, "")),
	} {
		if err == nil {
			t.Errorf("%s: build accepted", name)
		}
	}
}

func errOf(_ vendorapi.Request, err error) error { return err }

// TestFieldPolicyMatrix (plan 12A.5): missing required fields, wrong JSON
// types, repeated keys, bad timestamps, negative or quoted counts and a
// paging contract break fail the page as schema drift.
func TestFieldPolicyMatrix(t *testing.T) {
	conv := func(b, cur string) error { _, err := parseAppConversations(resp([]byte(b), cur)); return err }
	ev := func(b string) error { _, err := parseEvents(resp([]byte(b), "")); return err }
	wrap := func(items string) string { return `{"items":[` + items + `],"next_page_id":null}` }
	okConv := `{"id":"c1","created_at":"2026-10-30T09:00:00Z"}`
	okEv := `{"id":"e1","timestamp":"2026-10-30T09:00:00Z","source":"agent","kind":"ActionEvent"}`
	for name, err := range map[string]error{
		"items missing":       conv(`{"next_page_id":null}`, ""),
		"items object":        conv(`{"items":{}}`, ""),
		"page id repeats":     conv(`{"items":[],"next_page_id":"p1"}`, "p1"),
		"page id number":      conv(`{"items":[],"next_page_id":3}`, ""),
		"conv id missing":     conv(wrap(`{"created_at":"2026-10-30T09:00:00Z"}`), ""),
		"conv repeated":       conv(wrap(okConv+","+okConv), ""),
		"conv bad created":    conv(wrap(`{"id":"c1","created_at":"last week"}`), ""),
		"conv bad updated":    conv(wrap(`{"id":"c1","created_at":"2026-10-30T09:00:00Z","updated_at":5}`), ""),
		"cost negative":       conv(wrap(`{"id":"c1","created_at":"2026-10-30T09:00:00Z","metrics":{"accumulated_cost":-1}}`), ""),
		"cost quoted":         conv(wrap(`{"id":"c1","created_at":"2026-10-30T09:00:00Z","metrics":{"accumulated_cost":"1"}}`), ""),
		"tokens negative":     conv(wrap(`{"id":"c1","created_at":"2026-10-30T09:00:00Z","metrics":{"accumulated_token_usage":{"prompt_tokens":-3}}}`), ""),
		"tokens fractional":   conv(wrap(`{"id":"c1","created_at":"2026-10-30T09:00:00Z","metrics":{"accumulated_token_usage":{"prompt_tokens":1.5}}}`), ""),
		"pr number negative":  conv(wrap(`{"id":"c1","created_at":"2026-10-30T09:00:00Z","pr_number":[-1]}`), ""),
		"event id missing":    ev(wrap(`{"timestamp":"2026-10-30T09:00:00Z","source":"agent","kind":"ActionEvent"}`)),
		"event repeated":      ev(wrap(okEv + "," + okEv)),
		"event bad time":      ev(wrap(`{"id":"e1","timestamp":"soon","source":"agent","kind":"ActionEvent"}`)),
		"event kind missing":  ev(wrap(`{"id":"e1","timestamp":"2026-10-30T09:00:00Z","source":"agent"}`)),
		"message no content":  ev(wrap(`{"id":"e1","timestamp":"2026-10-30T09:00:00Z","source":"user","kind":"MessageEvent"}`)),
		"message parts wrong": ev(wrap(`{"id":"e1","timestamp":"2026-10-30T09:00:00Z","source":"user","kind":"MessageEvent","llm_message":{"content":"hi"}}`)),
	} {
		if !isDrift(err) {
			t.Errorf("%s: err %v, want schema drift", name, err)
		}
	}
	noID := resp([]byte(wrap(okEv)), "")
	noID.Params = nil
	if _, err := parseEvents(noID); !isDrift(err) {
		t.Errorf("events without a conversation parameter: %v", err)
	}
	if _, err := parseAppConversations(vendorapi.Response{Status: 500, Body: []byte(`{}`)}); !isDrift(err) {
		t.Errorf("non-200: %v", err)
	}
}

// TestDriversContract pins both drivers to their catalog rows and corpus
// ledgers (node-consumed: they have no org driver-table entry).
func TestDriversContract(t *testing.T) {
	for _, d := range []vendorapi.Driver{AppConversations(), Events()} {
		vendormock.CheckDriverContract(t, d)
		if !d.ClosedDTO || d.Tool != Tool || d.Auth.Scheme != vendorapi.SchemeBearer {
			t.Errorf("%s: driver %+v", d.Surface, d)
		}
	}
}

// TestConformance runs the shared conformance suite against both drivers
// through the pure adapter.
func TestConformance(t *testing.T) {
	for _, d := range []vendorapi.Driver{AppConversations(), Events()} {
		d := d
		t.Run(string(d.Surface), func(t *testing.T) { vendormock.RunPure(t, d, testParams, vendorapi.Window{}) })
	}
}
