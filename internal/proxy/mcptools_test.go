package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// Agent Access P4 W4d tests (doc3 §11.7 W4d): tools[] strip splice integrity
// + json.Valid on Anthropic AND OpenAI shapes, the hosted-connector parse
// table, the deny 403 shape, and the nil-seam byte-identical contract.
//
// Sol P3+P4 finding 5 (R-306 coverage): every tools[] entry is examined —
// boundary rows put the forbidden declaration at index 255 / 256 / 257 /
// 10,000, past a 300-approved prefix, and past the seam ceiling; a splice
// failure with pending drops REFUSES rather than forwarding the original.

const mcpAnthropicBody = `{"model":"claude-opus-4-8","max_tokens":64,"stream":false,` +
	`"metadata":{"user_id":"{\"session_id\":\"sess-mcp\"}"},` +
	`"system":[{"type":"text","text":"be brief","cache_control":{"type":"ephemeral"}}],` +
	`"tools":[` +
	`{"name":"Bash","description":"run","input_schema":{"type":"object"}},` +
	`{"name":"mcp__github__create_issue","description":"open an issue","input_schema":{"type":"object","properties":{"title":{"type":"string"}}}},` +
	`{ "name" : "mcp__slack__post_message" , "description":"post","input_schema":{"type":"object"}},` +
	`{"name":"mcp__github__list_repos","input_schema":{"type":"object"}}` +
	`],` +
	`"messages":[{"role":"user","content":"the word \"tools\":[] appears in text"}]}`

const mcpOpenAIChatBody = `{"model":"gpt-5","stream":true,` +
	`"tools":[` +
	`{"type":"function","function":{"name":"read_file","parameters":{"type":"object"}}},` +
	`{"type":"function","function":{"name":"mcp__jira__create_ticket","description":"x","parameters":{"type":"object"}}},` +
	`{"type":"function","function":{"name":"mcp__jira__search","parameters":{"type":"object"}}}` +
	`],"messages":[{"role":"user","content":"hi"}]}`

const mcpOpenAIResponsesBody = `{"model":"gpt-5","input":"hi",` +
	`"tools":[` +
	`{"type":"function","name":"mcp__notion__search","parameters":{"type":"object"}},` +
	`{"type":"mcp","server_label":"deepwiki","server_url":"https://mcp.deepwiki.com/mcp","require_approval":"never"},` +
	`{"type":"mcp","server_label":"dropbox","connector_id":"connector_dropbox","authorization":"tok"}` +
	`]}`

// mcpForbiddenName is the declaration every boundary row must strip.
const mcpForbiddenName = "mcp__evil__exfiltrate"

// mcpBoundaryBody builds a request with n MCP declarations at tools[]
// indices 0..n-1 — `mcp__ok__t<i>` everywhere except at each index in
// forbiddenAt, which carries mcpForbiddenName — followed by one non-MCP
// declaration ("Bash") at index n. openAI selects the Chat Completions
// function-nested shape; false is the Anthropic flat shape. extraTop is
// spliced verbatim after "model" (a hosted-connector key, for instance).
func mcpBoundaryBody(openAI bool, n int, forbiddenAt map[int]bool, extraTop string) string {
	var sb strings.Builder
	if openAI {
		sb.WriteString(`{"model":"gpt-5",`)
	} else {
		sb.WriteString(`{"model":"claude-opus-4-8","max_tokens":8,`)
	}
	sb.WriteString(extraTop)
	sb.WriteString(`"tools":[`)
	for i := 0; i < n; i++ {
		if i > 0 {
			sb.WriteByte(',')
		}
		name := fmt.Sprintf("mcp__ok__t%d", i)
		if forbiddenAt[i] {
			name = mcpForbiddenName
		}
		if openAI {
			sb.WriteString(`{"type":"function","function":{"name":"` + name + `","parameters":{"type":"object"}}}`)
		} else {
			sb.WriteString(`{"name":"` + name + `","input_schema":{"type":"object"}}`)
		}
	}
	if n > 0 {
		sb.WriteByte(',')
	}
	if openAI {
		sb.WriteString(`{"type":"function","function":{"name":"Bash","parameters":{"type":"object"}}}`)
	} else {
		sb.WriteString(`{"name":"Bash","input_schema":{"type":"object"}}`)
	}
	sb.WriteString(`],"messages":[{"role":"user","content":"hi"}]}`)
	return sb.String()
}

// countMCPToolNames re-parses a forwarded body the way an upstream would
// (last "tools" key wins) and returns how many tools[] entries carry an
// `mcp__` name, plus whether the forbidden name survived anywhere.
func countMCPToolNames(t *testing.T, body []byte) (mcpCount, total int) {
	t.Helper()
	if !json.Valid(body) {
		t.Fatalf("forwarded body is not valid JSON: %.200s", body)
	}
	var doc struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("re-parse forwarded body: %v", err)
	}
	for _, raw := range doc.Tools {
		var e proxyToolNameEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("forwarded tool entry malformed: %v (%s)", err, raw)
		}
		name := e.Name
		if name == "" && e.Function != nil {
			name = e.Function.Name
		}
		if strings.HasPrefix(name, mcpToolNamePrefix) {
			mcpCount++
		}
	}
	return mcpCount, len(doc.Tools)
}

// denyEvilSeam keeps every declaration whose server is not "evil" and
// approves every hosted connector.
func denyEvilSeam(in ToolsAllowlistInput) ToolsAllowlistResult {
	keep := make([]MCPToolDecl, 0, len(in.Decls))
	for _, d := range in.Decls {
		if d.Server != "evil" {
			keep = append(keep, d)
		}
	}
	return ToolsAllowlistResult{Keep: keep}
}

func TestParseMCPToolDecls_Rows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want []MCPToolDecl
	}{
		{"anthropic top-level names", mcpAnthropicBody, []MCPToolDecl{
			{Index: 1, Name: "mcp__github__create_issue", Server: "github", Tool: "create_issue"},
			{Index: 2, Name: "mcp__slack__post_message", Server: "slack", Tool: "post_message"},
			{Index: 3, Name: "mcp__github__list_repos", Server: "github", Tool: "list_repos"},
		}},
		{"openai chat nested function names", mcpOpenAIChatBody, []MCPToolDecl{
			{Index: 1, Name: "mcp__jira__create_ticket", Server: "jira", Tool: "create_ticket"},
			{Index: 2, Name: "mcp__jira__search", Server: "jira", Tool: "search"},
		}},
		{"openai responses top-level name; hosted mcp entries are not decls", mcpOpenAIResponsesBody, []MCPToolDecl{
			{Index: 0, Name: "mcp__notion__search", Server: "notion", Tool: "search"},
		}},
		{"server-only name keeps whole rest as tool", `{"tools":[{"name":"mcp__solo"}]}`, []MCPToolDecl{
			{Index: 0, Name: "mcp__solo", Server: "solo", Tool: "solo"},
		}},
		{"no tools", `{"model":"x"}`, nil},
		{"tools not an array", `{"tools":{"name":"mcp__a__b"}}`, nil},
		// A duplicated key with a wrong-shaped first value: the last array
		// is what an upstream honours, so it is what the parser reads.
		{"duplicate tools key, scalar first, last array parsed", `{"tools":"x","tools":[{"name":"mcp__a__b"}]}`, []MCPToolDecl{
			{Index: 0, Name: "mcp__a__b", Server: "a", Tool: "b"},
		}},
		{"malformed body", `{"tools":[`, nil},
		{"non-mcp only", `{"tools":[{"name":"Bash"}]}`, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			scan := parseMCPToolDecls([]byte(tc.body))
			got := scan.Decls
			if len(got) != len(tc.want) {
				t.Fatalf("decls = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("decl[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
			if scan.Overflow != nil {
				t.Errorf("overflow = %v on a small body, want nil", scan.Overflow)
			}
		})
	}
}

// TestParseMCPToolDecls_EveryEntryExamined pins Sol finding 5 at the parser:
// the tools array is never truncated. A forbidden declaration at index 255,
// 256, 257 or past a 300-approved prefix reaches the seam; one past the
// ceiling is reported in Overflow by index — never silently ignored.
func TestParseMCPToolDecls_EveryEntryExamined(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		openAI       bool
		n            int
		forbiddenAt  int
		wantDecls    int
		wantOverflow []int
	}{
		{"anthropic forbidden at 255 (256 decls)", false, 256, 255, 256, nil},
		{"anthropic forbidden at 256 (257 decls)", false, 257, 256, 257, nil},
		{"anthropic forbidden at 257 (258 decls)", false, 258, 257, 258, nil},
		{"openai forbidden at 255", true, 256, 255, 256, nil},
		{"openai forbidden at 256", true, 257, 256, 257, nil},
		{"openai forbidden at 257", true, 258, 257, 258, nil},
		{"300 approved + 1 forbidden", false, 301, 300, 301, nil},
		{"exactly at the ceiling: no overflow", false, maxProxyMCPDecls, maxProxyMCPDecls - 1, maxProxyMCPDecls, nil},
		{"one past the ceiling: the extra is overflow", false, maxProxyMCPDecls + 1, maxProxyMCPDecls, maxProxyMCPDecls, []int{maxProxyMCPDecls}},
		{"openai one past the ceiling", true, maxProxyMCPDecls + 1, maxProxyMCPDecls, maxProxyMCPDecls, []int{maxProxyMCPDecls}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			body := mcpBoundaryBody(tc.openAI, tc.n, map[int]bool{tc.forbiddenAt: true}, "")
			scan := parseMCPToolDecls([]byte(body))
			if len(scan.Decls) != tc.wantDecls {
				t.Fatalf("decls = %d, want %d", len(scan.Decls), tc.wantDecls)
			}
			if len(scan.Overflow) != len(tc.wantOverflow) {
				t.Fatalf("overflow = %v, want %v", scan.Overflow, tc.wantOverflow)
			}
			for i := range tc.wantOverflow {
				if scan.Overflow[i] != tc.wantOverflow[i] {
					t.Errorf("overflow[%d] = %d, want %d", i, scan.Overflow[i], tc.wantOverflow[i])
				}
			}
			// The forbidden declaration is either seam-visible at its exact
			// index or listed in Overflow — never absent from both.
			seen := false
			for _, d := range scan.Decls {
				if d.Name == mcpForbiddenName {
					if d.Index != tc.forbiddenAt || d.Server != "evil" || d.Tool != "exfiltrate" {
						t.Errorf("forbidden decl = %+v, want index %d server evil", d, tc.forbiddenAt)
					}
					seen = true
				}
			}
			for _, i := range scan.Overflow {
				if i == tc.forbiddenAt {
					seen = true
				}
			}
			if !seen {
				t.Errorf("forbidden declaration at index %d was neither parsed nor reported as overflow", tc.forbiddenAt)
			}
		})
	}

	t.Run("forbidden at 10,000 lands in overflow", func(t *testing.T) {
		t.Parallel()
		body := mcpBoundaryBody(false, 10001, map[int]bool{10000: true}, "")
		scan := parseMCPToolDecls([]byte(body))
		if len(scan.Decls) != maxProxyMCPDecls {
			t.Fatalf("decls = %d, want the ceiling %d", len(scan.Decls), maxProxyMCPDecls)
		}
		if want := 10001 - maxProxyMCPDecls; len(scan.Overflow) != want {
			t.Fatalf("overflow = %d entries, want %d", len(scan.Overflow), want)
		}
		if first, last := scan.Overflow[0], scan.Overflow[len(scan.Overflow)-1]; first != maxProxyMCPDecls || last != 10000 {
			t.Errorf("overflow span = [%d..%d], want [%d..10000]", first, last, maxProxyMCPDecls)
		}
	})
}

func TestParseHostedMCPConnectors_Rows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		provider string
		body     string
		want     []HostedMCPConnector
	}{
		{
			"anthropic mcp_servers url", models.ProviderAnthropic,
			`{"model":"c","mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"example"}]}`,
			[]HostedMCPConnector{{Provider: models.ProviderAnthropic, Kind: "anthropic_mcp_servers", Name: "example", URL: "https://mcp.example.com/sse"}},
		},
		{"openai responses url + connector_id", models.ProviderOpenAI, mcpOpenAIResponsesBody, []HostedMCPConnector{
			{Provider: models.ProviderOpenAI, Kind: "openai_responses_mcp", Name: "deepwiki", URL: "https://mcp.deepwiki.com/mcp"},
			{Provider: models.ProviderOpenAI, Kind: "openai_responses_mcp", Name: "dropbox", ConnectorID: "connector_dropbox"},
		}},
		{"function tools only: none", models.ProviderOpenAI, mcpOpenAIChatBody, nil},
		{"empty mcp_servers entries skipped", models.ProviderAnthropic, `{"mcp_servers":[{"type":"url"}]}`, nil},
		{"malformed", models.ProviderAnthropic, `{"mcp_servers":[`, nil},
		{"absent", models.ProviderAnthropic, mcpAnthropicBody, nil},
		{
			"duplicate mcp_servers key, scalar first, last array parsed", models.ProviderAnthropic,
			`{"mcp_servers":"x","mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"dup"}]}`,
			[]HostedMCPConnector{{Provider: models.ProviderAnthropic, Kind: "anthropic_mcp_servers", Name: "dup", URL: "https://mcp.example.com/sse"}},
		},
		{
			"hosted connector past a 300-decl prefix is still parsed", models.ProviderAnthropic,
			mcpBoundaryBody(false, 300, nil, `"mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"example"}],`),
			[]HostedMCPConnector{{Provider: models.ProviderAnthropic, Kind: "anthropic_mcp_servers", Name: "example", URL: "https://mcp.example.com/sse"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseHostedMCPConnectors(tc.provider, []byte(tc.body))
			if len(got) != len(tc.want) {
				t.Fatalf("connectors = %+v, want %+v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("connector[%d] = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestStripToolDecls_SpliceIntegrity pins the §12.5 integrity contract on
// both provider shapes: dropped declarations vanish, every kept declaration
// keeps its OWN bytes (including odd inter-token whitespace), every byte
// outside the tools array is verbatim, and the result is json.Valid.
func TestStripToolDecls_SpliceIntegrity(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		body      string
		drop      map[int]bool
		wantOK    bool
		mustKeep  []string
		mustDrop  []string
		wantTools int
	}{
		{
			name: "anthropic drop middle + last", body: mcpAnthropicBody, drop: map[int]bool{2: true, 3: true}, wantOK: true,
			mustKeep:  []string{`{"name":"Bash","description":"run","input_schema":{"type":"object"}}`, `"mcp__github__create_issue"`, `"cache_control":{"type":"ephemeral"}`, `the word \"tools\":[] appears in text`, `"metadata":{"user_id":"{\"session_id\":\"sess-mcp\"}"}`},
			mustDrop:  []string{"mcp__slack__post_message", "mcp__github__list_repos"},
			wantTools: 2,
		},
		{
			name: "anthropic keep whitespace-odd entry verbatim", body: mcpAnthropicBody, drop: map[int]bool{1: true}, wantOK: true,
			mustKeep:  []string{`{ "name" : "mcp__slack__post_message" , "description":"post","input_schema":{"type":"object"}}`},
			mustDrop:  []string{"mcp__github__create_issue"},
			wantTools: 3,
		},
		{
			name: "openai chat drop nested function", body: mcpOpenAIChatBody, drop: map[int]bool{1: true}, wantOK: true,
			mustKeep:  []string{`"mcp__jira__search"`, `"read_file"`, `"stream":true`},
			mustDrop:  []string{"mcp__jira__create_ticket"},
			wantTools: 2,
		},
		{
			name: "drop everything leaves an empty array", body: mcpOpenAIChatBody, drop: map[int]bool{0: true, 1: true, 2: true}, wantOK: true,
			mustKeep:  []string{`"tools":[]`, `"messages":[{"role":"user","content":"hi"}]`},
			wantTools: 0,
		},
		{
			name: "anthropic drop index 256 of 258", body: mcpBoundaryBody(false, 258, map[int]bool{256: true}, ""), drop: map[int]bool{256: true}, wantOK: true,
			mustKeep:  []string{`"mcp__ok__t255"`, `"mcp__ok__t257"`, `{"name":"Bash","input_schema":{"type":"object"}}`},
			mustDrop:  []string{mcpForbiddenName},
			wantTools: 258,
		},
		{
			name: "openai drop index 300 of 301", body: mcpBoundaryBody(true, 301, map[int]bool{300: true}, ""), drop: map[int]bool{300: true}, wantOK: true,
			mustKeep:  []string{`"mcp__ok__t299"`, `{"type":"function","function":{"name":"Bash","parameters":{"type":"object"}}}`},
			mustDrop:  []string{mcpForbiddenName},
			wantTools: 301,
		},
		{name: "nothing to drop is a no-op", body: mcpAnthropicBody, drop: nil, wantOK: false},
		{name: "tools absent refuses", body: `{"model":"x"}`, drop: map[int]bool{0: true}, wantOK: false},
		{name: "tools not an array refuses", body: `{"tools":{"a":1}}`, drop: map[int]bool{0: true}, wantOK: false},
		{name: "truncated document refuses", body: `{"tools":[{"name":"mcp__a__b"}]`, drop: map[int]bool{0: true}, wantOK: false},
		// A duplicated top-level "tools" key: the span scanner finds the
		// FIRST, a last-wins parser (ours, and the upstream's) reads the
		// LAST. The splice must not report success while the last array —
		// the one that carries the declaration to drop — survives intact.
		{name: "duplicate tools key, first is a scalar, refuses", body: `{"tools":"x","tools":[{"name":"mcp__a__b"}]}`, drop: map[int]bool{0: true}, wantOK: false},
		{name: "duplicate tools key, first array is a decoy, refuses", body: `{"tools":[{"name":"Bash"}],"tools":[{"name":"mcp__a__b"}]}`, drop: map[int]bool{0: true}, wantOK: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, ok := stripToolDecls([]byte(tc.body), tc.drop)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v (out=%.300s)", ok, tc.wantOK, out)
			}
			if !ok {
				return
			}
			if !json.Valid(out) {
				t.Fatalf("stripped body is not valid JSON: %.300s", out)
			}
			s := string(out)
			for _, k := range tc.mustKeep {
				if !strings.Contains(s, k) {
					t.Errorf("kept bytes missing %q in %.300s", k, s)
				}
			}
			for _, d := range tc.mustDrop {
				if strings.Contains(s, d) {
					t.Errorf("dropped decl %q survived in %.300s", d, s)
				}
			}
			var doc struct {
				Tools []json.RawMessage `json:"tools"`
			}
			if err := json.Unmarshal(out, &doc); err != nil {
				t.Fatalf("re-parse: %v", err)
			}
			if len(doc.Tools) != tc.wantTools {
				t.Errorf("tools len = %d, want %d", len(doc.Tools), tc.wantTools)
			}
			// Everything before the tools array and after it is verbatim.
			pre := strings.Index(tc.body, `"tools"`)
			if pre < 0 || !strings.HasPrefix(s, tc.body[:pre]) {
				t.Errorf("prefix before tools not preserved")
			}
			postIdx := strings.LastIndex(tc.body, `],`)
			if postIdx > 0 && !strings.HasSuffix(s, tc.body[postIdx+1:]) {
				t.Errorf("suffix after tools not preserved")
			}
		})
	}
}

// mcpToolsTestProxy wires a proxy with the given seam against a capturing
// Anthropic/OpenAI upstream.
func mcpToolsTestProxy(t *testing.T, seam ToolsAllowlistSeam) (*httptest.Server, *fakeSink, func() []byte, func()) {
	t.Helper()
	var (
		mu   sync.Mutex
		seen []byte
	)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		seen = b
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(anthropicOKBody))
	}))
	sink := &fakeSink{}
	p, err := New(Options{AnthropicUpstream: up.URL, OpenAIUpstream: up.URL, Sink: sink, ToolsAllowlist: seam})
	if err != nil {
		up.Close()
		t.Fatalf("proxy.New: %v", err)
	}
	ts := httptest.NewServer(p.Handler())
	return ts, sink, func() []byte { mu.Lock(); defer mu.Unlock(); return seen }, func() { ts.Close(); up.Close() }
}

func postMCPBody(t *testing.T, ts *httptest.Server, path, body string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest("POST", ts.URL+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if strings.HasPrefix(path, "/v1/messages") {
		req.Header.Set("X-Api-Key", "sk-ant-test")
	} else {
		req.Header.Set("Authorization", "Bearer sk-test")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	return resp
}

// TestToolsAllowlist_NilSeamByteIdentical pins the enabled=false contract:
// with no seam bound the upstream receives the EXACT original bytes even
// though the body declares MCP tools and a hosted connector.
func TestToolsAllowlist_NilSeamByteIdentical(t *testing.T) {
	t.Parallel()
	body := strings.Replace(mcpAnthropicBody, `"max_tokens":64,`, `"max_tokens":64,"mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"ex"}],`, 1)
	ts, _, seen, cleanup := mcpToolsTestProxy(t, nil)
	defer cleanup()
	resp := postMCPBody(t, ts, "/v1/messages", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(seen()) != body {
		t.Errorf("nil seam mutated the body:\n got %s\nwant %s", seen(), body)
	}
}

// TestToolsAllowlist_StripsDisallowedDecls pins the strip path end-to-end:
// the seam sees the parsed declarations, the upstream receives the spliced
// array, and the untouched fields are byte-identical.
func TestToolsAllowlist_StripsDisallowedDecls(t *testing.T) {
	t.Parallel()
	var (
		mu  sync.Mutex
		got ToolsAllowlistInput
	)
	seam := func(in ToolsAllowlistInput) ToolsAllowlistResult {
		mu.Lock()
		got = in
		mu.Unlock()
		var keep []MCPToolDecl
		for _, d := range in.Decls {
			if d.Server == "github" {
				keep = append(keep, d)
			}
		}
		return ToolsAllowlistResult{Keep: keep}
	}
	ts, sink, seen, cleanup := mcpToolsTestProxy(t, seam)
	defer cleanup()
	resp := postMCPBody(t, ts, "/v1/messages", mcpAnthropicBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	mu.Lock()
	in := got
	mu.Unlock()
	if in.Provider != models.ProviderAnthropic || len(in.Decls) != 3 || in.SessionID != "sess-mcp" || in.Overflow {
		t.Errorf("seam input = %+v", in)
	}
	up := string(seen())
	if !json.Valid([]byte(up)) {
		t.Fatalf("upstream body invalid JSON: %s", up)
	}
	if strings.Contains(up, "mcp__slack__post_message") {
		t.Errorf("disallowed decl forwarded: %s", up)
	}
	for _, k := range []string{`"mcp__github__create_issue"`, `"mcp__github__list_repos"`, `{"name":"Bash","description":"run","input_schema":{"type":"object"}}`, `"cache_control":{"type":"ephemeral"}`, `the word \"tools\":[] appears in text`} {
		if !strings.Contains(up, k) {
			t.Errorf("upstream missing %q: %s", k, up)
		}
	}
	// The landed turn's shape reflects the STRIPPED array (Bash + two
	// github decls), proving parseRequest ran after the splice.
	if turns := sink.all(); len(turns) != 1 || turns[0].ErrorMessage != "" || turns[0].ToolUseCount != 3 {
		t.Errorf("turns = %+v, want one clean turn with tool_use_count 3", turns)
	}
}

// TestToolsAllowlist_BoundaryIndicesStripped pins Sol finding 5 end-to-end
// on BOTH provider shapes: the forbidden declaration at index 255 / 256 /
// 257, past a 300-approved prefix, and at 10,000 never reaches the
// upstream; every approved declaration the seam could examine is forwarded
// verbatim; the forwarded body is json.Valid; a hosted connector beside a
// long tools array is unaffected. Past the seam ceiling the filter is
// conservative — every declaration it could not show the seam is dropped
// and the seam is told so via Overflow.
func TestToolsAllowlist_BoundaryIndicesStripped(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name         string
		openAI       bool
		n            int
		forbiddenAt  int
		extraTop     string
		wantMCP      int  // MCP declarations the upstream receives
		wantOverflow bool // what the seam must have been told
		mustKeep     []string
	}{
		{name: "anthropic forbidden at 255", n: 256, forbiddenAt: 255, wantMCP: 255, mustKeep: []string{`"mcp__ok__t254"`}},
		{name: "anthropic forbidden at 256", n: 257, forbiddenAt: 256, wantMCP: 256, mustKeep: []string{`"mcp__ok__t255"`}},
		{name: "anthropic forbidden at 257", n: 258, forbiddenAt: 257, wantMCP: 257, mustKeep: []string{`"mcp__ok__t256"`}},
		{name: "openai forbidden at 255", openAI: true, n: 256, forbiddenAt: 255, wantMCP: 255, mustKeep: []string{`"mcp__ok__t254"`}},
		{name: "openai forbidden at 256", openAI: true, n: 257, forbiddenAt: 256, wantMCP: 256, mustKeep: []string{`"mcp__ok__t255"`}},
		{name: "openai forbidden at 257", openAI: true, n: 258, forbiddenAt: 257, wantMCP: 257, mustKeep: []string{`"mcp__ok__t256"`}},
		{name: "anthropic 300 approved + 1 forbidden", n: 301, forbiddenAt: 300, wantMCP: 300, mustKeep: []string{`"mcp__ok__t0"`, `"mcp__ok__t299"`}},
		{name: "openai 300 approved + 1 forbidden", openAI: true, n: 301, forbiddenAt: 300, wantMCP: 300, mustKeep: []string{`"mcp__ok__t0"`, `"mcp__ok__t299"`}},
		{name: "anthropic forbidden at 10,000: overflow dropped conservatively", n: 10001, forbiddenAt: 10000, wantMCP: maxProxyMCPDecls, wantOverflow: true, mustKeep: []string{fmt.Sprintf(`"mcp__ok__t%d"`, maxProxyMCPDecls-1)}},
		{name: "openai forbidden at 10,000: overflow dropped conservatively", openAI: true, n: 10001, forbiddenAt: 10000, wantMCP: maxProxyMCPDecls, wantOverflow: true, mustKeep: []string{fmt.Sprintf(`"mcp__ok__t%d"`, maxProxyMCPDecls-1)}},
		{
			name: "anthropic hosted connector beside 300 decls is untouched", n: 301, forbiddenAt: 300, wantMCP: 300,
			extraTop: `"mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"example"}],`,
			mustKeep: []string{`"mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"example"}]`},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				mu   sync.Mutex
				seam ToolsAllowlistInput
			)
			ts, _, seen, cleanup := mcpToolsTestProxy(t, func(in ToolsAllowlistInput) ToolsAllowlistResult {
				mu.Lock()
				seam = in
				mu.Unlock()
				return denyEvilSeam(in)
			})
			defer cleanup()
			path := "/v1/messages"
			if tc.openAI {
				path = "/v1/chat/completions"
			}
			body := mcpBoundaryBody(tc.openAI, tc.n, map[int]bool{tc.forbiddenAt: true}, tc.extraTop)
			resp := postMCPBody(t, ts, path, body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("status = %d, want 200", resp.StatusCode)
			}
			up := seen()
			if up == nil {
				t.Fatal("upstream never received the request")
			}
			if strings.Contains(string(up), mcpForbiddenName) {
				t.Errorf("forbidden declaration at index %d forwarded to the upstream", tc.forbiddenAt)
			}
			mcpCount, total := countMCPToolNames(t, up)
			if mcpCount != tc.wantMCP || total != tc.wantMCP+1 {
				t.Errorf("upstream tools: %d mcp / %d total, want %d / %d", mcpCount, total, tc.wantMCP, tc.wantMCP+1)
			}
			for _, k := range tc.mustKeep {
				if !strings.Contains(string(up), k) {
					t.Errorf("upstream missing %q", k)
				}
			}
			// The non-MCP trailing declaration always survives.
			if !strings.Contains(string(up), `"Bash"`) {
				t.Error("non-MCP declaration was stripped")
			}
			mu.Lock()
			in := seam
			mu.Unlock()
			if in.Overflow != tc.wantOverflow {
				t.Errorf("seam told Overflow=%v, want %v", in.Overflow, tc.wantOverflow)
			}
			if wantSeen := min(tc.n, maxProxyMCPDecls); len(in.Decls) != wantSeen {
				t.Errorf("seam saw %d decls, want %d", len(in.Decls), wantSeen)
			}
		})
	}
}

// TestToolsAllowlist_OverflowDroppedEvenWhenSeamPanics pins the "never
// forwarded unexamined" half of the overflow contract: a panicking seam
// fails open for the declarations it was shown, but the ones past the
// ceiling still never reach the upstream.
func TestToolsAllowlist_OverflowDroppedEvenWhenSeamPanics(t *testing.T) {
	t.Parallel()
	ts, _, seen, cleanup := mcpToolsTestProxy(t, func(ToolsAllowlistInput) ToolsAllowlistResult { panic("seam exploded") })
	defer cleanup()
	body := mcpBoundaryBody(false, maxProxyMCPDecls+2, map[int]bool{maxProxyMCPDecls + 1: true}, "")
	resp := postMCPBody(t, ts, "/v1/messages", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 (panic fails open for the seam-visible prefix)", resp.StatusCode)
	}
	up := seen()
	if strings.Contains(string(up), mcpForbiddenName) {
		t.Error("overflow declaration forwarded after a seam panic")
	}
	if mcpCount, _ := countMCPToolNames(t, up); mcpCount != maxProxyMCPDecls {
		t.Errorf("upstream received %d mcp decls, want exactly the ceiling %d", mcpCount, maxProxyMCPDecls)
	}
}

// TestToolsAllowlist_SpliceFailureWithPendingDropsDenies pins the ruled
// failure path: when the policy said to strip something and the splice
// cannot do it, the request is REFUSED with the R-306 provider-shaped 403
// — forwarding the original body would forward the very declarations the
// policy stripped. The fixture is a duplicated top-level "tools" key: the
// parser (last wins) finds the forbidden declaration, the span scanner
// (first wins) cannot splice it out.
func TestToolsAllowlist_SpliceFailureWithPendingDropsDenies(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		path string
		body string
	}{
		{
			"anthropic duplicate tools key, scalar first",
			"/v1/messages",
			`{"model":"claude-opus-4-8","max_tokens":8,"tools":"x","tools":[{"name":"` + mcpForbiddenName + `","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			"anthropic duplicate tools key, decoy array first",
			"/v1/messages",
			`{"model":"claude-opus-4-8","max_tokens":8,"tools":[{"name":"Bash","input_schema":{"type":"object"}}],"tools":[{"name":"` + mcpForbiddenName + `","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`,
		},
		{
			"openai duplicate tools key, decoy array first",
			"/v1/chat/completions",
			`{"model":"gpt-5","tools":[{"type":"function","function":{"name":"read_file"}}],"tools":[{"type":"function","function":{"name":"` + mcpForbiddenName + `"}}],"messages":[{"role":"user","content":"hi"}]}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ts, sink, seen, cleanup := mcpToolsTestProxy(t, denyEvilSeam)
			defer cleanup()
			resp := postMCPBody(t, ts, tc.path, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusForbidden {
				t.Fatalf("status = %d, want 403 (upstream saw: %.200s)", resp.StatusCode, seen())
			}
			raw, _ := io.ReadAll(resp.Body)
			var envelope struct {
				Error struct {
					Type    string `json:"type"`
					Message string `json:"message"`
				} `json:"error"`
			}
			if err := json.Unmarshal(raw, &envelope); err != nil {
				t.Fatalf("deny body is not JSON: %v (%s)", err, raw)
			}
			if envelope.Error.Type != "invalid_request_error" || !strings.Contains(envelope.Error.Message, "[observer-guard R-306]") {
				t.Errorf("deny envelope = %+v, want R-306 provider-shaped error", envelope)
			}
			if seen() != nil {
				t.Errorf("upstream received a request the splice could not strip: %.200s", seen())
			}
			if turns := sink.all(); len(turns) != 1 || turns[0].HTTPStatus != http.StatusForbidden {
				t.Errorf("turns = %+v, want one 403 error turn", turns)
			}
		})
	}
}

// TestToolsAllowlist_SpliceFailureWithNothingToStripForwards pins the other
// half: the same odd body with NO disallowed declaration is not the
// filter's business — it forwards (the deny is tied to pending drops, not
// to body shape).
func TestToolsAllowlist_SpliceFailureWithNothingToStripForwards(t *testing.T) {
	t.Parallel()
	ts, _, seen, cleanup := mcpToolsTestProxy(t, denyEvilSeam)
	defer cleanup()
	body := `{"model":"claude-opus-4-8","max_tokens":8,"tools":"x","tools":[{"name":"mcp__ok__t0","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`
	resp := postMCPBody(t, ts, "/v1/messages", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if string(seen()) != body {
		t.Errorf("body with nothing to strip was mutated: %s", seen())
	}
}

// TestToolsAllowlist_DenyHostedConnector403 pins the R-307 refusal: a
// provider-shaped 403 carrying the rule id, no upstream call, and an error
// api_turn (the serveGuardDeny contract).
func TestToolsAllowlist_DenyHostedConnector403(t *testing.T) {
	t.Parallel()
	seam := func(in ToolsAllowlistInput) ToolsAllowlistResult {
		for _, c := range in.Connectors {
			if c.URL == "https://mcp.example.com/sse" {
				return ToolsAllowlistResult{DenyRuleID: "R-307", DenyReason: "hosted MCP connector " + c.Name + " is not approved by the org tools.mcp_access grant"}
			}
		}
		return ToolsAllowlistResult{Keep: in.Decls}
	}
	ts, sink, seen, cleanup := mcpToolsTestProxy(t, seam)
	defer cleanup()
	body := `{"model":"claude-opus-4-8","max_tokens":8,"mcp_servers":[{"type":"url","url":"https://mcp.example.com/sse","name":"ex"}],"messages":[{"role":"user","content":"x"}]}`
	resp := postMCPBody(t, ts, "/v1/messages", body)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Type  string `json:"type"`
		Error struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("deny body is not JSON: %v (%s)", err, raw)
	}
	if envelope.Type != "error" || envelope.Error.Type != "invalid_request_error" {
		t.Errorf("envelope = %+v, want Anthropic error shape", envelope)
	}
	if !strings.Contains(envelope.Error.Message, "[observer-guard R-307]") || !strings.Contains(envelope.Error.Message, "not approved") {
		t.Errorf("message %q missing rule marker/reason", envelope.Error.Message)
	}
	if seen() != nil {
		t.Error("upstream received a denied request")
	}
	if turns := sink.all(); len(turns) != 1 || turns[0].HTTPStatus != http.StatusForbidden {
		t.Errorf("turns = %+v, want one 403 error turn", turns)
	}
}

// TestToolsAllowlist_OpenAIResponsesDenyShape pins the OpenAI-shaped 403
// for a Responses-API hosted connector.
func TestToolsAllowlist_OpenAIResponsesDenyShape(t *testing.T) {
	t.Parallel()
	seam := func(in ToolsAllowlistInput) ToolsAllowlistResult {
		if len(in.Connectors) > 0 {
			return ToolsAllowlistResult{DenyRuleID: "R-307", DenyReason: "hosted connector not approved"}
		}
		return ToolsAllowlistResult{Keep: in.Decls}
	}
	ts, _, seen, cleanup := mcpToolsTestProxy(t, seam)
	defer cleanup()
	req, _ := http.NewRequest("POST", ts.URL+"/v1/responses", strings.NewReader(mcpOpenAIResponsesBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer sk-test")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var envelope struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("deny body not JSON: %v (%s)", err, raw)
	}
	if envelope.Error.Type != "invalid_request_error" || envelope.Error.Code != "observer_guard_denied" || !strings.Contains(envelope.Error.Message, "[observer-guard R-307]") {
		t.Errorf("openai deny envelope = %+v", envelope)
	}
	if seen() != nil {
		t.Error("upstream received a denied request")
	}
}

// TestToolsAllowlist_PanicFailsOpen pins the recover: a seam panic forwards
// the original body untouched (when nothing sits past the ceiling).
func TestToolsAllowlist_PanicFailsOpen(t *testing.T) {
	t.Parallel()
	seam := func(ToolsAllowlistInput) ToolsAllowlistResult { panic("seam exploded") }
	ts, _, seen, cleanup := mcpToolsTestProxy(t, seam)
	defer cleanup()
	resp := postMCPBody(t, ts, "/v1/messages", mcpAnthropicBody)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if string(seen()) != mcpAnthropicBody {
		t.Errorf("panicking seam mutated the body: %s", seen())
	}
}

// TestToolsAllowlist_NoMCPContentSkipsSeam pins the pre-scan's negative
// answer: a body with no `mcp__` name, no mcp_servers key and no hosted
// tool — literal OR escaped — never reaches the seam.
func TestToolsAllowlist_NoMCPContentSkipsSeam(t *testing.T) {
	t.Parallel()
	called := false
	var mu sync.Mutex
	seam := func(in ToolsAllowlistInput) ToolsAllowlistResult {
		mu.Lock()
		called = true
		mu.Unlock()
		return ToolsAllowlistResult{Keep: in.Decls}
	}
	ts, _, seen, cleanup := mcpToolsTestProxy(t, seam)
	defer cleanup()
	resp := postMCPBody(t, ts, "/v1/messages", routerReqBody)
	defer resp.Body.Close()
	mu.Lock()
	defer mu.Unlock()
	if called {
		t.Error("seam consulted for a body with no MCP content")
	}
	if string(seen()) != routerReqBody {
		t.Errorf("body mutated: %s", seen())
	}
}

// ---------------------------------------------------------------------------
// Sol P3+P4 fold finding 4 (R-306/R-307): the pre-scan in front of the parse
// is JSON-aware. A tool name, the mcp_servers key and the hosted-tool type
// written with \uXXXX escapes reach the seam exactly like their literal
// forms; the pre-scan never under-reports relative to the parsers; the nil
// seam and a no-MCP body stay allocation-free.
// ---------------------------------------------------------------------------

// mcpParserMarker is the reference predicate: what the two parsers act on,
// applied to an already-DECODED string value.
func mcpParserMarker(decoded string) bool {
	return strings.HasPrefix(strings.TrimSpace(decoded), mcpToolNamePrefix) ||
		strings.EqualFold(decoded, mcpServersKey) ||
		decoded == mcpHostedToolType
}

func TestBodyMayCarryMCP_Rows(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want bool
	}{
		// Literal forms.
		{"literal tool name", `{"tools":[{"name":"mcp__a__b"}]}`, true},
		{"literal connector key", `{"mcp_servers":[]}`, true},
		{"literal hosted type", `{"tools":[{"type":"mcp"}]}`, true},
		// The finding's exact bypass and its siblings.
		{"escaped underscores in tool name", `{"tools":[{"name":"mcp\u005f\u005fevil\u005f\u005fexfiltrate"}]}`, true},
		{"fully escaped prefix, uppercase hex", `{"tools":[{"name":"\u006D\u0063\u0070\u005F\u005Fx"}]}`, true},
		{"escaped leading whitespace before prefix", `{"tools":[{"name":"\t\u00a0 mcp\u005f_x"}]}`, true},
		{"raw unicode whitespace before prefix", "{\"tools\":[{\"name\":\"\u2003mcp__x\"}]}", true},
		{"escaped prefix with empty rest", `{"a":"mcp\u005f\u005f"}`, true},
		{"escaped connector key", `{"mcp\u005fservers":[{"type":"url","url":"u"}]}`, true},
		{"upper-case connector key (encoding/json folds keys)", `{"MCP_SERVERS":[]}`, true},
		{"long-s connector key (fold orbit of s)", "{\"mcp_\u017fervers\":[]}", true},
		{"escaped upper M connector key", `{"\u004dcp_servers":[]}`, true},
		{"escaped hosted type (first rune)", `{"tools":[{"type":"\u006dcp"}]}`, true},
		{"escaped hosted type (last rune)", `{"tools":[{"type":"mc\u0070"}]}`, true},
		{"marker after an escaped-quote string", `{"a":"x\"y\"","t":"mcp\u005f_x"}`, true},
		{"marker after a string ending in an escaped backslash", `{"a":"x\\","t":"mcp\u005f_x"}`, true},
		{"surrogate-pair noise then escaped marker", `{"tools":[{"description":"\ud83d\ude00 \udc00","name":"\u006dcp__x"}]}`, true},
		{"unterminated string is left to the parser", `{"tools":[{"name":"abc`, true},
		{"malformed escape is left to the parser", `{"tools":[{"name":"\q"}]}`, true},
		{"truncated \\u escape is left to the parser", `{"tools":[{"name":"\u00"}]}`, true},
		// No false alarm on bodies that carry nothing the parsers act on.
		{"router request body", routerReqBody, false},
		{"escaped backslash is not an escape of the marker", `{"a":"\\u006dcp__x"}`, false},
		{"lone low surrogate before the prefix", `{"a":"\udc00mcp__x"}`, false},
		{"unpaired high surrogate before the prefix", `{"a":"\ud83dmcp__x"}`, false},
		{"surrogate pair before the prefix", `{"a":"\ud83d\ude00mcp__x"}`, false},
		{"prefix-like but not the prefix", `{"a":"mcpx","b":"mcp_","c":"xmcp__y","d":"m\u0063p_"}`, false},
		{"connector key minus a rune", `{"mcp_server":[]}`, false},
		{"hosted type compared exactly", `{"type":"MCP","t2":"\u004dCP"}`, false},
		{"no strings at all", `[1,2,3,true,null]`, false},
		{"empty body", ``, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := bodyMayCarryMCP([]byte(tc.body)); got != tc.want {
				t.Errorf("bodyMayCarryMCP(%s) = %v, want %v", tc.body, got, tc.want)
			}
		})
	}
}

// escapeJSONStringVariant JSON-encodes s as a quoted string token, choosing
// per rune (two bits of mode, cycling) between the raw form, a lower-case
// \uXXXX escape, an upper-case \uXXXX escape and a short escape where one
// exists. Runes JSON forbids raw are always escaped; a supplementary rune
// in \u form is written as a surrogate pair; an invalid UTF-8 byte is
// written raw (encoding/json decodes it to U+FFFD).
func escapeJSONStringVariant(s string, mode uint64) string {
	var sb strings.Builder
	sb.WriteByte('"')
	bit := uint(0)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		raw := s[i : i+size]
		i += size
		m := (mode >> (bit % 64)) & 3
		bit += 2
		if r == utf8.RuneError && size == 1 {
			sb.WriteString(raw)
			continue
		}
		short := map[rune]string{'"': `\"`, '\\': `\\`, '/': `\/`, '\b': `\b`, '\f': `\f`, '\n': `\n`, '\r': `\r`, '\t': `\t`}[r]
		mustEscape := r == '"' || r == '\\' || r < 0x20
		if m == 3 && short != "" {
			sb.WriteString(short)
			continue
		}
		if m == 0 && !mustEscape {
			sb.WriteString(raw)
			continue
		}
		format := `\u%04x`
		if m == 2 {
			format = `\u%04X`
		}
		if r > 0xFFFF {
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&sb, format+format, r1, r2)
			continue
		}
		fmt.Fprintf(&sb, format, r)
	}
	sb.WriteByte('"')
	return sb.String()
}

// mcpPrescanAgreement asserts, for one string value and one escape
// variant, that (a) the token decodes to s, (b) the pre-scan's per-token
// verdict equals the reference predicate on the decoded value (exact, both
// directions), and (c) embedded in every position the parsers read, a body
// the parsers find something in is never gated off by bodyMayCarryMCP.
func mcpPrescanAgreement(t *testing.T, s string, mode uint64) {
	t.Helper()
	tok := escapeJSONStringVariant(s, mode)
	var decoded string
	if err := json.Unmarshal([]byte(tok), &decoded); err != nil {
		t.Fatalf("variant %s of %q does not decode: %v", tok, s, err)
	}
	want := mcpParserMarker(decoded)
	if got := jsonStringIsMCPMarker([]byte(tok[1 : len(tok)-1])); got != want {
		t.Fatalf("token %s (decoded %q): pre-scan %v, parser predicate %v", tok, decoded, got, want)
	}
	bodies := []string{
		`{"messages":[{"content":"x\\\""}],"tools":[{"name":` + tok + `}]}`,
		`{"tools":[{"type":"function","function":{"name":` + tok + `}}]}`,
		`{"tools":[{"type":` + tok + `,"server_label":"l","server_url":"u"}]}`,
		`{` + tok + `:[{"type":"url","url":"u","name":"n"}]}`,
	}
	for _, b := range bodies {
		scan := parseMCPToolDecls([]byte(b))
		conns := parseHostedMCPConnectors(models.ProviderAnthropic, []byte(b))
		if (len(scan.Decls) > 0 || len(conns) > 0) && !bodyMayCarryMCP([]byte(b)) {
			t.Fatalf("parsers find MCP content in %s but the pre-scan gated it off", b)
		}
	}
}

// TestBodyMayCarryMCP_NeverUnderReportsParser drives the agreement check
// over every interesting value × a spread of escape variants (including
// surrogate/unicode noise) and a seeded random corpus.
func TestBodyMayCarryMCP_NeverUnderReportsParser(t *testing.T) {
	t.Parallel()
	values := []string{
		"mcp__evil__exfiltrate", "mcp__", "mcp__a", " mcp__a", "\t\n\u00a0\u2003mcp__a", "\u000bmcp__a",
		"mcp_servers", "MCP_SERVERS", "Mcp_Servers", "mcp_\u017fervers", "mcp", "MCP", "Mcp",
		"mcpx", "mcp_", "mcp_server", "xmcp__", "\ufffdmcp__a", "\U0001F600mcp__a", "mcp__\U0001F600",
		"\"mcp__\"", "\\mcp__", "mcp/", "\u212a", "", "漢字mcp__", "mcp__漢字", "\xffmcp__a", "mcp\xff",
	}
	modes := []uint64{0, 0x5555555555555555, 0xAAAAAAAAAAAAAAAA, 0xFFFFFFFFFFFFFFFF, 0x1B1B1B1B1B1B1B1B, 0xE4E4E4E4E4E4E4E4, 0x0123456789ABCDEF}
	for _, v := range values {
		for _, m := range modes {
			mcpPrescanAgreement(t, v, m)
		}
	}
	rng := rand.New(rand.NewPCG(4, 2026))
	alphabet := []rune{'m', 'c', 'p', '_', 's', 'e', 'r', 'v', 'M', 'C', 'P', 'S', ' ', '\t', '\u00a0', '\u017f', '\U0001F600', '"', '\\', '/', '\n', 'x'}
	for i := 0; i < 20000; i++ {
		var sb strings.Builder
		if rng.IntN(2) == 0 {
			sb.WriteString([]string{"mcp__", "mcp_servers", "mcp", " mcp__"}[rng.IntN(4)])
		}
		for n := rng.IntN(6); n > 0; n-- {
			sb.WriteRune(alphabet[rng.IntN(len(alphabet))])
		}
		mcpPrescanAgreement(t, sb.String(), rng.Uint64())
	}
}

// FuzzBodyMayCarryMCP is the same agreement check as a fuzz target; the
// seed corpus runs on every `go test`.
func FuzzBodyMayCarryMCP(f *testing.F) {
	for _, s := range []string{"mcp__evil__x", "mcp_servers", "mcp", "\t mcp__a", "\U0001F600mcp__a", "mcp_\u017fervers"} {
		f.Add(s, uint64(0x5555555555555555))
		f.Add(s, uint64(0xE4E4E4E4E4E4E4E4))
	}
	f.Fuzz(func(t *testing.T, s string, mode uint64) {
		if len(s) > 256 {
			return
		}
		mcpPrescanAgreement(t, s, mode)
	})
}

// decodedMCPServers re-parses a forwarded body the way an upstream would
// and returns the DECODED server segment of every MCP declaration (a raw
// strings.Contains check cannot see an escaped name).
func decodedMCPServers(t *testing.T, body []byte) []string {
	t.Helper()
	if !json.Valid(body) {
		t.Fatalf("forwarded body is not valid JSON: %.300s", body)
	}
	var doc struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("re-parse forwarded body: %v", err)
	}
	var out []string
	for _, raw := range doc.Tools {
		var e proxyToolNameEntry
		if err := json.Unmarshal(raw, &e); err != nil {
			t.Fatalf("forwarded tool entry malformed: %v (%s)", err, raw)
		}
		name := e.Name
		if name == "" && e.Function != nil {
			name = e.Function.Name
		}
		if server, _, ok := splitMCPToolName(name); ok {
			out = append(out, server)
		}
	}
	return out
}

// TestToolsAllowlist_EscapedMarkersReachSeam is finding 4 end-to-end
// through the proxy handler (applyToolsAllowlist on the real request
// path): escaped tool names are stripped, an escaped connector key and an
// escaped hosted-tool type reach the seam and are refused, mixed escaped +
// literal declarations are filtered individually, unicode/surrogate noise
// changes nothing, and every forwarded body is json.Valid.
func TestToolsAllowlist_EscapedMarkersReachSeam(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		path        string
		body        string
		wantStatus  int
		wantRule    string   // on 403
		wantServers []string // decoded MCP servers the upstream receives (200)
		wantDecls   int      // declarations the seam saw
		wantConns   int      // connectors the seam saw
		mustKeep    []string // raw bytes that must survive verbatim (200)
		seamSilent  bool     // the seam must not be consulted at all
		identical   bool     // the upstream must receive the exact input bytes
	}{
		{
			name:       "the finding's body: escaped tool name is stripped",
			path:       "/v1/messages",
			body:       `{"model":"claude-opus-4-8","max_tokens":8,"tools":[{"name":"mcp\u005f\u005fevil\u005f\u005fexfiltrate"}],"messages":[{"role":"user","content":"hi"}]}`,
			wantStatus: http.StatusOK, wantServers: nil, wantDecls: 1,
		},
		{
			name:       "fully escaped prefix, openai chat function-nested",
			path:       "/v1/chat/completions",
			body:       `{"model":"gpt-5","tools":[{"type":"function","function":{"name":"read_file"}},{"type":"function","function":{"name":"\u006d\u0063\u0070\u005F\u005Fevil\u005f\u005fx","parameters":{"type":"object"}}}],"messages":[{"role":"user","content":"hi"}]}`,
			wantStatus: http.StatusOK, wantServers: nil, wantDecls: 1,
			mustKeep: []string{`{"type":"function","function":{"name":"read_file"}}`},
		},
		{
			name:       "escaped mcp_servers key reaches the seam and is refused",
			path:       "/v1/messages",
			body:       `{"model":"claude-opus-4-8","max_tokens":8,"mcp\u005fservers":[{"type":"url","url":"https://evil.example/sse","name":"evil"}],"messages":[{"role":"user","content":"hi"}]}`,
			wantStatus: http.StatusForbidden, wantRule: "R-307", wantConns: 1,
		},
		{
			name:       "escaped hosted-tool type reaches the seam and is refused",
			path:       "/v1/responses",
			body:       `{"model":"gpt-5","input":"hi","tools":[{"type":"\u006dcp","server_label":"evil","server_url":"https://evil.example/mcp"}]}`,
			wantStatus: http.StatusForbidden, wantRule: "R-307", wantConns: 1,
		},
		{
			name: "mixed escaped + literal: each declaration filtered on its own",
			path: "/v1/messages",
			body: `{"model":"claude-opus-4-8","max_tokens":8,"tools":[` +
				`{"name":"mcp__ok__t0","input_schema":{"type":"object"}},` +
				`{"name":"mcp\u005f\u005fevil\u005f\u005fexfiltrate","input_schema":{"type":"object"}},` +
				`{"name":"mcp\u005f\u005fok\u005f\u005ft1","input_schema":{"type":"object"}},` +
				`{"name":"mcp__evil__literal","input_schema":{"type":"object"}},` +
				`{"name":"Bash","input_schema":{"type":"object"}}],"messages":[{"role":"user","content":"hi"}]}`,
			wantStatus: http.StatusOK, wantServers: []string{"ok", "ok"}, wantDecls: 4,
			mustKeep: []string{`{"name":"mcp__ok__t0","input_schema":{"type":"object"}}`, `{"name":"mcp\u005f\u005fok\u005f\u005ft1","input_schema":{"type":"object"}}`, `{"name":"Bash","input_schema":{"type":"object"}}`},
		},
		{
			name: "surrogate/unicode noise around an escaped whitespace-led name",
			path: "/v1/messages",
			body: `{"model":"claude-opus-4-8","max_tokens":8,"system":"\ud83d\ude00 \udc00 漢字 \u001b[32mok\u001b[0m","tools":[` +
				`{"name":"\t\u00a0mcp\u005f\u005fevil\u005f\u005fx","description":"\ud83d\ude00\udc00é","input_schema":{"type":"object"}},` +
				`{"name":"mcp\u005f\u005fok\u005f\u005f\ud83d\ude00","input_schema":{"type":"object"}}],` +
				`"messages":[{"role":"user","content":"\udc00mcp__not_a_tool"}]}`,
			wantStatus: http.StatusOK, wantServers: []string{"ok"}, wantDecls: 2,
			mustKeep: []string{`{"name":"mcp\u005f\u005fok\u005f\u005f\ud83d\ude00","input_schema":{"type":"object"}}`, `"system":"\ud83d\ude00 \udc00 漢字 \u001b[32mok\u001b[0m"`, `"content":"\udc00mcp__not_a_tool"`},
		},
		{
			name:       "noise-only body carries no MCP content: seam silent, bytes identical",
			path:       "/v1/messages",
			body:       `{"model":"claude-opus-4-8","max_tokens":8,"tools":[{"name":"Bash","description":"\ud83d\ude00 \udc00 \\u006dcp__x"}],"messages":[{"role":"user","content":"\udc00mcp__x \u001b[0m"}]}`,
			wantStatus: http.StatusOK, seamSilent: true, identical: true,
		},
		{
			name:       "approved escaped declaration alone forwards byte-identical",
			path:       "/v1/messages",
			body:       `{"model":"claude-opus-4-8","max_tokens":8,"tools":[{"name":"mcp\u005f\u005fok\u005f\u005ft0"}],"messages":[{"role":"user","content":"hi"}]}`,
			wantStatus: http.StatusOK, wantServers: []string{"ok"}, wantDecls: 1, identical: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var (
				mu     sync.Mutex
				calls  int
				seamIn ToolsAllowlistInput
			)
			ts, _, seen, cleanup := mcpToolsTestProxy(t, func(in ToolsAllowlistInput) ToolsAllowlistResult {
				mu.Lock()
				calls++
				seamIn = in
				mu.Unlock()
				for _, c := range in.Connectors {
					if strings.Contains(c.URL, "evil") {
						return ToolsAllowlistResult{DenyRuleID: "R-307", DenyReason: "hosted MCP connector " + c.Name + " is not approved"}
					}
				}
				var keep []MCPToolDecl
				for _, d := range in.Decls {
					if d.Server == "ok" {
						keep = append(keep, d)
					}
				}
				return ToolsAllowlistResult{Keep: keep}
			})
			defer cleanup()
			resp := postMCPBody(t, ts, tc.path, tc.body)
			defer resp.Body.Close()
			if resp.StatusCode != tc.wantStatus {
				t.Fatalf("status = %d, want %d (upstream saw %.300s)", resp.StatusCode, tc.wantStatus, seen())
			}
			mu.Lock()
			n, in := calls, seamIn
			mu.Unlock()
			if tc.seamSilent {
				if n != 0 {
					t.Errorf("seam consulted %d times for a body with no MCP content", n)
				}
			} else {
				if n != 1 {
					t.Fatalf("seam consulted %d times, want 1", n)
				}
				if len(in.Decls) != tc.wantDecls || len(in.Connectors) != tc.wantConns {
					t.Errorf("seam saw %d decls / %d connectors, want %d / %d (%+v)", len(in.Decls), len(in.Connectors), tc.wantDecls, tc.wantConns, in)
				}
			}
			if tc.wantStatus == http.StatusForbidden {
				raw, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(raw), "[observer-guard "+tc.wantRule+"]") {
					t.Errorf("deny body %s missing rule %s", raw, tc.wantRule)
				}
				if seen() != nil {
					t.Errorf("upstream received a refused request: %.300s", seen())
				}
				return
			}
			up := seen()
			if up == nil {
				t.Fatal("upstream never received the request")
			}
			servers := decodedMCPServers(t, up) // asserts json.Valid
			if fmt.Sprint(servers) != fmt.Sprint(tc.wantServers) {
				t.Errorf("upstream MCP servers (decoded) = %v, want %v\nbody: %s", servers, tc.wantServers, up)
			}
			for _, k := range tc.mustKeep {
				if !strings.Contains(string(up), k) {
					t.Errorf("upstream missing verbatim %q", k)
				}
			}
			if tc.identical && string(up) != tc.body {
				t.Errorf("body mutated:\n got %s\nwant %s", up, tc.body)
			}
		})
	}
}

// TestToolsAllowlist_AllocationFreeGates pins the cost contract: the nil
// seam returns before touching the body, and a bound seam's pre-scan over
// a realistic no-MCP body (escapes, ANSI, surrogates) allocates nothing.
func TestToolsAllowlist_AllocationFreeGates(t *testing.T) {
	body := claudeCodeLikeBody(false)
	nilSeam := &Proxy{}
	if a := testing.AllocsPerRun(50, func() {
		if nilSeam.applyToolsAllowlist(models.ProviderAnthropic, body, "s").mutated {
			t.Fatal("nil seam mutated")
		}
	}); a != 0 {
		t.Errorf("nil seam: %v allocs/op, want 0", a)
	}
	if bodyMayCarryMCP(body) {
		t.Fatal("realistic no-MCP body flagged by the pre-scan")
	}
	if a := testing.AllocsPerRun(50, func() { _ = bodyMayCarryMCP(body) }); a != 0 {
		t.Errorf("pre-scan: %v allocs/op, want 0", a)
	}
}

// claudeCodeLikeBody builds a representative Claude Code /v1/messages body
// (~400 KB): a long system prompt, 17 built-in tool declarations with
// multi-KB descriptions + JSON schemas, and an 80-message tool-use
// conversation whose tool results carry source text (quotes, tabs,
// newlines), ANSI colour codes and emoji — i.e. dense in \n, \t, \" and
// \u001b escapes, the realistic worst case for a string-token scan.
// Serialized like Node's JSON.stringify (no HTML escaping). withMCP adds
// 12 MCP declarations, one of them \u-escaped.
func claudeCodeLikeBody(withMCP bool) []byte {
	para := strings.Repeat("You are an interactive CLI tool that helps users with software engineering tasks. Use the \"Read\" tool before editing.\n\t- Never guess file paths; run `ls` first.\n", 12)
	type schema = map[string]any
	var tools []any
	for _, n := range []string{"Task", "Bash", "Glob", "Grep", "LS", "ExitPlanMode", "Read", "Edit", "MultiEdit", "Write", "NotebookEdit", "WebFetch", "TodoWrite", "WebSearch", "BashOutput", "KillShell", "SlashCommand"} {
		tools = append(tools, schema{
			"name":        n,
			"description": para,
			"input_schema": schema{
				"type": "object", "additionalProperties": false, "required": []string{"command"},
				"properties": schema{"command": schema{"type": "string", "description": "The command to execute"}, "timeout": schema{"type": "number"}},
			},
		})
	}
	if withMCP {
		for i := 0; i < 11; i++ {
			tools = append(tools, schema{"name": fmt.Sprintf("mcp__github__tool_%d", i), "description": "GitHub MCP tool", "input_schema": schema{"type": "object"}})
		}
	}
	code := strings.Repeat("func (p *Proxy) handle(w http.ResponseWriter, r *http.Request) {\n\tif err := p.do(\"x\"); err != nil {\n\t\treturn // 🚀 done\n\t}\n}\n", 20)
	ansi := strings.Repeat("\x1b[32mok\x1b[0m  \tgithub.com/marmutapp/superbased-observer/internal/proxy\t10.310s\n", 15)
	var msgs []any
	for i := 0; i < 40; i++ {
		id := fmt.Sprintf("toolu_%024d", i)
		msgs = append(msgs,
			schema{"role": "assistant", "content": []any{
				schema{"type": "text", "text": "Let me look at the handler."},
				schema{"type": "tool_use", "id": id, "name": "Read", "input": schema{"file_path": "/home/u/repo/internal/proxy/proxy.go"}},
			}},
			schema{"role": "user", "content": []any{
				schema{"type": "tool_result", "tool_use_id": id, "content": code + ansi},
			}})
	}
	req := schema{
		"model": "claude-opus-4-8", "max_tokens": 32000, "stream": true,
		"metadata": schema{"user_id": "{\"session_id\":\"sess-bench\"}"},
		"system":   []any{schema{"type": "text", "text": strings.Repeat(para, 6), "cache_control": schema{"type": "ephemeral"}}},
		"tools":    tools, "messages": msgs,
	}
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(req); err != nil {
		panic(err)
	}
	out := strings.TrimSpace(buf.String())
	if withMCP {
		out = strings.Replace(out, `"tools":[`, `"tools":[{"name":"mcp\u005f\u005fevil\u005f\u005fexfiltrate","input_schema":{"type":"object"}},`, 1)
	}
	return []byte(out)
}

// oldLiteralPrecheck is the pre-fold raw-marker gate (kept here only as the
// benchmark baseline; it is the bypass finding 4 named).
func oldLiteralPrecheck(body []byte) bool {
	return bytes.Contains(body, []byte(`"`+mcpToolNamePrefix)) ||
		bytes.Contains(body, []byte(`"mcp_servers"`)) ||
		bytes.Contains(body, []byte(`"mcp"`))
}

func BenchmarkMCPToolsPrescan_ClaudeCodeNoMCP(b *testing.B) {
	body := claudeCodeLikeBody(false)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if bodyMayCarryMCP(body) {
			b.Fatal("flagged")
		}
	}
}

func BenchmarkMCPToolsOldLiteralPrecheck_ClaudeCodeNoMCP(b *testing.B) {
	body := claudeCodeLikeBody(false)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if oldLiteralPrecheck(body) {
			b.Fatal("flagged")
		}
	}
}

func BenchmarkMCPToolsAlwaysParse_ClaudeCodeNoMCP(b *testing.B) {
	body := claudeCodeLikeBody(false)
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		_ = parseMCPToolDecls(body)
		_ = parseHostedMCPConnectors(models.ProviderAnthropic, body)
	}
}

func BenchmarkToolsAllowlist_NilSeam(b *testing.B) {
	body := claudeCodeLikeBody(true)
	p := &Proxy{}
	b.ReportAllocs()
	for b.Loop() {
		_ = p.applyToolsAllowlist(models.ProviderAnthropic, body, "s")
	}
}

func BenchmarkToolsAllowlist_BoundNoMCP(b *testing.B) {
	body := claudeCodeLikeBody(false)
	p, err := New(Options{Sink: &fakeSink{}, ToolsAllowlist: denyEvilSeam})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if p.applyToolsAllowlist(models.ProviderAnthropic, body, "s").mutated {
			b.Fatal("mutated")
		}
	}
}

func BenchmarkToolsAllowlist_BoundEscapedMCPStrip(b *testing.B) {
	body := claudeCodeLikeBody(true)
	p, err := New(Options{Sink: &fakeSink{}, ToolsAllowlist: denyEvilSeam})
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		if out := p.applyToolsAllowlist(models.ProviderAnthropic, body, "s"); out.stripped != 1 {
			b.Fatalf("stripped = %d, want 1", out.stripped)
		}
	}
}
