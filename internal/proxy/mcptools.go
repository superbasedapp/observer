package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// Agent Access P4 W4d (doc3 §12.5): the proxy's tools[] filter seam.
//
// The proxy sees only inference routed through :8820, and even there it sees
// an MCP server ONLY as the `mcp__<server>__<tool>` declarations a coding
// agent copies into the request's tools array (plus, for two providers, a
// HOSTED connector the provider itself dials). This file extracts both
// shapes and hands them across ONE seam function — Options.ToolsAllowlist —
// which the daemon composition binds to the compiled node decision table.
// The proxy never imports internal/mcprelay / internal/mcpgw (the reverse-
// import boundary, tests/invariant/agentaccess_boundary_test.go); it gets a
// plain result back and applies it with the same byte-span splice +
// json.Valid backstop rewriteTopLevelModel uses.
//
// A nil seam is INERT: no parse, no splice, byte-identical forwarding.
//
// Coverage contract (Sol P3+P4 finding 5, R-306): EVERY tools[] entry is
// parsed — the request body is already bounded by maxRequestBodyBytes, so a
// parser-side cap would buy nothing but an unexamined suffix a client could
// hide a forbidden declaration in. The only ceiling left is the seam-input
// sanity bound maxProxyMCPDecls, and it is enforced as an explicit OVERFLOW
// state: a declaration past it is never handed to the seam AND never
// forwarded — it is dropped unconditionally. When a drop cannot be spliced
// the request is REFUSED (provider-shaped 403, R-306), never forwarded with
// the declarations the policy said to strip.
//
// Pre-scan contract (Sol P3+P4 fold finding 4, R-306/R-307): the gate in
// front of the parse is JSON-AWARE. JSON lets every character of a tool
// name, an object key and a string value be written as a \uXXXX escape, so
// a raw-byte marker test (`"mcp__`) cannot be a security gate. The gate is
// bodyMayCarryMCP, which walks every string token and decodes its escapes
// exactly the way encoding/json does before matching. It can over-report (a
// false positive costs one parse) but never under-report relative to the
// two parsers below.

// MCPToolDecl is one `mcp__*`-prefixed declaration found in a request's
// tools array, identified by its array index so the splice can drop it
// without re-emitting the kept siblings.
type MCPToolDecl struct {
	// Index is the declaration's position in the top-level tools array.
	Index int
	// Name is the wire tool name (`mcp__github__create_issue`).
	Name string
	// Server is the MCP server segment of the name ("github").
	Server string
	// Tool is the bare tool segment ("create_issue"); equals Name when the
	// declaration carries no `__` separator after the server.
	Tool string
}

// HostedMCPConnector is one provider-hosted MCP connector declared on the
// request: Anthropic's top-level `mcp_servers[]` (type "url") and the OpenAI
// Responses API's `tools[]` entry of type "mcp" (server_url or connector_id).
// Neither shape was parsed before this wave (doc3 §12.7: hosted/remote MCP
// was invisible to the proxy point).
type HostedMCPConnector struct {
	// Provider is the request's provider id (models.ProviderAnthropic /
	// models.ProviderOpenAI).
	Provider string
	// Kind is the shape it came from: "anthropic_mcp_servers" or
	// "openai_responses_mcp".
	Kind string
	// Name is the connector's declared name / server_label.
	Name string
	// URL is the connector's declared URL (server_url); empty for an OpenAI
	// connector_id-style hosted connector.
	URL string
	// ConnectorID is OpenAI's hosted connector id ("connector_dropbox");
	// empty for URL-style connectors.
	ConnectorID string
}

// ToolsAllowlistInput is what the seam is asked about for one request.
type ToolsAllowlistInput struct {
	// Provider is the request's provider id.
	Provider string
	// SessionID is the resolved API session id ("" when unresolved).
	SessionID string
	// Decls are the request's `mcp__*` tool declarations, in array order —
	// the first maxProxyMCPDecls of them. Every entry of the tools array is
	// parsed; see Overflow for what happens past the ceiling.
	Decls []MCPToolDecl
	// Connectors are the request's provider-hosted MCP connectors.
	Connectors []HostedMCPConnector
	// Overflow is true when the request carried MORE `mcp__*` declarations
	// than maxProxyMCPDecls. The seam never sees those extra declarations
	// and cannot keep them: the filter drops every one of them from the
	// forwarded tools array unconditionally (never forwarded unexamined).
	// Informational for the seam (log/observe); additive, zero on the
	// common path.
	Overflow bool
}

// ToolsAllowlistResult is the seam's plain answer. Keep lists the
// declarations that stay on the wire (every other Decl is spliced out);
// DenyRuleID/DenyReason non-empty means the WHOLE request is refused with a
// provider-shaped 403 (a non-approved hosted connector, R-307).
type ToolsAllowlistResult struct {
	// Keep is the subset of the input Decls to leave in the tools array.
	Keep []MCPToolDecl
	// DenyRuleID is the guard rule id the refusal is attributed to
	// ("R-307"); empty means forward (after stripping).
	DenyRuleID string
	// DenyReason is the bounded, agent-readable reason for a refusal.
	DenyReason string
	// DenyHumanLine is an optional developer-facing first line.
	DenyHumanLine string
}

// ToolsAllowlistSeam is the ONE seam function (doc3 §12.5
// `toolsAllowlistSeam`) the daemon composition binds. It is called once per
// proxied inference request that carries at least one `mcp__*` declaration
// or hosted connector, and must be cheap and non-blocking. nil = inert.
type ToolsAllowlistSeam func(in ToolsAllowlistInput) ToolsAllowlistResult

// maxProxyMCPDecls is the seam-input sanity ceiling: the most `mcp__*`
// declarations one request hands to the seam. It is NOT a parse cap — every
// tools[] entry is examined — and it is NOT a forwarding allowance: a
// declaration past it is reported as ToolsAllowlistInput.Overflow and
// dropped from the forwarded body unconditionally. It bounds the seam's
// per-request work (one decision-table lookup per declaration on the
// request path); the body itself is already bounded by maxRequestBodyBytes.
// Claude Code sends the full tools array every turn and MCP-heavy setups
// run to a few hundred declarations, so a legitimate request never reaches
// it.
const maxProxyMCPDecls = 4096

// mcpToolNamePrefix is the wire prefix every client uses for an MCP tool.
const mcpToolNamePrefix = "mcp__"

// mcpStripRuleID is the guard rule a refusal on the strip path is
// attributed to (doc3 §12.6: R-306, MCP tool declaration for a non-approved
// server, enforce → deny at the proxy request).
const mcpStripRuleID = "R-306"

// proxyToolNameEntry is the minimal per-tool projection: Anthropic
// declarations carry `name` at the top level; OpenAI Chat Completions nest
// it under `function`; OpenAI Responses carry `name` at the top level for
// function tools and `type:"mcp"` for hosted connectors.
type proxyToolNameEntry struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Function *struct {
		Name string `json:"name"`
	} `json:"function"`
	// OpenAI Responses hosted MCP tool fields.
	ServerLabel string `json:"server_label"`
	ServerURL   string `json:"server_url"`
	ConnectorID string `json:"connector_id"`
}

// splitMCPToolName splits `mcp__<server>__<tool>` into its two segments.
// ok=false when the name is not MCP-prefixed or has an empty server.
func splitMCPToolName(name string) (server, tool string, ok bool) {
	rest, has := strings.CutPrefix(strings.TrimSpace(name), mcpToolNamePrefix)
	if !has || rest == "" {
		return "", "", false
	}
	if i := strings.Index(rest, "__"); i > 0 {
		return rest[:i], rest[i+2:], true
	}
	return rest, rest, true
}

// decodeToleratingTypeErrors unmarshals body into v the way an upstream's
// last-wins parser reads it: a *json.UnmarshalTypeError (one key held a
// value of the wrong shape) is NOT a failure, because encoding/json still
// fills every other field — including a later DUPLICATE of the offending
// key. Treating it as "no tools" would forward a body whose second "tools"
// key the upstream honours while the proxy examined nothing. Any other
// error (malformed JSON) is a real failure.
func decodeToleratingTypeErrors(body []byte, v any) bool {
	err := json.Unmarshal(body, v)
	if err == nil {
		return true
	}
	var typeErr *json.UnmarshalTypeError
	return errors.As(err, &typeErr)
}

// mcpToolDeclScan is parseMCPToolDecls' result: the declarations the seam
// is asked about (the first maxProxyMCPDecls, in array order) and the
// array indices of every FURTHER `mcp__*` declaration past that ceiling.
// Overflow is never forwarded: applyToolsAllowlist drops each index
// unconditionally.
type mcpToolDeclScan struct {
	// Decls are the seam-visible declarations (at most maxProxyMCPDecls).
	Decls []MCPToolDecl
	// Overflow lists the tools[] indices of the MCP declarations past the
	// ceiling, in array order. nil on every request under the ceiling.
	Overflow []int
}

// parseMCPToolDecls extracts the `mcp__*` declarations from the request's
// top-level tools array, tolerant of every provider shape (any entry that
// does not parse or is not MCP-prefixed is skipped, never an error). EVERY
// entry is examined: the array is never truncated, so no declaration can
// hide past a parser limit — the ones past maxProxyMCPDecls are reported
// by index in Overflow instead of being silently ignored.
func parseMCPToolDecls(body []byte) mcpToolDeclScan {
	var raw struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if !decodeToleratingTypeErrors(body, &raw) || len(raw.Tools) == 0 {
		return mcpToolDeclScan{}
	}
	var scan mcpToolDeclScan
	for i, t := range raw.Tools {
		var e proxyToolNameEntry
		if json.Unmarshal(t, &e) != nil {
			continue
		}
		name := e.Name
		if name == "" && e.Function != nil {
			name = e.Function.Name
		}
		server, tool, ok := splitMCPToolName(name)
		if !ok {
			continue
		}
		if len(scan.Decls) >= maxProxyMCPDecls {
			scan.Overflow = append(scan.Overflow, i)
			continue
		}
		scan.Decls = append(scan.Decls, MCPToolDecl{Index: i, Name: strings.TrimSpace(name), Server: server, Tool: tool})
	}
	return scan
}

// parseHostedMCPConnectors extracts provider-hosted MCP connectors: the
// Anthropic Messages `mcp_servers[]` array (type "url") and the OpenAI
// Responses `tools[]` entries of type "mcp". Both shapes are optional and
// absent on most requests; a missing/malformed field yields no connectors.
func parseHostedMCPConnectors(provider string, body []byte) []HostedMCPConnector {
	var raw struct {
		MCPServers []struct {
			Type string `json:"type"`
			URL  string `json:"url"`
			Name string `json:"name"`
		} `json:"mcp_servers"`
		Tools []json.RawMessage `json:"tools"`
	}
	if !decodeToleratingTypeErrors(body, &raw) {
		return nil
	}
	var out []HostedMCPConnector
	for _, s := range raw.MCPServers {
		if s.URL == "" && s.Name == "" {
			continue
		}
		out = append(out, HostedMCPConnector{
			Provider: provider, Kind: "anthropic_mcp_servers",
			Name: s.Name, URL: s.URL,
		})
	}
	for _, t := range raw.Tools {
		var e proxyToolNameEntry
		if json.Unmarshal(t, &e) != nil || e.Type != "mcp" {
			continue
		}
		if e.ServerURL == "" && e.ConnectorID == "" && e.ServerLabel == "" {
			continue
		}
		out = append(out, HostedMCPConnector{
			Provider: provider, Kind: "openai_responses_mcp",
			Name: e.ServerLabel, URL: e.ServerURL, ConnectorID: e.ConnectorID,
		})
	}
	return out
}

// stripToolDecls rewrites the request's top-level tools array without the
// declarations at the given indices, leaving every other byte of the
// document — and every kept declaration's own bytes — verbatim. The array
// is re-emitted from the kept elements' raw bytes (no re-marshal), the
// splice reuses rewriteTopLevelModel's span scanner, and the result is
// json.Valid-checked AND re-read: the tools array a last-wins parser (the
// parser this file's own scan used, and what the upstream sees) finds in
// the output must hold exactly the kept count, so a body whose span scanner
// and parser disagree (a duplicated top-level "tools" key) can never pass
// as a successful strip while the dropped declarations survive.
//
// ok=false on any anomaly. The caller must NOT forward the original body
// on ok=false when drop was non-empty: that would forward the very
// declarations the policy said to strip (the R-306 bypass Sol finding 5
// named) — applyToolsAllowlist refuses the request instead.
func stripToolDecls(body []byte, drop map[int]bool) ([]byte, bool) {
	if len(drop) == 0 {
		return body, false
	}
	span, ok := topLevelValueSpan(body, "tools")
	if !ok {
		return nil, false
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(spanValueBytes(body, span), &tools); err != nil {
		return nil, false
	}
	var arr bytes.Buffer
	arr.WriteByte('[')
	kept := 0
	for i, t := range tools {
		if drop[i] {
			continue
		}
		if kept > 0 {
			arr.WriteByte(',')
		}
		arr.Write(bytes.TrimSpace(t))
		kept++
	}
	arr.WriteByte(']')
	out := spliceSpan(body, span, arr.String())
	if !json.Valid(out) {
		return nil, false
	}
	var check struct {
		Tools []json.RawMessage `json:"tools"`
	}
	if json.Unmarshal(out, &check) != nil || len(check.Tools) != kept {
		return nil, false
	}
	return out, true
}

// mcpToolsOutcome is what applyToolsAllowlist reports back to the request
// path.
type mcpToolsOutcome struct {
	// body is the (possibly stripped) request body.
	body []byte
	// mutated is true when body differs from the input.
	mutated bool
	// deny is non-nil when the whole request must be refused.
	deny *GuardRequestResult
	// stripped is the number of declarations removed.
	stripped int
}

// applyToolsAllowlist runs the seam for one request. It is a no-op (no
// parse, no allocation) when no seam is bound, and when the JSON-aware
// pre-scan (bodyMayCarryMCP) finds no string token that decodes to an
// `mcp__*` name, an `mcp_servers` key or the hosted-tool type "mcp".
//
// Drop set = (seam-visible declarations the seam did not Keep) ∪ (every
// overflow declaration past maxProxyMCPDecls). A non-empty drop set that
// cannot be spliced refuses the request (R-306, provider-shaped 403): the
// only alternative is forwarding the declarations the policy stripped.
func (p *Proxy) applyToolsAllowlist(provider string, body []byte, sessionID string) mcpToolsOutcome {
	out := mcpToolsOutcome{body: body}
	if p.toolsAllowlist == nil || len(body) == 0 {
		return out
	}
	// JSON-aware pre-scan (fold finding 4): a body none of whose decoded
	// string tokens is an `mcp__*` name, an `mcp_servers` key or the hosted
	// tool type "mcp" can carry nothing the seam decides on. Escaped forms
	// (`mcp\u005f\u005f…`) are decoded before matching, so they cannot
	// slip past; see bodyMayCarryMCP.
	if !bodyMayCarryMCP(body) {
		return out
	}
	scan := parseMCPToolDecls(body)
	in := ToolsAllowlistInput{
		Provider:   provider,
		SessionID:  sessionID,
		Decls:      scan.Decls,
		Connectors: parseHostedMCPConnectors(provider, body),
		Overflow:   len(scan.Overflow) > 0,
	}
	if len(in.Decls) == 0 && len(in.Connectors) == 0 {
		return out
	}
	res := p.safeToolsAllowlist(in)
	if res.DenyRuleID != "" || res.DenyReason != "" {
		ruleID := res.DenyRuleID
		if ruleID == "" {
			ruleID = "R-307"
		}
		out.deny = &GuardRequestResult{
			Action:    "deny",
			RuleID:    ruleID,
			Reason:    res.DenyReason,
			HumanLine: res.DenyHumanLine,
			Status:    http.StatusForbidden,
		}
		return out
	}
	if len(in.Decls) == 0 {
		return out
	}
	keep := make(map[int]bool, len(res.Keep))
	for _, d := range res.Keep {
		keep[d.Index] = true
	}
	drop := make(map[int]bool)
	for _, d := range in.Decls {
		if !keep[d.Index] {
			drop[d.Index] = true
		}
	}
	// Overflow is dropped regardless of the seam's answer: it never saw
	// those declarations, so it cannot have approved them.
	for _, i := range scan.Overflow {
		drop[i] = true
	}
	if in.Overflow {
		p.logger.Warn("proxy: mcp tools[] exceeds the seam ceiling; dropping every declaration past it",
			"session_id", sessionID, "ceiling", maxProxyMCPDecls, "overflow", len(scan.Overflow))
	}
	if len(drop) == 0 {
		return out
	}
	stripped, ok := stripToolDecls(body, drop)
	if !ok {
		// Forwarding the original body here would forward the declarations
		// the policy said to strip — a bypass, not a fail-open. Refuse.
		p.logger.Warn("proxy: mcp tools[] strip splice failed with pending drops; refusing request",
			"session_id", sessionID, "to_strip", len(drop), "rule", mcpStripRuleID)
		out.deny = &GuardRequestResult{
			Action: "deny",
			RuleID: mcpStripRuleID,
			Reason: fmt.Sprintf("request declares %d MCP tool(s) not permitted by the node's tools.mcp_access table and the tools[] array could not be rewritten to remove them; remove the disallowed mcp__* declarations and retry", len(drop)),
			Status: http.StatusForbidden,
		}
		return out
	}
	out.body, out.mutated, out.stripped = stripped, true, len(drop)
	return out
}

// safeToolsAllowlist runs the seam behind a recover: a panicking seam must
// never take the request path down — it forwards the seam-visible
// declarations untouched (fail-open, like safeDecide for the router seam).
// Overflow declarations are still dropped by the caller: they were never
// the seam's to keep.
func (p *Proxy) safeToolsAllowlist(in ToolsAllowlistInput) (res ToolsAllowlistResult) {
	defer func() {
		if r := recover(); r != nil {
			p.logger.Warn("proxy: tools allowlist seam panicked; forwarding original body", "panic", r)
			res = ToolsAllowlistResult{Keep: in.Decls}
		}
	}()
	return p.toolsAllowlist(in)
}

// The three decoded string values the parsers act on.
const (
	// mcpServersKey is the Anthropic hosted-connector key. encoding/json
	// matches object keys to struct tags case-insensitively (bytes.EqualFold
	// semantics), so the pre-scan compares it folded too.
	mcpServersKey = "mcp_servers"
	// mcpHostedToolType is the OpenAI Responses hosted-tool type, compared
	// exactly (proxyToolNameEntry.Type == "mcp").
	mcpHostedToolType = "mcp"
)

// bodyMayCarryMCP is the security gate in front of parseMCPToolDecls and
// parseHostedMCPConnectors (Sol P3+P4 fold finding 4). It reports true when
// ANY JSON string token of body — key or value, at any depth — decodes to a
// value either parser acts on:
//
//   - a string whose leading-whitespace-trimmed form starts with `mcp__`
//     (splitMCPToolName trims then cuts the prefix);
//   - a string equal to `mcp_servers` under bytes.EqualFold (how
//     encoding/json matches the `json:"mcp_servers"` key);
//   - a string exactly equal to `mcp` (the hosted-tool type).
//
// It may over-report — a message text that is exactly "mcp" costs one
// parse — but it must never under-report relative to the parsers: escapes
// are decoded rune by rune with encoding/json's rules (short escapes,
// \uXXXX, surrogate pairs, invalid UTF-8 and unpaired surrogates to
// U+FFFD). An unterminated string or a malformed escape returns true and
// leaves the verdict to the parser, which then fails closed on its own.
//
// There is deliberately NO raw-byte literal fast path (`"mcp__`,
// `"mcp_servers"`, `"mcp"`) in front of the scan: a literal miss proves
// nothing once escapes exist, and a literal hit only saves work on a body
// that is about to be parsed anyway. Measured on a ~228 KB Claude Code-like
// body the token scan alone (~150 µs, zero allocations) is cheaper than the
// three literal bytes.Contains passes it replaced (~490 µs) — see
// BenchmarkMCPTools* in mcptools_test.go.
func bodyMayCarryMCP(body []byte) bool {
	for i := 0; i < len(body); {
		q := bytes.IndexByte(body[i:], '"')
		if q < 0 {
			return false
		}
		start := i + q + 1
		end, ok := jsonStringEnd(body, start)
		if !ok {
			return true
		}
		if jsonStringIsMCPMarker(body[start:end]) {
			return true
		}
		i = end + 1
	}
	return false
}

// jsonStringEnd returns the index of the quote that closes the JSON string
// whose contents begin at start: the first `"` preceded by an EVEN number of
// backslashes. ok=false when the string is unterminated.
func jsonStringEnd(body []byte, start int) (int, bool) {
	for j := start; j <= len(body); {
		k := bytes.IndexByte(body[j:], '"')
		if k < 0 {
			return 0, false
		}
		end := j + k
		n := 0
		for b := end - 1; b >= start && body[b] == '\\'; b-- {
			n++
		}
		if n%2 == 0 {
			return end, true
		}
		j = end + 1
	}
	return 0, false
}

// jsonStringIsMCPMarker applies the three bodyMayCarryMCP predicates to one
// string token's RAW contents (between the quotes). A token without a
// backslash decodes to its own bytes (invalid UTF-8 becomes U+FFFD, which is
// neither whitespace nor foldable to ASCII, so matching the raw bytes gives
// the same answer); a token with one is decoded rune by rune.
func jsonStringIsMCPMarker(raw []byte) bool {
	if bytes.IndexByte(raw, '\\') < 0 {
		return bytes.HasPrefix(bytes.TrimLeftFunc(raw, unicode.IsSpace), []byte(mcpToolNamePrefix)) ||
			bytes.EqualFold(raw, []byte(mcpServersKey)) ||
			string(raw) == mcpHostedToolType
	}
	return escapedJSONStringMatches(raw, mcpToolNamePrefix, matchTrimmedPrefix) ||
		escapedJSONStringMatches(raw, mcpServersKey, matchFold) ||
		escapedJSONStringMatches(raw, mcpHostedToolType, matchExact)
}

// jsonMatchMode selects how escapedJSONStringMatches compares.
type jsonMatchMode uint8

const (
	// matchExact: the decoded string equals want.
	matchExact jsonMatchMode = iota
	// matchFold: the decoded string equals want under Unicode simple
	// folding (bytes.EqualFold / encoding/json key matching).
	matchFold
	// matchTrimmedPrefix: the decoded string, after leading
	// unicode.IsSpace runes, starts with want.
	matchTrimmedPrefix
)

// escapedJSONStringMatches decodes raw (a JSON string's contents, escapes
// intact) lazily and compares it against the ASCII string want. A malformed
// escape reports true: the pre-scan never decides a document it cannot
// decode, the parser does.
func escapedJSONStringMatches(raw []byte, want string, mode jsonMatchMode) bool {
	rd := jsonRuneReader{b: raw}
	r, ok := rd.next()
	if mode == matchTrimmedPrefix {
		for ok && unicode.IsSpace(r) {
			r, ok = rd.next()
		}
	}
	for i := 0; i < len(want); i++ {
		if !ok {
			return rd.bad
		}
		w := rune(want[i])
		if r != w && (mode != matchFold || !foldEqualRune(r, w)) {
			return false
		}
		r, ok = rd.next()
	}
	if mode == matchTrimmedPrefix {
		return true
	}
	return !ok // at end of string (or malformed: conservative)
}

// foldEqualRune reports whether r is in w's Unicode simple-fold orbit —
// the per-rune comparison bytes.EqualFold performs (so `ſ` matches `s` and
// the Kelvin sign matches `k`, exactly as encoding/json key matching does).
func foldEqualRune(r, w rune) bool {
	if r == w {
		return true
	}
	for f := unicode.SimpleFold(w); f != w; f = unicode.SimpleFold(f) {
		if f == r {
			return true
		}
	}
	return false
}

// jsonRuneReader decodes a JSON string's raw contents one rune at a time
// with encoding/json's unquote rules, without allocating.
type jsonRuneReader struct {
	b []byte
	i int
	// bad is set when next stopped on a malformed escape rather than at
	// the end of the string.
	bad bool
}

// next returns the next decoded rune; ok=false at the end of the string or
// on a malformed escape (bad=true).
func (rd *jsonRuneReader) next() (rune, bool) {
	if rd.i >= len(rd.b) {
		return 0, false
	}
	if c := rd.b[rd.i]; c != '\\' {
		r, size := utf8.DecodeRune(rd.b[rd.i:])
		rd.i += size
		return r, true
	}
	if rd.i+1 >= len(rd.b) {
		rd.bad = true
		return 0, false
	}
	switch e := rd.b[rd.i+1]; e {
	case '"', '\\', '/':
		rd.i += 2
		return rune(e), true
	case 'b':
		rd.i += 2
		return '\b', true
	case 'f':
		rd.i += 2
		return '\f', true
	case 'n':
		rd.i += 2
		return '\n', true
	case 'r':
		rd.i += 2
		return '\r', true
	case 't':
		rd.i += 2
		return '\t', true
	case 'u':
		r, ok := jsonHex4(rd.b, rd.i+2)
		if !ok {
			rd.bad = true
			return 0, false
		}
		rd.i += 6
		if !utf16.IsSurrogate(r) {
			return r, true
		}
		// encoding/json: a surrogate combines with an immediately
		// following \uXXXX when the pair is valid (consuming it);
		// otherwise it decodes to U+FFFD and the next escape stands alone.
		if rd.i+1 < len(rd.b) && rd.b[rd.i] == '\\' && rd.b[rd.i+1] == 'u' {
			if r2, ok := jsonHex4(rd.b, rd.i+2); ok {
				if dec := utf16.DecodeRune(r, r2); dec != unicode.ReplacementChar {
					rd.i += 6
					return dec, true
				}
			}
		}
		return unicode.ReplacementChar, true
	default:
		rd.bad = true
		return 0, false
	}
}

// jsonHex4 parses the four hex digits at b[at:at+4].
func jsonHex4(b []byte, at int) (rune, bool) {
	if at+4 > len(b) {
		return 0, false
	}
	var r rune
	for _, c := range b[at : at+4] {
		switch {
		case '0' <= c && c <= '9':
			c -= '0'
		case 'a' <= c && c <= 'f':
			c = c - 'a' + 10
		case 'A' <= c && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, false
		}
		r = r<<4 | rune(c)
	}
	return r, true
}
