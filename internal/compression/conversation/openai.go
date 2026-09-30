package conversation

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/compression/conversation/types"
)

// openaiMessage is the Chat Completions per-message shape. Only the
// fields conversation compression needs are decoded; everything else
// rides through on the preserved Raw bytes.
type openaiMessage struct {
	Role       string          `json:"role"`
	Content    json.RawMessage `json:"content"`
	ToolCallID string          `json:"tool_call_id,omitempty"`
	ToolCalls  json.RawMessage `json:"tool_calls,omitempty"`
	Name       string          `json:"name,omitempty"`
}

// openaiContentPart covers the common parts: text and image_url. Other
// part types (audio, file) are preserved verbatim via the containing
// message's Raw bytes — they just don't contribute scoring text.
type openaiContentPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

// openaiExtractedMessage is the per-message parsed state — analogous
// to extractedMessage in anthropic.go.
type openaiExtractedMessage struct {
	raw        json.RawMessage
	role       string
	toolCallID string
	toolUseIDs []string
	// contentString is populated when the content field was a bare
	// string; contentParts when it was an array. Exactly one is set
	// for a well-formed message.
	contentString string
	contentParts  []openaiContentPart
	// flatText is the scorer input — the bare string, or the
	// concatenation of text parts.
	flatText string
	// isToolResult is true when role == "tool" (a Chat Completions
	// tool output). The enforcer targets these for per-type
	// compression the same way Anthropic targets tool_result blocks.
	isToolResult bool
	// toolName is the producing assistant.tool_calls[*].function.name,
	// resolved via a per-request tool_call_id → name map. Empty when
	// the producer wasn't observed in this request body or when the
	// message isn't a tool result. Used by per-type compression
	// dispatch and by the MCP-skip predicate.
	toolName string
	// filename is the producing tool call's file-path argument, when
	// detected via [extractFilePathFromArgs]. Empty when no path-shaped
	// argument was found. Lifts types.Detect's accuracy on per-type
	// compression by giving it an extension hint.
	filename string
	// compressionText is the body the per-type compressor and stash
	// pass operate on. For tool-result messages it equals flatText; for
	// other roles it's empty (no per-block compression target). Kept
	// alongside flatText so the shared pre-pass code (which reads
	// compressionText) works against both extractor shapes.
	compressionText string
	// compressedText is the post-pre-pass body, populated by
	// [substituteOpenAIChatRedundantReads], [compressOpenAIChatToolResults],
	// and [stashOpenAIChatLargeBodies]. Empty means "use the original".
	// Read by [openaiToConversationMessages] when projecting to
	// conversation.Message and by [serializeOpenAI] when rewriting the
	// content field.
	compressedText string
}

type openaiResponsesExtractedMessage struct {
	raw           json.RawMessage
	role          string
	itemType      string
	itemID        string
	toolCallID    string
	contentString string
	contentParts  []openaiContentPart
	outputString  string
	// compressionText is the exact text body the budget enforcer should
	// score/compress for this item. For function_call_output items this
	// is the raw `output` field so the compressor and serializer operate
	// on the same bytes; for message-shaped items it falls back to the
	// flattened content text.
	compressionText string
	flatText        string
	isToolResult    bool
	// toolName is the producing function_call's `name`, resolved via a
	// per-request call_id → name map. Empty when this item is itself a
	// function_call (no producer to back-resolve from), when the producer
	// wasn't observed in this request body, or when the item isn't a
	// tool result. Used by per-type compression dispatch and by the
	// MCP-skip predicate.
	toolName string
	// filename is the producing function_call's file-path argument, when
	// detected via a best-effort scan of `arguments` JSON. Empty when no
	// path-shaped argument was found. Lifts types.Detect's accuracy by
	// giving it an extension hint instead of the empty filename.
	filename string
	// compressedText is the post-compression / post-stash body for this
	// item, populated by [compressOpenAIResponsesToolResults] and
	// [stashOpenAIResponsesLargeBodies] before scoring. Empty string means
	// "use the original — no compression fired or compression didn't
	// shrink". Read by [serializeOpenAIResponses] when rewriting the item.
	compressedText string
}

// openaiExtract parses a Chat Completions request body. Returns ok=false
// when the body isn't a recognizable envelope (no parse, no messages
// array). Responses API bodies (`{input: [...]}`) fall into that bucket
// today — a future adapter can add a second detection path.
func openaiExtract(body []byte) (envelope map[string]json.RawMessage, extracted []openaiExtractedMessage, ok bool) {
	envelope = make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, false
	}
	raw, found := envelope["messages"]
	if !found {
		return nil, nil, false
	}
	var msgs []json.RawMessage
	if err := json.Unmarshal(raw, &msgs); err != nil {
		return nil, nil, false
	}
	extracted = make([]openaiExtractedMessage, 0, len(msgs))
	for _, m := range msgs {
		var hdr openaiMessage
		if err := json.Unmarshal(m, &hdr); err != nil {
			// Preserve raw so serialization forwards the original.
			extracted = append(extracted, openaiExtractedMessage{raw: m})
			continue
		}
		em := openaiExtractedMessage{
			raw:          m,
			role:         hdr.Role,
			toolCallID:   hdr.ToolCallID,
			toolUseIDs:   parseOpenAIToolCallIDs(hdr.ToolCalls),
			isToolResult: hdr.Role == "tool",
		}
		// Content can be a bare string, an array of parts, or null
		// (assistant messages that are pure tool_calls). Try string
		// first since it's the common case.
		var s string
		if err := json.Unmarshal(hdr.Content, &s); err == nil {
			em.contentString = s
			em.flatText = s
		} else {
			var parts []openaiContentPart
			if err := json.Unmarshal(hdr.Content, &parts); err == nil {
				em.contentParts = parts
				texts := make([]string, 0, len(parts))
				for _, p := range parts {
					if p.Type == "text" && p.Text != "" {
						texts = append(texts, p.Text)
					}
				}
				em.flatText = strings.Join(texts, "\n")
			}
			// null content (pure tool_calls message): flatText stays "".
		}
		if em.isToolResult {
			em.compressionText = em.flatText
		}
		extracted = append(extracted, em)
	}
	resolveOpenAIChatToolCalls(extracted)
	return envelope, extracted, true
}

// resolveOpenAIChatToolCalls walks assistant messages with `tool_calls`,
// builds a per-request `tool_call_id → {name, filePath}` index from each
// tool_calls[].function.{name, arguments}, then back-fills toolName +
// filename onto every role:"tool" message via toolCallID. Linear in the
// total message count.
//
// Why we need this: a tool message carries `tool_call_id` + `content`
// only — the producing tool's name lives on the earlier assistant
// message's `tool_calls[]`. Per-block compression dispatch (and the
// MCP-skip predicate) need the name. The producer is always earlier in
// `messages` than the result.
func resolveOpenAIChatToolCalls(extracted []openaiExtractedMessage) {
	type callInfo struct {
		Name     string
		FilePath string
	}
	index := make(map[string]callInfo)
	for _, em := range extracted {
		if len(em.toolUseIDs) == 0 {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(em.raw, &obj); err != nil {
			continue
		}
		var calls []struct {
			ID       string `json:"id"`
			Function struct {
				Name      string `json:"name"`
				Arguments string `json:"arguments"`
			} `json:"function"`
		}
		if err := json.Unmarshal(obj["tool_calls"], &calls); err != nil {
			continue
		}
		for _, c := range calls {
			if c.ID == "" {
				continue
			}
			info := callInfo{Name: c.Function.Name}
			if c.Function.Arguments != "" {
				info.FilePath = extractFilePathFromArgs(c.Function.Arguments)
			}
			index[c.ID] = info
		}
	}
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult || em.toolCallID == "" {
			continue
		}
		if info, ok := index[em.toolCallID]; ok {
			em.toolName = info.Name
			em.filename = info.FilePath
		}
	}
}

// openaiToConversationMessages projects openaiExtractedMessage →
// conversation.Message so the shared scorer + budget enforcer can run.
func openaiResponsesExtract(body []byte) (envelope map[string]json.RawMessage, extracted []openaiResponsesExtractedMessage, ok bool) {
	envelope = make(map[string]json.RawMessage)
	if err := json.Unmarshal(body, &envelope); err != nil {
		return nil, nil, false
	}
	raw, found := envelope["input"]
	if !found {
		return nil, nil, false
	}
	var input []json.RawMessage
	if err := json.Unmarshal(raw, &input); err != nil {
		return nil, nil, false
	}
	extracted = make([]openaiResponsesExtractedMessage, 0, len(input))
	for _, item := range input {
		em := openaiResponsesExtractedMessage{raw: item}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil {
			extracted = append(extracted, em)
			continue
		}
		em.role = rawString(obj["role"])
		em.itemType = rawString(obj["type"])
		em.itemID = firstRawString(obj["call_id"], obj["id"])
		em.toolCallID = firstRawString(obj["call_id"], obj["tool_call_id"], obj["id"])
		em.outputString = rawString(obj["output"])
		em.contentString, em.contentParts, em.flatText = parseOpenAITextContent(obj["content"])
		if em.outputString != "" {
			if em.flatText != "" {
				em.flatText += "\n" + em.outputString
			} else {
				em.flatText = em.outputString
			}
			em.compressionText = em.outputString
		} else {
			em.compressionText = em.flatText
		}
		// Tool RESULTS are role:"tool" (Chat shape) or *_output items
		// (Responses shape: function_call_output / custom_tool_call_output
		// / local_shell_call_output). The former `strings.Contains(
		// itemType, "tool")` clause was over-broad — it also swallowed
		// tool-DEFINITION items and *_call producer items, neither of
		// which is a result. GPT-5.6 Codex (wire_api="responses") ships
		// its tool definitions as the FIRST input item —
		// `{"type":"additional_tools","role":"developer","tools":[...]}`
		// — not a top-level `tools` array; `Contains("additional_tools",
		// "tool")` matched, so the whole tool set was misclassified as a
		// tool result, remapped to RoleTool, and dropped by the budget
		// enforcer (the model then reported it had no tools). Match
		// result shapes only; definitions are pinned separately.
		em.isToolResult = em.role == "tool" ||
			em.itemType == "function_call_output" ||
			strings.HasSuffix(em.itemType, "_output")
		extracted = append(extracted, em)
	}
	resolveOpenAIResponsesToolCalls(extracted)
	return envelope, extracted, true
}

// resolveOpenAIResponsesToolCalls walks function_call items, builds a
// call_id → {toolName, filePath} map from each call's `name` and
// `arguments` JSON, then back-fills toolName + filename onto every
// function_call_output (or *_output) item via toolCallID. Linear in the
// total item count.
//
// Why we need this: codex's function_call_output items carry `call_id`
// + `output` only — the tool name lives on the producing function_call.
// Per-block compression dispatch (and the MCP-skip predicate) need the
// name. The producer is always earlier in `input` than the output.
func resolveOpenAIResponsesToolCalls(extracted []openaiResponsesExtractedMessage) {
	type callInfo struct {
		Name     string
		FilePath string
	}
	index := make(map[string]callInfo)
	for _, em := range extracted {
		if em.itemType != "function_call" && em.itemType != "custom_tool_call" {
			continue
		}
		if em.toolCallID == "" {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(em.raw, &obj); err != nil {
			continue
		}
		info := callInfo{Name: rawString(obj["name"])}
		// arguments is a JSON-encoded string for function_call; for
		// custom_tool_call it can be a string under `input`. Try both.
		argsStr := rawString(obj["arguments"])
		if argsStr == "" {
			argsStr = rawString(obj["input"])
		}
		if argsStr != "" {
			info.FilePath = extractFilePathFromArgs(argsStr)
		}
		index[em.toolCallID] = info
	}
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult || em.toolCallID == "" {
			continue
		}
		if info, ok := index[em.toolCallID]; ok {
			em.toolName = info.Name
			em.filename = info.FilePath
		}
	}
}

// extractFilePathFromArgs returns a best-effort file path from a
// function_call's `arguments` JSON string. Tries explicit path keys
// (`file_path`, `path`, `filename`) first; falls back to a heuristic
// scan of `cmd` / `command` for `cat <path>` / `head <flags> <path>` /
// `tail <flags> <path>` / `less <path>` / `more <path>` patterns —
// codex's dominant read pattern is `exec_command` with a freeform cmd.
//
// Returns "" when no recognized path is present. The path returned is
// always the LAST positional argument of a recognized read-style
// command, which is typically the file (heuristic; works for
// `cat foo`, `head -50 foo`, `tail -n 100 foo`, `less /path/to/foo`).
// Multi-file `cat` (`cat a b c`) returns just the last path — good
// enough for the cache key heuristic; readers wanting full coverage
// should use a real read tool.
func extractFilePathFromArgs(argsJSON string) string {
	var args map[string]json.RawMessage
	if err := json.Unmarshal([]byte(argsJSON), &args); err != nil {
		return ""
	}
	for _, k := range []string{"file_path", "path", "filename"} {
		if v, ok := args[k]; ok {
			if s := rawString(v); s != "" {
				return s
			}
		}
	}
	// Heuristic: parse a freeform shell command for read-style verbs.
	for _, k := range []string{"cmd", "command"} {
		if v, ok := args[k]; ok {
			s := rawString(v)
			if s == "" {
				// `command` may also be an array shape: ["bash","-lc","cat foo"].
				var arr []string
				if err := json.Unmarshal(v, &arr); err == nil && len(arr) > 0 {
					s = arr[len(arr)-1]
				}
			}
			if path := parseReadCmdForPath(s); path != "" {
				return path
			}
		}
	}
	return ""
}

// parseReadCmdForPath returns the file path from a recognized
// read-style shell command, or "" when the command isn't a recognized
// read shape. Conservative — only fires on the dominant read verbs so we
// don't false-positive on commands like `grep foo bar.txt` (which reads
// bar.txt but has different cache semantics). Covers both Unix readers
// (cat / head / tail / less / more / nl) and the PowerShell / Windows
// readers codex emits on Windows (Get-Content and its gc / type / cat
// aliases, with -Path / -LiteralPath / -TotalCount / -Tail flags).
func parseReadCmdForPath(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	// Strip a `bash -c` / `bash -lc` wrapper if present so we get to
	// the underlying command. Keep it simple — single level of nesting.
	for _, prefix := range []string{"bash -lc ", "bash -c ", "sh -c "} {
		if strings.HasPrefix(cmd, prefix) {
			rest := strings.TrimSpace(cmd[len(prefix):])
			rest = strings.Trim(rest, "'\"")
			cmd = rest
			break
		}
	}
	// Split on first space; first token is the verb.
	verb := cmd
	rest := ""
	if i := strings.IndexByte(cmd, ' '); i > 0 {
		verb = cmd[:i]
		rest = strings.TrimSpace(cmd[i+1:])
	}
	// Recognized read verbs: Unix readers plus the PowerShell / Windows
	// readers codex emits on Windows (Get-Content + its gc/type/cat
	// aliases). PowerShell is case-insensitive, so fold the verb.
	switch strings.ToLower(verb) {
	case "cat", "head", "tail", "less", "more", "nl",
		"get-content", "gc", "type":
	default:
		return ""
	}
	if rest == "" {
		return ""
	}
	// Skip leading flags (anything starting with '-'). Pick the last
	// non-flag token as the path. Handles `head -50 foo`, `tail -n 100
	// foo`, `cat foo`, etc.
	tokens := strings.Fields(rest)
	var last string
	skipNext := false
	for _, tok := range tokens {
		if skipNext {
			skipNext = false
			continue
		}
		if strings.HasPrefix(tok, "-") {
			// Count-style flags consume the next token: Unix `-n`/`-c`
			// (head/tail) and PowerShell `-TotalCount`/`-Tail`/`-First`/
			// `-Last`/`-Head`/`-ReadCount`/`-Skip` (Get-Content). A
			// `-Path`/`-LiteralPath` flag names the path in the NEXT token,
			// which is a non-flag and so is captured as `last` below.
			switch strings.ToLower(tok) {
			case "-n", "-c",
				"-totalcount", "-tail", "-first", "-last", "-head",
				"-readcount", "-skip":
				skipNext = true
			}
			continue
		}
		last = tok
	}
	// Codex/PowerShell paths are frequently quoted; strip a single layer.
	return strings.Trim(last, "'\"")
}

// substituteOpenAIRedundantReads is the C16 (read-cache auto-
// substitution) pass for codex. Walks function_call_output items,
// hashing each output by (filename, content). When the same
// (filename, hash) tuple was already seen earlier in this same call,
// replaces the body with a deterministic marker.
//
// Per-call scoping: codex's Responses API request body includes the
// entire conversation history every turn (no SDK-side truncation),
// so when the model re-Reads a file in turn N+1, both turn N's and
// turn N+1's outputs appear in this single Run call. The first
// occurrence stays as-is (it's part of the cached prefix); the
// duplicate gets the marker.
//
// Gated on sessionID being non-empty (parity with the Anthropic side)
// so legacy callers / unit tests without session context get the
// previous behaviour. The hash is taken on post-line-numbers-strip
// bytes (matching what types.Detect / per-type compressors see).
//
// MCP-skip: tool_results from MCP tools (resolved via toolName) are
// NEVER substituted. MCP outputs carry structured query data where
// the values ARE the answer; if two consecutive search_past_outputs
// calls return the same hits the second one MUST still surface
// verbatim — the model's behavior depends on seeing it.
func substituteOpenAIRedundantReads(extracted []openaiResponsesExtractedMessage, sessionID string) []Event {
	if sessionID == "" {
		return nil
	}
	type fileKey struct{ filename, hash string }
	seen := map[fileKey]bool{}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult {
			continue
		}
		// Filename heuristic only fires on read-style tools, but the
		// MCP-skip predicate handles MCP tool outputs whose name
		// happens to contain a path-keyed argument.
		if isOpenAIMCPCall(em.toolName, nil) {
			continue
		}
		body := em.compressedText
		if body == "" {
			body = em.compressionText
		}
		if body == "" || em.filename == "" {
			continue
		}
		hashInput := []byte(body)
		if types.IsLineNumbered(hashInput) {
			hashInput = types.StripLineNumbers(hashInput)
		}
		h := sha256.Sum256(hashInput)
		hashHex := hex.EncodeToString(h[:])
		key := fileKey{filename: em.filename, hash: hashHex}
		if seen[key] {
			marker := formatReadCacheMarker(em.filename)
			if len(marker) >= len(body) {
				continue
			}
			em.compressedText = marker
			events = append(events, Event{
				Mechanism:       "read_cache",
				OriginalBytes:   len(body),
				CompressedBytes: len(marker),
				MsgIndex:        i,
				BodyHash:        bodyHashHex(body),
			})
			continue
		}
		seen[key] = true
	}
	return events
}

func openaiToConversationMessages(extracted []openaiExtractedMessage) []Message {
	msgs := make([]Message, len(extracted))
	for i, em := range extracted {
		text := em.flatText
		byteLen := len(em.raw)
		// Per-block pre-pass overrides flatText when compressedText is set
		// by [substituteOpenAIChatRedundantReads],
		// [compressOpenAIChatToolResults], or
		// [stashOpenAIChatLargeBodies]. Adjust ByteLen by the
		// compressed-vs-original delta so the budget enforcer sees the
		// true post-compression size on the wire.
		if em.compressedText != "" && em.compressedText != em.flatText {
			delta := len(em.compressedText) - len(em.flatText)
			text = em.compressedText
			byteLen = len(em.raw) + delta
			if byteLen < 0 {
				byteLen = 0
			}
		}
		// NoCompress: tool_results from MCP tools opt out of budget-pass
		// per-type compression — same correctness invariant as the
		// Anthropic and Responses-API paths. MCP responses carry
		// structured query data where the values ARE the answer, and
		// compressing them with JSON/code/logs replaces scalars with
		// type sentinels and corrupts the response.
		noCompress := em.isToolResult && isOpenAIMCPCall(em.toolName, nil)
		msg := Message{
			Role:       normalizeOpenAIRole(em.role, em.isToolResult),
			Text:       text,
			ByteLen:    byteLen,
			RawIndex:   i,
			Raw:        em.raw,
			Pinned:     len(em.toolUseIDs) > 0,
			NoCompress: noCompress,
		}
		if em.isToolResult && em.toolCallID != "" {
			// Tool output messages reference their assistant tool_call
			// via tool_call_id — mirror Anthropic's referencedIDs so
			// the scorer's reference-weight kicks in.
			msg.ReferencedIDs = []string{em.toolCallID}
		}
		if len(em.toolUseIDs) > 0 {
			msg.ToolUseIDs = append([]string{}, em.toolUseIDs...)
		}
		msgs[i] = msg
	}
	return msgs
}

func openaiResponsesToConversationMessages(extracted []openaiResponsesExtractedMessage, mcpSet map[string]bool) []Message {
	msgs := make([]Message, len(extracted))
	for i, em := range extracted {
		text := em.compressionText
		byteLen := len(em.raw)
		// Per-block compression overrides compressionText when populated
		// by [compressOpenAIResponsesToolResults] /
		// [stashOpenAIResponsesLargeBodies]. Adjust ByteLen by the
		// compressed-vs-original delta so the budget enforcer sees the
		// true post-compression size on the wire (preventing it from
		// dropping a message whose body is already shrunk).
		if em.compressedText != "" && em.compressedText != em.compressionText {
			delta := len(em.compressedText) - len(em.compressionText)
			text = em.compressedText
			byteLen = len(em.raw) + delta
			if byteLen < 0 {
				byteLen = 0
			}
		}
		// NoCompress: tool_results from MCP tools opt out of budget-pass
		// per-type compression — same correctness invariant as Anthropic
		// (MCP responses carry structured query data where the values
		// ARE the answer; compressing them with JSON/code/logs replaces
		// scalars with type sentinels and corrupts the response).
		noCompress := em.isToolResult && isOpenAIMCPCall(em.toolName, mcpSet)
		msg := Message{
			Role:       normalizeOpenAIRole(em.role, em.isToolResult),
			Text:       text,
			ByteLen:    byteLen,
			RawIndex:   i,
			Raw:        em.raw,
			Pinned:     isOpenAIResponsesToolCallItem(em.itemType) || isOpenAIResponsesToolDefinitionItem(em.itemType),
			NoCompress: noCompress,
		}
		if isOpenAIResponsesToolCallItem(em.itemType) && em.itemID != "" {
			msg.ToolUseIDs = []string{em.itemID}
		}
		if em.isToolResult && em.toolCallID != "" {
			msg.ReferencedIDs = []string{em.toolCallID}
		}
		msgs[i] = msg
	}
	return msgs
}

// normalizeOpenAIRole maps Chat Completions roles onto the scorer's
// four-role vocabulary. role="tool" is the OpenAI equivalent of an
// Anthropic user-message-carrying-tool_result and is what per-type
// compression targets.
func normalizeOpenAIRole(role string, isToolResult bool) string {
	if isToolResult {
		return RoleTool
	}
	switch role {
	case "user":
		return RoleUser
	case "assistant":
		return RoleAssistant
	case "system":
		return RoleSystem
	case "tool":
		return RoleTool
	}
	return role
}

// isOpenAIResponsesToolDefinitionItem reports whether a Responses-API
// `input` item carries TOOL DEFINITIONS rather than a tool call or a
// tool result. GPT-5.6 Codex (wire_api="responses") ships its tool
// definitions as the first `input` array item —
// `{"type":"additional_tools","role":"developer","tools":[...]}` —
// instead of a top-level `tools` array. Such an item MUST survive
// compression byte-for-byte (it is [Message.Pinned] so scoring always
// preserves it and the serializer forwards its raw bytes): dropping it
// strips the model's entire tool set, after which the model reports it
// has no tools available.
func isOpenAIResponsesToolDefinitionItem(itemType string) bool {
	return itemType == "additional_tools"
}

// isOpenAIResponsesToolCallItem reports whether a Responses-API `input`
// item is a tool-call PRODUCER that pairs with a later `*_output` item
// via `call_id`: `function_call` ↔ `function_call_output`,
// `custom_tool_call` ↔ `custom_tool_call_output` (GPT-5.6 Codex's `exec`
// tool), `local_shell_call` ↔ `local_shell_call_output`. Producers are
// [Message.Pinned] and contribute their `call_id` to
// [Message.ToolUseIDs] so scoring's tool-pair-integrity rule preserves
// BOTH sides of a live pair — dropping either half leaves the survivor
// orphaned and the provider rejects the request.
//
// Deliberately NOT here: item types that embed their result inline with
// no paired output item (`web_search_call`, `file_search_call`,
// `mcp_call`, and similar) — dropping those cannot orphan a pair, so
// they stay under normal scoring.
func isOpenAIResponsesToolCallItem(itemType string) bool {
	switch itemType {
	case "function_call", "custom_tool_call", "local_shell_call":
		return true
	}
	return false
}

// serializeOpenAI rebuilds a Chat Completions body from the original
// envelope + the post-enforcement Message slice. Messages with Raw !=
// nil pass through untouched when their Text is unchanged; tool-result
// messages whose Text shrunk have their content field rewritten;
// Raw == nil means the message is a compression marker.
//
// Chat Completions has no standardized cache marker today, so
// cacheBreakpointIdx is accepted for API parity with serializeAnthropic
// but intentionally ignored. A future Responses-API adapter can use
// this slot.
func serializeOpenAI(envelope map[string]json.RawMessage, original []openaiExtractedMessage, final []Message, _ int) ([]byte, error) {
	msgs := make([]json.RawMessage, 0, len(final))
	for _, m := range final {
		if m.Raw == nil {
			// Marker message — synthesize as user-role prose.
			obj, err := json.Marshal(map[string]any{
				"role":    "user",
				"content": m.Text,
			})
			if err != nil {
				return nil, fmt.Errorf("serializeOpenAI: marshal marker: %w", err)
			}
			msgs = append(msgs, obj)
			continue
		}
		em := findOpenAIByRaw(original, m.Raw)
		// Only rewrite when it's a tool-result message whose compressed
		// Text differs from the original content — mirrors the
		// Anthropic rule that keeps non-tool messages verbatim.
		if em == nil || !em.isToolResult || m.Text == em.flatText {
			msgs = append(msgs, m.Raw)
			continue
		}
		rewritten, err := rewriteOpenAIContent(em, m.Text)
		if err != nil {
			// Never poison the forward path — fall back to original.
			msgs = append(msgs, m.Raw)
			continue
		}
		msgs = append(msgs, rewritten)
	}
	envelope["messages"], _ = json.Marshal(msgs)
	return marshalEnvelope(envelope)
}

func serializeOpenAIResponses(envelope map[string]json.RawMessage, original []openaiResponsesExtractedMessage, final []Message) ([]byte, error) {
	input := make([]json.RawMessage, 0, len(final))
	for _, m := range final {
		if m.Raw == nil {
			obj, err := json.Marshal(map[string]any{
				"type": "message",
				"role": "user",
				"content": []map[string]string{
					{"type": "input_text", "text": m.Text},
				},
			})
			if err != nil {
				return nil, fmt.Errorf("serializeOpenAIResponses: marshal marker: %w", err)
			}
			input = append(input, obj)
			continue
		}
		em := findOpenAIResponseByRaw(original, m.Raw)
		if em == nil || !em.isToolResult {
			input = append(input, m.Raw)
			continue
		}
		// Three sources for the compressed body, in order of authority:
		//   1. m.Text differs from compressionText → enforcer mutated it.
		//   2. em.compressedText set → per-block compression / stash mutated it.
		//   3. neither → forward original.
		var compressed string
		switch {
		case m.Text != "" && m.Text != em.compressionText:
			compressed = m.Text
		case em.compressedText != "" && em.compressedText != em.compressionText:
			compressed = em.compressedText
		default:
			input = append(input, m.Raw)
			continue
		}
		rewritten, err := rewriteOpenAIResponseContent(em, compressed)
		if err != nil {
			input = append(input, m.Raw)
			continue
		}
		input = append(input, rewritten)
	}
	envelope["input"], _ = json.Marshal(input)
	return marshalEnvelope(envelope)
}

// rewriteOpenAIContent returns a new raw JSON object for em with its
// content field replaced by the compressed body. When the original
// content was a part array, the rewrite keeps the array shape with a
// single text entry; when it was a bare string, the rewrite emits a
// bare string.
func rewriteOpenAIContent(em *openaiExtractedMessage, compressed string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(em.raw, &obj); err != nil {
		return nil, err
	}
	var contentBytes []byte
	var err error
	if len(em.contentParts) > 0 {
		contentBytes, err = json.Marshal([]map[string]string{
			{"type": "text", "text": compressed},
		})
	} else {
		contentBytes, err = json.Marshal(compressed)
	}
	if err != nil {
		return nil, err
	}
	obj["content"] = contentBytes
	return marshalEnvelope(obj)
}

func rewriteOpenAIResponseContent(em *openaiResponsesExtractedMessage, compressed string) ([]byte, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(em.raw, &obj); err != nil {
		return nil, err
	}
	if em.outputString != "" {
		outputBytes, err := json.Marshal(compressed)
		if err != nil {
			return nil, err
		}
		obj["output"] = outputBytes
		return marshalEnvelope(obj)
	}
	var contentBytes []byte
	var err error
	if len(em.contentParts) > 0 {
		contentBytes, err = json.Marshal([]map[string]string{
			{"type": "output_text", "text": compressed},
		})
	} else {
		contentBytes, err = json.Marshal(compressed)
	}
	if err != nil {
		return nil, err
	}
	obj["content"] = contentBytes
	return marshalEnvelope(obj)
}

// findOpenAIByRaw returns the extractedMessage whose raw bytes equal
// target, or nil when not found. Linear scan — a single request rarely
// carries more than a few dozen messages.
func findOpenAIByRaw(ex []openaiExtractedMessage, target json.RawMessage) *openaiExtractedMessage {
	for i := range ex {
		if bytes.Equal(ex[i].raw, target) {
			return &ex[i]
		}
	}
	return nil
}

func findOpenAIResponseByRaw(ex []openaiResponsesExtractedMessage, target json.RawMessage) *openaiResponsesExtractedMessage {
	for i := range ex {
		if bytes.Equal(ex[i].raw, target) {
			return &ex[i]
		}
	}
	return nil
}

func parseOpenAITextContent(raw json.RawMessage) (contentString string, contentParts []openaiContentPart, flatText string) {
	if len(raw) == 0 {
		return "", nil, ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil, s
	}
	var parts []openaiContentPart
	if err := json.Unmarshal(raw, &parts); err != nil {
		return "", nil, ""
	}
	texts := make([]string, 0, len(parts))
	for _, p := range parts {
		if p.Text != "" && (p.Type == "text" || strings.HasSuffix(p.Type, "_text")) {
			texts = append(texts, p.Text)
		}
	}
	return "", parts, strings.Join(texts, "\n")
}

func rawString(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func firstRawString(values ...json.RawMessage) string {
	for _, raw := range values {
		if s := rawString(raw); s != "" {
			return s
		}
	}
	return ""
}

func parseOpenAIToolCallIDs(raw json.RawMessage) []string {
	if len(raw) == 0 {
		return nil
	}
	var calls []struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &calls); err != nil {
		return nil
	}
	out := make([]string, 0, len(calls))
	for _, call := range calls {
		if call.ID != "" {
			out = append(out, call.ID)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// collectOpenAIMCPToolNames walks envelope["tools"] for entries with
// `type:"namespace"` whose name starts with `mcp__`, and returns the
// set of names (both bare and prefixed) that count as MCP tools for
// the per-session MCP-skip predicate.
//
// The set contains two forms per nested function:
//   - the bare name as it appears under the namespace (e.g.,
//     `check_file_freshness`)
//   - the prefixed form (`<namespace_name><bare_name>`, e.g.,
//     `mcp__observer_capture__check_file_freshness`)
//
// Both forms are needed because codex may emit function_call.name in
// either form on the wire — we cover both cases. The namespace's own
// description is treated as compressible (description-trim applies)
// but the namespace itself is never marked as MCP for tool-result skip
// purposes; it has no `output`.
//
// Returns an empty set when the envelope has no tools, the tools field
// doesn't unmarshal as an array, or no `mcp__`-prefixed namespace is
// present. Callers should treat empty set + the `mcp__` HasPrefix
// fallback as the union predicate.
func collectOpenAIMCPToolNames(envelope map[string]json.RawMessage) map[string]bool {
	out := make(map[string]bool)
	rawTools, ok := envelope["tools"]
	if !ok || len(rawTools) == 0 {
		return out
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil {
		return out
	}
	for _, raw := range tools {
		var tool map[string]json.RawMessage
		if err := json.Unmarshal(raw, &tool); err != nil {
			continue
		}
		if rawString(tool["type"]) != "namespace" {
			continue
		}
		nsName := rawString(tool["name"])
		if !strings.HasPrefix(nsName, "mcp__") {
			continue
		}
		var nested []json.RawMessage
		if err := json.Unmarshal(tool["tools"], &nested); err != nil {
			continue
		}
		for _, n := range nested {
			var nt map[string]json.RawMessage
			if err := json.Unmarshal(n, &nt); err != nil {
				continue
			}
			bare := rawString(nt["name"])
			if bare == "" {
				continue
			}
			out[bare] = true
			out[nsName+bare] = true
		}
	}
	return out
}

// isOpenAIMCPCall reports whether a function_call.name (or
// function_call_output's resolved toolName) belongs to an MCP server.
// Union predicate: matches when the name is in mcpSet (built from the
// namespace walk) OR has the canonical `mcp__` prefix. The HasPrefix
// fallback covers cases where codex emits prefixed call names that
// weren't seen as namespace-nested in the current request (e.g., when
// the namespace was stripped from `tools` by tool_choice config but
// the prior conversation history still references those calls).
func isOpenAIMCPCall(name string, mcpSet map[string]bool) bool {
	if name == "" {
		return false
	}
	if mcpSet != nil && mcpSet[name] {
		return true
	}
	return strings.HasPrefix(name, "mcp__")
}

// compressOpenAIResponsesToolResults runs per-type compression on every
// function_call_output (and *_output) item in extracted, mutating
// em.compressedText in place. Each item is compressed independently —
// codex's Responses API has function_call_output as top-level array
// items (one output per item), so there's no parallel-tool-result
// invariance concern. Returns the per-item compression events for
// telemetry.
//
// MCP-tool skip: outputs whose resolved toolName is in mcpSet or carries
// the `mcp__` prefix are left untouched. This is the same correctness
// invariant as the Anthropic side — MCP tool_results carry structured
// query data where the values ARE the answer, and compressing them with
// JSON/code/logs replaces scalars with type sentinels and corrupts the
// response.
//
// Read-tool line-numbered output (cat -n style) is stripped before
// detection + compression, mirroring the Anthropic path.
func compressOpenAIResponsesToolResults(extracted []openaiResponsesExtractedMessage, registry *Registry, allow map[types.ContentType]bool, mcpSet map[string]bool, buildHints hinter, collapse codeCollapser) []Event {
	if registry == nil {
		return nil
	}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult {
			continue
		}
		// Read-cache substitution may have already replaced the body
		// with a marker — don't overwrite it with per-type compression.
		// The marker is the final compressed form for that item.
		if em.compressedText != "" {
			continue
		}
		body := em.compressionText
		if body == "" {
			continue
		}
		if isOpenAIMCPCall(em.toolName, mcpSet) {
			continue
		}
		compressInput := []byte(body)
		if types.IsLineNumbered(compressInput) {
			compressInput = types.StripLineNumbers(compressInput)
		}
		ct := types.Detect(compressInput, em.filename)
		if ct == types.Unknown {
			continue
		}
		// Aggressive code-collapse (codeintel Phase 2, ADR-0005): opt-in,
		// exact-span-gated, runs INSTEAD of the content-preserving
		// CodeCompressor when it fires — independent of the compress_types
		// allow-list. Mirror of compressToolResults (anthropic.go).
		if ct == types.Code && collapse != nil && em.filename != "" {
			out, evs, fired := collapse(em.filename, compressInput, i)
			if len(evs) > 0 {
				events = append(events, evs...)
			}
			if fired {
				em.compressedText = string(out)
				continue
			}
		}
		if !allow[ct] {
			// V7-19: previously `if allow != nil && !allow[ct]` — that
			// short-circuited to false when allow was nil, silently
			// inverting compress_types=[] into "compress all". Nil-map
			// access returns zero-value (false), so `!allow[ct]` on a
			// nil map returns true and we skip per-type compression
			// uniformly. buildAllow now returns an empty non-nil map
			// for safety in depth.
			continue
		}
		c, ok := registry.Get(ct)
		if !ok {
			continue
		}
		// V7-11 / v1.7.7 marker enrichment — same shape as
		// compressToolResults (anthropic.go). The hinter closure
		// returns the zero CompressHints when the code index is
		// unavailable / stale / not configured.
		var out []byte
		if hc, ok := c.(HintedCompressor); ok && buildHints != nil {
			out = hc.CompressHinted(compressInput, buildHints(em.filename))
		} else {
			out = c.Compress(compressInput)
		}
		if len(out) >= len(body) {
			continue
		}
		em.compressedText = string(out)
		events = append(events, Event{
			Mechanism:       string(ct),
			OriginalBytes:   len(body),
			CompressedBytes: len(out),
			MsgIndex:        i,
			BodyHash:        bodyHashHex(body),
		})
	}
	return events
}

// stashOpenAIResponsesLargeBodies offloads function_call_output bodies
// whose post-per-type-compression size still exceeds threshold into the
// CCR stash, replacing the inline body with a deterministic marker. The
// model retrieves originals via the `retrieve_stashed` MCP tool. Same
// MCP-tool skip as compressOpenAIResponsesToolResults.
//
// The marker rendered for codex matches the Anthropic-side phrasing
// (directive form including the explicit `mcp__observer__retrieve_stashed`
// tool name + sha argument shape) — the model's MCP tool call shape is
// the same regardless of provider.
func stashOpenAIResponsesLargeBodies(extracted []openaiResponsesExtractedMessage, store interface {
	Write(body []byte) (string, error)
}, threshold int, mcpSet map[string]bool,
) []Event {
	if store == nil || threshold <= 0 {
		return nil
	}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult {
			continue
		}
		if isOpenAIMCPCall(em.toolName, mcpSet) {
			continue
		}
		body := em.compressedText
		if body == "" {
			body = em.compressionText
		}
		if len(body) <= threshold {
			continue
		}
		sha, err := store.Write([]byte(body))
		if err != nil {
			continue
		}
		marker := formatStashMarker(len(body), sha)
		if len(marker) >= len(body) {
			continue
		}
		em.compressedText = marker
		events = append(events, Event{
			Mechanism:       "stash",
			OriginalBytes:   len(body),
			CompressedBytes: len(marker),
			MsgIndex:        i,
			BodyHash:        bodyHashHex(body),
		})
	}
	return events
}

// compressOpenAIResponsesToolDefinitions strips informational fields
// from envelope["tools"], mutating the envelope in place. Returns the
// per-tool compression events for telemetry. No-op when the envelope
// has no `tools`, when the field doesn't unmarshal as a JSON array, or
// when nothing shrunk.
//
// Two transforms applied per tool, mirroring the Anthropic path:
//   - description-tail trim (keep first 2 paragraphs of 3+)
//   - deep `examples` strip from `parameters` (Responses API; Anthropic
//     uses `input_schema` — same JSON-Schema semantics).
//
// Namespace recursion: when an entry is `{type:"namespace", tools:[...]}`,
// the same two transforms apply recursively to each nested function tool
// AND to the namespace's own description. Forbidden list is universal:
// no `parameters` / `properties` / `required` / `enum` / numeric bounds
// touched at any depth.
//
// Cross-turn invariance: pure function of input bytes. Same `tools`
// array compresses byte-identically every turn, preserving the OpenAI
// `prompt_cache_key` cache hit on warm turns (when the tools array is
// part of the cached prefix).
func compressOpenAIResponsesToolDefinitions(envelope map[string]json.RawMessage) []Event {
	rawTools, ok := envelope["tools"]
	if !ok || len(rawTools) == 0 {
		return nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil || len(tools) == 0 {
		return nil
	}

	var events []Event
	originalTotal := len(rawTools)
	changed := false

	for i, raw := range tools {
		newRaw, toolEvents, didShrink := compressOpenAIResponsesToolEntry(raw)
		if didShrink {
			tools[i] = newRaw
			events = append(events, toolEvents...)
			changed = true
		}
	}

	if !changed {
		return nil
	}
	newToolsRaw, err := json.Marshal(tools)
	if err != nil {
		return nil
	}
	if len(newToolsRaw) >= originalTotal {
		// Net no-op or grew. Restore original to honour the standard
		// `len(out) >= len(body)` short-circuit at the envelope-tools
		// scope.
		return nil
	}
	envelope["tools"] = newToolsRaw
	return events
}

// compressOpenAIResponsesToolEntry trims one tool entry. Handles three
// shapes: function-typed (description trim + parameters.examples strip),
// namespace-typed (recurse into nested tools + trim namespace's own
// description), and other types (web_search, etc.) which pass through
// unchanged.
func compressOpenAIResponsesToolEntry(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var tool map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tool); err != nil {
		return raw, nil, false
	}
	originalLen := len(raw)
	toolType := rawString(tool["type"])

	var events []Event
	changed := false

	// Description-tail trim (applies to function and namespace).
	if descRaw, ok := tool["description"]; ok {
		var desc string
		if err := json.Unmarshal(descRaw, &desc); err == nil {
			if trimmed, trimmedOK := trimDescriptionTail(desc); trimmedOK {
				if encoded, err := json.Marshal(trimmed); err == nil {
					tool["description"] = encoded
					changed = true
				}
			}
		}
	}

	// Function-typed: deep examples strip from `parameters`.
	if toolType == "function" {
		if paramsRaw, ok := tool["parameters"]; ok && len(paramsRaw) > 0 {
			var params any
			if err := json.Unmarshal(paramsRaw, &params); err == nil {
				if stripped, didStrip := stripExamplesDeep(params); didStrip {
					if encoded, err := json.Marshal(stripped); err == nil {
						tool["parameters"] = encoded
						changed = true
					}
				}
			}
		}
	}

	// Namespace-typed: recurse into nested tools.
	if toolType == "namespace" {
		if nestedRaw, ok := tool["tools"]; ok && len(nestedRaw) > 0 {
			var nested []json.RawMessage
			if err := json.Unmarshal(nestedRaw, &nested); err == nil {
				nestedChanged := false
				for j, nrRaw := range nested {
					if newNR, nrEvents, didShrink := compressOpenAIResponsesToolEntry(nrRaw); didShrink {
						nested[j] = newNR
						events = append(events, nrEvents...)
						nestedChanged = true
					}
				}
				if nestedChanged {
					if encoded, err := json.Marshal(nested); err == nil {
						tool["tools"] = encoded
						changed = true
					}
				}
			}
		}
	}

	if !changed {
		return raw, nil, false
	}
	newRaw, err := marshalEnvelope(tool)
	if err != nil {
		return raw, nil, false
	}
	if len(newRaw) >= originalLen {
		// This entry didn't actually shrink — return original and
		// forfeit any nested events recorded under it (we won't apply
		// them since we're handing back the original bytes).
		return raw, nil, false
	}
	events = append(events, Event{
		Mechanism:       "tools",
		OriginalBytes:   originalLen,
		CompressedBytes: len(newRaw),
		MsgIndex:        -1,
		BodyHash:        bodyHashHex(string(raw)),
	})
	return newRaw, events, true
}

// substituteOpenAIChatRedundantReads is the C16 (read-cache auto-
// substitution) pass for Chat Completions. Walks role:"tool" messages,
// hashing each output by (filename, content). When the same
// (filename, hash) tuple was already seen earlier in this same call,
// replaces the body with a deterministic marker.
//
// Per-call scoping: Chat Completions clients (cursor / cline /
// copilot-style hosts) include the entire conversation history every
// turn, so when the model re-reads a file in turn N+1, both turn N's
// and turn N+1's tool messages appear in this single Run call.
//
// Gated on sessionID (parity with Responses API) so legacy callers /
// tests without session context keep the previous behaviour.
//
// MCP-skip: tool messages whose resolved toolName has the `mcp__`
// prefix are NEVER substituted — same correctness invariant as the
// Anthropic and Responses-API paths.
func substituteOpenAIChatRedundantReads(extracted []openaiExtractedMessage, sessionID string) []Event {
	if sessionID == "" {
		return nil
	}
	type fileKey struct{ filename, hash string }
	seen := map[fileKey]bool{}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult {
			continue
		}
		if isOpenAIMCPCall(em.toolName, nil) {
			continue
		}
		body := em.compressedText
		if body == "" {
			body = em.compressionText
		}
		if body == "" || em.filename == "" {
			continue
		}
		hashInput := []byte(body)
		if types.IsLineNumbered(hashInput) {
			hashInput = types.StripLineNumbers(hashInput)
		}
		h := sha256.Sum256(hashInput)
		hashHex := hex.EncodeToString(h[:])
		key := fileKey{filename: em.filename, hash: hashHex}
		if seen[key] {
			marker := formatReadCacheMarker(em.filename)
			if len(marker) >= len(body) {
				continue
			}
			em.compressedText = marker
			events = append(events, Event{
				Mechanism:       "read_cache",
				OriginalBytes:   len(body),
				CompressedBytes: len(marker),
				MsgIndex:        i,
				BodyHash:        bodyHashHex(body),
			})
			continue
		}
		seen[key] = true
	}
	return events
}

// compressOpenAIChatToolResults runs per-type compression on every
// role:"tool" message in extracted, mutating em.compressedText in place.
// Mirrors compressOpenAIResponsesToolResults — same MCP-skip invariant,
// same line-numbered-strip, same len(out) >= len(body) short-circuit.
//
// Read-cache substitution may have already populated em.compressedText
// with a marker; this pass MUST NOT overwrite it (the marker is the
// final compressed form for that item).
func compressOpenAIChatToolResults(extracted []openaiExtractedMessage, registry *Registry, allow map[types.ContentType]bool, buildHints hinter, collapse codeCollapser) []Event {
	if registry == nil {
		return nil
	}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult {
			continue
		}
		if em.compressedText != "" {
			continue
		}
		body := em.compressionText
		if body == "" {
			continue
		}
		if isOpenAIMCPCall(em.toolName, nil) {
			continue
		}
		compressInput := []byte(body)
		if types.IsLineNumbered(compressInput) {
			compressInput = types.StripLineNumbers(compressInput)
		}
		ct := types.Detect(compressInput, em.filename)
		if ct == types.Unknown {
			continue
		}
		// Aggressive code-collapse (codeintel Phase 2, ADR-0005): opt-in,
		// exact-span-gated, runs INSTEAD of the content-preserving
		// CodeCompressor when it fires — independent of the compress_types
		// allow-list (it is its own opt-in). Mirror of compressToolResults
		// (anthropic.go). Preview mode records events without changing body.
		if ct == types.Code && collapse != nil && em.filename != "" {
			out, evs, fired := collapse(em.filename, compressInput, i)
			if len(evs) > 0 {
				events = append(events, evs...)
			}
			if fired {
				em.compressedText = string(out)
				continue
			}
		}
		if !allow[ct] {
			// V7-19: previously `if allow != nil && !allow[ct]` — that
			// short-circuited to false when allow was nil, silently
			// inverting compress_types=[] into "compress all". Nil-map
			// access returns zero-value (false), so `!allow[ct]` on a
			// nil map returns true and we skip per-type compression
			// uniformly. buildAllow now returns an empty non-nil map
			// for safety in depth.
			continue
		}
		c, ok := registry.Get(ct)
		if !ok {
			continue
		}
		// V7-11 / v1.7.7 marker enrichment — same shape as
		// compressOpenAIResponsesToolResults / compressToolResults.
		var out []byte
		if hc, ok := c.(HintedCompressor); ok && buildHints != nil {
			out = hc.CompressHinted(compressInput, buildHints(em.filename))
		} else {
			out = c.Compress(compressInput)
		}
		if len(out) >= len(body) {
			continue
		}
		em.compressedText = string(out)
		events = append(events, Event{
			Mechanism:       string(ct),
			OriginalBytes:   len(body),
			CompressedBytes: len(out),
			MsgIndex:        i,
			BodyHash:        bodyHashHex(body),
		})
	}
	return events
}

// stashOpenAIChatLargeBodies offloads role:"tool" message bodies whose
// post-per-type-compression size still exceeds threshold into the CCR
// stash, replacing the inline body with a deterministic marker. Same
// MCP-skip invariant as compressOpenAIChatToolResults; same marker
// shape as the Anthropic and Responses-API paths.
func stashOpenAIChatLargeBodies(extracted []openaiExtractedMessage, store interface {
	Write(body []byte) (string, error)
}, threshold int,
) []Event {
	if store == nil || threshold <= 0 {
		return nil
	}
	var events []Event
	for i := range extracted {
		em := &extracted[i]
		if !em.isToolResult {
			continue
		}
		if isOpenAIMCPCall(em.toolName, nil) {
			continue
		}
		body := em.compressedText
		if body == "" {
			body = em.compressionText
		}
		if len(body) <= threshold {
			continue
		}
		sha, err := store.Write([]byte(body))
		if err != nil {
			continue
		}
		marker := formatStashMarker(len(body), sha)
		if len(marker) >= len(body) {
			continue
		}
		em.compressedText = marker
		events = append(events, Event{
			Mechanism:       "stash",
			OriginalBytes:   len(body),
			CompressedBytes: len(marker),
			MsgIndex:        i,
			BodyHash:        bodyHashHex(body),
		})
	}
	return events
}

// compressOpenAIChatToolDefinitions strips informational fields from
// envelope["tools"] for the Chat Completions wire shape, mutating the
// envelope in place. Returns the per-tool compression events for
// telemetry. No-op when the envelope has no `tools`, when the field
// doesn't unmarshal as a JSON array, or when nothing shrunk.
//
// Chat Completions wraps function definitions one level deeper than the
// Responses API — `{type:"function", function:{name, description,
// parameters}}` instead of `{type:"function", name, description,
// parameters}`. We descend through `function` to access description /
// parameters. Non-function types (web_search, etc.) pass through
// unchanged.
//
// Two transforms applied per tool, mirroring the Responses-API path:
//   - description-tail trim (keep first 2 paragraphs of 3+)
//   - deep `examples` strip from `parameters`
//
// Forbidden list is universal: no `parameters` / `properties` /
// `required` / `enum` / numeric bounds touched at any depth.
//
// Cross-turn invariance: pure function of input bytes. Same `tools`
// array compresses byte-identically every turn, preserving the OpenAI
// `prompt_cache_key` cache hit on warm turns.
func compressOpenAIChatToolDefinitions(envelope map[string]json.RawMessage) []Event {
	rawTools, ok := envelope["tools"]
	if !ok || len(rawTools) == 0 {
		return nil
	}
	var tools []json.RawMessage
	if err := json.Unmarshal(rawTools, &tools); err != nil || len(tools) == 0 {
		return nil
	}

	var events []Event
	originalTotal := len(rawTools)
	changed := false

	for i, raw := range tools {
		newRaw, toolEvents, didShrink := compressOpenAIChatToolEntry(raw)
		if didShrink {
			tools[i] = newRaw
			events = append(events, toolEvents...)
			changed = true
		}
	}

	if !changed {
		return nil
	}
	newToolsRaw, err := json.Marshal(tools)
	if err != nil {
		return nil
	}
	if len(newToolsRaw) >= originalTotal {
		return nil
	}
	envelope["tools"] = newToolsRaw
	return events
}

// compressOpenAIChatToolEntry trims one Chat Completions tool entry.
// Only function-typed entries are touched — descends through `function`
// to apply description-tail trim + deep `examples` strip on `parameters`.
// Non-function entries (web_search, mcp, etc.) pass through unchanged so
// future tool types don't get accidentally mutated.
func compressOpenAIChatToolEntry(raw json.RawMessage) (json.RawMessage, []Event, bool) {
	var tool map[string]json.RawMessage
	if err := json.Unmarshal(raw, &tool); err != nil {
		return raw, nil, false
	}
	originalLen := len(raw)
	if rawString(tool["type"]) != "function" {
		return raw, nil, false
	}
	fnRaw, ok := tool["function"]
	if !ok || len(fnRaw) == 0 {
		return raw, nil, false
	}
	var fn map[string]json.RawMessage
	if err := json.Unmarshal(fnRaw, &fn); err != nil {
		return raw, nil, false
	}

	changed := false

	if descRaw, ok := fn["description"]; ok {
		var desc string
		if err := json.Unmarshal(descRaw, &desc); err == nil {
			if trimmed, trimmedOK := trimDescriptionTail(desc); trimmedOK {
				if encoded, err := json.Marshal(trimmed); err == nil {
					fn["description"] = encoded
					changed = true
				}
			}
		}
	}

	if paramsRaw, ok := fn["parameters"]; ok && len(paramsRaw) > 0 {
		var params any
		if err := json.Unmarshal(paramsRaw, &params); err == nil {
			if stripped, didStrip := stripExamplesDeep(params); didStrip {
				if encoded, err := json.Marshal(stripped); err == nil {
					fn["parameters"] = encoded
					changed = true
				}
			}
		}
	}

	if !changed {
		return raw, nil, false
	}
	fnEncoded, err := marshalEnvelope(fn)
	if err != nil {
		return raw, nil, false
	}
	tool["function"] = fnEncoded
	newRaw, err := marshalEnvelope(tool)
	if err != nil {
		return raw, nil, false
	}
	if len(newRaw) >= originalLen {
		return raw, nil, false
	}
	events := []Event{{
		Mechanism:       "tools",
		OriginalBytes:   originalLen,
		CompressedBytes: len(newRaw),
		MsgIndex:        -1,
		BodyHash:        bodyHashHex(string(raw)),
	}}
	return newRaw, events, true
}
