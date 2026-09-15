package cline

import (
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// Cline's legacy bundle does NOT use Anthropic `tool_use` content
// blocks for its own built-in tools. It prompts the model to emit
// XML-ish pseudo-tags inside an ordinary assistant `text` block:
//
//	<read_file>
//	<path>src/main.go</path>
//	</read_file>
//
// Before this scanner every such call was swallowed whole into the
// assistant_message row (audit IDE-07: 0 tool rows across the two live
// tasks on the operator's box, despite the tasks being nothing but
// tool calls), and the swallowed text additionally tripped the
// scrubber — `<ask_followup_question>` contains the substring
// `sk_followup_question`, which matches the generic
// `(?i)(?:sk|pk|ak)[_-][A-Za-z0-9_-]{16,}` API-key rule, so the whole
// tag rendered as `<a[REDACTED]>`.
//
// The scanner below extracts every occurrence, mints one tool
// ToolEvent per call, and returns the assistant prose with the XML
// spans REMOVED, so prose stays prose and the scrubber no longer sees
// the tag name.

// xmlTool is one row of the pseudo-tool table.
type xmlTool struct {
	// tag is the XML element name, which is ALSO the raw tool name —
	// Cline names the element after the tool, so the same string feeds
	// the actionMap lookup the `tool_use` path uses (adapter.go).
	tag string
	// targetChild is the child element carrying the row's Target
	// (`path`, `command`, `regex`, `question`, …). Empty means the
	// call has no canonical single target.
	targetChild string
	// prefixChild, when set, is a child element prepended to the
	// target as "<prefix>:<target>" — mirrors extractTarget's
	// server_name handling for the two MCP tools so an XML-shaped MCP
	// call and a tool_use-shaped one render identically.
	prefixChild string
	// contentChild, when set, names the child element whose body is
	// FILE CONTENT rather than call metadata: `<write_to_file>`'s
	// `<content>` IS the file being written, `<replace_in_file>`'s
	// `<diff>` IS the patch. CLAUDE.md forbids storing file contents
	// in the DB, so xmlToolEvent keeps only the path (Target) and
	// replaces this child's body with a bounded excerpt before the
	// value ever reaches RawToolInput.
	contentChild string
}

// xmlToolTags is THE table of Cline pseudo-tool tags. Ordered for
// readability only; the scanner matches whichever opening tag occurs
// EARLIEST in the text, so table order never decides the emitted
// sequence.
//
// The rawToolName is the tag itself and is resolved through the SAME
// package-level actionMap the `tool_use` path uses, so a tag and a
// block of the same name can never disagree about action_type.
//
// KNOWN GAP (deliberate, documented): `list_code_definition_names`,
// `new_task` and `plan_mode_respond` are real Cline tags with no row
// in actionMap and no row in internal/tooltax, so they classify as
// models.ActionUnknown. Emitting them as `unknown` tool rows is
// strictly better than the pre-scanner behaviour (swallowed into
// prose, invisible), and adding a classification would require a
// paired internal/tooltax row — out of this ticket's file ownership.
var xmlToolTags = []xmlTool{
	{tag: "read_file", targetChild: "path"},
	{tag: "write_to_file", targetChild: "path", contentChild: "content"},
	{tag: "replace_in_file", targetChild: "path", contentChild: "diff"},
	{tag: "execute_command", targetChild: "command"},
	{tag: "search_files", targetChild: "regex"},
	{tag: "list_files", targetChild: "path"},
	{tag: "list_code_definition_names", targetChild: "path"},
	{tag: "browser_action", targetChild: "action"},
	{tag: "use_mcp_tool", targetChild: "tool_name", prefixChild: "server_name"},
	{tag: "access_mcp_resource", targetChild: "uri", prefixChild: "server_name"},
	{tag: "attempt_completion", targetChild: "result"},
	{tag: "ask_followup_question", targetChild: "question"},
	{tag: "new_task", targetChild: "context"},
	{tag: "plan_mode_respond", targetChild: "response"},
}

// xmlToolCall is one extracted occurrence: which table row matched and
// the raw inner body between the opening and closing tag.
type xmlToolCall struct {
	tool  xmlTool
	inner string
}

// thinkingOpen / thinkingClose delimit Cline's own inline reasoning.
// A `<thinking>` span is neither scanned for tool calls nor removed
// from the prose: the model's reasoning stays reasoning.
const (
	thinkingOpen  = "<thinking>"
	thinkingClose = "</thinking>"
)

// scanXMLTools extracts every top-level pseudo-tool occurrence from an
// assistant text block, in wire order, and returns the text with those
// spans removed.
//
// The scan is a plain left-to-right LINE walk — no regex, so there is
// no catastrophic-backtracking surface on a megabyte-scale assistant
// message. Cost is O(len(xmlToolTags) x len(text)).
//
// # What counts as a call (and why the anchoring matters)
//
// Cline emits a real call as its own block, the opening tag alone on
// its line. An earlier version of this scanner matched the opening tag
// ANYWHERE in the text, which minted phantom rows — and silently
// excised the prose that mentioned the tag — for three shapes that
// occur constantly in real assistant messages:
//
//   - prose that MENTIONS a tag ("the `<execute_command>` tag wraps a
//     shell command") became a run_command action;
//   - a ```xml documentation fence containing `<write_to_file>` became
//     an ActionWriteFile against whatever path the example used;
//   - a `<thinking>` block's contents were swallowed into a row's
//     raw_tool_input.
//
// So an opener counts ONLY when all of the following hold:
//
//   - it starts at the beginning of a line (leading spaces/tabs are
//     allowed, nothing else);
//   - the byte right after `<tag>` is '\n', '\r' or '<' (a real call
//     breaks the line or goes straight into its first parameter — a
//     prose mention is followed by a space or punctuation);
//   - it is not inside a fenced code block (``` or ~~~, any info
//     string; an unterminated fence protects the rest of the text) nor
//     inside a `<thinking>` span.
//
// Tolerance rules:
//
//   - An opening tag with no matching closing tag (a truncated /
//     still-streaming message) is NOT a call: the opener stays in the
//     returned prose verbatim and the scan resumes after it.
//   - Nesting is not interpreted. Cline's tags are flat (parameters
//     are direct children) and the FIRST closing tag wins, which is
//     the correct reading for that shape.
func scanXMLTools(text string) (calls []xmlToolCall, prose string) {
	var b strings.Builder
	fence := "" // the open fence marker, "" outside a fence
	inThinking := false
	atLineStart := true
	i := 0
	for i < len(text) {
		end, next := lineSpan(text, i)
		line := text[i:end]
		switch {
		case !atLineStart:
			// Tail of the line an extracted span ended on — prose,
			// and never an anchor for another opener.
		case fence != "":
			if closesFence(line, fence) {
				fence = ""
			}
		case inThinking:
			if strings.Contains(line, thinkingClose) {
				inThinking = false
			}
		default:
			if m := fenceMarker(line); m != "" {
				fence = m
				break
			}
			if k := strings.Index(line, thinkingOpen); k >= 0 {
				inThinking = !strings.Contains(line[k+len(thinkingOpen):], thinkingClose)
				break
			}
			idx, tool, ok := lineOpensTool(text, i, end)
			if !ok {
				break
			}
			closer := "</" + tool.tag + ">"
			bodyStart := idx + len(tool.tag) + len("<>")
			rel := strings.Index(text[bodyStart:], closer)
			if rel < 0 {
				break // unclosed opener: prose, not a call
			}
			b.WriteString(text[i:idx])
			calls = append(calls, xmlToolCall{tool: tool, inner: text[bodyStart : bodyStart+rel]})
			i = bodyStart + rel + len(closer)
			atLineStart = false
			continue
		}
		b.WriteString(text[i:next])
		i = next
		atLineStart = true
	}
	return calls, strings.TrimSpace(b.String())
}

// lineSpan returns the end of the line starting at i (excluding its
// terminator, CRLF included) and the index the next line starts at.
func lineSpan(text string, i int) (end, next int) {
	rel := strings.IndexByte(text[i:], '\n')
	if rel < 0 {
		return len(text), len(text)
	}
	end, next = i+rel, i+rel+1
	if end > i && text[end-1] == '\r' {
		end--
	}
	return end, next
}

// fenceMarker returns the code-fence marker a line opens (a run of at
// least three '`' or '~'), or "" when the line opens no fence. An info
// string after the run ("```xml") is allowed and ignored — that is
// exactly the documentation shape that used to mint phantom rows.
func fenceMarker(line string) string {
	s := strings.TrimLeft(line, " \t")
	if len(s) < 3 || (s[0] != '`' && s[0] != '~') {
		return ""
	}
	n := 0
	for n < len(s) && s[n] == s[0] {
		n++
	}
	if n < 3 {
		return ""
	}
	return s[:n]
}

// closesFence reports whether line closes a fence opened with marker:
// same fence character, at least as long, and nothing but whitespace
// after it (a closing fence carries no info string).
func closesFence(line, marker string) bool {
	m := fenceMarker(line)
	if m == "" || m[0] != marker[0] || len(m) < len(marker) {
		return false
	}
	return strings.TrimSpace(strings.TrimLeft(line, " \t")[len(m):]) == ""
}

// lineOpensTool reports whether the line [lineStart,lineEnd) opens a
// pseudo-tool call, returning the absolute index of the opening tag
// and its table row. See scanXMLTools for the anchoring rules.
func lineOpensTool(text string, lineStart, lineEnd int) (int, xmlTool, bool) {
	i := lineStart
	for i < lineEnd && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	rest := text[i:lineEnd]
	for _, t := range xmlToolTags {
		open := "<" + t.tag + ">"
		if !strings.HasPrefix(rest, open) {
			continue
		}
		after := i + len(open)
		if after < len(text) {
			if c := text[after]; c == '\n' || c == '\r' || c == '<' {
				return i, t, true
			}
		}
		// Tag names are distinct, so at most one row can prefix-match.
		return 0, xmlTool{}, false
	}
	return 0, xmlTool{}, false
}

// xmlChildValue pulls one direct child element's body out of a pseudo-
// tool's inner text. Returns "" when the child is absent or unclosed.
func xmlChildValue(inner, child string) string {
	if child == "" {
		return ""
	}
	open := "<" + child + ">"
	start := strings.Index(inner, open)
	if start < 0 {
		return ""
	}
	start += len(open)
	end := strings.Index(inner[start:], "</"+child+">")
	if end < 0 {
		return ""
	}
	return strings.TrimSpace(inner[start : start+end])
}

// xmlToolTarget renders the Target string for one extracted call:
// the targetChild body, optionally prefixed with the prefixChild body
// as "<prefix>:<target>" (the MCP convention extractTarget uses).
func xmlToolTarget(c xmlToolCall) string {
	target := xmlChildValue(c.inner, c.tool.targetChild)
	if c.tool.prefixChild == "" {
		return target
	}
	if prefix := xmlChildValue(c.inner, c.tool.prefixChild); prefix != "" {
		if target == "" {
			return prefix
		}
		return prefix + ":" + target
	}
	return target
}

// assistantTextBlockEvents converts ONE `text` content block on a
// role=assistant message into its rows.
//
// XML PSEUDO-TOOLS (audit IDE-07): Cline's legacy bundle embeds its
// built-in tool calls as XML inside this very block, so the spans are
// extracted FIRST. What remains is prose and becomes at most one
// assistant_message row; each extracted call becomes one tool row. The
// order is prose-then-calls, matching how the model wrote it (a call is
// the tail of the turn it narrates).
//
// Extracting first is also what keeps `<ask_followup_question>` out of
// the scrubber's reach — see the xmltools.go package comment.
//
// reasoning is the per-message thinking buffer; each minted tool row
// carries it exactly like a tool_use row does (FAN-OUT). xmlSeq is the
// per-MESSAGE occurrence counter, advanced in place so the
// `<msgIdx>:xml:<n>` dedup key stays unique across a message's blocks.
func (a *Adapter) assistantTextBlockEvents(
	sourceFile, toolID, sessionID, projectRoot, gitBranch, gitRemote, model string,
	ts time.Time,
	msgIdx, blockIdx int,
	text, reasoning string,
	xmlSeq *int,
) []models.ToolEvent {
	calls, prose := scanXMLTools(text)
	var out []models.ToolEvent
	if body := strings.TrimSpace(prose); body != "" {
		// The row's SourceEventID hashes the ORIGINAL block text, not
		// the XML-stripped prose — see assistantTextEvent.
		out = append(out, a.assistantTextEvent(sourceFile, toolID, sessionID, projectRoot, gitBranch, gitRemote, model, ts, msgIdx, blockIdx, body, strings.TrimSpace(text)))
	}
	for _, call := range calls {
		evt := a.xmlToolEvent(sourceFile, toolID, sessionID, projectRoot, gitBranch, gitRemote, model, ts, msgIdx, *xmlSeq, call)
		if reasoning != "" {
			evt.PrecedingReasoning = truncate(a.scrubber.String(reasoning), 2048)
		}
		*xmlSeq++
		out = append(out, evt)
	}
	return out
}

// xmlToolEvent mints the ToolEvent for one extracted pseudo-tool call.
//
// SourceEventID is `<messageIndex>:xml:<n>` where n counts occurrences
// within the message (across its text blocks), so the whole-file
// re-parse this adapter performs on every poll dedupes through the
// store's UNIQUE(source_file, source_event_id) exactly like the
// tool_use path does with its block ids.
//
// LIMITATION (documented, not a bug to be silently papered over):
// Success is always true. Cline reports an XML call's outcome in the
// NEXT user message as free text (`[replace_in_file for 'x'] Result:
// …`), which has no machine-readable error flag — unlike a tool_result
// block's `is_error`. Correlating that prose would be a heuristic; the
// row therefore records that the call was MADE, not that it succeeded.
func (a *Adapter) xmlToolEvent(
	sourceFile, toolID, sessionID, projectRoot, gitBranch, gitRemote, model string,
	ts time.Time,
	msgIdx, occurrence int,
	c xmlToolCall,
) models.ToolEvent {
	actionType, ok := actionMap[c.tool.tag]
	if !ok {
		actionType = models.ActionUnknown
	}
	target := xmlToolTarget(c)
	// Path-shaped targets are relativised against the project root the
	// same way extractTarget does for the tool_use path, so an XML
	// call and a block call render one identical target string.
	if c.tool.targetChild == "path" && target != "" && projectRoot != "" {
		target = git.RelativePath(projectRoot, target)
	}
	return models.ToolEvent{
		SourceFile:    sourceFile,
		SourceEventID: fmt.Sprintf("%d:xml:%d", msgIdx, occurrence),
		SessionID:     sessionID,
		ProjectRoot:   projectRoot,
		Timestamp:     ts,
		GitBranch:     gitBranch,
		GitRemote:     gitRemote,
		Model:         model,
		Tool:          toolID,
		ActionType:    actionType,
		Target:        a.scrubber.String(target),
		Success:       true,
		RawToolName:   c.tool.tag,
		RawToolInput:  scrub.Truncate(a.scrubber.String(xmlRawToolInput(c))),
	}
}

// xmlContentExcerptBytes caps the excerpt kept for a content-bearing
// child element (see xmlTool.contentChild). Enough to identify what
// was written; far short of storing the file.
const xmlContentExcerptBytes = 512

// xmlRawToolInput renders the raw_tool_input value for one extracted
// call: the inner XML, with a content-bearing child's body replaced by
// a bounded excerpt.
//
// The caller still passes the result through scrub.Truncate (the same
// 1 MiB raw_tool_input ceiling the `tool_use` path applies via
// scrub.RawJSON): Scrubber.String does NOT truncate, so a
// `<execute_command>` carrying a megabyte heredoc would otherwise land
// in the DB whole.
func xmlRawToolInput(c xmlToolCall) string {
	inner := strings.TrimSpace(c.inner)
	if c.tool.contentChild == "" {
		return inner
	}
	return excerptChild(inner, c.tool.contentChild, xmlContentExcerptBytes)
}

// excerptChild replaces the body of the `child` element inside inner
// with a maxBytes excerpt, leaving the surrounding XML (crucially the
// `<path>`) intact. An absent child is a no-op; an UNCLOSED one (a
// truncated stream) excerpts everything from its opener to the end,
// because that tail is the file body too.
func excerptChild(inner, child string, maxBytes int) string {
	open, closer := "<"+child+">", "</"+child+">"
	start := strings.Index(inner, open)
	if start < 0 {
		return inner
	}
	bodyStart := start + len(open)
	rel := strings.Index(inner[bodyStart:], closer)
	if rel < 0 {
		return inner[:bodyStart] + scrub.TruncateN(inner[bodyStart:], maxBytes)
	}
	return inner[:bodyStart] +
		scrub.TruncateN(inner[bodyStart:bodyStart+rel], maxBytes) +
		inner[bodyStart+rel:]
}
