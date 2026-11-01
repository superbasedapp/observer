package deepagents

import (
	"strings"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/models"
)

// msgTime resolves a message's timestamp. An AI message carries the
// provider's response clock (`response_metadata.created`, epoch seconds —
// grounded on OpenRouter); every other message has no clock of its own, so it
// takes the embedded time of the checkpoint its write hung off.
func msgTime(m *rawMessage) time.Time {
	if m.Role == "ai" {
		if c := asInt64(m.ResponseMetadata["created"]); c > 0 {
			if c > 1e12 { // epoch milliseconds
				return time.UnixMilli(c).UTC()
			}
			return time.Unix(c, 0).UTC()
		}
	}
	if ts, ok := uuidTime(m.CheckpointID); ok {
		return ts
	}
	return time.Time{}
}

// resultOutcome reads a ToolMessage's verdict: its status, then (for the
// shell tool) the exit code dcode records in the message artifact
// (`{"exit_code": N}`, grounded on `execute`).
func resultOutcome(res *rawMessage) (success bool, errMsg string) {
	if strings.EqualFold(res.Status, "error") {
		return false, contentText(res.Content)
	}
	if art := asMap(res.Artifact); art != nil {
		if code, ok := art["exit_code"]; ok && asInt64(code) != 0 {
			return false, contentText(res.Content)
		}
	}
	return true, ""
}

// userAttachments extracts presence + kind of the media blocks of a human
// message (never names or bytes). dcode's pasted images are OpenAI-style
// `image_url` blocks carrying a data: URI; pasted video is a LangChain
// standard block with a `mime_type`.
func userAttachments(content any) []models.UserAttachment {
	blocks, ok := content.([]any)
	if !ok {
		return nil
	}
	var out []models.UserAttachment
	for _, b := range blocks {
		bm := asMap(b)
		if bm == nil {
			continue
		}
		typ := strings.ToLower(firstString(bm, "type"))
		media := firstString(bm, "mime_type", "media_type")
		switch typ {
		case "image_url", "input_image", "image":
			if media == "" {
				media = dataURIMedia(firstString(asMap(bm["image_url"]), "url"))
			}
			out = append(out, models.UserAttachment{Kind: "image", MediaType: media})
		case "audio", "input_audio":
			out = append(out, models.UserAttachment{Kind: "audio", MediaType: media})
		case "video", "file", "document", "input_file":
			out = append(out, models.UserAttachment{Kind: "file", MediaType: media})
		}
	}
	return out
}

// dataURIMedia returns the media type of a `data:<type>;base64,…` URI.
func dataURIMedia(u string) string {
	if !strings.HasPrefix(u, "data:") {
		return ""
	}
	rest := u[len("data:"):]
	end := strings.IndexAny(rest, ";,")
	if end <= 0 {
		return ""
	}
	return rest[:end]
}

// mapTool resolves a dcode tool name onto the normalized action taxonomy and
// derives a display target from the arguments. The filesystem tools are the
// SDK's FsToolName set (ls read_file write_file edit_file delete glob grep
// execute); task / write_todos / ask_user / web_search / fetch_url /
// js_eval / compact_conversation are the harness tools. A name outside this
// set (an MCP tool is exported as `<server>_<tool>` with no marker, or a
// plugin tool) stays ActionUnknown with the raw name preserved.
func mapTool(name string, args map[string]any) (actionType, target string) {
	path := firstString(args, "file_path", "path")
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "execute":
		return models.ActionRunCommand, firstNonEmpty(firstString(args, "command"), name)
	case "js_eval":
		return models.ActionRunCommand, firstNonEmpty(firstLine(firstString(args, "code")), name)
	case "read_file":
		return models.ActionReadFile, firstNonEmpty(path, name)
	case "write_file":
		return models.ActionWriteFile, firstNonEmpty(path, name)
	case "edit_file", "delete":
		return models.ActionEditFile, firstNonEmpty(path, name)
	case "ls":
		return models.ActionSearchFiles, firstNonEmpty(path, name)
	case "glob":
		return models.ActionSearchFiles, firstNonEmpty(firstString(args, "pattern"), path, name)
	case "grep":
		return models.ActionSearchText, firstNonEmpty(firstString(args, "pattern"), name)
	case "web_search":
		return models.ActionWebSearch, firstNonEmpty(firstString(args, "query"), name)
	case "fetch_url":
		return models.ActionWebFetch, firstNonEmpty(firstString(args, "url"), name)
	case "task":
		return models.ActionSpawnSubagent, firstNonEmpty(firstString(args, "subagent_type"), firstString(args, "description"), name)
	case "write_todos":
		return models.ActionTodoUpdate, name
	case "ask_user":
		return models.ActionAskUser, name
	case "compact_conversation":
		return models.ActionContextCompacted, name
	}
	return models.ActionUnknown, firstNonEmpty(firstString(args, "command", "file_path", "path", "query", "url"), name)
}

// authoredBytes returns the byte length of code the model authored in a
// write / edit tool call.
func authoredBytes(name string, args map[string]any) int64 {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "write_file":
		return int64(len(firstString(args, "content")))
	case "edit_file":
		return int64(len(firstString(args, "new_string")))
	}
	return 0
}

// byteOrderMark is U+FEFF, built from its code point so no raw BOM byte
// sequence appears in this source file.
var byteOrderMark = string(rune(0xFEFF))

// cleanPromptText trims a prompt for display: surrounding whitespace and a
// leading UTF-8 byte-order mark. A prompt piped into `dcode -n` from
// Windows PowerShell arrives as "<U+FEFF>\n\n<text>" (grounded 2026-10-21
// on the Windows store), and U+FEFF is not whitespace to strings.TrimSpace.
func cleanPromptText(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasPrefix(s, byteOrderMark) {
		s = strings.TrimSpace(strings.TrimPrefix(s, byteOrderMark))
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func firstLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if t := strings.TrimSpace(line); t != "" {
			return t
		}
	}
	return ""
}

// truncate cuts s to at most n bytes without splitting a UTF-8 sequence.
func truncate(s string, n int) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// clockMs returns the milliseconds between two checkpoint-id clocks, or 0
// when either id carries no clock or the span is not positive.
func clockMs(fromID, toID string) int64 {
	from, ok1 := uuidTime(fromID)
	to, ok2 := uuidTime(toID)
	if !ok1 || !ok2 || !to.After(from) {
		return 0
	}
	return to.Sub(from).Milliseconds()
}
