package antigravity

import (
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/adapter"
	"github.com/marmutapp/superbased-observer/internal/git"
	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/platform/pathnorm"
	"github.com/marmutapp/superbased-observer/internal/platform/protowire"
)

// classify walks the decrypted plaintext and emits ToolEvent /
// TokenEvent records based on observed shape heuristics. The
// .proto schema is undocumented; we rely on:
//
//   - Length-delimited fields whose contents are >90% printable
//     UTF-8 and ≥8 bytes long: candidate message bodies.
//   - Varints with values 1.7e9..2e9 (seconds) or 1.7e12..2e12 (ms):
//     candidate timestamps.
//   - Length-delimited fields whose contents look like a tool name
//     (matches IsLikelyToolName) AND have a sibling JSON-shape
//     length-delimited field: candidate tool calls.
//   - Length-delimited fields containing "claude-", "gemini-",
//     "gpt-", or "auto" prefixes: candidate model identifiers.
//
// Heuristics ship behind warnings — every classification decision
// that backs off appends to res.Warnings, so observability is high
// when classifier choices need refinement.
func (a *Adapter) classify(path, conversationID string, plaintext []byte, idx *indexEntry) (adapter.ParseResult, []string, error) {
	var res adapter.ParseResult
	var warnings []string

	if conversationID == "" {
		conversationID = "antigravity-session-unknown"
	}

	// Walk top-level fields only. For each top-level length-delimited
	// payload, inner-walk to collect its fields as one group. This
	// gives us per-entry grouping even for repeated top-level fields
	// where every repetition shares the same wire-format path.
	var groups [][]protowire.Field
	topErr := walkTopLevelOnly(plaintext, func(top protowire.Field) error {
		if top.WireType != protowire.WireBytes {
			groups = append(groups, []protowire.Field{copyField(top)})
			return nil
		}
		var inner []protowire.Field
		_ = protowire.Walk(top.Bytes, func(f protowire.Field) error {
			inner = append(inner, copyField(f))
			return nil
		})
		if len(inner) == 0 {
			groups = append(groups, []protowire.Field{copyField(top)})
		} else {
			groups = append(groups, inner)
		}
		return nil
	})
	if topErr != nil {
		warnings = append(warnings, fmt.Sprintf("antigravity.classify: walk err: %v (partial result)", topErr))
	}

	// Classify per group.
	startTime := time.Now().UTC()
	if idx != nil && idx.created.After(time.Time{}) {
		startTime = idx.created
	}

	projectRoot, gitRemote, projectIdentity := "[antigravity]", "", git.Identity{}
	if idx != nil && idx.workspaceURI != "" {
		projectRoot, gitRemote, projectIdentity = decodeFileURIToRoot(idx.workspaceURI)
	}

	sessionID := conversationID
	turnIdx := 0
	seenSourceIDs := map[string]bool{}

	for _, group := range groups {
		text, role, ts, model, toolName, toolArgs := digestGroup(group)
		if ts.IsZero() {
			ts = startTime.Add(time.Duration(turnIdx) * time.Millisecond)
		}
		if text == "" && toolName == "" {
			continue
		}

		// Tool call.
		if toolName != "" {
			eventID := stableSourceID(seenSourceIDs, "tool", path, conversationID, toolName, contentHash(toolArgs))
			res.ToolEvents = append(res.ToolEvents, models.ToolEvent{
				SourceFile:    path,
				SourceEventID: eventID,
				SessionID:     sessionID,
				ProjectRoot:   projectRoot,
				GitRemote:     gitRemote,
				Timestamp:     ts,
				Model:         coalesce(model, idxModel(idx)),
				Tool:          models.ToolAntigravity,
				ActionType:    mapToolName(toolName),
				Target:        truncate(targetFromToolArgs(toolArgs, toolName), 200),
				Success:       true,
				RawToolName:   toolName,
				RawToolInput:  a.scrubber.RawJSON([]byte(toolArgs)),
				MessageID:     "antigravity:" + conversationID + ":" + eventID,
			})
			turnIdx++
			continue
		}

		// Message text. Heuristic role classification:
		//   role == 0 / no role var → user (user prompts are typically
		//     the first text in a conversation).
		//   role == 1 → model.
		//   role == 2 / >= 2 → tool result / system.
		actionType := models.ActionUserPrompt
		if role == 1 {
			// The model's spoken response — use the dedicated
			// assistant_message type (was task_complete) for vocabulary
			// consistency across adapters. Display-neutral: RawToolName
			// stays "message.model" (this OSCrypt-decrypt fallback path
			// is distinct from the structured.assistant_text enrichment
			// path that drives the dashboard's assistant-text surface,
			// so the name is left untouched to avoid double-surfacing).
			actionType = models.ActionAssistantMessage
		}
		if role >= 2 {
			actionType = models.ActionUnknown
		}

		eventID := stableSourceID(seenSourceIDs, "msg", path, conversationID, fmt.Sprintf("%d", turnIdx), contentHash(text))
		ev := models.ToolEvent{
			SourceFile:    path,
			SourceEventID: eventID,
			SessionID:     sessionID,
			ProjectRoot:   projectRoot,
			GitRemote:     gitRemote,
			Timestamp:     ts,
			Model:         coalesce(model, idxModel(idx)),
			Tool:          models.ToolAntigravity,
			ActionType:    actionType,
			Target:        truncate(text, 200),
			Success:       true,
			RawToolName:   "message." + roleName(role),
			RawToolInput:  a.scrubber.String(text),
			MessageID:     "antigravity:" + conversationID + ":" + eventID,
		}
		if actionType == models.ActionAssistantMessage {
			ev.ToolOutput = a.scrubber.String(text)
		}
		res.ToolEvents = append(res.ToolEvents, ev)
		turnIdx++
	}

	// Token rows: scan for varints that look like token counts in
	// magnitude and proximity (input + output adjacent in the same
	// group). Conservative — most groups won't have token data; the
	// ones that do typically expose 2–4 varints with magnitudes 100..1e6.
	for _, group := range groups {
		input, output, cacheRead, reasoning, model, ts := digestTokenRow(group)
		if input == 0 && output == 0 && cacheRead == 0 && reasoning == 0 {
			continue
		}
		if ts.IsZero() {
			ts = startTime
		}
		eventID := stableSourceID(seenSourceIDs, "usage", path, conversationID, fmt.Sprintf("%d-%d", input, output))
		res.TokenEvents = append(res.TokenEvents, models.TokenEvent{
			SourceFile:      path,
			SourceEventID:   eventID,
			SessionID:       sessionID,
			ProjectRoot:     projectRoot,
			GitRemote:       gitRemote,
			Timestamp:       ts,
			Tool:            models.ToolAntigravity,
			Model:           coalesce(model, idxModel(idx)),
			InputTokens:     input,
			OutputTokens:    output,
			CacheReadTokens: cacheRead,
			ReasoningTokens: reasoning,
			Source:          models.TokenSourceJSONL,
			Reliability:     models.ReliabilityUnreliable, // upgrade to approximate after live smoke
			MessageID:       "antigravity:" + conversationID + ":" + eventID,
		})
	}

	if len(res.ToolEvents) == 0 && len(res.TokenEvents) == 0 {
		warnings = append(warnings, "antigravity.classify: walked plaintext yielded no events; the .proto shape may have drifted")
	}
	adapter.ApplyProjectIdentity(&res, projectIdentity)
	return res, warnings, nil
}

// walkTopLevelOnly invokes yield for each top-level field in buf
// (depth 0) without recursing into nested submessages. The caller
// can drive recursion explicitly when desired.
func walkTopLevelOnly(buf []byte, yield func(protowire.Field) error) error {
	pos := 0
	for pos < len(buf) {
		tag, n, err := decodeVarint(buf[pos:])
		if err != nil {
			return err
		}
		pos += n
		fn := int(tag >> 3)
		wt := protowire.WireType(tag & 0x07)
		if fn <= 0 {
			return fmt.Errorf("invalid field number %d", fn)
		}
		var f protowire.Field
		f.Path = []int{fn}
		f.Depth = 0
		f.FieldNumber = fn
		f.WireType = wt
		switch wt {
		case protowire.WireVarint:
			v, n, err := decodeVarint(buf[pos:])
			if err != nil {
				return err
			}
			pos += n
			f.Varint = v
		case protowire.WireFixed64:
			if pos+8 > len(buf) {
				return fmt.Errorf("truncated fixed64")
			}
			f.Bytes = buf[pos : pos+8]
			pos += 8
		case protowire.WireFixed32:
			if pos+4 > len(buf) {
				return fmt.Errorf("truncated fixed32")
			}
			f.Bytes = buf[pos : pos+4]
			pos += 4
		case protowire.WireBytes:
			length, n, err := decodeVarint(buf[pos:])
			if err != nil {
				return err
			}
			pos += n
			if uint64(pos)+length > uint64(len(buf)) {
				return fmt.Errorf("truncated bytes")
			}
			f.Bytes = buf[pos : pos+int(length)]
			pos += int(length)
		default:
			return fmt.Errorf("invalid wire type %d", wt)
		}
		if err := yield(f); err != nil {
			return err
		}
	}
	return nil
}

// decodeVarint mirrors the protowire helper for the local top-level
// walker (the package-level one isn't exported).
func decodeVarint(b []byte) (uint64, int, error) {
	var result uint64
	var shift uint
	for i := 0; i < len(b); i++ {
		bb := b[i]
		if shift >= 64 {
			return 0, 0, fmt.Errorf("varint overflow")
		}
		result |= uint64(bb&0x7f) << shift
		if bb&0x80 == 0 {
			return result, i + 1, nil
		}
		shift += 7
	}
	return 0, 0, fmt.Errorf("truncated varint")
}

// copyField deep-copies a protowire.Field — Walk's slice references
// alias into the input buffer; classify needs stable copies for
// later inspection.
func copyField(f protowire.Field) protowire.Field {
	return protowire.Field{
		Path:        append([]int(nil), f.Path...),
		Depth:       f.Depth,
		FieldNumber: f.FieldNumber,
		WireType:    f.WireType,
		Bytes:       append([]byte(nil), f.Bytes...),
		Varint:      f.Varint,
	}
}

// digestGroup extracts the highest-confidence text body, role enum,
// timestamp, model identifier, and tool-call shape from a group.
// Heuristic — every value may legitimately be empty.
func digestGroup(fields []protowire.Field) (text string, role uint64, ts time.Time, model string, toolName string, toolArgs string) {
	textCandidates := []string{}
	for _, f := range fields {
		switch f.WireType {
		case protowire.WireVarint:
			if role == 0 && f.Varint <= 4 {
				role = f.Varint
			}
			if protowire.IsLikelyUnixTimestamp(f.Varint) && ts.IsZero() {
				ts = parseUnixTimestamp(f.Varint)
			}
		case protowire.WireFixed64:
			if protowire.IsLikelyUnixTimestamp(f.Varint) && ts.IsZero() {
				ts = parseUnixTimestamp(f.Varint)
			}
		case protowire.WireBytes:
			s := string(f.Bytes)
			if isModelIdentifier(s) && model == "" {
				model = s
				continue
			}
			if protowire.IsLikelyToolName(s) && toolName == "" {
				toolName = s
				continue
			}
			if looksLikeJSONArgs(s) && toolArgs == "" {
				toolArgs = s
				continue
			}
			if protowire.IsLikelyText(f.Bytes) {
				textCandidates = append(textCandidates, s)
			}
		}
	}
	// Pick the longest text candidate as the message body.
	for _, t := range textCandidates {
		if len(t) > len(text) {
			text = t
		}
	}
	return text, role, ts, model, toolName, toolArgs
}

// digestTokenRow looks for "this group contains 2..4 varints whose
// magnitudes are plausible token counts" and returns them.
func digestTokenRow(fields []protowire.Field) (input, output, cacheRead, reasoning int64, model string, ts time.Time) {
	var counts []int64
	for _, f := range fields {
		switch f.WireType {
		case protowire.WireVarint:
			if protowire.IsLikelyUnixTimestamp(f.Varint) {
				if ts.IsZero() {
					ts = parseUnixTimestamp(f.Varint)
				}
				continue
			}
			if f.Varint >= 1 && f.Varint <= 5_000_000 {
				counts = append(counts, int64(f.Varint))
			}
		case protowire.WireBytes:
			s := string(f.Bytes)
			if isModelIdentifier(s) && model == "" {
				model = s
			}
		}
	}
	if len(counts) < 2 {
		return 0, 0, 0, 0, "", time.Time{}
	}
	// Conservative mapping: largest = input, second largest = output.
	// Real proto field-numbers would let us do this exactly; we don't
	// have them. Token rows are tagged Reliability=unreliable so
	// downstream consumers know to treat with skepticism.
	sorted := append([]int64(nil), counts...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] > sorted[j] })
	if len(sorted) >= 1 {
		input = sorted[0]
	}
	if len(sorted) >= 2 {
		output = sorted[1]
	}
	if len(sorted) >= 3 {
		cacheRead = sorted[2]
	}
	if len(sorted) >= 4 {
		reasoning = sorted[3]
	}
	return input, output, cacheRead, reasoning, model, ts
}

func parseUnixTimestamp(v uint64) time.Time {
	if v >= 1_700_000_000_000 {
		return time.UnixMilli(int64(v)).UTC()
	}
	if v >= 1_700_000_000 {
		return time.Unix(int64(v), 0).UTC()
	}
	return time.Time{}
}

func isModelIdentifier(s string) bool {
	if len(s) > 80 {
		return false
	}
	if strings.EqualFold(s, "auto") {
		return true
	}
	if len(s) < 5 {
		return false
	}
	lower := strings.ToLower(s)
	for _, prefix := range []string{
		"claude-",
		"gemini-",
		"gpt-",
		"capi-", // Antigravity's internal proprietary models
		"grok-",
	} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return strings.HasSuffix(lower, "-auto")
}

func looksLikeJSONArgs(s string) bool {
	t := strings.TrimSpace(s)
	if len(t) < 2 {
		return false
	}
	return (t[0] == '{' && t[len(t)-1] == '}') || (t[0] == '[' && t[len(t)-1] == ']')
}

func mapToolName(name string) string {
	key := strings.ToLower(strings.TrimSpace(name))
	key = strings.ReplaceAll(key, "_", "")
	key = strings.ReplaceAll(key, "-", "")
	switch key {
	case "readfile", "read", "viewfile", "view", "cat":
		return models.ActionReadFile
	// "writetofile" / "replacefilecontent" / "listdir" / "findbyname" are
	// the desktop IDE's tool_calls[].name spellings, live-grounded
	// 2026-09-03 from brain/<uuid>/.system_generated/logs/transcript.jsonl
	// (transcript.go). Every case here needs a matching row in
	// internal/tooltax/table.go::antigravityRows (conformance-pinned).
	case "writefile", "write", "createfile", "create", "writetofile":
		return models.ActionWriteFile
	case "replace", "edit", "editfile", "applypatch", "patch", "replacefilecontent":
		return models.ActionEditFile
	case "runshellcommand", "shell", "bash", "exec", "execute", "runcommand", "run",
		"powershell", "pwsh", "cmd", "cmdexe":
		return models.ActionRunCommand
	case "googlewebsearch", "websearch", "search":
		return models.ActionWebSearch
	case "webfetch", "fetch", "fetchurl", "fetchwebpage":
		return models.ActionWebFetch
	case "grep", "searchtext", "findtext":
		return models.ActionSearchText
	case "glob", "findfiles", "filesearch", "ls", "listfiles", "listdir", "findbyname":
		return models.ActionSearchFiles
	default:
		if strings.HasPrefix(key, "mcp") || strings.Contains(name, "__") {
			return models.ActionMCPCall
		}
		return models.ActionUnknown
	}
}

func targetFromToolArgs(args, fallback string) string {
	if args == "" {
		return fallback
	}
	// Cheap pattern match without full JSON unmarshaling: look for
	// "path": "..." or "command": "..." inside the args body.
	for _, key := range []string{"absolute_path", "absolutePath", "path", "file_path", "filePath", "file", "command", "cmd", "url", "query"} {
		needle := `"` + key + `"`
		idx := strings.Index(args, needle)
		if idx < 0 {
			continue
		}
		rest := args[idx+len(needle):]
		colon := strings.IndexByte(rest, ':')
		if colon < 0 {
			continue
		}
		rest = rest[colon+1:]
		open := strings.IndexByte(rest, '"')
		if open < 0 {
			continue
		}
		rest = rest[open+1:]
		close := strings.IndexByte(rest, '"')
		if close < 0 {
			continue
		}
		return rest[:close]
	}
	return fallback
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

func coalesce(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func roleName(role uint64) string {
	switch role {
	case 0:
		return "user"
	case 1:
		return "model"
	case 2:
		return "tool"
	default:
		return fmt.Sprintf("role%d", role)
	}
}

func idxModel(idx *indexEntry) string {
	if idx == nil {
		return ""
	}
	return idx.modelHint
}

// stableSourceID generates an event ID that's both deterministic
// across re-parses and unique within a single classify pass. Adapter
// downstream guarantees idempotence via (source_file, source_event_id),
// so re-parses should produce the same IDs for the same content.
func stableSourceID(seen map[string]bool, kind, path, sessionID, key string, extra ...string) string {
	parts := append([]string{kind, path, sessionID, key}, extra...)
	id := contentHash(parts...)
	candidate := kind + ":" + id
	for i := 0; seen[candidate]; i++ {
		candidate = kind + ":" + id + fmt.Sprintf("-%d", i+1)
	}
	seen[candidate] = true
	return candidate
}

// decodeFileURIToRoot accepts file:// or vscode-remote:// URIs (and
// bare paths), returning a usable project root via internal/git.
//
// Handles URL-encoded characters (Antigravity emits `file:///c%3A/foo`
// for Windows drives), the `/C:/...` drive-prefix form, and (on WSL2)
// translates Windows-style paths to their `/mnt/c/...` equivalents
// so git.Resolve can walk to the real worktree. If the URI points at
// a file (has an extension), strips to the parent directory before
// resolving — Antigravity's index sometimes records a recently-edited
// file as the workspace URI rather than the workspace folder itself.
// decodeFileURIToRoot translates a workspace URI captured from
// Antigravity's trajectory into a project-root path the observer can
// resolve. Handles two scheme families:
//
//   - file://… — standard file URIs. Routed through pathnorm so the
//     full pipeline (percent-decoding, cross-mount translation,
//     surrounding-quote stripping, etc.) applies.
//   - vscode-remote://… — Antigravity's remote-workspace scheme.
//     The path component looks like `/d:/programsx/foo` after stripping
//     the scheme; pathnorm.Normalize handles the leading-slash drive
//     stripping that decodeFileURIPath does inside file://, but the
//     scheme has to be removed by the caller because pathnorm doesn't
//     model `vscode-remote://`.
//
// After path canonicalisation, trailing-filename → parent-dir rewrite
// (Antigravity sometimes records a recently-edited file as the
// workspace URI rather than the workspace folder itself) and
// git.Resolve walks happen as before.
func decodeFileURIToRoot(uri string) (root, remote string, id git.Identity) {
	root = strings.TrimSpace(uri)
	if root == "" {
		return "[antigravity]", "", git.Identity{}
	}
	// vscode-remote:// is antigravity-specific; pathnorm doesn't
	// model it, so strip the scheme + percent-decode here and let
	// pathnorm classify the inner path.
	if strings.HasPrefix(root, "vscode-remote://") {
		root = strings.TrimPrefix(root, "vscode-remote://")
		if decoded, err := url.PathUnescape(root); err == nil {
			root = decoded
		}
		// `/d:/foo` → `d:/foo` so pathnorm's Windows-drive layer fires.
		if strings.HasPrefix(root, "/") && len(root) >= 3 && root[2] == ':' &&
			((root[1] >= 'A' && root[1] <= 'Z') || (root[1] >= 'a' && root[1] <= 'z')) {
			root = root[1:]
		}
	}
	// pathnorm handles file:// URIs natively, plus percent-decoding,
	// cross-mount translation, surrounding quotes, extended-length
	// prefix, and the rest of the format pipeline. Non-URI inputs
	// (already-decoded paths from the vscode-remote branch above)
	// pass through the remaining layers.
	root = pathnorm.Normalize(root)
	if root == "" {
		return "[antigravity]", "", git.Identity{}
	}
	if ext := filepath.Ext(root); ext != "" {
		if dir := filepath.Dir(root); dir != "" && dir != "." && dir != "/" {
			root = dir
		}
	}
	if identity, err := git.ResolveIdentity(root, git.IdentityOptions{}); err == nil {
		// identity.Remote is already NormalizeRemote'd by ResolveIdentity.
		return identity.Root, identity.Remote, identity
	}
	return root, "", git.Identity{}
}
