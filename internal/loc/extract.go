package loc

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/codexpatch"
)

// truncationMarker is the suffix internal/scrub appends when it caps an
// oversized raw_tool_input. A capped input is not a shorter edit, it is a
// PARTIAL one, so the ladder refuses to count it rather than reporting a
// number that is silently short.
const truncationMarker = "…[truncated]"

// Extract walks the input-shape ladder over one edit/write action's
// already-scrubbed raw_tool_input and returns one FileStats per file the
// action touched.
//
// The ladder is a TABLE (see extractShapes), walked top-down, one row per
// shape observed on a live corpus; each row has a golden test. Adding a
// new adapter shape is adding a row, never extending a conditional
// (CLAUDE.md rule #5).
//
// Extract never errors: an input it cannot place yields one FileStats with
// Shape ShapeUnrecognized, zero counts and ConfidenceLow, so the file is
// still recorded as touched and the row's own Shape says why it carries no
// numbers. It never panics, never allocates unboundedly, and never returns
// file content.
//
// Ordering matters and is load-bearing:
//
//  1. A truncated payload is rejected FIRST — it may still look like every
//     other shape and would be counted short.
//  2. JSON shapes are tried before text shapes, and within JSON the codex
//     `changes` map is tried before the key-pair shapes, because its top
//     level is paths rather than known keys.
//  3. The `edits[]` array is tried before `old_string/new_string`, because
//     a MultiEdit payload carries `file_path` at the top level too.
//  4. Path-only is tried before plain-content, because a cursor
//     afterFileEdit row's whole body is a path that would otherwise be
//     counted as a one-line file.
func Extract(in Input) []FileStats {
	raw := in.RawToolInput
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if strings.HasSuffix(raw, truncationMarker) {
		return []FileStats{unparsed(in.Target, ShapeTruncated)}
	}

	var obj map[string]json.RawMessage
	if trimmed := strings.TrimSpace(raw); strings.HasPrefix(trimmed, "{") {
		if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
			obj = nil
		}
	}

	for _, rule := range extractShapes {
		if !rule.match(in, raw, obj) {
			continue
		}
		if out := rule.parse(in, raw, obj); len(out) > 0 {
			return out
		}
	}
	if obj != nil {
		return []FileStats{unparsed(in.Target, ShapeUnrecognized)}
	}
	return []FileStats{unparsed(in.Target, ShapeUnrecognized)}
}

// extractShapeRule is one row of the input-shape ladder. match decides
// whether the row applies; parse produces the rows. A parse that yields
// nothing falls through to the next rule, so a match predicate may be
// cheap and optimistic.
type extractShapeRule struct {
	name  Shape
	match func(in Input, raw string, obj map[string]json.RawMessage) bool
	parse func(in Input, raw string, obj map[string]json.RawMessage) []FileStats
}

// extractShapes is the ladder, in evaluation order. See Extract's doc
// comment for why the order is what it is.
var extractShapes = []extractShapeRule{
	// ibm-bob's exact change record FIRST: the same payload also carries
	// the call's own arguments (search/replace, content, ...), which the
	// later rows would only estimate from.
	{ShapeBobChanges, matchJSONKey(BobChangesKey), parseBobChanges},
	{ShapeCodexChanges, matchCodexChanges, parseCodexChanges},
	{ShapeEdits, matchJSONKey("edits"), parseEditsArray},
	{ShapeAnchorEdits, matchJSONKey("files"), parseAnchorEdits},
	{ShapeASTReplace, matchJSONAll("operation", "targets"), parseASTTargets},
	{ShapeOldNewString, matchJSONAny("old_string", "new_string"), parseKeyPair("old_string", "new_string")},
	{ShapeOldNewCamel, matchJSONAny("oldString", "newString"), parseKeyPair("oldString", "newString")},
	{ShapeOldNewSnakeAbb, matchJSONAny("old_str", "new_str"), parseKeyPair("old_str", "new_str")},
	{ShapeNewSource, matchJSONAny("new_source", "old_source"), parseKeyPair("old_source", "new_source")},
	{ShapeOldNewText, matchJSONAny("oldText", "newText"), parseKeyPair("oldText", "newText")},
	{ShapeSearchReplKeys, matchJSONAll("search", "replace"), parseKeyPair("search", "replace")},
	// insert_content BEFORE content: its `content` is an inserted
	// fragment, never the file's whole after-image.
	{ShapeInsertContent, matchJSONAll("line", "content"), parseInsertContent},
	{ShapeContent, matchJSONKey("content"), parseContentKey},
	{ShapeContents, matchJSONKey("contents"), parseContentsKey},
	{ShapeFileText, matchJSONKey("file_text"), parseFileTextKey},
	{ShapeSearchReplace, matchJSONKey("diff"), parseSearchReplaceDiff},
	{ShapeSearchReplace, matchJSONKey("blocks"), parseSearchReplaceBlocksKey},
	{ShapeWrappedPatch, matchJSONAny("patch", "input"), parseWrappedPatchKey},
	{ShapePatchDiff, matchJSONKey("patch"), parsePatchDiffKey},
	{ShapeWrappedPatch, matchJSONStringBeginPatch, parseJSONStringBeginPatch},
	{ShapeCodexPatch, matchBeginPatch, parseBeginPatchText},
	{ShapeCodexJS, matchCodexJS, parseCodexJS},
	{ShapePathOnly, matchPathOnly, parsePathOnly},
	{ShapePlainContent, matchPlainContent, parsePlainContent},
}

// matchJSONKey builds a predicate for "this JSON object has this key".
func matchJSONKey(key string) func(Input, string, map[string]json.RawMessage) bool {
	return func(_ Input, _ string, obj map[string]json.RawMessage) bool {
		_, ok := obj[key]
		return ok
	}
}

// matchJSONAll builds a predicate for "this JSON object has every one of
// these keys". Used where a single key is too generic to identify the
// shape on its own (ibm-bob's `search`, `line`).
func matchJSONAll(keys ...string) func(Input, string, map[string]json.RawMessage) bool {
	return func(_ Input, _ string, obj map[string]json.RawMessage) bool {
		if obj == nil {
			return false
		}
		for _, k := range keys {
			if _, ok := obj[k]; !ok {
				return false
			}
		}
		return true
	}
}

// matchJSONAny builds a predicate for "this JSON object has at least one
// of these keys". An edit that inserts at the top of a file legitimately
// carries an empty old_string, and some adapters omit the empty side
// entirely, so requiring both keys would drop real edits.
func matchJSONAny(keys ...string) func(Input, string, map[string]json.RawMessage) bool {
	return func(_ Input, _ string, obj map[string]json.RawMessage) bool {
		for _, k := range keys {
			if _, ok := obj[k]; ok {
				return true
			}
		}
		return false
	}
}

// pathKeys are the JSON keys adapters use for the edited file's path, in
// preference order. The action's own Target is the fallback.
var pathKeys = []string{
	"file_path", "filePath", "notebook_path", "notebookPath",
	"path", "target_file", "absolute_path", "file",
}

// pathFromJSON resolves the edited file's path from a payload, falling
// back to the action's target.
func pathFromJSON(in Input, obj map[string]json.RawMessage) string {
	for _, k := range pathKeys {
		if raw, ok := obj[k]; ok {
			var s string
			if err := json.Unmarshal(raw, &s); err == nil && s != "" {
				return s
			}
		}
	}
	return in.Target
}

// jsonString decodes a JSON string field, returning "" for an absent,
// null or non-string value.
func jsonString(obj map[string]json.RawMessage, key string) string {
	raw, ok := obj[key]
	if !ok {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

// parseKeyPair builds a parser for the two-key before/after shapes:
// old_string/new_string (claude-code, gemini, cowork, command-code),
// oldString/newString (opencode), old_str/new_str (copilot-cli),
// old_source/new_source (NotebookEdit — whose old side is usually absent,
// which is exactly the "insert at top" case an empty before-image covers).
func parseKeyPair(oldKey, newKey string) func(Input, string, map[string]json.RawMessage) []FileStats {
	return func(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
		path := pathFromJSON(in, obj)
		fs := editStats(path, jsonString(obj, oldKey), jsonString(obj, newKey))
		fs.Shape = shapeForKeyPair(oldKey)
		return []FileStats{fs}
	}
}

// shapeForKeyPair names the ladder row a key pair belongs to. It is a
// table rather than a switch so a new pair is one line.
var keyPairShapes = map[string]Shape{
	"old_string": ShapeOldNewString,
	"oldString":  ShapeOldNewCamel,
	"old_str":    ShapeOldNewSnakeAbb,
	"old_source": ShapeNewSource,
	"oldText":    ShapeOldNewText,
	"search":     ShapeSearchReplKeys,
}

// shapeForKeyPair maps a before-key to its Shape, defaulting to the
// dominant claude-code shape.
func shapeForKeyPair(oldKey string) Shape {
	if s, ok := keyPairShapes[oldKey]; ok {
		return s
	}
	return ShapeOldNewString
}

// multiEdit is one entry of a MultiEdit payload's edits array. Both key
// spellings are accepted because the same array shape appears under both
// the snake_case and camelCase adapters.
//
// The pi-mono family (pi, kimchi) spells the pair oldText/newText:
// `{"path","edits":[{"oldText","newText"}]}` (live: kimchi
// testdata/kimchi/session-wsl.jsonl, pi's own Windows store 2026-10-21).
// Before loc.Version 3 that spelling decoded to two empty sides and the
// edit counted ZERO lines silently.
type multiEdit struct {
	OldString string `json:"old_string"`
	NewString string `json:"new_string"`
	OldAlt    string `json:"oldString"`
	NewAlt    string `json:"newString"`
	OldText   string `json:"oldText"`
	NewText   string `json:"newText"`
}

// firstNonEmpty returns the first non-empty string.
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// old returns the before-image of one MultiEdit entry.
func (m multiEdit) old() string {
	return firstNonEmpty(m.OldString, m.OldAlt, m.OldText)
}

// new returns the after-image of one MultiEdit entry.
func (m multiEdit) after() string {
	return firstNonEmpty(m.NewString, m.NewAlt, m.NewText)
}

// parseEditsArray handles MultiEdit: several before/after pairs against
// ONE file. Each pair is diffed on its own — they are separate fragments
// of the file, and concatenating them would invent adjacency that does
// not exist — and the Stats are summed into a single row for the file.
func parseEditsArray(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	var edits []multiEdit
	if err := json.Unmarshal(obj["edits"], &edits); err != nil || len(edits) == 0 {
		return nil
	}
	path := pathFromJSON(in, obj)
	lang, cat := Language(path)
	out := FileStats{
		Path:       path,
		Lang:       lang,
		Category:   cat,
		Shape:      ShapeEdits,
		Confidence: ConfidenceHigh,
	}
	var digest strings.Builder
	for _, e := range edits {
		part := editStats(path, e.old(), e.after())
		out.Stats.Add(part.Stats)
		out.Confidence = out.Confidence.Min(part.Confidence)
		digest.WriteString(normalizeBody(e.old()))
		digest.WriteString("\x00")
		digest.WriteString(normalizeBody(e.after()))
		digest.WriteString("\x00")
	}
	out.InputDigest = digestOf(digest.String())
	return []FileStats{out}
}

// parseContentKey handles a whole-file Write: the payload carries the
// complete after-image and no before-image at all.
func parseContentKey(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	path := pathFromJSON(in, obj)
	fs := wholeContentStats(in, path, jsonString(obj, "content"))
	fs.Shape = ShapeContent
	return []FileStats{fs}
}

// parseFileTextKey handles goose's developer-extension `write`:
// `{"command":"write","path":…,"file_text":…}`. The body is the complete
// after-image, exactly like a claude-code Write's `content`, so it lands
// on the same whole-content path and gets the same before-image
// reconstruction (review finding L2).
func parseFileTextKey(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	path := pathFromJSON(in, obj)
	fs := wholeContentStats(in, path, jsonString(obj, "file_text"))
	fs.Shape = ShapeFileText
	return []FileStats{fs}
}

// parseContentsKey handles autohand's `write_file`:
// `{"path":…,"contents":…}` (live, testdata/autohand). The body is the
// complete after-image, the same as a claude-code Write's `content`.
func parseContentsKey(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	path := pathFromJSON(in, obj)
	fs := wholeContentStats(in, path, jsonString(obj, "contents"))
	fs.Shape = ShapeContents
	return []FileStats{fs}
}

// parseInsertContent handles ibm-bob's `insert_content`:
// `{"path":…,"line":N,"content":…}` (bobshell 2.0.6 tool definition:
// "adding new lines of content into a file without modifying existing
// content"; line 0 appends). The body is an inserted FRAGMENT, so every
// line is an addition and nothing is removed: it must never reach the
// whole-file `content` row, which would treat the fragment as the file's
// after-image (an overwrite of everything else).
func parseInsertContent(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	content := jsonString(obj, "content")
	if content == "" {
		return nil
	}
	path := pathFromJSON(in, obj)
	fs := addedContentStats(path, content)
	fs.Shape = ShapeInsertContent
	return []FileStats{fs}
}

// parseSearchReplaceBlocksKey handles autohand's `search_replace`:
// `{"path":…,"blocks":"<<<<<<< SEARCH…=======…>>>>>>> REPLACE"}` (live,
// testdata/autohand). Same block grammar as cline's `diff`, different key.
func parseSearchReplaceBlocksKey(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	return searchReplaceStats(in, obj, jsonString(obj, "blocks"))
}

// beginPatchPrefix opens a codex-style apply_patch envelope.
const beginPatchPrefix = "*** Begin Patch"

// parseWrappedPatchKey handles an apply_patch envelope wrapped in a JSON
// object: vtcode stores its apply_patch arguments as
// `{"input":"*** Begin Patch…"}` or `{"patch":"*** Begin Patch…"}`
// (internal/adapter/vtcode/tools.go patchText). Only a value that IS an
// envelope matches; a `patch` holding a unified diff falls through to
// parsePatchDiffKey, and a generic `input` falls through entirely.
func parseWrappedPatchKey(_ Input, _ string, obj map[string]json.RawMessage) []FileStats {
	for _, k := range []string{"input", "patch"} {
		if s := jsonString(obj, k); strings.HasPrefix(strings.TrimSpace(s), beginPatchPrefix) {
			return parseBeginPatch(s, ShapeWrappedPatch)
		}
	}
	return nil
}

// parsePatchDiffKey handles autohand's `apply_patch`:
// `{"path":…,"patch":"<unified diff>"}` (autohand-cli dist tool
// definition "Apply a unified diff to a file", required [path, patch]).
// The diff is per-file, so the path comes from the payload.
func parsePatchDiffKey(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	patch := jsonString(obj, "patch")
	if strings.TrimSpace(patch) == "" {
		return nil
	}
	fs := unifiedDiffStats(pathFromJSON(in, obj), patch)
	fs.Shape = ShapePatchDiff
	return []FileStats{fs}
}

// matchJSONStringBeginPatch recognises an apply_patch envelope stored as
// a JSON STRING literal (vtcode's bare-string apply_patch arguments).
// Without this row the quoted string fell to plain_content and was
// counted as a whole-file write of the patch text — a wrong number, not a
// missing one.
func matchJSONStringBeginPatch(_ Input, raw string, obj map[string]json.RawMessage) bool {
	if obj != nil {
		return false
	}
	return strings.HasPrefix(strings.TrimSpace(raw), `"`+beginPatchPrefix)
}

// parseJSONStringBeginPatch decodes the string literal and counts the
// envelope inside it.
func parseJSONStringBeginPatch(_ Input, raw string, _ map[string]json.RawMessage) []FileStats {
	var s string
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &s); err != nil {
		return nil
	}
	return parseBeginPatch(s, ShapeWrappedPatch)
}

// anchorDelimiter separates a dirac line anchor's opaque ID from the
// exact current source line it names ("Apple§first line";
// dirac-cli shared/utils/line-hashing.ts ANCHOR_DELIMITER).
const anchorDelimiter = "§"

// anchorFile / anchorEdit are dirac `edit_file`'s argument shape:
// `{"files":[{"path":…,"edits":[{"edit_type":"replace"|"insert_after"|
// "insert_before","anchor":"ID§line","end_anchor":"ID§line"|null,
// "text":…}]}]}` (live Windows task 1792584662340; dirac-cli
// EditFileTool.ts).
type anchorFile struct {
	Path  string       `json:"path"`
	Edits []anchorEdit `json:"edits"`
}

type anchorEdit struct {
	EditType  string  `json:"edit_type"`
	Anchor    string  `json:"anchor"`
	EndAnchor *string `json:"end_anchor"`
	Text      string  `json:"text"`
}

// anchorLine returns the source line an anchor names (the text after the
// delimiter); an anchor with no delimiter is taken verbatim.
func anchorLine(anchor string) string {
	if i := strings.Index(anchor, anchorDelimiter); i >= 0 {
		return anchor[i+len(anchorDelimiter):]
	}
	return anchor
}

// anchorEditStats measures one dirac anchor edit. Inserts are pure
// additions (exact). A replace names only its first and last line, so a
// one-line replace (anchor == end_anchor) is exact, while a multi-line
// replace knows its endpoints but not the lines between them: it is
// measured over the two known lines and marked ConfidenceLow so the UI
// can say the removed side is partial. An unknown edit_type yields
// nothing.
func anchorEditStats(path string, e anchorEdit) (FileStats, bool) {
	switch e.EditType {
	case "insert_after", "insert_before":
		return editStats(path, "", e.Text), true
	case "replace":
		start := anchorLine(e.Anchor)
		if e.EndAnchor == nil || *e.EndAnchor == "" || *e.EndAnchor == e.Anchor {
			return editStats(path, start, e.Text), true
		}
		fs := editStats(path, start+"\n"+anchorLine(*e.EndAnchor), e.Text)
		fs.Confidence = ConfidenceLow
		return fs, true
	}
	return FileStats{}, false
}

// parseAnchorEdits counts dirac `edit_file`, one row per file, summing
// its edits the way parseEditsArray sums a MultiEdit.
func parseAnchorEdits(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	var files []anchorFile
	if err := json.Unmarshal(obj["files"], &files); err != nil || len(files) == 0 {
		return nil
	}
	byPath := map[string]*FileStats{}
	digests := map[string]*strings.Builder{}
	for _, f := range files {
		if len(f.Edits) == 0 {
			continue
		}
		path := f.Path
		if path == "" {
			path = in.Target
		}
		row, ok := byPath[path]
		if !ok {
			lang, cat := Language(path)
			row = &FileStats{Path: path, Lang: lang, Category: cat, Shape: ShapeAnchorEdits, Confidence: ConfidenceHigh}
			byPath[path] = row
			digests[path] = &strings.Builder{}
		}
		for _, e := range f.Edits {
			part, ok := anchorEditStats(path, e)
			if !ok {
				row.Confidence = ConfidenceLow
				continue
			}
			row.Stats.Add(part.Stats)
			row.Confidence = row.Confidence.Min(part.Confidence)
			d := digests[path]
			d.WriteString(e.EditType + "\x00" + normalizeBody(anchorLine(e.Anchor)) + "\x00")
			if e.EndAnchor != nil {
				d.WriteString(normalizeBody(anchorLine(*e.EndAnchor)))
			}
			d.WriteString("\x00" + normalizeBody(e.Text) + "\x00")
		}
	}
	if len(byPath) == 0 {
		return nil
	}
	out := make([]FileStats, 0, len(byPath))
	for p, row := range byPath {
		row.InputDigest = digestOf(digests[p].String())
		out = append(out, *row)
	}
	sortFileStats(out)
	return out
}

// astTarget is one entry of dirac `edit_ast`'s targets array:
// `{"operation":"rename"|"replace","targets":[{"path","symbol",
// "replacement"}]}` (dirac-cli EditAstTool.ts).
type astTarget struct {
	Path        string `json:"path"`
	Symbol      string `json:"symbol"`
	Replacement string `json:"replacement"`
}

// parseASTTargets counts dirac `edit_ast`.
//
//   - replace: `replacement` is the complete new definition; the replaced
//     definition is NOT in the payload. Its lines are booked as additions
//     at ConfidenceLow (the removed side is unknown).
//   - rename: `replacement` is a symbol name and the edited reference
//     sites are resolved by the tool, so nothing is measurable: each
//     target file is recorded as touched (path_only, actor unknown).
func parseASTTargets(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	var targets []astTarget
	if err := json.Unmarshal(obj["targets"], &targets); err != nil || len(targets) == 0 {
		return nil
	}
	op := jsonString(obj, "operation")
	byPath := map[string]*FileStats{}
	digests := map[string]*strings.Builder{}
	for _, t := range targets {
		path := t.Path
		if path == "" {
			path = in.Target
		}
		if op != "replace" {
			if _, seen := byPath[path]; !seen {
				fs := unparsed(path, ShapePathOnly)
				byPath[path] = &fs
				digests[path] = &strings.Builder{}
			}
			digests[path].WriteString(op + "\x00" + t.Symbol + "\x00" + t.Replacement + "\x00")
			continue
		}
		part := editStats(path, "", t.Replacement)
		row, ok := byPath[path]
		if !ok {
			lang, cat := Language(path)
			row = &FileStats{Path: path, Lang: lang, Category: cat, Shape: ShapeASTReplace, Confidence: ConfidenceLow}
			byPath[path] = row
			digests[path] = &strings.Builder{}
		}
		row.Stats.Add(part.Stats)
		row.Confidence = row.Confidence.Min(part.Confidence)
		digests[path].WriteString("replace\x00" + t.Symbol + "\x00" + normalizeBody(t.Replacement) + "\x00")
	}
	out := make([]FileStats, 0, len(byPath))
	for p, row := range byPath {
		row.InputDigest = digestOf(digests[p].String())
		out = append(out, *row)
	}
	sortFileStats(out)
	return out
}

// searchReplaceMarkers are the two block-delimiter families cline (and
// its Kilo fork) emit for `replace_in_file`. Current builds write the
// dashed form; older ones write the conflict-marker form, and a corpus
// spans both because the tool updates under the user.
//
// Each is {search-open, divider, replace-close}. A block is
//
//	<open>\n  <the text to find>  \n<divider>\n  <the replacement>  \n<close>
//
// and one payload may carry several blocks against ONE file.
var searchReplaceMarkers = [][3]string{
	{"------- SEARCH", "=======", "+++++++ REPLACE"},
	{"<<<<<<< SEARCH", "=======", ">>>>>>> REPLACE"},
}

// parseSearchReplaceDiff counts cline's `replace_in_file` payload:
// `{"path":…,"diff":"------- SEARCH…"}` (review finding L2).
//
// Each SEARCH/REPLACE block is measured as its OWN fragment and the
// Stats are summed into one row for the file — the same treatment
// MultiEdit's `edits[]` gets, and for the same reason: the blocks are
// separated by unknown amounts of untouched text, so concatenating them
// would invent adjacency.
//
// A payload whose `diff` carries no recognisable block yields nothing, so
// the ladder falls through rather than reporting a confident zero.
func parseSearchReplaceDiff(in Input, _ string, obj map[string]json.RawMessage) []FileStats {
	return searchReplaceStats(in, obj, jsonString(obj, "diff"))
}

// searchReplaceStats measures a SEARCH/REPLACE block body, whichever key
// carried it.
func searchReplaceStats(in Input, obj map[string]json.RawMessage, body string) []FileStats {
	blocks := parseSearchReplaceBlocks(body)
	if len(blocks) == 0 {
		return nil
	}
	path := pathFromJSON(in, obj)
	lang, cat := Language(path)
	out := FileStats{
		Path:       path,
		Lang:       lang,
		Category:   cat,
		Shape:      ShapeSearchReplace,
		Confidence: ConfidenceHigh,
	}
	var digest strings.Builder
	for _, b := range blocks {
		part := editStats(path, b.search, b.replace)
		out.Stats.Add(part.Stats)
		out.Confidence = out.Confidence.Min(part.Confidence)
		digest.WriteString(normalizeBody(b.search))
		digest.WriteString("\x00")
		digest.WriteString(normalizeBody(b.replace))
		digest.WriteString("\x00")
	}
	out.InputDigest = digestOf(digest.String())
	return []FileStats{out}
}

// searchReplaceBlock is one SEARCH/REPLACE pair.
type searchReplaceBlock struct{ search, replace string }

// parseSearchReplaceBlocks splits a `diff` body into its blocks.
//
// It is a small state machine rather than a regexp so a truncated tail
// (a block that opened but never closed) is DROPPED instead of being
// counted as a deletion of everything after it: the marker sequence, not
// the line content, is what advances the state.
func parseSearchReplaceBlocks(diff string) []searchReplaceBlock {
	if strings.TrimSpace(diff) == "" {
		return nil
	}
	lines := SplitLines(diff)
	var out []searchReplaceBlock
	for _, m := range searchReplaceMarkers {
		open, divider, closer := m[0], m[1], m[2]
		var (
			inSearch, inReplace bool
			search, replace     []string
		)
		for _, line := range lines {
			trimmed := strings.TrimRight(line, " \t")
			switch {
			case strings.HasPrefix(trimmed, open):
				inSearch, inReplace = true, false
				search, replace = nil, nil
			case inSearch && trimmed == divider:
				inSearch, inReplace = false, true
			case inReplace && strings.HasPrefix(trimmed, closer):
				out = append(out, searchReplaceBlock{
					search:  strings.Join(search, "\n"),
					replace: strings.Join(replace, "\n"),
				})
				inSearch, inReplace = false, false
			case inSearch:
				search = append(search, line)
			case inReplace:
				replace = append(replace, line)
			}
		}
		if len(out) > 0 {
			// The two marker families never mix inside one payload, so the
			// first family that produced blocks is the payload's family.
			return out
		}
	}
	return out
}

// codexChange is one entry of a codex patch_apply_end `changes` map. The
// map's KEYS are file paths; `update` carries a unified diff, `add`
// carries the new file's whole content, `delete` carries neither.
type codexChange struct {
	Type        string `json:"type"`
	Content     string `json:"content"`
	UnifiedDiff string `json:"unified_diff"`
	MovePath    any    `json:"move_path"`
}

// matchCodexChanges recognises the executor shape: every top-level value
// is an object carrying a known change type. The keys are paths, so no
// key-name test can identify this shape — the VALUES must.
func matchCodexChanges(_ Input, _ string, obj map[string]json.RawMessage) bool {
	if len(obj) == 0 {
		return false
	}
	for _, raw := range obj {
		var ch codexChange
		if err := json.Unmarshal(raw, &ch); err != nil {
			return false
		}
		switch ch.Type {
		case "update", "add", "delete":
		default:
			return false
		}
	}
	return true
}

// parseCodexChanges emits one row per file in the executor's changes map.
func parseCodexChanges(_ Input, _ string, obj map[string]json.RawMessage) []FileStats {
	out := make([]FileStats, 0, len(obj))
	for path, raw := range obj {
		var ch codexChange
		if err := json.Unmarshal(raw, &ch); err != nil {
			continue
		}
		fs := codexChangeStats(path, ch)
		fs.Shape = ShapeCodexChanges
		out = append(out, fs)
	}
	sortFileStats(out)
	return out
}

// codexChangeStats counts one entry of the changes map.
func codexChangeStats(path string, ch codexChange) FileStats {
	switch ch.Type {
	case "add":
		fs := addedContentStats(path, ch.Content)
		fs.NewFile = true
		fs.InputDigest = digestOf(normalizeBody(ch.Content))
		return fs
	case "delete":
		lang, cat := Language(path)
		return FileStats{
			Path: path, Lang: lang, Category: cat,
			DeletedFile: true,
			// A delete carries no body, so its removed lines are not
			// countable. The row exists to record that the file went
			// away, not to guess how big it was.
			Confidence:  ConfidenceMedium,
			InputDigest: digestOf("delete\x00" + path),
		}
	default:
		return unifiedDiffStats(path, ch.UnifiedDiff)
	}
}

// matchBeginPatch recognises a bare apply_patch envelope stored as plain
// text (no JSON wrapper).
func matchBeginPatch(_ Input, raw string, obj map[string]json.RawMessage) bool {
	return obj == nil && strings.HasPrefix(strings.TrimSpace(raw), "*** Begin Patch")
}

// parseBeginPatchText counts a bare `*** Begin Patch` envelope, which may
// touch several files.
func parseBeginPatchText(_ Input, raw string, _ map[string]json.RawMessage) []FileStats {
	return parseBeginPatch(raw, ShapeCodexPatch)
}

// matchCodexJS recognises the codex unified-exec JavaScript wrapper: a
// program that hoists the patch envelope into a string binding and hands
// it to the injected dispatcher.
func matchCodexJS(_ Input, raw string, obj map[string]json.RawMessage) bool {
	if obj != nil {
		return false
	}
	return strings.Contains(raw, "Begin Patch") &&
		(strings.Contains(raw, "apply_patch") || strings.Contains(raw, "const ") ||
			strings.Contains(raw, "let ") || strings.Contains(raw, "var "))
}

// parseCodexJS decodes the JS wrapper through internal/codexpatch — the
// SAME extractor the codex adapter uses to resolve a patch target, so a
// program the adapter could read is never one the counter cannot.
func parseCodexJS(_ Input, raw string, _ map[string]json.RawMessage) []FileStats {
	patch := codexpatch.ExtractPatch(raw)
	if strings.TrimSpace(patch) == "" {
		return nil
	}
	return parseBeginPatch(patch, ShapeCodexJS)
}

// matchPathOnly recognises the cursor afterFileEdit hook row, whose whole
// raw_tool_input is the edited file's path: the hook reports THAT a file
// changed, never what changed in it. Counting its single line as a
// one-line file would be a fabrication, so it degrades to unknown.
//
// Cursor emits two rows per edit — a transcript StrReplace row that DOES
// carry before/after text, and this hook row — so the information is not
// lost, it just lives on the other row.
func matchPathOnly(in Input, raw string, obj map[string]json.RawMessage) bool {
	if obj != nil {
		return false
	}
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" || strings.ContainsAny(trimmed, "\n\r") {
		return false
	}
	if in.Target != "" && trimmed == strings.TrimSpace(in.Target) {
		return true
	}
	return looksLikePath(trimmed)
}

// parsePathOnly records the file as touched with no countable lines.
func parsePathOnly(_ Input, raw string, _ map[string]json.RawMessage) []FileStats {
	return []FileStats{unparsed(strings.TrimSpace(raw), ShapePathOnly)}
}

// matchPlainContent is the last text row: a payload that is neither JSON,
// nor a patch, nor a path is the file's after-content verbatim. Junie
// stores exactly this (its adapter writes the change's AfterContent into
// raw_tool_input with no envelope at all).
func matchPlainContent(_ Input, raw string, obj map[string]json.RawMessage) bool {
	return obj == nil && strings.TrimSpace(raw) != ""
}

// parsePlainContent treats the body as a whole-file after-image, with the
// same before-image reconstruction a JSON Write gets.
func parsePlainContent(in Input, raw string, _ map[string]json.RawMessage) []FileStats {
	fs := wholeContentStats(in, in.Target, raw)
	fs.Shape = ShapePlainContent
	return []FileStats{fs}
}

// looksLikePath reports whether a single-line body is a filesystem path
// rather than a one-line file body. It requires a separator and no
// whitespace — deliberately strict, because a false positive silently
// drops a real one-line edit.
func looksLikePath(s string) bool {
	if strings.ContainsAny(s, " \t") {
		return false
	}
	return strings.ContainsAny(s, "/\\")
}

// unparsed builds the zero-count row for a shape that identified the file
// but could not measure it.
func unparsed(path string, shape Shape) FileStats {
	lang, cat := Language(path)
	return FileStats{
		Path:       path,
		Lang:       lang,
		Category:   cat,
		Shape:      shape,
		Confidence: ConfidenceLow,
	}
}

// editStats is the core measurement: classify both images, align them,
// and fold the alignment into buckets. Every before/after shape in the
// ladder funnels through here, so all of them count identically.
func editStats(path, oldText, newText string) FileStats {
	lang, cat := Language(path)
	fs := FileStats{
		Path:        path,
		Lang:        lang,
		Category:    cat,
		Confidence:  ConfidenceHigh,
		InputDigest: digestOf(normalizeBody(oldText) + "\x00" + normalizeBody(newText)),
	}
	if !cat.Counted() {
		// Generated, vendored and binary files are RECOGNISED and
		// recorded, never counted. The row lets the UI say "N files
		// skipped as generated" instead of the file vanishing.
		fs.Confidence = ConfidenceHigh
		return fs
	}
	oldLines := SplitLines(oldText)
	newLines := SplitLines(newText)
	oldClasses, oldConf := ClassifyLines(lang, oldText)
	newClasses, newConf := ClassifyLines(lang, newText)
	fs.Stats = Count(Diff(oldLines, newLines), oldClasses, newClasses, oldLines, newLines)
	fs.Confidence = oldConf.Min(newConf)
	if DiffDegraded(oldLines, newLines) {
		fs.Confidence = ConfidenceLow
	}
	return fs
}

// addedContentStats counts a body that is entirely new: no before-image
// exists and none is implied.
func addedContentStats(path, content string) FileStats {
	fs := editStats(path, "", content)
	fs.InputDigest = digestOf(normalizeBody(content))
	applyGeneratedHeader(&fs, content)
	return fs
}

// applyGeneratedHeader downgrades a whole-content row to CategoryGenerated
// when the body carries the machine-generated banner, and zeroes its
// counts.
//
// It runs AFTER the counts are computed rather than before, so there is
// exactly one place that decides what "generated" means for a row and the
// per-shape parsers do not each have to remember to ask. Cost is one scan
// of three lines.
//
// The row survives with zero counts, which is the same treatment a
// path-denylisted file gets: the UI can say "N files skipped as
// generated" instead of the file silently vanishing.
func applyGeneratedHeader(fs *FileStats, content string) {
	if !fs.Category.Counted() || !HasGeneratedHeader(content) {
		return
	}
	fs.Lang = LangUnknown
	fs.Category = CategoryGenerated
	fs.Stats = Stats{}
	fs.Confidence = ConfidenceHigh
}

// wholeContentStats counts a whole-file write, reconstructing the
// before-image the plan's §6 ruling 3 allows.
//
// Three cases, and the row says which one it is:
//
//   - the file did not exist: NewFile, every line is an addition,
//     ConfidenceHigh.
//   - the file existed and the caller recovered a before-image LINE COUNT
//     from the preceding read of the same file: Overwrite, and the count
//     is fed in as that many UNCLASSIFIABLE old lines. The transition
//     table then reports min(before, after) pairs as one Unknown (the old
//     side, never measured) plus one added line of the new side's class,
//     which is exactly what is and is not known. ConfidenceMedium.
//   - the file existed and no before-image is available: Overwrite, every
//     line counts as an addition, ConfidenceLow. The UI labels it.
func wholeContentStats(in Input, path, content string) FileStats {
	if !in.Existed {
		fs := addedContentStats(path, content)
		fs.NewFile = true
		return fs
	}
	if in.BeforeLines <= 0 {
		fs := addedContentStats(path, content)
		fs.Overwrite = true
		fs.Confidence = ConfidenceLow
		return fs
	}

	lang, cat := Language(path)
	fs := FileStats{
		Path:        path,
		Lang:        lang,
		Category:    cat,
		Overwrite:   true,
		Confidence:  ConfidenceMedium,
		InputDigest: digestOf(normalizeBody(content)),
	}
	if !cat.Counted() {
		return fs
	}
	newLines := SplitLines(content)
	newClasses, newConf := ClassifyLines(lang, content)
	// Placeholder old lines: unique per index so the diff can never pair
	// one as equal to a real line, and classified Unknown so the
	// transition table books them honestly as un-measured.
	oldLines := make([]string, in.BeforeLines)
	oldClasses := make([]LineClass, in.BeforeLines)
	for i := range oldLines {
		oldLines[i] = "\x00loc-before-image\x00" + itoa(i)
		oldClasses[i] = ClassUnknown
	}
	fs.Stats = Count(Diff(oldLines, newLines), oldClasses, newClasses, oldLines, newLines)
	fs.Confidence = ConfidenceMedium.Min(newConf)
	applyGeneratedHeader(&fs, content)
	return fs
}

// itoa is a dependency-free small-integer formatter for the before-image
// placeholder lines (strconv would be fine; this keeps the placeholder
// construction obviously allocation-cheap and self-contained).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// digestOf hashes normalized patch text into the hex digest the store
// dedups on. It is a digest OF a patch, never the patch: it is one-way,
// fixed length, and never reversible into content.
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// normalizeBody makes two renderings of the same change hash alike.
//
// This is what lets the store collapse codex's DUPLICATE PAIR: the model's
// invocation row carries `*** Begin Patch` with bare `@@` markers, while
// the executor's patch_apply_end row carries a `unified_diff` with
// `@@ -a,b +c,d @@` counts. Same change, different rendering. Dropping
// every `@@` header line and trailing whitespace makes the two digests
// equal, so the pair collapses on
// (session_id, file_path_hash, input_digest) and authorship is counted
// ONCE — the double-count that content_bytes still lives with
// (internal/adapter/codex/adapter.go, authoredBytesFromPatchChanges).
func normalizeBody(s string) string {
	if s == "" {
		return ""
	}
	lines := SplitLines(s)
	kept := make([]string, 0, len(lines))
	for _, line := range lines {
		if strings.HasPrefix(line, "@@") {
			continue
		}
		kept = append(kept, strings.TrimRight(line, " \t"))
	}
	return strings.Join(kept, "\n")
}

// sortFileStats orders rows by path so a multi-file patch produces a
// deterministic row order (map iteration is not ordered, and a
// non-deterministic order would make the goldens flap).
func sortFileStats(rows []FileStats) {
	for i := 1; i < len(rows); i++ {
		for j := i; j > 0 && rows[j].Path < rows[j-1].Path; j-- {
			rows[j], rows[j-1] = rows[j-1], rows[j]
		}
	}
}
