package ibmbob

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/loc"
	"github.com/marmutapp/superbased-observer/internal/models"
)

// fileChange is one value of a tool result's `_meta.changes` map. Bob
// records {before, after, patch} per touched file (live-grounded on
// write_file and search_and_replace results, WSL and Windows, bobshell
// 2.0.6). Only `patch` is decoded: before/after are whole-file images and
// are never kept.
type fileChange struct {
	Patch string `json:"patch"`
}

// changeRecord is one element the adapter adds to an edit/write call's raw
// input under loc.BobChangesKey.
type changeRecord struct {
	Path  string `json:"path"`
	Hunks string `json:"hunks"`
}

// rawToolInput is the scrubbed raw input of one tool call. For an edit or
// write whose result carried `_meta.changes`, the exact change Bob applied
// is added under loc.BobChangesKey (one record per file, the diff reduced
// to its +/- lines by changedLines), so the LOC counter
// (internal/loc ShapeBobChanges) counts what the tool did instead of
// estimating it from the arguments. The argument members are kept as they
// are. Anything that does not fit falls back to the plain arguments: no
// change record, arguments that are not a JSON object, a vendor member that
// already uses the key, or a combined payload the raw-input cap would
// truncate when the arguments alone fit.
func (a *Adapter) rawToolInput(actionType string, args json.RawMessage, changes map[string]fileChange) string {
	plain := a.scrubRaw(args)
	if actionType != models.ActionEditFile && actionType != models.ActionWriteFile {
		return plain
	}
	records := changeRecords(args, changes)
	if len(records) == 0 {
		return plain
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(args, &obj); err != nil || obj == nil {
		return plain
	}
	if _, taken := obj[loc.BobChangesKey]; taken {
		return plain
	}
	enc, err := json.Marshal(records)
	if err != nil {
		return plain
	}
	obj[loc.BobChangesKey] = enc
	merged, err := json.Marshal(obj)
	if err != nil {
		return plain
	}
	out := a.scrubRaw(merged)
	if strings.HasSuffix(out, truncationMarker) && !strings.HasSuffix(plain, truncationMarker) {
		return plain
	}
	return out
}

// truncationMarker is the suffix scrub.Truncate appends to a capped raw
// input.
const truncationMarker = "…[truncated]"

// changeRecords turns a `_meta.changes` map into sorted change records. The
// path is the call's own `path` argument when the call touched exactly one
// file (the same string the action's target and the argument-based LOC rows
// use, so the file hashes alike), else the file URI decoded to a path. An
// entry whose diff holds no changed line is dropped.
func changeRecords(args json.RawMessage, changes map[string]fileChange) []changeRecord {
	if len(changes) == 0 {
		return nil
	}
	var in struct {
		Path string `json:"path"`
	}
	_ = json.Unmarshal(args, &in)
	out := make([]changeRecord, 0, len(changes))
	for uri, c := range changes {
		hunks := changedLines(c.Patch)
		if hunks == "" {
			continue
		}
		path := uriPath(uri)
		if len(changes) == 1 && strings.TrimSpace(in.Path) != "" {
			path = in.Path
		}
		out = append(out, changeRecord{Path: path, Hunks: hunks})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// changedLines reduces a unified diff to its changed lines. The file
// headers (`Index:`, `===`, `---`, `+++`) before the first hunk are
// dropped; inside the hunks every `+`/`-` line is kept verbatim, each run of
// context lines (and each `@@ -a,b +c,d @@` header) becomes one bare `@@`
// separator, and the "\ No newline at end of file" marker is dropped. The
// separators keep runs that context separated from being paired with each
// other, so the line counts equal the full diff's while no unchanged file
// content is kept. Returns "" when the diff holds no changed line.
func changedLines(patch string) string {
	var b strings.Builder
	started, needSep := false, true
	for _, line := range strings.Split(patch, "\n") {
		switch {
		case strings.HasPrefix(line, "@@"):
			started, needSep = true, true
		case !started:
			// File headers before the first hunk.
		case strings.HasPrefix(line, "+") || strings.HasPrefix(line, "-"):
			if needSep {
				b.WriteString("@@\n")
				needSep = false
			}
			b.WriteString(line)
			b.WriteByte('\n')
		case strings.HasPrefix(line, `\`):
			// "\ No newline at end of file": an annotation, not a line.
		default:
			// A context line (or the empty tail after the final newline)
			// ends the current run.
			needSep = true
		}
	}
	return b.String()
}

// uriPath decodes a `_meta.changes` key ("file:///home/u/a.py",
// "file:///C:/Users/u/a.py") into a path ("/home/u/a.py",
// "C:/Users/u/a.py"). A key that is not a file URI is returned as-is.
func uriPath(uri string) string {
	if !strings.HasPrefix(strings.ToLower(uri), "file:") {
		return uri
	}
	u, err := url.Parse(uri)
	if err != nil || u.Path == "" {
		return strings.TrimPrefix(uri, "file://")
	}
	p := u.Path
	// "/C:/Users/..." -> "C:/Users/...".
	if len(p) >= 3 && p[0] == '/' && p[2] == ':' && isASCIILetter(p[1]) {
		p = p[1:]
	}
	return p
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
