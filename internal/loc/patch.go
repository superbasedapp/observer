package loc

import "strings"

// The apply_patch envelope's structural markers. Codex writes this
// format both as the model's own tool input (`*** Begin Patch …`) and,
// inside the unified-exec wrapper, as a hoisted JavaScript string.
const (
	patchBegin      = "*** Begin Patch"
	patchEnd        = "*** End Patch"
	patchUpdateFile = "*** Update File: "
	patchAddFile    = "*** Add File: "
	patchDeleteFile = "*** Delete File: "
	patchMoveTo     = "*** Move to: "
	patchEndOfFile  = "*** End of File"
)

// patchHunk is one aligned region of an apply_patch or unified diff: the
// lines it removed and the lines it added, with the surrounding context
// kept on BOTH sides so the fragment lexer sees a realistic neighbourhood
// (a `-` line that sits inside a block comment must classify as a
// comment, and only the context tells it so).
type patchHunk struct {
	old []string
	new []string
	// chg is the hunk's CHANGE lines only — the `-` and `+` lines with
	// their prefix kept — and is what the input digest is built from.
	//
	// It is deliberately NOT the verbatim body. Codex renders the SAME
	// change twice with different amounts of surrounding context: the
	// model's `*** Begin Patch` hunk carries whatever context the model
	// felt like including (usually none), while the executor's
	// `unified_diff` is generated with the standard three lines of
	// context plus `\ No newline at end of file` annotations. Digesting
	// the whole body made those two renderings hash differently, so the
	// read-side collapse on (session, file, input_digest) kept both and
	// every codex patch was counted twice (review finding H2). The
	// CHANGE is the thing the two renderings agree on, so the change is
	// what identifies the patch.
	chg []string
}

// patchFile accumulates every hunk that targets one path within a single
// patch envelope, plus the structural verdict on the file itself.
type patchFile struct {
	path    string
	hunks   []patchHunk
	added   bool // *** Add File: — the whole body is new content
	deleted bool // *** Delete File: — no body, removed lines unknowable
	content []string
}

// parseBeginPatch parses a whole `*** Begin Patch` envelope, which may
// touch several files, and returns one FileStats per file.
//
// It is deliberately tolerant of the real corpus rather than of the
// format's specification: bare `@@` markers with no line numbers (the
// dominant form codex emits), an envelope with no `*** End Patch`
// terminator (a truncated rollout), context lines written with no leading
// space, and `*** Move to:` following an update. Anything it cannot place
// inside a file section is treated as context, which is the conservative
// choice — context lines are counted on neither side.
func parseBeginPatch(text string, shape Shape) []FileStats {
	files := parsePatchFiles(text)
	if len(files) == 0 {
		return nil
	}
	out := make([]FileStats, 0, len(files))
	for _, f := range files {
		fs := patchFileStats(f)
		fs.Shape = shape
		out = append(out, fs)
	}
	sortFileStats(out)
	return out
}

// parsePatchFiles splits an envelope into per-file sections.
func parsePatchFiles(text string) []*patchFile {
	lines := SplitLines(text)
	var files []*patchFile
	var cur *patchFile
	var hunk *patchHunk

	flushHunk := func() {
		if cur != nil && hunk != nil && (len(hunk.old) > 0 || len(hunk.new) > 0) {
			cur.hunks = append(cur.hunks, *hunk)
		}
		hunk = nil
	}
	startFile := func(path string) *patchFile {
		flushHunk()
		f := &patchFile{path: strings.TrimSpace(path)}
		files = append(files, f)
		return f
	}

	for _, line := range lines {
		switch {
		case strings.HasPrefix(line, patchBegin), strings.HasPrefix(line, patchEnd),
			strings.HasPrefix(line, patchEndOfFile):
			flushHunk()
			continue
		case strings.HasPrefix(line, patchUpdateFile):
			cur = startFile(strings.TrimPrefix(line, patchUpdateFile))
			continue
		case strings.HasPrefix(line, patchAddFile):
			cur = startFile(strings.TrimPrefix(line, patchAddFile))
			cur.added = true
			continue
		case strings.HasPrefix(line, patchDeleteFile):
			cur = startFile(strings.TrimPrefix(line, patchDeleteFile))
			cur.deleted = true
			continue
		case strings.HasPrefix(line, patchMoveTo):
			// A rename keeps the same hunks; the destination path is the
			// one that now exists, so it wins.
			if cur != nil {
				cur.path = strings.TrimSpace(strings.TrimPrefix(line, patchMoveTo))
			}
			continue
		}
		if cur == nil {
			continue
		}
		if cur.added {
			// An Add File body is all `+` lines. Anything else inside one
			// is a producer quirk; take it verbatim so no authored line
			// is silently dropped.
			cur.content = append(cur.content, strings.TrimPrefix(line, "+"))
			continue
		}
		if cur.deleted {
			continue
		}
		if strings.HasPrefix(line, "@@") {
			flushHunk()
			hunk = &patchHunk{}
			continue
		}
		if hunk == nil {
			hunk = &patchHunk{}
		}
		appendPatchLine(hunk, line)
	}
	flushHunk()
	return files
}

// appendPatchLine books one body line onto a hunk. This is the ONE place
// the `-` / `+` / context convention is interpreted, so the apply_patch
// envelope and a bare unified diff cannot drift apart.
func appendPatchLine(h *patchHunk, line string) {
	switch {
	case strings.HasPrefix(line, "-"):
		h.old = append(h.old, line[1:])
		h.chg = append(h.chg, line)
	case strings.HasPrefix(line, "+"):
		h.new = append(h.new, line[1:])
		h.chg = append(h.chg, line)
	case strings.HasPrefix(line, "\\"):
		// "\ No newline at end of file" — a diff annotation, not content.
	case strings.HasPrefix(line, " "):
		h.old = append(h.old, line[1:])
		h.new = append(h.new, line[1:])
	default:
		// A context line whose leading space was stripped somewhere in
		// transit (the empty line is the common case). Counting it as
		// context is safe: context contributes to no bucket.
		h.old = append(h.old, line)
		h.new = append(h.new, line)
	}
}

// unifiedDiffStats counts a bare unified diff — the shape codex's
// executor stores under `changes["<path>"].unified_diff`. It reuses the
// envelope's own hunk parser so an update counted from the executor row
// and the same update counted from the model's invocation row agree.
func unifiedDiffStats(path, diff string) FileStats {
	f := &patchFile{path: path}
	var hunk *patchHunk
	for _, line := range SplitLines(diff) {
		switch {
		case strings.HasPrefix(line, "@@"):
			if hunk != nil && (len(hunk.old) > 0 || len(hunk.new) > 0) {
				f.hunks = append(f.hunks, *hunk)
			}
			hunk = &patchHunk{}
			continue
		case hunk == nil && (strings.HasPrefix(line, "--- ") || strings.HasPrefix(line, "+++ ") ||
			strings.HasPrefix(line, "diff --git ") || strings.HasPrefix(line, "index ")):
			// Unified-diff file headers. They are metadata, not content,
			// and must never be booked as a deleted/added line.
			//
			// The `hunk == nil` guard is load-bearing: headers only ever
			// appear BEFORE the first `@@`. Inside a hunk body those same
			// prefixes are ordinary content — a deleted `-- old comment`
			// in SQL, Lua, Haskell or Ada renders as `--- old comment`,
			// and skipping it dropped a real deleted comment line AND
			// forked the digest from the invocation side that counted it
			// (review findings L1 / H2).
			continue
		}
		if hunk == nil {
			hunk = &patchHunk{}
		}
		appendPatchLine(hunk, line)
	}
	if hunk != nil && (len(hunk.old) > 0 || len(hunk.new) > 0) {
		f.hunks = append(f.hunks, *hunk)
	}
	return patchFileStats(f)
}

// patchFileStats folds one file's patch sections into a FileStats.
//
// Each hunk is measured as its OWN fragment rather than by concatenating
// every hunk into one pseudo-file: hunks are separated by unknown amounts
// of untouched text, so concatenating them would invent adjacency and let
// a block comment opened in one hunk "close" in another. The confidence
// of the file is the weakest confidence of any of its hunks.
func patchFileStats(f *patchFile) FileStats {
	lang, cat := Language(f.path)

	switch {
	case f.deleted:
		return FileStats{
			Path: f.path, Lang: lang, Category: cat,
			DeletedFile: true,
			// A Delete File section carries no body, so the removed lines
			// are not countable. Reporting zero is honest; guessing is not.
			Confidence:  ConfidenceMedium,
			InputDigest: digestOf("delete\x00" + f.path),
		}
	case f.added:
		body := strings.Join(f.content, "\n")
		fs := addedContentStats(f.path, body)
		fs.NewFile = true
		return fs
	}

	fs := FileStats{
		Path: f.path, Lang: lang, Category: cat,
		Confidence: ConfidenceHigh,
	}
	// The digest is over the CHANGE lines only (see patchHunk.chg): the
	// same change rendered with and without context must hash alike, or
	// the codex invocation/executor pair never collapses.
	var digest strings.Builder
	for _, h := range f.hunks {
		digest.WriteString(normalizeBody(strings.Join(h.chg, "\n")))
		digest.WriteString("\n")
	}
	fs.InputDigest = digestOf(strings.TrimRight(digest.String(), "\n"))
	if !cat.Counted() {
		return fs
	}
	if len(f.hunks) == 0 {
		fs.Confidence = ConfidenceLow
		return fs
	}
	for _, h := range f.hunks {
		oldText := strings.Join(h.old, "\n")
		newText := strings.Join(h.new, "\n")
		oldClasses, oldConf := ClassifyLines(lang, oldText)
		newClasses, newConf := ClassifyLines(lang, newText)
		fs.Stats.Add(Count(Diff(h.old, h.new), oldClasses, newClasses, h.old, h.new))
		fs.Confidence = fs.Confidence.Min(oldConf).Min(newConf)
	}
	return fs
}
