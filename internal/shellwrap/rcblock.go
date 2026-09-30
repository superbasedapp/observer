package shellwrap

import (
	"errors"
	"fmt"
	"strings"
)

// Block markers. Every supported start-up file language (POSIX sh, fish,
// PowerShell) treats a leading '#' as a comment, so one spelling serves all
// of them. BlockBegin is a PREFIX: the begin line may carry flags after it
// (see blockFlags) recording what the insert had to add, so RemoveBlock can
// undo exactly that and nothing else.
const (
	BlockBegin = "# >>> superbased-observer shell-wrap >>>"
	BlockEnd   = "# <<< superbased-observer shell-wrap <<<"
)

// Begin-line flags. A flag is present as a bare word after BlockBegin.
const (
	// flagCreated: the file did not exist before the first insert, so a
	// removal that leaves it empty deletes it.
	flagCreated = "created"
	// flagNewline: the file did not end in a newline before the first
	// insert, so the insert added one (in the file's line ending) and the
	// removal takes it back.
	flagNewline = "added-newline"
)

// ErrMalformedBlock reports a start-up file whose markers are unbalanced or
// duplicated. The applier refuses to touch such a file rather than guess
// where the block ends.
var ErrMalformedBlock = errors.New("shellwrap: malformed shell-wrap block")

// blockSpan locates the managed block in content. found=false (and a nil
// error) when there is none. start is the offset of the begin line's first
// byte; end is the offset just past the end line's line terminator (or the
// end of content when the end line is the last, unterminated line).
type blockSpan struct {
	start, end int
	flags      map[string]bool
}

// findBlock walks content line by line for the markers.
func findBlock(content string) (blockSpan, bool, error) {
	var (
		span      blockSpan
		haveBegin bool
		haveEnd   bool
	)
	pos := 0
	for pos < len(content) {
		nl := strings.IndexByte(content[pos:], '\n')
		lineEnd, next := len(content), len(content)
		if nl >= 0 {
			lineEnd, next = pos+nl, pos+nl+1
		}
		line := strings.TrimRight(content[pos:lineEnd], "\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(trimmed, BlockBegin):
			if haveBegin {
				return blockSpan{}, false, fmt.Errorf("%w: a second begin marker", ErrMalformedBlock)
			}
			haveBegin = true
			span.start = pos
			span.flags = parseFlags(strings.TrimPrefix(trimmed, BlockBegin))
		case trimmed == BlockEnd:
			if !haveBegin || haveEnd {
				return blockSpan{}, false, fmt.Errorf("%w: an end marker without a begin marker", ErrMalformedBlock)
			}
			haveEnd = true
			span.end = next
		}
		pos = next
	}
	switch {
	case !haveBegin:
		return blockSpan{}, false, nil
	case !haveEnd:
		return blockSpan{}, false, fmt.Errorf("%w: a begin marker without an end marker", ErrMalformedBlock)
	}
	return span, true, nil
}

func parseFlags(rest string) map[string]bool {
	out := map[string]bool{}
	for _, f := range strings.Fields(rest) {
		out[f] = true
	}
	return out
}

// eolOf returns the file's line ending: CRLF when the file already uses it,
// LF otherwise (and for an empty file).
func eolOf(content string) string {
	if strings.Contains(content, "\r\n") {
		return "\r\n"
	}
	return "\n"
}

// renderBlock renders the full marked block (begin line, body, end line), each
// line terminated by eol.
func renderBlock(body string, flags []string, eol string) string {
	var b strings.Builder
	b.WriteString(BlockBegin)
	for _, f := range flags {
		b.WriteString(" ")
		b.WriteString(f)
	}
	b.WriteString(eol)
	for _, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		b.WriteString(line)
		b.WriteString(eol)
	}
	b.WriteString(BlockEnd)
	b.WriteString(eol)
	return b.String()
}

// InsertBlock returns content with the managed block set to body. exists
// reports whether the file existed before (a file that did not is recorded
// as created so RemoveBlock can delete it again).
//
//   - An existing block is replaced IN PLACE, keeping the flags its first
//     insert recorded; the rest of the file is untouched. An unchanged body
//     returns content unchanged (idempotent).
//   - Otherwise the block is appended at the end, so it runs after anything
//     else in the file prepends to PATH. When the file does not end in a
//     newline one is added first and recorded.
//
// A malformed block (unbalanced or duplicated markers) is an error and the
// content is returned unchanged.
func InsertBlock(content, body string, exists bool) (string, error) {
	eol := eolOf(content)
	span, found, err := findBlock(content)
	if err != nil {
		return content, err
	}
	if found {
		var flags []string
		for _, f := range []string{flagCreated, flagNewline} {
			if span.flags[f] {
				flags = append(flags, f)
			}
		}
		block := renderBlock(body, flags, eol)
		if span.end == len(content) && !strings.HasSuffix(content, "\n") {
			// The end line was the last, unterminated line: keep it so.
			block = strings.TrimSuffix(block, eol)
		}
		return content[:span.start] + block + content[span.end:], nil
	}
	var flags []string
	prefix := content
	if !exists && content == "" {
		flags = append(flags, flagCreated)
	}
	if content != "" && !strings.HasSuffix(content, "\n") {
		flags = append(flags, flagNewline)
		prefix += eol
	}
	return prefix + renderBlock(body, flags, eol), nil
}

// RemoveResult is RemoveBlock's outcome.
type RemoveResult struct {
	// Content is the file without the block (the original bytes).
	Content string
	// Found reports whether a block was present.
	Found bool
	// DeleteFile reports that the insert created the file and nothing but
	// the block was ever added to it, so undo means deleting it.
	DeleteFile bool
}

// RemoveBlock strips the managed block from content, byte-for-byte restoring
// what InsertBlock found: the newline it had to add is taken back, and a file
// it had to create is reported for deletion when nothing else was written to
// it since. Absent block: Found=false, Content unchanged.
func RemoveBlock(content string) (RemoveResult, error) {
	span, found, err := findBlock(content)
	if err != nil {
		return RemoveResult{Content: content}, err
	}
	if !found {
		return RemoveResult{Content: content}, nil
	}
	start := span.start
	if span.flags[flagNewline] {
		switch {
		case strings.HasSuffix(content[:start], "\r\n"):
			start -= 2
		case strings.HasSuffix(content[:start], "\n"):
			start--
		}
	}
	out := content[:start] + content[span.end:]
	return RemoveResult{
		Content:    out,
		Found:      true,
		DeleteFile: span.flags[flagCreated] && out == "",
	}, nil
}

// HasBlock reports whether content carries a (well-formed) managed block.
func HasBlock(content string) (bool, error) {
	_, found, err := findBlock(content)
	return found, err
}

// BlockBody returns the body lines of the managed block (without markers),
// normalized to LF, for comparing an installed block against a fresh plan.
func BlockBody(content string) (string, bool, error) {
	span, found, err := findBlock(content)
	if err != nil || !found {
		return "", found, err
	}
	block := strings.ReplaceAll(content[span.start:span.end], "\r\n", "\n")
	lines := strings.Split(strings.TrimRight(block, "\n"), "\n")
	if len(lines) < 2 {
		return "", true, nil
	}
	return strings.Join(lines[1:len(lines)-1], "\n") + "\n", true, nil
}
