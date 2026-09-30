package alignment

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Bounds from the plan (§4 W5a): the assembled prompt never exceeds
// maxPromptBytes total; each hunk excerpt is capped at maxHunkBytes before
// assembly; at most maxHunks hunks and maxFiles files are shown (the rest
// are named as an omitted count, never silently dropped without a trace).
const (
	maxPromptBytes = 24 << 10 // 24 KiB
	maxHunkBytes   = 2 << 10  // 2 KiB
	maxHunks       = 20
	maxFiles       = 200
)

// systemInstructions is the fixed grading contract given to the judge on
// every call — verbatim per the plan's prompt design.
const systemInstructions = `You grade whether a code commit delivered what a developer asked an AI coding tool for. Return ONLY JSON {"delivered":[],"missed":[],"extra":[],"confidence":0-1,"notes":""}. Base every item on the evidence; if evidence is insufficient say so in notes and lower confidence.`

// truncationMarker is appended whenever content is cut for a byte bound.
// It is never itself counted against the bound it closes out (the caller
// reserves room for it before slicing).
const truncationMarker = "\n…[truncated]"

// BuildPrompt renders in into one deterministic, bounded prompt string: the
// same Input always produces the same output, and the output never exceeds
// maxPromptBytes. Files and hunks beyond the caps are named as an omitted
// count rather than silently dropped, so a judge (and anyone reading the
// prompt later) can tell the evidence was truncated, not that the commit
// was small.
func BuildPrompt(in Input) string {
	var b strings.Builder

	b.WriteString(systemInstructions)
	b.WriteString("\n\n")

	b.WriteString("## Developer prompt\n")
	b.WriteString(in.PromptText)
	b.WriteString("\n\n")

	b.WriteString("## Commit\n")
	b.WriteString("Subject: ")
	b.WriteString(in.CommitSubject)
	b.WriteString("\n")
	if in.Tool != "" {
		b.WriteString("Tool: ")
		b.WriteString(in.Tool)
		b.WriteString("\n")
	}
	b.WriteString("Link status: ")
	b.WriteString(in.LinkStatus)
	b.WriteString("\n\n")

	files := in.Files
	omittedFiles := 0
	if len(files) > maxFiles {
		omittedFiles = len(files) - maxFiles
		files = files[:maxFiles]
	}
	fmt.Fprintf(&b, "## Files changed (%d)\n", len(in.Files))
	for _, f := range files {
		fmt.Fprintf(&b, "+%d -%d %s\n", f.Added, f.Deleted, f.Path)
	}
	if omittedFiles > 0 {
		fmt.Fprintf(&b, "...and %d more files omitted\n", omittedFiles)
	}
	b.WriteString("\n")

	hunks := in.Hunks
	omittedHunks := 0
	if len(hunks) > maxHunks {
		omittedHunks = len(hunks) - maxHunks
		hunks = hunks[:maxHunks]
	}
	fmt.Fprintf(&b, "## Edited hunks (%d)\n", len(in.Hunks))
	for _, h := range hunks {
		b.WriteString("### ")
		b.WriteString(h.Path)
		b.WriteString("\n")
		b.WriteString(truncateBytes(h.Excerpt, maxHunkBytes))
		b.WriteString("\n\n")
	}
	if omittedHunks > 0 {
		fmt.Fprintf(&b, "...and %d more hunks omitted\n", omittedHunks)
	}

	return truncateBytes(b.String(), maxPromptBytes)
}

// truncateBytes returns s unchanged when it already fits within max bytes;
// otherwise it cuts s at a rune boundary so the result (INCLUDING
// truncationMarker) fits within max bytes. max<=0 always truncates to just
// the marker's own prefix (defensive; never hit by the bounds above).
func truncateBytes(s string, max int) string {
	if len(s) <= max {
		return s
	}
	cut := max - len(truncationMarker)
	if cut < 0 {
		cut = 0
	}
	if cut > len(s) {
		cut = len(s)
	}
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + truncationMarker
}
