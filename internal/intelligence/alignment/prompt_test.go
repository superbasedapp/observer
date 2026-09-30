package alignment

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func smallInput() Input {
	return Input{
		PromptText:    "add a retry to the upload client",
		CommitSubject: "feat(upload): retry on transient failure",
		Files: []FileStat{
			{Path: "internal/upload/client.go", Added: 12, Deleted: 3},
		},
		Hunks: []Hunk{
			{Path: "internal/upload/client.go", Excerpt: "+func retry() {}"},
		},
		LinkStatus: "committed",
		Tool:       "claude-code",
	}
}

// TestBuildPromptDeterministic pins the golden shape of the prompt for a
// fixed small Input — the same Input must always compile to the exact same
// string (BuildPrompt does no randomness, no timestamps, no map iteration).
func TestBuildPromptDeterministic(t *testing.T) {
	const want = `You grade whether a code commit delivered what a developer asked an AI coding tool for. Return ONLY JSON {"delivered":[],"missed":[],"extra":[],"confidence":0-1,"notes":""}. Base every item on the evidence; if evidence is insufficient say so in notes and lower confidence.

## Developer prompt
add a retry to the upload client

## Commit
Subject: feat(upload): retry on transient failure
Tool: claude-code
Link status: committed

## Files changed (1)
+12 -3 internal/upload/client.go

## Edited hunks (1)
### internal/upload/client.go
+func retry() {}

`
	got := BuildPrompt(smallInput())
	if got != want {
		t.Fatalf("BuildPrompt mismatch\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}

	// Determinism: building the same Input again yields byte-identical output.
	got2 := BuildPrompt(smallInput())
	if got != got2 {
		t.Fatalf("BuildPrompt is not deterministic across calls")
	}
}

// TestBuildPromptOmitsTool pins that an empty Tool drops the "Tool:" line
// entirely rather than rendering it blank.
func TestBuildPromptOmitsTool(t *testing.T) {
	in := smallInput()
	in.Tool = ""
	got := BuildPrompt(in)
	if strings.Contains(got, "Tool:") {
		t.Fatalf("BuildPrompt with empty Tool should omit the Tool: line, got:\n%s", got)
	}
}

// TestBuildPromptCapsFiles pins the maxFiles bound (§4 W5a: "max 20 hunks /
// 200 files") and the omitted-count trace line.
func TestBuildPromptCapsFiles(t *testing.T) {
	in := smallInput()
	in.Files = nil
	for i := 0; i < maxFiles+37; i++ {
		in.Files = append(in.Files, FileStat{Path: "f.go", Added: 1})
	}
	got := BuildPrompt(in)
	if !strings.Contains(got, "## Files changed (237)") {
		t.Fatalf("expected the header to report the TRUE file count (237), got:\n%s", firstLines(got, 30))
	}
	if !strings.Contains(got, "...and 37 more files omitted") {
		t.Fatalf("expected an omitted-files trace line, got:\n%s", firstLines(got, 40))
	}
	if strings.Count(got, "f.go\n") != maxFiles {
		t.Fatalf("expected exactly %d file lines rendered, counted %d", maxFiles, strings.Count(got, "f.go\n"))
	}
}

// TestBuildPromptCapsHunks pins the maxHunks bound and per-hunk byte cap.
func TestBuildPromptCapsHunks(t *testing.T) {
	in := smallInput()
	in.Hunks = nil
	for i := 0; i < maxHunks+5; i++ {
		in.Hunks = append(in.Hunks, Hunk{Path: "f.go", Excerpt: "small change"})
	}
	got := BuildPrompt(in)
	if !strings.Contains(got, "## Edited hunks (25)") {
		t.Fatalf("expected the header to report the TRUE hunk count (25), got:\n%s", firstLines(got, 5))
	}
	if !strings.Contains(got, "...and 5 more hunks omitted") {
		t.Fatalf("expected an omitted-hunks trace line, got:\n%s", got)
	}
	if strings.Count(got, "### f.go") != maxHunks {
		t.Fatalf("expected exactly %d hunk headers rendered, counted %d", maxHunks, strings.Count(got, "### f.go"))
	}
}

// TestBuildPromptCapsHunkExcerptBytes pins the per-hunk maxHunkBytes cap
// (kept to a SINGLE hunk so the total-prompt bound below cannot also be
// the reason the excerpt was cut — this test isolates the per-hunk cap).
func TestBuildPromptCapsHunkExcerptBytes(t *testing.T) {
	in := smallInput()
	big := strings.Repeat("x", maxHunkBytes+500)
	in.Hunks = []Hunk{{Path: "internal/upload/client.go", Excerpt: big}}
	got := BuildPrompt(in)
	if strings.Contains(got, big) {
		t.Fatalf("a full %d-byte hunk excerpt rode into the prompt uncapped", len(big))
	}
	if !strings.Contains(got, truncationMarker) {
		t.Fatalf("expected the truncation marker in a capped hunk excerpt")
	}
}

// TestBuildPromptTotalBound pins the maxPromptBytes overall cap even when
// every per-section cap is individually respected (many small-but-not-
// individually-capped hunks can still sum past the total bound).
func TestBuildPromptTotalBound(t *testing.T) {
	in := smallInput()
	in.Hunks = nil
	for i := 0; i < maxHunks; i++ {
		in.Hunks = append(in.Hunks, Hunk{Path: "f.go", Excerpt: strings.Repeat("y", maxHunkBytes)})
	}
	got := BuildPrompt(in)
	if len(got) > maxPromptBytes {
		t.Fatalf("BuildPrompt exceeded maxPromptBytes: got %d bytes, want <= %d", len(got), maxPromptBytes)
	}
}

// TestBuildPromptPromptTextNotTruncatedWhenSmall guards against an
// over-eager truncator clipping a normal-sized prompt.
func TestBuildPromptPromptTextNotTruncatedWhenSmall(t *testing.T) {
	in := smallInput()
	got := BuildPrompt(in)
	if !strings.Contains(got, in.PromptText) {
		t.Fatalf("a small PromptText was unexpectedly altered")
	}
}

// TestTruncateBytesRuneSafe pins that truncateBytes never splits a
// multi-byte UTF-8 rune.
func TestTruncateBytesRuneSafe(t *testing.T) {
	s := strings.Repeat("héllo", 500) // multi-byte 'é' throughout
	got := truncateBytes(s, 100)
	if !utf8.ValidString(got) {
		t.Fatalf("truncateBytes produced invalid UTF-8: %q", got)
	}
	if len(got) > 100 {
		t.Fatalf("truncateBytes exceeded max: got %d bytes, want <= 100", len(got))
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
