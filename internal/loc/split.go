package loc

// split.go is the ONE derivation of "how much of the AI-authored text was
// code, and how much was comments" (operator ask 2026-09-28: "often most of
// the changed lines are comments; we need a sense of code generated vs
// comments generated"). Every surface that shows AI lines - the node
// session card, the Sessions list, the Projects list/detail/commit ledger,
// the lines-per-dollar tile, the org People/Person/Project/session drawer
// and the org trend - obtains its code/comment/share triple from
// SplitAuthored, never from its own arithmetic, so the node and org
// dashboards cannot disagree about what "comment share" means.
//
// THE DEFINITION, stated once:
//
//   - CodeLines    = added_code + modified_code (a one-line code
//     replacement counts once; deletions are never summed in - this is
//     authorship, not churn).
//   - CommentLines = added_comment. There is no modified_comment bucket
//     (a comment replaced by a comment books as one deleted_comment plus
//     one added_comment), so added_comment already covers rewritten
//     comments; deleted_comment is removal, not authorship.
//   - CommentShare = CommentLines / (CodeLines + CommentLines), a
//     fraction in [0,1]. Absent (nil) when both are zero - "no authored
//     lines" is not "0% comments".
//
// Blank, whitespace-only and unknown lines are in NEITHER number. They are
// reported by their own buckets where a surface shows them; folding them
// into either side would let a reindent or an unparsable input move the
// share.
//
// WHAT THIS SHARE IS NOT. It is the comment share of AI-authored lines,
// which needs no human measurement at all. It is never an AI-vs-human
// share: that one stays forbidden wherever human_capture is "none"
// (docs/loc-tracking.md).

// AuthoredSplit is the code-vs-comment split of one scope's authored lines.
type AuthoredSplit struct {
	// CodeLines is added + modified code lines.
	CodeLines int64 `json:"code_lines"`
	// CommentLines is added comment lines.
	CommentLines int64 `json:"comment_lines"`
	// CommentShare is CommentLines / (CodeLines + CommentLines), in [0,1].
	// Nil when both counts are zero, so a consumer can never render an
	// empty scope as "0% comments".
	CommentShare *float64 `json:"comment_share,omitempty"`
}

// SplitAuthored builds the split from the two authored-line counts. A
// negative input (which no store read produces) is clamped to zero rather
// than allowed to push the share outside [0,1].
func SplitAuthored(codeLines, commentLines int64) AuthoredSplit {
	if codeLines < 0 {
		codeLines = 0
	}
	if commentLines < 0 {
		commentLines = 0
	}
	out := AuthoredSplit{CodeLines: codeLines, CommentLines: commentLines}
	if total := codeLines + commentLines; total > 0 {
		share := float64(commentLines) / float64(total)
		out.CommentShare = &share
	}
	return out
}

// Add returns the split of the two scopes' combined counts - the share is
// recomputed from the summed counts, never averaged from the two shares.
func (a AuthoredSplit) Add(b AuthoredSplit) AuthoredSplit {
	return SplitAuthored(a.CodeLines+b.CodeLines, a.CommentLines+b.CommentLines)
}

// AuthoredSplit returns the split for one bucket set: code = AddedCode +
// ModifiedCode, comment = AddedComment. The caller is responsible for
// passing only category=code buckets (docs/config lines are counted but
// never code, docs/loc-tracking.md "Categories").
func (s Stats) AuthoredSplit() AuthoredSplit {
	return SplitAuthored(int64(s.AddedCode+s.ModifiedCode), int64(s.AddedComment))
}
