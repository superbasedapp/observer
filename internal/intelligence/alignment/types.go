package alignment

import "context"

// FileStat is one file the commit under grading touched, as a compact
// +added/-deleted line count (no content — the prompt only needs to show
// the judge the shape of the change, the hunks below carry the substance).
type FileStat struct {
	Path           string
	Added, Deleted int
}

// Hunk is one bounded excerpt of an AI-edited change that the commit under
// grading carried — sourced from actions.raw_tool_input for the linked
// edits (§3.6: "never re-reads the repo"). Excerpt is assumed already
// scrubbed by the caller; this package does no secret redaction itself
// (that is the store/proxy seam's job elsewhere in the codebase).
type Hunk struct {
	Path, Excerpt string
}

// Input is everything BuildPrompt needs to grade one prompt-to-commit link.
// PromptText and CommitSubject are assumed already scrubbed by the caller.
// LinkStatus is the R4 attribution status ("committed", "partial",
// "uncommitted", "superseded", "no_edits") the local heuristic (L tier,
// internal/projectroi) already computed — it is given to the judge as
// context, not asked of it. Tool is the AI tool that produced the prompt
// (e.g. "claude-code"), shown for context only.
type Input struct {
	PromptText    string
	CommitSubject string
	Files         []FileStat
	Hunks         []Hunk
	LinkStatus    string
	Tool          string
	// Authority is the prompt's session's data-authority classification
	// (internal/dataauthority.Authority's string value: "personal",
	// "org", or "" when the caller has not classified it, or the
	// classification lookup failed) — JUDGE-1, docs/security.md. This
	// package stays decoupled from the dataauthority package (kept as a
	// plain string, the same discipline as Tool); a Judge that wants to
	// enforce data-authority egress rules implements EgressGate and reads
	// this field back through its own dataauthority.Authority(in.Authority)
	// conversion.
	//
	// Grade itself does NOT special-case the empty string — it is simply
	// passed through to whatever EgressGate the Judge implements. This
	// package's own shipped gate
	// (cmd/observer/alignment_wire.go::alignmentJudgeAdapter.AllowInput,
	// via dataauthority.JudgeEgressAllowed) treats "" as "unknown," which
	// that package's convention folds into the SAME restrictive bucket as
	// AuthorityOrg (allowed only over loopback or an org-pinned judge
	// config). This is a deliberate FAIL-CLOSED default: a caller that has
	// not been wired to populate Authority, or whose classification
	// lookup errored, gets the org-strength gate rather than an
	// unconditional pass. The one-line hook a caller adds to populate a
	// real classification is:
	//
	//	in.Authority = string(classification.Authority) // from store.SessionAuthority
	Authority string
}

// Result is one grading verdict: which asked-for outcomes the commit
// delivered, which it missed, and what extra (unasked-for) changes rode
// along, plus the judge's own confidence and any caveat it wants to
// surface. Confidence is always in [0,1] — ParseResult clamps it.
type Result struct {
	Delivered  []string
	Missed     []string
	Extra      []string
	Confidence float64
	Notes      string
}

// Judge is the one thing this package needs injected: a single-turn LLM
// call that takes a prompt and returns the model's raw reply text. The
// host binds a concrete implementation (cmd/observer/alignment_wire.go);
// this package never dials out itself.
type Judge interface {
	Judge(ctx context.Context, prompt string) (string, error)
}
