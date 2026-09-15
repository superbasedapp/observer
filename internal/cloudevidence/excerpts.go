package cloudevidence

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// excerpts.go selects WHICH raw texts a bounded-context envelope may carry. It
// is PURE selection — it does not scrub and it does not decide whether content
// is allowed at all. Those two gates stay where they already are:
//
//   - the CONSENT gate is BuildEnvelope's `opts.hasPurpose(PurposeContextEnrichment)`
//     check: excerpts handed in under any other purpose are dropped on the floor;
//   - the SCRUB gate is boundExcerpts, which runs every selected text through the
//     injected scrubber and caps it.
//
// So this file's job is only to pick a small, deterministic, high-signal set and
// to keep harness noise out of it.

// ExcerptCapBytes is the per-excerpt pre-scrub byte cap this selection applies.
// It is deliberately far below cloudcontract.MaxExcerptBytes: a title/description
// needs the OPENING of a prompt, not a whole pasted document, and a tighter cap
// is a smaller disclosure for the same result quality.
const ExcerptCapBytes = 1024

// maxSpreadUserPrompts is how many FURTHER user prompts (past the first) are
// sampled across the session.
//
// 6 -> 14 on 2026-09-16 (operator ruling): the developer's own prompts are
// short and they are the DIRECTION of a session - the planning, the
// corrections, the "no, do it this way" - while the assistant text that
// brackets a session is mostly orientation (opening reads) and verification
// (closing test/lint runs). Spending the widened contract budget on prompts
// gives the model the intent; the structural sample already gives it the work.
const maxSpreadUserPrompts = 14

// maxErrorExcerpts is how many TOP failure classes (by occurrence count) may
// ride along, and maxErrorExcerptsTotal adds the one further slot the LAST
// observed class may occupy when it differs from both of them.
//
// EXCERPT BUDGET ARITHMETIC. 1 first prompt + maxSpreadUserPrompts further
// prompts + 1 final assistant message + maxErrorExcerptsTotal error classes
// must stay within cloudcontract.MaxContextExcerpts (12), so the priority order
// is never actually exercised as a DROP order for the error classes:
// 1 + 14 + 1 + 3 = 19 <= 20. TestExcerptBudgetFitsWithinTheContractBound pins it.
const (
	maxErrorExcerpts      = 2
	maxErrorExcerptsTotal = maxErrorExcerpts + 1
)

// ErrorClassCapBytes is the cap on an error excerpt. An error excerpt's text is
// a CLASS LABEL from the closed table below — never any part of the recorded
// message — so the cap only has to admit the longest label.
//
// WHY A CLASS AND NOT A HEADLINE (the F1 fix). A recorded tool-failure message
// is not a curated diagnostic: the hook copies the failing tool's own error
// BODY, which routinely embeds the command's captured stdout (`customer_balance
// =12345`, a row dump, a stack frame with a path). Tool output must never
// upload, and "just the first line, capped at 240 bytes" does not prevent that —
// a single-line stdout, or `Error: <stdout>`, is 240 bytes of tool output. So the
// message is never carried at ALL: it is only ever MATCHED against a pattern
// table, and what ships is the matched label. An unmatched message ships
// nothing.
const ErrorClassCapBytes = 64

// Excerpt source labels. They double as evidence refs
// (cloudcontract.AllowedEvidenceRefs admits every ContextExcerpt.Source), so the
// model can cite "first_user_prompt" and the citation is grounded.
//
// The labels are DEFINED in internal/cloudcontract (vocabulary.go) and only
// aliased here, the same way the error classes are, because the hosted
// out-of-purpose gate dispatches on SourceFirstUserPrompt
// (cloudcontract.Envelope.ContextIsFirstPromptOnly).
const (
	// SourceFirstUserPrompt is the session's first REAL user prompt — the one
	// excerpt the narrowed first_user_prompt_excerpt field class authorizes.
	SourceFirstUserPrompt = cloudcontract.ExcerptSourceFirstUserPrompt
	// SourceUserPrompt is a later user prompt sampled across the session.
	SourceUserPrompt = cloudcontract.ExcerptSourceUserPrompt
	// SourceFinalAssistantMessage is the last assistant message.
	SourceFinalAssistantMessage = cloudcontract.ExcerptSourceFinalAssistantMessage
	// SourceErrorClass is a CLOSED-VOCABULARY failure class derived from the
	// session's recorded tool-failure messages, with its occurrence COUNT. Its
	// Text is "<class> x<count>" — a label from the closed table plus an
	// integer, never a substring of any message. See ErrorClassCapBytes.
	SourceErrorClass = cloudcontract.ExcerptSourceErrorClass
	// SourceErrorClassLast is the class of the session's LAST observed failure,
	// carried in the same "<class> x<count>" form when it is not already one of
	// the top classes. The last failure is disproportionately informative — it
	// is usually the one the session ended on, or did not resolve — and ranking
	// purely by count hides it behind a noisy repeated class.
	SourceErrorClassLast = cloudcontract.ExcerptSourceErrorClassLast
)

// SessionTexts is the raw, node-local text substrate the store seam reads for
// one session. Every field is pre-scrub local content; nothing here reaches an
// envelope except through SelectExcerpts + the builder's scrubber.
type SessionTexts struct {
	// UserPrompts are the session's user-prompt texts in time order, including
	// harness-injected ones (filtering is this file's job, not the store's).
	UserPrompts []string
	// FinalAssistantMessage is the last non-empty assistant message.
	FinalAssistantMessage string
	// AssistantMessages contains bounded main-thread prose in time order.
	// Only the last entry is labelled final_assistant_message.
	AssistantMessages []string
	// Errors are recorded tool-failure messages in time order. Ignored when
	// ErrorTally is set.
	Errors []string
	// ErrorTally, when non-nil, IS the failure population — already classified
	// and counted by a streaming reader that never materialized the messages
	// (A8). It takes precedence over Errors, which is the in-memory form kept
	// for callers that already hold the population.
	ErrorTally *ErrorClassTally
}

// ExcerptSelection specifies explicit limits, including zero, for each source.
// UserMessages counts the first prompt as part of its total.
type ExcerptSelection struct {
	UserMessages, AssistantMessages, FailureClasses, Bytes int
}

// SelectExcerptsWithSettings applies explicit limits to the available text.
// Consent admission and scrubbing still happen in BuildEnvelope.
func SelectExcerptsWithSettings(texts SessionTexts, selection ExcerptSelection) []ExcerptInput {
	capBytes := max(128, min(selection.Bytes, ExcerptCapBytes))
	var out []ExcerptInput
	prompts := cleanedPrompts(texts.UserPrompts)
	if selection.UserMessages > 0 && len(prompts) > 0 {
		out = append(out, ExcerptInput{Source: SourceFirstUserPrompt, Text: prompts[0], CapBytes: capBytes})
		for _, p := range strideSample(prompts[1:], min(selection.UserMessages-1, cloudcontract.MaxContextExcerpts-1)) {
			out = append(out, ExcerptInput{Source: SourceUserPrompt, Text: p, CapBytes: capBytes})
		}
	}
	assistants := texts.AssistantMessages
	if len(assistants) == 0 && texts.FinalAssistantMessage != "" {
		assistants = []string{texts.FinalAssistantMessage}
	}
	start := max(0, len(assistants)-max(0, selection.AssistantMessages))
	for i := start; i < len(assistants); i++ {
		if body := strings.TrimSpace(assistants[i]); body != "" {
			source := "assistant_message"
			if i == len(assistants)-1 {
				source = SourceFinalAssistantMessage
			}
			out = append(out, ExcerptInput{Source: source, Text: body, CapBytes: capBytes})
		}
	}
	if selection.FailureClasses > 0 {
		var failures []ExcerptInput
		if texts.ErrorTally != nil {
			failures = texts.ErrorTally.Excerpts()
		} else {
			failures = selectErrorClasses(texts.Errors)
		}
		out = append(out, failures[:min(selection.FailureClasses, len(failures))]...)
	}
	return out[:min(len(out), cloudcontract.MaxContextExcerpts)]
}

// harnessPromptPrefixes marks a "user prompt" the HARNESS injected rather than
// one the developer typed: slash-command envelopes, the local-command caveat,
// and system reminders. They are noise for a title and would waste the bounded
// excerpt budget, so the first REAL prompt skips past them.
var harnessPromptPrefixes = []string{
	"<command-name>",
	"<command-message>",
	"<command-args>",
	"<local-command-caveat>",
	"<local-command-stdout>",
	"<local-command-stderr>",
	"<system-reminder>",
	"<user-prompt-submit-hook>",
}

// pasteBarPrefixes are the Claude Code paste-rendering line bars. They are
// STRIPPED, not skipped: a bar-prefixed prompt is the developer's real text,
// just rendered with a gutter.
var pasteBarPrefixes = []string{"▎", "│", "┃"}

// isHarnessPrompt reports whether a prompt text is a harness injection.
func isHarnessPrompt(text string) bool {
	t := strings.TrimSpace(text)
	for _, p := range harnessPromptPrefixes {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	return false
}

// stripPasteBars removes a leading paste-gutter bar from every line and trims
// the result. It never removes content, only the rendering gutter.
func stripPasteBars(text string) string {
	lines := strings.Split(text, "\n")
	for i, ln := range lines {
		trimmed := strings.TrimLeft(ln, " \t")
		for _, bar := range pasteBarPrefixes {
			if strings.HasPrefix(trimmed, bar) {
				trimmed = strings.TrimPrefix(trimmed, bar)
				trimmed = strings.TrimPrefix(trimmed, " ")
				break
			}
		}
		lines[i] = trimmed
	}
	return strings.TrimSpace(strings.Join(lines, "\n"))
}

// cleanPromptText normalizes one candidate prompt: paste bars stripped, edges
// trimmed. An empty result means "nothing usable here".
func cleanPromptText(text string) string {
	return stripPasteBars(text)
}

// dedupeKeyBytes is how much of a cleaned text the dedupe key covers. Adapters
// commonly record the SAME prompt twice (a hook row with a short target and a
// watcher row with the full body), so two texts sharing a long prefix are the
// same prompt and only one may spend excerpt budget.
const dedupeKeyBytes = 160

// dedupeKey returns the comparison key for a cleaned text.
func dedupeKey(s string) string {
	key := strings.Join(strings.Fields(s), " ")
	if len(key) > dedupeKeyBytes {
		key = key[:dedupeKeyBytes]
	}
	return key
}

// SelectExcerpts picks the bounded, deterministic excerpt set for a session, in
// a FIXED priority order:
//
//  1. the first REAL user prompt              (source first_user_prompt)
//  2. up to 14 further user prompts, evenly   (source user_prompt)
//     strided across the remaining prompts
//     (every one of them when there are at most 14; first and last of the
//     remainder always kept when there are more)
//  3. the final assistant message             (source final_assistant_message)
//  4. the 2 most frequent failure CLASSES     (source error_class)
//     with their counts, plus the LAST        (source error_class_last)
//     observed class when it differs
//
// The order is also the DROP order: the builder caps the list at
// MaxContextExcerpts by truncating the tail, so the first prompt can never be
// the thing that falls off. titleOnly returns just step 1 — the exact set the
// narrowed first_user_prompt_excerpt field class authorizes.
//
// It NEVER emits a command, a tool output, a file body, or a path. Prompt text
// and assistant prose are carried (scrubbed and capped by the builder); a
// recorded error message is only ever CLASSIFIED, never carried.
func SelectExcerpts(texts SessionTexts, titleOnly bool) []ExcerptInput {
	prompts := cleanedPrompts(texts.UserPrompts)
	out := make([]ExcerptInput, 0, cloudcontract.MaxContextExcerpts)
	if len(prompts) > 0 {
		out = append(out, ExcerptInput{Source: SourceFirstUserPrompt, Text: prompts[0], CapBytes: ExcerptCapBytes})
	}
	if titleOnly {
		return out
	}
	for _, p := range strideSample(prompts[minInt(1, len(prompts)):], maxSpreadUserPrompts) {
		out = append(out, ExcerptInput{Source: SourceUserPrompt, Text: p, CapBytes: ExcerptCapBytes})
	}
	if final := strings.TrimSpace(texts.FinalAssistantMessage); final != "" {
		out = append(out, ExcerptInput{Source: SourceFinalAssistantMessage, Text: final, CapBytes: ExcerptCapBytes})
	}
	if texts.ErrorTally != nil {
		out = append(out, texts.ErrorTally.Excerpts()...)
	} else {
		out = append(out, selectErrorClasses(texts.Errors)...)
	}
	if len(out) > cloudcontract.MaxContextExcerpts {
		out = out[:cloudcontract.MaxContextExcerpts]
	}
	return out
}

// cleanedPrompts drops harness injections and duplicates, preserving order.
func cleanedPrompts(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		if isHarnessPrompt(raw) {
			continue
		}
		text := cleanPromptText(raw)
		if text == "" {
			continue
		}
		key := dedupeKey(text)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, text)
	}
	return out
}

// strideSample returns at most max items evenly strided across in, always
// including the first and (when max > 1) the last. It is the same deterministic
// rule the action sampler uses, so "a spread across the whole session" means
// one thing everywhere.
func strideSample[T any](in []T, max int) []T {
	if max <= 0 || len(in) == 0 {
		return nil
	}
	if len(in) <= max {
		return in
	}
	if max == 1 {
		return in[:1]
	}
	out := make([]T, 0, max)
	n := len(in)
	for i := 0; i < max; i++ {
		out = append(out, in[i*(n-1)/(max-1)])
	}
	return out
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// -- failure classification (closed vocabulary) -------------------------------

// The failure classes. This list IS the vocabulary: an error excerpt's text is
// always exactly one of these strings (plus an integer count), so no byte of a
// recorded message can ever ride out on this lane. A message matching none of
// them yields "" and is OMITTED — an honest silence is the only safe fallback,
// because the fallback "ship the message" is the whole defect.
//
// The labels are DEFINED in internal/cloudcontract (vocabulary.go) and only
// aliased here, so the hosted prompt that explains them to the model reads the
// same list this file emits from — see cloudcontract.ErrorClasses() (N5).
const (
	ErrorClassExitCodeNonzero  = cloudcontract.ErrorClassExitCodeNonzero
	ErrorClassTimeout          = cloudcontract.ErrorClassTimeout
	ErrorClassFileNotFound     = cloudcontract.ErrorClassFileNotFound
	ErrorClassPermissionDenied = cloudcontract.ErrorClassPermissionDenied
	ErrorClassFileTooLarge     = cloudcontract.ErrorClassFileTooLarge
	ErrorClassSyntaxError      = cloudcontract.ErrorClassSyntaxError
	ErrorClassTestFailure      = cloudcontract.ErrorClassTestFailure
	ErrorClassNetworkError     = cloudcontract.ErrorClassNetworkError
	ErrorClassRateLimited      = cloudcontract.ErrorClassRateLimited
)

// errorClassRule is one row of the classification table: the label that ships
// and the lowercase phrases that select it. The PHRASES are only ever compared
// against; they are never emitted, and neither is the text they matched.
type errorClassRule struct {
	class   string
	phrases []string
}

// errorClassRules is ORDERED — the first matching row wins — so a SPECIFIC
// class always precedes a class whose phrases a specific failure also mentions.
//
// WHY THIS ORDER (the N8 fix). network_error used to sit above test_failure and
// syntax_error, so a Go test failure whose output mentioned a refused connection
// ("--- FAIL: TestDial … connection refused") classified as a NETWORK error: the
// most specific and most useful signal in the corpus, silently relabelled as
// infrastructure noise. The rule is now explicit: the classes that name WHAT
// FAILED (a test, a parse, a size refusal, a rate limit) come before the classes
// that name a TRANSPORT or an EXIT CODE, which almost any failure can mention in
// passing.
//
// Two phrase sets were also over-broad. Bare "dns" matched any message
// containing the substring (a hostname, a path segment, `--dns-timeout`), and
// "429 " matched any message with that number followed by a space (a byte
// offset, a line number, a duration). Both are now spelled out.
var errorClassRules = []errorClassRule{
	{ErrorClassRateLimited, []string{
		"rate limit", "rate_limit", "too many requests", "quota exceeded",
		"status 429", "http 429", "(429)", "429:",
	}},
	{ErrorClassFileTooLarge, []string{
		"exceeds maximum allowed size", "file too large", "too large to read",
		"maximum allowed size", "exceeds the maximum", "efbig",
	}},
	{ErrorClassTestFailure, []string{
		"--- fail", "test failed", "tests failed", "assertion", "assertionerror",
		"failing test", "expected but got", "fail:",
	}},
	{ErrorClassSyntaxError, []string{
		"syntax error", "parse error", "unexpected token", "invalid syntax",
		"compile error", "compilation failed", "cannot parse", "unexpected eof",
	}},
	{ErrorClassTimeout, []string{
		"timed out", "timeout", "deadline exceeded", "etimedout",
	}},
	{ErrorClassPermissionDenied, []string{
		"permission denied", "access denied", "eacces", "eperm",
		"operation not permitted", "not permitted", "forbidden", "unauthorized",
	}},
	{ErrorClassFileNotFound, []string{
		"no such file", "enoent", "not found", "does not exist", "cannot find",
		"could not find", "no such directory",
	}},
	{ErrorClassNetworkError, []string{
		"connection refused", "connection reset", "econnrefused", "econnreset",
		"network is unreachable", "no route to host", "tls handshake",
		"i/o timeout", "dns resolution", "no such host", "name resolution",
		"eai_again",
	}},
	{ErrorClassExitCodeNonzero, []string{
		"exit code", "exit status", "exited with", "non-zero", "nonzero exit",
		"command failed",
	}},
}

// errorClassVocabulary returns the closed set of labels this file may emit. It
// is derived from the CONTRACT's vocabulary, not from the rule table, so a rule
// row that invented a label of its own would fail the membership test rather
// than quietly widening the vocabulary.
func errorClassVocabulary() map[string]bool {
	classes := cloudcontract.ErrorClasses()
	out := make(map[string]bool, len(classes))
	for _, c := range classes {
		out[c] = true
	}
	return out
}

// classifyErrorMessage walks the ordered table and returns the FIRST matching
// class label, or "" when nothing matches (the message is then omitted). The
// message itself is only lowercased for comparison — it is never returned, in
// whole or in part.
func classifyErrorMessage(msg string) string {
	lower := strings.ToLower(msg)
	if strings.TrimSpace(lower) == "" {
		return ""
	}
	for _, r := range errorClassRules {
		for _, p := range r.phrases {
			if strings.Contains(lower, p) {
				return r.class
			}
		}
	}
	return ""
}

// errorClassCount is one failure class, how many of the session's recorded
// failures matched it, and where it first appeared (a deterministic tie-break).
type errorClassCount struct {
	class string
	count int
	first int
}

// tallyErrorClasses classifies EVERY message it is given and returns the
// per-class counts (in first-appearance order) plus the class of the LAST
// classifiable message.
//
// WHY THE WHOLE POPULATION (the Q1 honesty fix). The store used to hand over
// only the EARLIEST 8 failure rows, and the selector kept the first 2 distinct
// classes it saw with no counts at all. On a session with 300 failures that is
// not a summary of the session's failures — it is a summary of its first eight,
// which is exactly the sample bias the action sampler was fixed for. A class
// that occurred once in the opening minute outranked one that occurred 200
// times, and the model was given no way to tell the difference. Counting the
// whole (bounded) population and shipping the count costs one integer per class
// and still uploads no message byte.
func tallyErrorClasses(msgs []string) (counts []errorClassCount, last string) {
	var t ErrorClassTally
	for _, m := range msgs {
		t.Add(m)
	}
	return t.counts, t.last
}

// ErrorClassTally accumulates failure classes over a STREAM of recorded failure
// messages, keeping only the per-class counters — never the messages.
//
// It exists so the whole failure population can be classified without being
// materialized (A8). The counts were previously computed over a head+tail window
// of the population and then presented as whole-session facts, so a session
// whose DOMINANT failure class lived in the omitted middle reported a
// distribution that was simply not its own. A streaming tally has no window and
// no cap: memory is this struct, whose size is the number of DISTINCT classes —
// at most the nine in the closed vocabulary.
type ErrorClassTally struct {
	counts []errorClassCount
	index  map[string]int
	last   string
}

// Add classifies one recorded failure message and folds it in. The message
// itself is never retained — only the class it matched, and only as a counter.
// A message matching no class is silently skipped, as it always was.
func (t *ErrorClassTally) Add(msg string) {
	class := classifyErrorMessage(msg)
	if class == "" {
		return
	}
	t.last = class
	if t.index == nil {
		t.index = make(map[string]int, len(errorClassRules))
	}
	if i, ok := t.index[class]; ok {
		t.counts[i].count++
		return
	}
	t.index[class] = len(t.counts)
	t.counts = append(t.counts, errorClassCount{class: class, count: 1, first: len(t.counts)})
}

// Excerpts returns the bounded error-class excerpts for everything added so far.
func (t *ErrorClassTally) Excerpts() []ExcerptInput {
	return rankErrorClasses(t.counts, t.last)
}

// selectErrorClasses returns the bounded error-class excerpts for a session: the
// maxErrorExcerpts most FREQUENT classes, plus the LAST observed class when it
// is neither of them. Ranking is by count descending, ties broken by first
// appearance, so two builds of an unchanged session always select the same set
// in the same order.
func selectErrorClasses(msgs []string) []ExcerptInput {
	counts, last := tallyErrorClasses(msgs)
	return rankErrorClasses(counts, last)
}

// rankErrorClasses is the shared ranking + rendering both the in-memory and the
// streaming tally end in, so a streamed session and a materialized one produce
// the same excerpts from the same population.
func rankErrorClasses(counts []errorClassCount, last string) []ExcerptInput {
	if len(counts) == 0 {
		return nil
	}
	ranked := append([]errorClassCount(nil), counts...)
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].count != ranked[j].count {
			return ranked[i].count > ranked[j].count
		}
		return ranked[i].first < ranked[j].first
	})
	if len(ranked) > maxErrorExcerpts {
		ranked = ranked[:maxErrorExcerpts]
	}
	out := make([]ExcerptInput, 0, maxErrorExcerptsTotal)
	chosen := make(map[string]bool, len(ranked))
	for _, c := range ranked {
		chosen[c.class] = true
		out = append(out, ExcerptInput{
			Source:   SourceErrorClass,
			Text:     formatErrorClass(c.class, c.count),
			CapBytes: ErrorClassCapBytes,
		})
	}
	if last != "" && !chosen[last] {
		for _, c := range counts {
			if c.class != last {
				continue
			}
			out = append(out, ExcerptInput{
				Source:   SourceErrorClassLast,
				Text:     formatErrorClass(c.class, c.count),
				CapBytes: ErrorClassCapBytes,
			})
			break
		}
	}
	return out
}

// formatErrorClass renders one class + count as "<class> x<count>". The output
// is a closed-vocabulary label, a space, an 'x' and an integer — there is no
// position in it that a recorded message could occupy.
func formatErrorClass(class string, count int) string {
	return class + " x" + refIndex(count)
}
