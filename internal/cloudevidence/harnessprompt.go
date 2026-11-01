package cloudevidence

import "strings"

// harnessprompt.go recognises "user prompts" the HARNESS wrote (T-966). An AI
// coding tool records some of its own messages on the user's channel: Claude
// Code delivers a background task's completion as a `<task-notification>`
// user turn, another agent's hand-back as `<agent-message from="...">`, the
// IDE's open file as `<ide_opened_file>`, a `!` shell run as `<bash-stdout>`.
// The UserPromptSubmit hook and the transcript both record them as
// user_prompt rows (11,134 of them on the operator's node on 2026-10-24, most
// of them task notifications).
//
// They are not the developer's words, and they routinely carry local paths,
// request ids and command output. So two rules follow, both owned here:
//
//   - an injected message is NEVER an excerpt (cleanedPrompts skips it);
//   - it does not count as user_prompt in the activity mix or the action
//     sample; it is re-labelled to the closest existing action kind
//     (ReclassifyPromptKind, HarnessPromptTally).
//
// The fix lives at the evidence boundary rather than in the adapters on
// purpose: the stored rows stay as captured (every other reader is unchanged)
// and the 11,134 rows already on disk are handled too.

// harnessPromptRule is one row of the ordered recognition table: a message
// whose leading tag is Tag was written by the harness, and Kind is the action
// kind it is counted as instead of user_prompt.
type harnessPromptRule struct {
	Tag  string
	Kind string
}

// Kinds an injected message is re-labelled to. All three are members of
// knownActionKinds, so the activity mix keeps them as themselves.
const (
	harnessKindTaskEvent     = "task_event"
	harnessKindAgentMessage  = "agent_message"
	harnessKindPromptContext = "prompt_context"
)

// harnessPromptRules is the recognition table. A tag matches only as a whole
// leading element name (`<tag>`, `<tag attr=...>` or `<tag/>`), never as a
// prefix of a longer name. The grounding counts are the operator's node on
// 2026-10-24 (user_prompt rows whose text starts with the tag).
var harnessPromptRules = []harnessPromptRule{
	// Background task completions (8,800).
	{"task-notification", harnessKindTaskEvent},
	// Another agent's hand-back, `<agent-message from="...">` (985).
	{"agent-message", harnessKindAgentMessage},
	// Harness context injections.
	{"system-reminder", harnessKindPromptContext},                     // 1,588
	{"local-command-caveat", harnessKindPromptContext},                // 533
	{"command-name", harnessKindPromptContext},                        // 532 (slash-command envelope)
	{"command-message", harnessKindPromptContext},                     // 9
	{"command-args", harnessKindPromptContext},                        // slash-command envelope
	{"local-command-stdout", harnessKindPromptContext},                // 205 (command output)
	{"local-command-stderr", harnessKindPromptContext},                // command output
	{"fork-boilerplate", harnessKindPromptContext},                    // 88
	{"bash-input", harnessKindPromptContext},                          // 33 (a `!` shell command)
	{"bash-stdout", harnessKindPromptContext},                         // 33 (command output)
	{"bash-stderr", harnessKindPromptContext},                         // command output
	{"in-app-browser-context", harnessKindPromptContext},              // 30
	{"artifact-content-authored-by-others", harnessKindPromptContext}, // 24
	{"ide_opened_file", harnessKindPromptContext},                     // 11
	{"ide_selection", harnessKindPromptContext},                       // 1
	{"uploaded_files", harnessKindPromptContext},                      // 4 (attachment listing)
	{"codex_delegation", harnessKindPromptContext},                    // 1 (a parent agent's brief)
	{"user-prompt-submit-hook", harnessKindPromptContext},
}

// harnessPromptTextPrefixes are injected messages that do not open with a tag.
var harnessPromptTextPrefixes = []harnessPromptRule{
	{"Caveat: the messages below", harnessKindPromptContext},
}

// HarnessPromptKind reports whether a user-prompt text was written by the
// harness and, when it was, the action kind it should be counted as. Only the
// opening of the text is inspected, so a 64-byte head is enough.
func HarnessPromptKind(text string) (kind string, injected bool) {
	t := strings.TrimSpace(text)
	if name, ok := leadingTagName(t); ok {
		for _, r := range harnessPromptRules {
			if name == r.Tag {
				return r.Kind, true
			}
		}
	}
	for _, r := range harnessPromptTextPrefixes {
		if strings.HasPrefix(t, r.Tag) {
			return r.Kind, true
		}
	}
	return "", false
}

// leadingTagName returns the element name of a text that opens with `<name`
// followed by `>`, whitespace or `/`. It does not parse XML; it only names the
// opening element so the table compares whole names.
func leadingTagName(t string) (string, bool) {
	if !strings.HasPrefix(t, "<") {
		return "", false
	}
	rest := t[1:]
	end := strings.IndexAny(rest, "> \t\r\n/")
	if end <= 0 {
		return "", false
	}
	return rest[:end], true
}

// ReclassifyPromptKind returns the kind an action is counted as: a user_prompt
// the harness wrote takes its table kind, everything else keeps its own.
func ReclassifyPromptKind(kind, text string) string {
	if kind != userPromptKind {
		return kind
	}
	if k, ok := HarnessPromptKind(text); ok {
		return k
	}
	return kind
}

// userPromptKind is the action kind HarnessPromptTally re-labels from.
const userPromptKind = "user_prompt"

// HarnessPromptTally counts, over a STREAM of a session's user_prompt texts,
// how many were written by the harness and what each is counted as instead.
// It keeps only counters (the texts are never retained), so it can see the
// whole population the way OutcomeTally and ErrorClassTally do.
type HarnessPromptTally struct {
	moved map[string]int
}

// Add classifies one user_prompt text (its opening is enough).
func (t *HarnessPromptTally) Add(text string) {
	kind, ok := HarnessPromptKind(text)
	if !ok {
		return
	}
	if t.moved == nil {
		t.moved = make(map[string]int, 3)
	}
	t.moved[kind]++
}

// Reclassify moves the counted injected messages out of the mix's user_prompt
// entry into their own kinds. It never takes user_prompt below zero (a tally
// larger than the entry moves only what the entry holds), drops a user_prompt
// entry that reaches zero, and leaves the input slice unmodified.
func (t *HarnessPromptTally) Reclassify(mix []ActivityMixInput) []ActivityMixInput {
	if len(t.moved) == 0 {
		return mix
	}
	out := make([]ActivityMixInput, 0, len(mix)+len(t.moved))
	available := 0
	for _, e := range mix {
		if e.Kind == userPromptKind {
			available += e.Count
		}
	}
	// Deterministic order over the closed set of target kinds.
	moves := make([]ActivityMixInput, 0, len(t.moved))
	for _, k := range []string{harnessKindTaskEvent, harnessKindAgentMessage, harnessKindPromptContext} {
		n := min(t.moved[k], available)
		if n <= 0 {
			continue
		}
		available -= n
		moves = append(moves, ActivityMixInput{Kind: k, Count: n})
	}
	for _, e := range mix {
		if e.Kind == userPromptKind {
			if available > 0 {
				out = append(out, ActivityMixInput{Kind: userPromptKind, Count: available})
				available = 0
			}
			continue
		}
		out = append(out, e)
	}
	return append(out, moves...)
}
