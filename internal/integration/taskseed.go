package integration

import (
	"errors"
	"strings"
)

// taskseed.go declares how a launchable tool's interactive TUI takes a FIRST
// PROMPT on argv when the dashboard starts it with a task (the Code security
// page's "Fix with an agent", docs/plans/fix-findings-with-agent-plan-2026-11-13.md
// section 4). It is the same grounded seed shape the `--continue-from`
// launchers inject a handover with (cmd/observer/continuefrom.go
// promptInjection); cmd/observer/taskseed_pin_test.go parses every launcher's
// literal and fails when this table and the launcher disagree.
//
// It is a side table keyed by registry tool (the productLifecycles pattern),
// so adding it touched no registry row. The zero value TaskSeed{} is the
// honest floor: no grounded seed, the task is shown for the user to paste.
// Callers dispatch on TaskSeed.Kind, never on a tool name (CLAUDE.md #3).

// TaskSeedKind names where the prompt sits on the tool's argv.
type TaskSeedKind string

// The seed kinds.
const (
	// TaskSeedNone (zero value): the tool takes no grounded first prompt on
	// argv; the task is shown for pasting.
	TaskSeedNone TaskSeedKind = ""
	// TaskSeedLeadingPositional: the prompt is the first argument
	// (claude "<prompt>").
	TaskSeedLeadingPositional TaskSeedKind = "leading_positional"
	// TaskSeedTrailingPositional: the prompt is the last argument
	// (codex "<prompt>").
	TaskSeedTrailingPositional TaskSeedKind = "trailing_positional"
	// TaskSeedFlag: the prompt is the value of Flag (gemini -i "<prompt>").
	TaskSeedFlag TaskSeedKind = "flag"
)

// TaskSeed is one tool's first-prompt shape.
type TaskSeed struct {
	Kind TaskSeedKind
	// Flag is the flag that introduces the prompt; set only for TaskSeedFlag.
	Flag string
	// Note says why a launchable tool has no seed (TaskSeedNone). Required
	// for a launchable tool whose launcher does seed a handover, so the gap
	// is explained rather than silent (taskseed_test.go).
	Note string
}

// Seeds reports whether the tool takes the task on argv.
func (t TaskSeed) Seeds() bool { return t.Kind != TaskSeedNone }

// Wire is the seed's wire value: the kind, or "none".
func (t TaskSeed) Wire() string {
	if t.Kind == TaskSeedNone {
		return "none"
	}
	return string(t.Kind)
}

// taskSeeds is the table. Every row mirrors the tool's `--continue-from`
// promptInjection (taskseed_pin_test.go), except the rows with a Note.
var taskSeeds = map[string]TaskSeed{
	"claude-code":      {Kind: TaskSeedLeadingPositional},
	"codex":            {Kind: TaskSeedTrailingPositional},
	"cursor":           {Kind: TaskSeedTrailingPositional},
	"pi":               {Kind: TaskSeedTrailingPositional},
	"droid":            {Kind: TaskSeedTrailingPositional},
	"grok":             {Kind: TaskSeedTrailingPositional},
	"kiro-cli":         {Kind: TaskSeedTrailingPositional},
	"muse":             {Kind: TaskSeedTrailingPositional},
	"open-interpreter": {Kind: TaskSeedTrailingPositional},
	"command-code":     {Kind: TaskSeedTrailingPositional},
	"prime-agent":      {Kind: TaskSeedTrailingPositional},
	"mistral-code":     {Kind: TaskSeedTrailingPositional},
	"gemini-cli":       {Kind: TaskSeedFlag, Flag: "-i"},
	"copilot-cli":      {Kind: TaskSeedFlag, Flag: "-i"},
	"cline-cli":        {Kind: TaskSeedFlag, Flag: "-i"},
	"antigravity-cli":  {Kind: TaskSeedFlag, Flag: "-i"},
	"qoder":            {Kind: TaskSeedFlag, Flag: "-i"},
	"qwen-code":        {Kind: TaskSeedFlag, Flag: "-i"},
	"goose":            {Kind: TaskSeedFlag, Flag: "-t"},
	"opencode":         {Kind: TaskSeedFlag, Flag: "--prompt"},
	"kilo-code-cli":    {Kind: TaskSeedFlag, Flag: "--prompt"},
	"zcode":            {Kind: TaskSeedFlag, Flag: "--prompt"},
	// devin's prompt must follow a `--`, which `observer devin` itself reads
	// as the end of its own flags, so a fresh launch cannot pass it through.
	"devin": {Note: "the prompt must follow --, which the observer launcher reads as its own separator"},
	// openclaw seeds through its `chat --message` subcommand on the
	// --continue-from path only (run non-proxied); a fresh launch has no
	// grounded first-prompt form.
	"openclaw": {Note: "the first prompt is grounded only through `openclaw chat --message` on the handoff path"},
}

// TaskSeedFor returns tool's first-prompt shape (the zero value when it has
// none).
func TaskSeedFor(tool string) TaskSeed { return taskSeeds[tool] }

// MaxTaskPromptBytes bounds a task prompt on argv. Linux caps ONE argument at
// 128 KiB (MAX_ARG_STRLEN); the handoff seed's own bound is 100 KiB.
const MaxTaskPromptBytes = 64 << 10

// ErrTaskSeed is returned for a prompt TaskSeedArgs cannot place.
var ErrTaskSeed = errors.New("task prompt cannot be passed")

// TaskSeedArgs places prompt on args by seed's kind: first, last, or as the
// value of its flag (appended last). It refuses a tool with no seed, an empty
// prompt, a prompt that starts with '-' (it would read as a flag), one with
// a NUL byte, and one over MaxTaskPromptBytes. args is not modified.
func TaskSeedArgs(seed TaskSeed, args []string, prompt string) ([]string, error) {
	switch {
	case strings.TrimSpace(prompt) == "":
		return nil, errors.Join(ErrTaskSeed, errors.New("empty prompt"))
	case strings.HasPrefix(prompt, "-"):
		return nil, errors.Join(ErrTaskSeed, errors.New("a prompt may not start with -"))
	case strings.ContainsRune(prompt, 0):
		return nil, errors.Join(ErrTaskSeed, errors.New("NUL byte in prompt"))
	case len(prompt) > MaxTaskPromptBytes:
		return nil, errors.Join(ErrTaskSeed, errors.New("prompt too long"))
	}
	out := make([]string, 0, len(args)+2)
	switch seed.Kind {
	case TaskSeedLeadingPositional:
		out = append(append(out, prompt), args...)
	case TaskSeedTrailingPositional:
		out = append(append(out, args...), prompt)
	case TaskSeedFlag:
		if seed.Flag == "" {
			return nil, errors.Join(ErrTaskSeed, errors.New("flag seed without a flag"))
		}
		out = append(append(out, args...), seed.Flag, prompt)
	default:
		return nil, errors.Join(ErrTaskSeed, errors.New("tool has no first-prompt seed"))
	}
	return out, nil
}
