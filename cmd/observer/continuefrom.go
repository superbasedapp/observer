// continuefrom.go — shared `--continue-from` plumbing for the launcher
// subcommands (observer claude / codex …). It runs a session handoff for
// THIS launcher's own tool (delivery=inject_prompt, plan §10) and returns
// the rendered handover doc to seed as the tool's first user prompt.

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/handoff"
	"github.com/marmutapp/superbased-observer/internal/handoffsvc"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// continueFromMaxPromptBytes bounds how much handover text is inlined as
// the launched tool's first prompt. A distilled_tail doc is a few KB; a
// `full` carry can be tens of KB. Linux argv is ~2MB/arg so the value is a
// sanity bound, not a hard OS limit: past it the launcher injects a short
// pointer prompt (still carrying the handoff marker for the P3 linker) and
// leaves the full doc on disk.
const continueFromMaxPromptBytes = 100 * 1024

// continueFromOutcome is what a launcher needs to seed a `--continue-from`
// session: the prompt text plus enough context to print an honest note.
type continueFromOutcome struct {
	Prompt   string // text to prepend/append as the tool's first prompt
	DocPath  string // on-disk HANDOFF-*.md (always written)
	ShortID  string // handoff short id (the marker id)
	Degraded bool   // true when Prompt is the pointer, not the full doc
	Note     string // svc DegradeReason (e.g. metadata-carry fallback), "" when none
	// ProjectRoot is the source session's project root, RESOLVED to a path
	// reachable from this (the daemon's) OS — the handoff service already
	// translated a foreign-OS root (`C:\proj` -> `/mnt/c/proj`). The
	// launcher starts the continued tool in this directory so a cross-OS
	// continuation lands in the real project folder, not the daemon's cwd.
	ProjectRoot string
}

// resolveContinueFrom runs one handoff for the launcher's own tool with
// the inject_prompt delivery lane and returns the first-prompt text. It
// opens AND closes its own DB handle (via loadConfigAndDB's cleanup) so
// nothing leaks into the launched child's lifetime — the prompt text is
// fully materialized before the handle closes.
//
// tool is the TARGET tool's canonical registry name (e.g. "claude-code",
// "codex"); the svc validates the inject_prompt lane against that tool's
// grounded HandoffCapability, so a launcher for a tool that does not
// declare InjectPrompt errors honestly rather than silently no-op'ing.
func resolveContinueFrom(ctx context.Context, configPath, sessionID, tool, carry string, fork handoff.ForkPoint) (continueFromOutcome, error) {
	if strings.TrimSpace(sessionID) == "" {
		return continueFromOutcome{}, fmt.Errorf("--continue-from requires a source session id")
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return continueFromOutcome{}, err
	}
	defer cleanup()

	run := handoffRunner(cfg, database)
	res, err := run(ctx, handoffsvc.Request{
		SessionID:  sessionID,
		TargetTool: tool,
		Fork:       fork,
		Carry:      handoff.CarryMode(carry),
		Delivery:   integration.InjectPrompt,
	})
	if err != nil {
		return continueFromOutcome{}, err
	}

	// The injected prompt is passed as a single argv string to the launched
	// tool (e.g. `agy -i "<prompt>"`), so it is bounded by the OS per-arg
	// limit (Linux MAX_ARG_STRLEN = 128KB); a larger prompt fails exec with
	// E2BIG. So EVERY carry mode — including full_cache, whose un-excerpted
	// doc routinely runs to hundreds of KB — degrades to a pointer past
	// continueFromMaxPromptBytes: the full content lives in the on-disk
	// HANDOFF doc and the prompt tells the tool to read it first (which
	// loads the source read cache into the new session all the same).
	prompt := buildInjectedPrompt(res.Doc, res.DocPath, continueFromMaxPromptBytes)
	return continueFromOutcome{
		Prompt:      prompt,
		DocPath:     res.DocPath,
		ShortID:     res.ShortID,
		Degraded:    prompt != res.Doc,
		Note:        res.DegradeReason,
		ProjectRoot: res.ProjectRoot,
	}, nil
}

// resolveContinueFromDoc runs one handoff for the launcher's own tool with
// the FILE delivery lane and returns the on-disk HANDOFF-<shortid>.md path
// (no prompt text). It is the seam for a LaunchDocAssisted launcher — a tool
// whose interactive TUI takes no initial-prompt seed (hermes) — where the
// handover is delivered as a file the user references/pastes rather than
// injected as an argument. It opens AND closes its own DB handle, so nothing
// leaks into the launched child's lifetime.
func resolveContinueFromDoc(ctx context.Context, configPath, sessionID, tool, carry string, fork handoff.ForkPoint) (continueFromOutcome, error) {
	if strings.TrimSpace(sessionID) == "" {
		return continueFromOutcome{}, fmt.Errorf("--continue-from requires a source session id")
	}
	cfg, database, cleanup, err := loadConfigAndDB(ctx, configPath)
	if err != nil {
		return continueFromOutcome{}, err
	}
	defer cleanup()

	run := handoffRunner(cfg, database)
	res, err := run(ctx, handoffsvc.Request{
		SessionID:  sessionID,
		TargetTool: tool,
		Fork:       fork,
		Carry:      handoff.CarryMode(carry),
		Delivery:   integration.InjectFile,
	})
	if err != nil {
		return continueFromOutcome{}, err
	}
	return continueFromOutcome{
		DocPath:     res.DocPath,
		ShortID:     res.ShortID,
		Note:        res.DegradeReason,
		ProjectRoot: res.ProjectRoot,
	}, nil
}

// launchDir returns projectRoot when it names a directory reachable from
// this process, else "" (an empty exec.Cmd.Dir inherits the caller's cwd).
// It is the stat-gate that keeps a `--continue-from` launch from chdir-ing
// into an unreachable path — e.g. a foreign-OS root that translation could
// not map to a live mount — so a launch never breaks on a bad project root,
// it just falls back to inheriting the current directory.
func launchDir(projectRoot string) string {
	if projectRoot == "" {
		return ""
	}
	if fi, err := os.Stat(projectRoot); err == nil && fi.IsDir() { //nolint:gosec // G703: a metadata read of the user's own local path; no privilege boundary is crossed
		return projectRoot
	}
	return ""
}

// buildInjectedPrompt returns the text to seed as the tool's first prompt:
// the full handover doc when it fits within maxBytes, else a short pointer
// prompt telling the tool to read the on-disk file (the doc is written
// regardless). The pointer keeps the leading `<!-- superbased-handoff … -->`
// marker line so the P3 target-session linker still finds it in the target
// transcript. maxBytes <= 0 disables the bound (inline always).
func buildInjectedPrompt(doc, docPath string, maxBytes int) string {
	if maxBytes <= 0 || len(doc) <= maxBytes {
		return doc
	}
	var b strings.Builder
	if m := handoffMarkerLine(doc); m != "" {
		b.WriteString(m)
		b.WriteString("\n\n")
	}
	fmt.Fprintf(&b,
		"This session continues a previous one. A full handover document - a distilled, "+
			"priced session handover reported from the source tool - was written to %s. "+
			"Read that file first before continuing; it was too large to inline here.",
		docPath)
	return b.String()
}

// handoffMarkerLine returns the leading `<!-- superbased-handoff … -->`
// line of a rendered handover doc, or "" when the doc does not start with
// one (defensive — RenderMarkdown always emits it when a short id is set).
func handoffMarkerLine(doc string) string {
	line := doc
	if i := strings.IndexByte(doc, '\n'); i >= 0 {
		line = doc[:i]
	}
	if strings.HasPrefix(strings.TrimSpace(line), "<!-- superbased-handoff") {
		return strings.TrimRight(line, "\r")
	}
	return ""
}

// forkFromFlags builds a handoff.ForkPoint from the shared --from-message /
// --from-time launcher flags (mirrors the `observer handoff` verb). The
// zero value (both unset) means "fork at the last message".
func forkFromFlags(fromMessage int, fromTime string) (handoff.ForkPoint, error) {
	if fromMessage > 0 && fromTime != "" {
		return handoff.ForkPoint{}, fmt.Errorf("--from-message and --from-time are mutually exclusive")
	}
	if fromMessage > 0 {
		return handoff.ForkPoint{Kind: handoff.ForkMessageIndex, MessageIndex: fromMessage}, nil
	}
	if fromTime != "" {
		t, err := time.Parse(time.RFC3339, fromTime)
		if err != nil {
			return handoff.ForkPoint{}, fmt.Errorf("--from-time must be RFC3339 (e.g. 2026-07-03T10:00:00Z): %w", err)
		}
		return handoff.ForkPoint{Kind: handoff.ForkTime, Time: t}, nil
	}
	return handoff.ForkPoint{}, nil
}

// forwardedPromptConflict reports whether the user-forwarded launcher args
// appear to already carry a positional prompt, which would collide with the
// handover the --continue-from injection seeds as the first prompt.
//
// The check is deliberately grammar-light (we do not embed each tool's full
// flag table): a token is treated as a candidate positional prompt when it
// (a) does not start with "-", (b) contains no "=" (so `-c key=value` style
// values and `--flag=value` values are skipped), and (c) is not a known
// subcommand token (e.g. codex `exec`). It errs toward reporting a conflict
// — forward value-flags in `--flag=value` form so their value is not
// mistaken for a prompt (documented in docs/session-handoff.md).
func forwardedPromptConflict(args []string, subcommands map[string]bool) bool {
	for _, a := range args {
		switch {
		case strings.HasPrefix(a, "-"):
			continue
		case strings.Contains(a, "="):
			continue
		case subcommands[a]:
			continue
		default:
			return true
		}
	}
	return false
}

// codexSubcommands are the codex argv tokens that are subcommands, not a
// prompt — so forwardedPromptConflict does not misread `codex exec` as a
// forwarded prompt.
var codexSubcommands = map[string]bool{
	"exec": true, "resume": true, "login": true, "logout": true,
	"mcp": true, "apply": true, "completion": true, "proto": true,
	"debug": true, "sandbox": true,
}

// forwardedFlagConflict reports whether any of flags already appears in
// args, in either the bare (`-i`) or combined (`-i=value`) form. Used by
// the flag-value injection kind to detect a user who already forwarded the
// tool's own prompt-seed flag (e.g. gemini `-i`/`--prompt-interactive`, or
// the headless `-p`/`--prompt`) which would collide with the seeded
// handover.
func forwardedFlagConflict(args []string, flags ...string) bool {
	for _, a := range args {
		for _, f := range flags {
			if a == f || strings.HasPrefix(a, f+"=") {
				return true
			}
		}
	}
	return false
}

// promptInjectKind names HOW a launcher seeds the handover as its target
// tool's first prompt. It is a declared CAPABILITY of the launcher, not a
// tool-name branch: each launcher states its kind and injectPrompt applies
// it uniformly (CLAUDE.md #3 — branch on capability shape, never source
// identity).
type promptInjectKind int

const (
	// injectLeadingPositional prepends the prompt as the leading positional
	// argument (claude: `claude "<handover>" …`).
	injectLeadingPositional promptInjectKind = iota
	// injectTrailingPositional appends the prompt as the trailing positional
	// argument (codex / pi: `codex … "<handover>"`).
	injectTrailingPositional
	// injectFlagValue passes the prompt as the value of a dedicated
	// interactive-seed flag (gemini: `gemini -i "<handover>"`).
	injectFlagValue
	// injectTrailingPositionalAfterDashDash appends a `--` separator and then
	// the prompt as the trailing positional (devin: `devin -- "<handover>"` —
	// the CLI's clap grammar shows the prompt as `[-- <PROMPT>...]`, a
	// last-only positional that can ONLY be supplied after `--`; the operator
	// verified `devin -- "<h>"` opens a seeded interactive session on a real
	// TTY). It is the trailing-positional shape for tools that mandate the
	// `--` guard before their prompt.
	injectTrailingPositionalAfterDashDash
)

// promptInjection is a launcher's declared prompt-seed strategy. Flag is
// set only for injectFlagValue (the flag actually emitted); ConflictFlags
// lists flags whose presence in the forwarded argv collides with the
// seeded prompt (the seed flag + its aliases + any headless-prompt flag);
// Subcommands lists argv tokens that are a subcommand rather than a
// forwarded positional prompt (so the two-prompt check doesn't misread
// them).
type promptInjection struct {
	Kind          promptInjectKind
	Flag          string
	ConflictFlags []string
	Subcommands   map[string]bool
	// BarePositionalIsPrompt marks a flag-value launcher whose tool ALSO
	// accepts an initial prompt as a bare positional (gemini's `query`), so a
	// forwarded bare positional competes with the seeded handover and must
	// trip the collision check. It is false for tools whose bare positional
	// is NOT a prompt — a project path (opencode/kilo `--prompt`) or nothing
	// (copilot/cline seed only via the `-i` value) — where flagging a
	// forwarded positional would be a false collision. Ignored for the
	// positional injection kinds (they always treat a bare positional as a
	// competing prompt). A capability flag, not a tool branch (CLAUDE.md #3).
	BarePositionalIsPrompt bool
}

// promptConflict reports whether the forwarded launcher args already carry
// a prompt that would collide with the seeded handover: a positional prompt
// for the positional kinds, or the seed flag (or a headless-prompt flag) OR
// a bare positional for the flag-value kind.
func promptConflict(args []string, spec promptInjection) bool {
	if spec.Kind == injectFlagValue {
		if forwardedFlagConflict(args, spec.ConflictFlags...) {
			return true
		}
		// A forwarded bare positional collides with the seeded handover only
		// when this tool's bare positional is itself a prompt (gemini query).
		// For tools whose positional is a path or which seed only via the flag
		// value, a forwarded positional is not a competing prompt.
		if spec.BarePositionalIsPrompt {
			return forwardedPromptConflict(args, spec.Subcommands)
		}
		return false
	}
	return forwardedPromptConflict(args, spec.Subcommands)
}

// injectPrompt seeds prompt into the forwarded launcher args per spec and
// returns the launch argv. It errors when the user already forwarded a
// colliding prompt (promptConflict) so a two-prompt collision is loud, not
// silent. The prompt is never duplicated — flag-value injection emits the
// flag exactly once.
func injectPrompt(args []string, spec promptInjection, prompt string) ([]string, error) {
	if promptConflict(args, spec) {
		return nil, errForwardedPrompt
	}
	switch spec.Kind {
	case injectLeadingPositional:
		return append([]string{prompt}, args...), nil
	case injectTrailingPositional:
		return append(append([]string{}, args...), prompt), nil
	case injectTrailingPositionalAfterDashDash:
		return append(append(append([]string{}, args...), "--"), prompt), nil
	case injectFlagValue:
		if spec.Flag == "" {
			return nil, fmt.Errorf("injectPrompt: flag-value injection requires a flag")
		}
		return append(append([]string{}, args...), spec.Flag, prompt), nil
	default:
		return nil, fmt.Errorf("injectPrompt: unknown injection kind %d", spec.Kind)
	}
}

// errForwardedPrompt is the sentinel injectPrompt returns on a two-prompt
// collision; continueFromArgs wraps it into a launcher-labelled message.
var errForwardedPrompt = fmt.Errorf("forwarded prompt collides with the seeded handover")

// continueFromParams carries everything continueFromArgs needs to run one
// --continue-from handoff for a launcher and seed the rendered doc into the
// forwarded argv per the launcher's declared injection descriptor.
type continueFromParams struct {
	tool        string // canonical registry name (svc lane validation)
	label       string // stderr prefix + error label, e.g. "claude", "gemini"
	configPath  string
	sessionID   string
	carry       string
	fromMessage int
	fromTime    string
	args        []string
	inject      promptInjection
	stderr      io.Writer
}

// continueFromArgs runs the --continue-from handoff for p.tool, prints the
// shared stderr notes (doc path, pointer-degrade, svc note), and returns
// the launch argv with the handover seeded per p.inject. It is the single
// shared seam every launcher's --continue-from path calls, so the injection
// STRATEGY (leading/trailing positional, flag value) is declared data, not
// a per-tool code branch on the run hot path.
//
// It also returns the launch working directory: the source session's
// project root, translated to a path reachable from this OS by the handoff
// service and stat-gated by launchDir (so an unreachable root yields "" =
// inherit the caller's cwd). The launcher sets exec.Cmd.Dir to it so a
// cross-OS `--continue-from` lands the continued tool in the real project
// folder rather than the daemon's own working directory.
func continueFromArgs(ctx context.Context, p continueFromParams) (args []string, cwd string, err error) {
	fork, err := forkFromFlags(p.fromMessage, p.fromTime)
	if err != nil {
		return nil, "", err
	}
	// Fail fast on a forwarded-prompt collision before the (comparatively
	// expensive) handoff render.
	if promptConflict(p.args, p.inject) {
		return nil, "", fmt.Errorf(
			"--continue-from seeds the handover as %s's first prompt, but you also forwarded a prompt - drop the extra prompt (forward value-flags as --flag=value so their value isn't mistaken for a prompt)",
			p.label,
		)
	}
	out, err := resolveContinueFrom(ctx, p.configPath, p.sessionID, p.tool, p.carry, fork)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprintf(p.stderr,
		"observer %s: seeded from session %s - handover written to %s (%d bytes as the prompt)\n",
		p.label, p.sessionID, out.DocPath, len(out.Prompt))
	if out.Degraded {
		fmt.Fprintf(p.stderr,
			"observer %s: handover exceeded %dKB - injected a pointer prompt; the full doc is at %s\n",
			p.label, continueFromMaxPromptBytes/1024, out.DocPath)
	}
	if out.Note != "" {
		fmt.Fprintf(p.stderr, "observer %s: %s\n", p.label, out.Note)
	}
	dir := launchDir(out.ProjectRoot)
	if dir != "" {
		fmt.Fprintf(p.stderr, "observer %s: continuing in %s\n", p.label, dir)
	}
	seeded, err := injectPrompt(p.args, p.inject, out.Prompt)
	if err != nil {
		return nil, "", err
	}
	return seeded, dir, nil
}

// continueFromLaunchers maps a target tool to the `observer <x>` launcher
// that implements --continue-from for it (Seeded or DocAssisted). It is the
// hand-maintained half of the bidirectional pin
// TestLaunchCapabilityMatchesWiredLauncher holds against the registry's
// Handoff.Launch rows, so the `observer handoff` hint stays honest about what
// actually exists. A data table (CLAUDE.md #5), not a switch.
var continueFromLaunchers = map[string]string{
	"claude-code":      "observer claude",
	"codex":            "observer codex",
	"gemini-cli":       "observer gemini",
	"pi":               "observer pi",
	"opencode":         "observer opencode",
	"copilot-cli":      "observer copilot-cli",
	"cline-cli":        "observer cline-cli",
	"kilo-code-cli":    "observer kilo",
	"cursor":           "observer cursor",
	"openclaw":         "observer openclaw",
	"hermes":           "observer hermes",
	"antigravity-cli":  "observer antigravity-cli",
	"qwen-code":        "observer qwen",
	"kiro-cli":         "observer kiro",
	"kimi-code":        "observer kimi",
	"grok":             "observer grok",
	"qoder":            "observer qoder",
	"goose":            "observer goose",
	"devin":            "observer devin",
	"droid":            "observer droid",
	"open-interpreter": "observer open-interpreter",
	"command-code":     "observer command-code",
	"muse":             "observer muse",
	"prime-agent":      "observer prime-agent",
	"zcode":            "observer zcode",
	"mistral-code":     "observer vibe",
	"freebuff":         "observer freebuff",
	// The 2026-10-03 terminal-picker coverage wave (all doc-assisted).
	"aider":    "observer aider",
	"crush":    "observer crush",
	"junie":    "observer junie",
	"poolside": "observer pool",
}

// continueFromLauncher returns the `observer <x>` launcher that implements
// --continue-from for tool, or "" when none is wired.
func continueFromLauncher(tool string) string {
	return continueFromLaunchers[tool]
}
