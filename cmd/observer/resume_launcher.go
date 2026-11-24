// resume_launcher.go — the ONE shared native-resume gate every non-flagship
// `observer <verb>` launcher funnels through (native-resume wave, 2026-07-24).
//
// It mirrors attach_launcher.go's discipline: the launcher-specific bits stay
// DATA (a per-verb translation row), so shared code never branches on tool
// identity (CLAUDE.md #3/#5). A launcher opts into native resume by (a)
// registering the uniform `--resume <id>` flag via registerResumeFlag (grounded-
// only, capability-gated on the tool's ResumeNative registry row), (b) forwarding
// it across the attach socket via resumeAttachPassthrough (so `--attach --resume`
// resumes into a daemon-owned PTY the dashboard can join — the mortality backstop),
// and (c) calling applyLauncherResume on the bare path to reject the mutually-
// exclusive handoff-fork family, take the durable cross-process claim, and
// translate the uniform tail into the tool's OWN resume argv.
//
// claude/codex are NOT migrated onto this table: their resume paths carry
// bespoke logic the shared seam does not model — claude's `--session-id` /
// `--fork-session` interplay (forceClaudeSessionID) and codex's subcommand-form
// resume + rollout-discovery short-circuit + argv-first proxy routing. Their
// dedicated helpers (injectClaudeResume / injectCodexResume, the per-tool
// reject/passthrough) stay as-is, pinned by resume_test.go; folding them in would
// not be byte-equal cheaply, so they remain bespoke by design.

package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// resumeTranslation is one launcher verb's native-resume argv contract: how the
// uniform `observer <verb> --resume <id>` maps onto the tool's OWN resume argv.
// It is DATA (CLAUDE.md #5): injectNativeResume walks this table, never a
// per-tool switch. Every row is grounded against the live 2026-07-24
// verification (see the registry Resume comments for the per-tool evidence).
type resumeTranslation struct {
	// flag is the tool's native id-carrying resume flag (e.g. "--session",
	// "--resume", "--id", "--session-id", "--conversation", "--resume-id").
	flag string
	// subcommand, when non-empty, is the leading subcommand the resume flag
	// lives under (kiro "chat", goose "session"); ensured to lead the argv.
	// Empty = the resume flag prepends the tool's top-level argv.
	subcommand string
	// preFlags are bare flags injected before the id-carrying flag under the
	// subcommand (goose "--resume"). Empty for the common plain-flag case.
	preFlags []string
	// transform maps observer's stored SessionID to the tool's native id form
	// (goose scope-strip; kimi ensure-prefix). nil = identity (raw id).
	transform func(string) string
	// joined emits `--flag=<id>` as ONE argv element instead of the default
	// two-element `--flag <id>`. Required when the tool declares the flag with
	// an OPTIONAL value (commander.js `--resume [chatId]`, which reports
	// `default: false`): such options do not reliably consume the following
	// token, so the space-separated form leaves the flag bare and lets the id
	// fall through as a positional. cursor + droid are the grounded cases.
	joined bool
	// positional marks a subcommand-scoped row whose id is the subcommand's
	// POSITIONAL argument rather than a flag value — `<tool> resume <id>`
	// (open-interpreter, whose `resume --help` declares
	// `[SESSION_ID] [PROMPT]`). It requires a non-empty subcommand and an
	// empty flag; the composer emits `<sub> [preFlags…] <id> [rest]`.
	positional bool
}

// resumeTranslations is the per-verb native-resume argv table. Keyed by the
// observer launcher verb (== the ResumeSpec.Subcommand in the integration
// registry). Adding a launcher = one row here plus the registry Resume field.
var resumeTranslations = map[string]resumeTranslation{
	// Plain-flag tools: `<tool> <flag> <id> [user args]`.
	"opencode":        {flag: "--session"},
	"kilo":            {flag: "--session"},
	"cline-cli":       {flag: "--id"},
	"gemini":          {flag: "--resume"},
	"copilot-cli":     {flag: "--session-id"},
	"pi":              {flag: "--session"},
	"qwen":            {flag: "--resume"},
	"grok":            {flag: "--resume"},
	"devin":           {flag: "--resume"},
	"hermes":          {flag: "--resume"},
	"qoder":           {flag: "--resume"},
	"antigravity-cli": {flag: "--conversation"},
	// cursor: `cursor-agent --resume=<chatId>` (live-confirmed 2026-07-25).
	// The chatId is our stored SessionID VERBATIM — the ~/.cursor/chats dirs
	// are named with the exact sessions.id values — so no transform.
	// joined: cursor declares the flag with an OPTIONAL value
	// (`--resume [chatId]`, `default: false`), so the `=` form is the correct
	// and unambiguous spelling; the space-separated form relies on the parser
	// choosing to consume the next token rather than leaving the flag bare.
	"cursor": {flag: "--resume", joined: true},
	// droid: `droid --resume=<sessionId>` (live-confirmed 2026-07-29,
	// zero-spend: a real ~/.factory/sessions uuid reopened that session's TUI,
	// a bogus one exited silently). The sessionId is our stored SessionID
	// VERBATIM — the transcript is `<uuid>.jsonl` and its `session_start` line
	// carries the same `id` — so no transform. joined: droid declares
	// `-r, --resume [sessionId]` with an OPTIONAL value (the commander.js
	// shape cursor hit), so `=` is the unambiguous spelling.
	"droid": {flag: "--resume", joined: true},
	// command-code: `commandcode --session <id>`. `--session <path|id>` is the
	// REQUIRED-value resume spelling ("Resume a session by transcript path
	// (.jsonl) or a unique session-id prefix"), so the plain two-token form is
	// correct; the sibling `-r/--resume [name]` is optional-value and also
	// resolves display names, so it is deliberately not used. The id is our
	// stored SessionID verbatim (the `<uuid>.jsonl` basename).
	"command-code": {flag: "--session"},
	// kimi: `-S/--session` needs the PREFIXED id `session_<uuid>` (bare uuid
	// HARD-FAILS). Our adapter already stores the prefixed form, so the
	// transform is an idempotent ensure-prefix.
	"kimi": {flag: "--session", transform: ensureKimiSessionPrefix},
	// Subcommand-scoped tools.
	// kiro: `kiro-cli chat --resume-id <id>` — the flag lives on `chat`.
	"kiro": {flag: "--resume-id", subcommand: "chat"},
	// goose: `goose session --resume --session-id <RAW>` — a DIFFERENT
	// subcommand from the seed lane (`run`), and the id must be the raw goose
	// id, so the scoped `<id>@<hash8>` observer SessionID is stripped.
	"goose": {flag: "--session-id", subcommand: "session", preFlags: []string{"--resume"}, transform: stripGooseScope},
	// open-interpreter: `interpreter resume <SESSION_ID>` — the codex shape
	// (this fork IS codex), grounded on its own `resume --help`:
	// `Usage: interpreter resume [OPTIONS] [SESSION_ID] [PROMPT]`,
	// `[SESSION_ID]  Session id (UUID) or session name`. The id is our stored
	// SessionID verbatim (the rollout `session_meta` UUID the codex parser
	// adopts), so no transform.
	"open-interpreter": {subcommand: "resume", positional: true},
	// muse: `muse resume <session-uuid>` (grounded off `muse resume --help`:
	// `Usage: muse resume` / `muse resume --last` / `muse resume
	// <session-uuid>`) — the same positional-under-subcommand shape as
	// open-interpreter. The id is our stored SessionID verbatim (muse's own
	// directory-name uuid), so no transform.
	"muse": {subcommand: "resume", positional: true},
	// prime-agent: `prime-agent --resume <path|id>` — a REQUIRED-value flag
	// (angle brackets, not `[path|id]`), so the plain two-token form is
	// unambiguous (grounded off `prime-agent --help`). The id is our stored
	// SessionID verbatim (the `<uuid>.jsonl` filename stem), so no transform.
	"prime-agent": {flag: "--resume"},
	// zcode: `zcode --resume <sessionId>` — a REQUIRED-value flag (grounded
	// off `zcode --help`, zcode 0.16.3). The id is our stored SessionID
	// verbatim (zcode's own `sess_<uuid>`), so no transform.
	"zcode": {flag: "--resume"},
	// vibe (mistral-code): `vibe --resume <8hex>` — a REQUIRED-value flag.
	// The id is our stored SessionID verbatim (the session dir's 8-hex
	// suffix), so no transform.
	"vibe": {flag: "--resume"},
	// freebuff: `freebuff --continue=<id>` — a commander.js OPTIONAL-value
	// flag (`--continue [conversation-id]`), so joined `=` spelling is the
	// unambiguous form (the cursor/droid shape). The id is our stored
	// SessionID verbatim (the chat dir's RFC3339 name), so no transform.
	"freebuff": {flag: "--continue", joined: true},
}

// injectNativeResume translates the uniform observer `--resume <id>` into the
// tool's native resume argv for verb, composing it onto the forwarded user args.
// It is the single translation seam (CLAUDE.md #3/#5): a launcher calls it
// instead of hand-writing the tool's resume flag. An unknown verb returns args
// unchanged (fail-open — the caller has already gated on a grounded ResumeNative
// row, so this is defensive only).
func injectNativeResume(verb, id string, args []string) []string {
	t, ok := resumeTranslations[verb]
	if !ok {
		return args
	}
	nid := id
	if t.transform != nil {
		nid = t.transform(id)
	}
	if t.subcommand == "" {
		// Plain flag: `<flag> <id>` (or `<flag>=<id>` when joined) LEADS the
		// tool's argv, before the user's forwarded remainder, so it is
		// unambiguously the tool's own.
		if t.joined {
			return append([]string{t.flag + "=" + nid}, args...)
		}
		return append([]string{t.flag, nid}, args...)
	}
	// Subcommand-scoped: `<sub> [preFlags…] <flag> <id> [rest]`, or
	// `<sub> [preFlags…] <id> [rest]` when the id is the subcommand's
	// positional. Strip a user-forwarded duplicate of the leading subcommand
	// so it is not doubled.
	rest := args
	if len(rest) > 0 && rest[0] == t.subcommand {
		rest = rest[1:]
	}
	out := make([]string, 0, len(t.preFlags)+3+len(rest))
	out = append(out, t.subcommand)
	out = append(out, t.preFlags...)
	if !t.positional {
		out = append(out, t.flag)
	}
	out = append(out, nid)
	return append(out, rest...)
}

// stripGooseScope recovers goose's own session id from observer's store-scoped
// SessionID `<goose id>@<hash8>` (scopedSessionID) by dropping everything from
// the first '@'. A bare id (no '@') passes through unchanged.
func stripGooseScope(id string) string {
	if i := strings.IndexByte(id, '@'); i >= 0 {
		return id[:i]
	}
	return id
}

// ensureKimiSessionPrefix makes a kimi-code session id carry the `session_`
// prefix kimi's `-S/--session` resume REQUIRES (a bare uuid hard-fails). It is
// idempotent: our adapter already stores the prefixed `session_<uuid>` form
// (internal/adapter/kimicode/paths.go::sessionIDFromPath), so a stored id passes
// through; a bare uuid (or a defensive future change) is prefixed.
func ensureKimiSessionPrefix(id string) string {
	if strings.HasPrefix(id, "session_") {
		return id
	}
	return "session_" + id
}

// registerResumeFlag registers the uniform `--resume <id>` flag on a launcher
// ONLY when the tool's registry row grounds a ResumeNative contract (capability
// dispatch, never a tool-name branch — CLAUDE.md #3). It returns the bound
// pointer; when the capability is ungrounded the pointer stays "" (its flag is
// never registered), so a launcher can pass *resume into applyLauncherResume
// unconditionally. Mirrors registerAttachFlags.
func registerResumeFlag(cmd *cobra.Command, tool string) *string {
	resume := new(string)
	if capab, _ := integration.For(tool); capab.Resume.Kind == integration.ResumeNative {
		cmd.Flags().StringVar(resume, "resume", "",
			"Resume a CLOSED session by its id: reattaches the tool's REAL prior conversation via its native resume mechanism - NOT a distilled fork. Mutually exclusive with --continue-from/--carry/--from-message/--from-time. Combine with --attach to resume into a daemon-owned session the dashboard can join. See https://superbased.app/docs/guides/terminals.")
	}
	return resume
}

// resumeAttachPassthrough returns the --resume passthrough forwarded to the
// daemon-spawned inner launcher so `observer <verb> --attach --resume <id>`
// resumes the REAL session into a daemon-owned PTY the dashboard can join
// (design §2.4 mortality backstop). Empty (never rejected) when no resume was
// asked. Mirrors claude/codex's *AttachPassthrough resume handling.
func resumeAttachPassthrough(resume string) []string {
	if resume != "" {
		return []string{"--resume", resume}
	}
	return nil
}

// rejectIncompatibleResumeFlags fails a native `--resume` fast for the handoff-
// fork family (--continue-from and its --carry/--from-message/--from-time
// modifiers), which composes a NEW session from a distilled handover — the
// opposite of native resume's real-transcript reattach. Naming each conflict
// keeps it loud rather than silently dropping one. The shared analogue of
// rejectIncompatibleClaudeResumeFlags / …CodexResumeFlags (which stay bespoke).
func rejectIncompatibleResumeFlags(label, continueFrom, carry string, fromMessage int, fromTime string) error {
	switch {
	case continueFrom != "":
		return fmt.Errorf("observer %s: --resume (native, reattaches the REAL session) is mutually exclusive with --continue-from (distilled fork into a NEW session) - pick one", label)
	case carry != "":
		return fmt.Errorf("observer %s: --carry only applies to --continue-from and cannot be combined with --resume", label)
	case fromMessage != 0:
		return fmt.Errorf("observer %s: --from-message only applies to --continue-from and cannot be combined with --resume", label)
	case fromTime != "":
		return fmt.Errorf("observer %s: --from-time only applies to --continue-from and cannot be combined with --resume", label)
	}
	return nil
}

// launcherResumeSpec is one launcher's native-resume request, handed to
// applyLauncherResume on the bare path.
type launcherResumeSpec struct {
	verb         string    // resume-translation key + registry ResumeSpec.Subcommand (e.g. "opencode")
	label        string    // stderr label (e.g. "opencode")
	configPath   string    // --config override; used only to resolve the DB path for the resume claim
	id           string    // *resume — the stored session id ("" = not a resume launch)
	continueFrom string    // the handoff-fork family (all mutually exclusive with resume)
	carry        string    //
	fromMessage  int       //
	fromTime     string    //
	args         []string  // the forwarded user args
	stderr       io.Writer //
}

// applyLauncherResume runs the shared bare native-resume path (the analogue of
// claude.go/codex.go's inline resume block): it rejects the mutually-exclusive
// handoff-fork family, takes the DURABLE cross-process resume claim (H3), echoes
// the resumed id to the daemon over the trusted OOB channel (a no-op for a bare,
// non-daemon-spawned launch) so an `--attach --resume` correlates, and translates
// the uniform `--resume <id>` into verb's native argv.
//
// A no-op (id == "") returns the args unchanged, a no-op release, ok=true. On a
// conflict/claim failure it returns ok=false and an err the caller must return
// (the honest message is already printed). On success it returns the resume-
// injected args + a release func the caller DEFERS for the child's lifetime.
func applyLauncherResume(s launcherResumeSpec) (args []string, release func(), ok bool, err error) {
	release = func() {}
	if s.id == "" {
		return s.args, release, true, nil
	}
	if rerr := rejectIncompatibleResumeFlags(s.label, s.continueFrom, s.carry, s.fromMessage, s.fromTime); rerr != nil {
		fmt.Fprintln(s.stderr, rerr)
		return s.args, release, false, rerr
	}
	// Resolve the DB path for the durable claim from the launcher's config
	// (fail-open to "" — acquireBareResumeClaim then no-ops rather than blocking
	// a legitimate resume; the daemon-side guard still applies when it is up).
	var dbPath string
	if cfg, cerr := config.Load(config.LoadOptions{GlobalPath: s.configPath}); cerr == nil {
		dbPath = cfg.Observer.DBPath
	}
	rel, claimed := acquireBareResumeClaim(s.stderr, dbPath, s.label, s.id)
	if !claimed {
		return s.args, release, false, exitErr(1)
	}
	// Session-attach Phase 2 (P2-1): when this is a daemon-spawned launcher (a
	// live OOB channel), announce the RESUMED id — the id the DAEMON knows and
	// the adapter captures (the stored form, e.g. goose's scoped id / kimi's
	// prefixed id), NOT the native argv id the transform derives — so the run
	// correlates at OOB confidence. No-op for a bare launch (no OOB channel).
	announceOOBSession(s.id)
	out := injectNativeResume(s.verb, s.id, s.args)
	fmt.Fprintf(s.stderr,
		"observer %s: native resume - reattaching session %s (real transcript, not a fork)\n",
		s.label, s.id)
	return out, rel, true, nil
}
