package main

import (
	"context"
	"os"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/processobs"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// launchseed.go — the launcher half of direct process attribution for
// `observer <tool>` launches (migration 086).
//
// THE GAP this closes: the session_pid_bridge seed has historically been
// written by exactly one producer per tool — the Claude Code SessionStart
// hook's ancestor walk, plus later codex/cursor/hermes seeds. Every other
// launched tool fell through to the medium-confidence lazy CorrelateCrossOS
// pass, which is why the session-detail process/network panels are blank for
// most tools (cmd/observer/terminal_pidseed.go states this verbatim for
// daemon-launched terminals; docs/audits/
// process-attribution-coverage-audit-2026-07-15.md root cause #1).
//
// A bridge row needs a REAL session id, and sessions are created by adapter
// ingestion of the tool's own storage — unknowable at spawn. So the launcher
// records the child pid in launch_seeds AFTER a successful Start (the only
// moment the pid is knowable) and that is ALL it does: the daemon's
// correlation sweep consumes the seed once a matching session is ingested,
// and the 1h expiry pass cleans up seeds whose launches never produced one.
//
// The launcher deliberately does NOT retract the seed on child exit (live-
// verified 2026-08-21: a headless grok run exits seconds after spawn — long
// before the 90s sweep tick — so an exit-retract deleted the seed before it
// could ever be consumed). A pending seed is not identity: it carries no
// session id and every reader treats it as a hint, so leaving one behind is
// harmless and bounded by expiry.
//
// Best-effort by contract: every failure degrades to the pre-existing lazy
// correlation path and is reported on the launcher's stderr — it must never
// block or fail the launch itself.

// launchSeedWriteTimeout bounds the launcher's DB work so a wedged DB can
// never stall a tool launch.
const launchSeedWriteTimeout = 3 * time.Second

// launchSeedIdentity resolves the (tool, cwd) pair a launch seed is recorded
// with. It is split out of recordLaunchSeed — and takes its working directory
// as an injected func rather than calling os.Getwd itself — so the whole
// decision is pure and table-testable, with the I/O left to the caller
// (CLAUDE.md rule 1). Both halves fix a silent-miss class in
// processobs.MatchLaunchSeeds, which pairs a seed to a session by EXACT tool
// equality and project-root equality:
//
//   - TOOL. Launchers pass their own label, and a label is not always the
//     canonical adapter key MatchLaunchSeeds compares against sessions.tool
//     (`gemini` → `gemini-cli`, `kilo` → `kilo-code-cli`, `vibe` →
//     `mistral-code`, …). Every launcher that differs has had to REMEMBER to
//     translate at its own call site; gemini is the one that was caught and
//     patched (launch.go's seedTool override) and nothing pinned the rest. So
//     the ONE seam every launcher funnels through canonicalizes through the
//     registry that already owns the verb→tool mapping
//     (integration.ToolForLaunchSubcommand — CLAUDE.md rules 3 and 4: resolve
//     at the boundary, one owner). A name that is not a launcher verb — i.e.
//     an already-canonical tool key like "claude-code" — passes through
//     untouched, so this can only ever correct a verb, never rewrite a tool.
//
//   - CWD. `dir` is set only by --continue-from; a FRESH launch (which every
//     dashboard "New Terminal" launch is) leaves it empty, and an empty seed
//     CWD is a WILDCARD in the matcher — it pairs with a same-tool session in
//     any project. Two concurrent fresh launches of one tool in different
//     projects could then cross-bind, and a bridge row is HIGH-confidence
//     identity every reader trusts. The launcher's own working directory is
//     exactly the discriminator that is missing: the child is spawned into it
//     (child.Dir == "" inherits), so it is the directory the tool will report
//     as its project root.
func launchSeedIdentity(tool, dir string, getwd func() (string, error)) (string, string) {
	if canonical, ok := integration.ToolForLaunchSubcommand(tool); ok && canonical != "" {
		tool = canonical
	}
	if dir == "" && getwd != nil {
		// Best-effort: an unreadable cwd leaves the wildcard in place rather
		// than failing the seed — a wildcard match still beats no seed at all.
		if wd, err := getwd(); err == nil {
			dir = wd
		}
	}
	return tool, dir
}

// launchSeedRunID resolves the terminal run this launcher belongs to, or ""
// when it belongs to none (migration 091 / task 9f). Both inputs are injected
// so the whole decision is pure and table-testable (CLAUDE.md rule 1).
//
// The daemon already hands every PTY child its run id in OBSERVER_OOB_RUN, so
// there is no new variable and no new plumbing — the value simply stops being
// informational. What it needs is a guard, because ENV IS INHERITED: a nested
// `observer <tool>` typed inside a dashboard terminal sees its PARENT run's id
// and would bind its own child to the outer run's session. That is a worse
// answer than the heuristic, not a better one.
//
// oobActive is that guard, and it is exact rather than approximate. The
// trusted out-of-band channel is an inherited pipe on fd 3 that the direct
// launcher marks close-on-exec precisely so the untrusted tool child cannot
// write to it (oob_emit_unix.go / session-attach design §2.1b). A nested
// invocation therefore inherits the OBSERVER_OOB_* env but NOT a usable fd, so
// its Hello never authenticates and oobChannelActive() is false. "I hold the
// authenticated channel for this run" and "I am the process the daemon spawned
// for this run" are the same fact, so no separate marker is needed.
//
// Consequence: on a platform with no OOB channel (non-unix — see
// oob_emit_other.go) this always returns "", and every launch there keeps the
// 086 heuristic. That is the honest outcome, not a gap to paper over: without
// the channel there is no way to tell the daemon's own child from a descendant
// that merely inherited its environment.
func launchSeedRunID(getenv func(string) string, oobActive bool) string {
	if !oobActive || getenv == nil {
		return ""
	}
	return getenv(envOOBRun)
}

// recordLaunchSeed inserts the launch_seeds row for a successfully started
// child. Fire-and-forget: failures are reported on warn (the launcher's
// stderr) and degrade to lazy correlation.
func recordLaunchSeed(dbPath, tool, dir string, pid int, warn interface{ Write([]byte) (int, error) }) {
	if dbPath == "" || pid <= 0 || tool == "" {
		return
	}
	seedTool, seedCWD := launchSeedIdentity(tool, dir, os.Getwd)
	ctx, cancel := context.WithTimeout(context.Background(), launchSeedWriteTimeout)
	defer cancel()
	database, err := db.Open(ctx, db.Options{Path: dbPath})
	if err != nil {
		launchSeedWarn(warn, tool, "open db", err)
		return
	}
	defer database.Close()
	if err := store.New(database).InsertLaunchSeed(ctx, processobs.LaunchSeed{
		PID:   pid,
		Tool:  seedTool,
		CWD:   seedCWD,
		RunID: launchSeedRunID(os.Getenv, oobChannelActive()),
	}); err != nil {
		launchSeedWarn(warn, tool, "record launch seed", err)
	}
}

// launchSeedWarn reports a best-effort failure on the launcher's stderr in
// the same one-line shape the launchers already use.
func launchSeedWarn(w interface{ Write([]byte) (int, error) }, tool, what string, err error) {
	if w == nil {
		return
	}
	_, _ = w.Write([]byte("observer " + tool + ": " + what +
		" (process attribution falls back to lazy correlation): " + err.Error() + "\n"))
}
