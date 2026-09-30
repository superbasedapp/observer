// Package skillscan is the skills-history git step (S10-SKILLS,
// docs/projects-page.md "Skills: versions across commits and sessions").
//
// It is NOT its own daemon loop: it runs as the commit scanner's AfterScan
// callback (internal/commitscan.Options.AfterScan, wired in
// cmd/observer/commitscan_wire.go), only after a SUCCESSFUL commit scan of
// a root. It therefore inherits the commit scanner's active-project set,
// per-root backoff, unborn/not-a-repo classification and pinned HEAD, and
// never re-learns them.
//
// Per project with a skill signal (a skill guidance row, a committed path
// under a skill directory, or a previous skill scan) one Step:
//
//  1. probes core.ignorecase / the object format / shallowness (each its
//     own invocation, refreshed daily, so an old git that lacks one flag
//     only loses that field);
//  2. persists the HEAD reflog incrementally (newest first, stopping at
//     the first already-captured entry), so the "HEAD at session start"
//     column survives git's own reflog expiry once captured;
//  3. memoises the skill-directory tree (`ls-tree`) of HEAD, of every
//     commit the timeline says touched a skill path, and of every commit
//     the reflog says HEAD pointed at - capped per tick; a tree is an
//     immutable fact about a sha, so each is listed once;
//  4. replaces the skill paths' working-tree status (the status
//     porcelain), git's own answer to "uncommitted" / "untracked" /
//     "ignored".
//
// Every git invocation goes through the injected Exec seam, which
// production wires to internal/gitview.RunReadOnlyTimeout - the ONE
// read-only git envelope (forced safe -c config, no hooks, no pager, no
// prompts, GIT_NO_LAZY_FETCH=1, capped output, timeout). This package adds
// no subprocess primitive of its own, and every argv is static or derived
// from internal/guidance's discovery table, never from repository content.
//
// I/O is injected (CLAUDE.md rule #1): no database/sql, net/http, os/exec
// or fsnotify import, and no internal/store import (imports_test.go).
package skillscan
