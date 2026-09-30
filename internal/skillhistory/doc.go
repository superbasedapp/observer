// Package skillhistory derives, per project, the version history of every
// skill the project's AI tools can load and which version each session had
// available and invoked (docs/projects-page.md "Skills: versions across
// commits and sessions"; plan of record S10-SKILLS v2).
//
// It reports THREE facts per (session, skill) and never merges them:
//
//  1. Observed: what a hook snapshot hashed on disk at session start
//     (and again on resume/compact). Exact, not inferred.
//  2. HEAD at session start: the commit the git reflog says HEAD pointed at
//     when the session started, and the SKILL.md blob in that commit's
//     tree. A fact about git, not about the working copy.
//  3. Invoked: each captured skill invocation, joined by tool_use_id to
//     the snapshot the hook took of the invoked SKILL.md.
//
// Every cell resolves through an ORDERED rule table (CLAUDE.md rule #5)
// whose outputs include first-class "not captured" / "unknown" / "pending"
// states: a version is never guessed.
//
// A skill is a DIRECTORY (".claude/skills/<name>/"); its version identity
// is the git blob id of its SKILL.md, which is what lets a hook-observed
// file be matched to the commit that introduced it. Which paths are skill
// directories, and which tools read them, comes from internal/guidance's
// discovery table (the KindSkill rows) - data, never a tool-name branch.
//
// The package is PURE (CLAUDE.md rule #1): no database/sql, net/http,
// os, os/exec or fsnotify, and no internal/store import. The store seam
// (internal/store/skillhistory.go) loads plain rows into [Input]; [Build]
// returns a plain [Result]. Purity is pinned by imports_test.go.
package skillhistory
