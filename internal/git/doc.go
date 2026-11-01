// Package git resolves a project's git root, current branch, and remote URL
// and produces project-relative paths for targets. All observer data is
// organized by git root (spec §20). Implementation uses os.Stat walks up for
// .git — no external git binary calls on the hot path.
//
// # Linked worktrees (F0-14, lane shr-worktree)
//
// A linked worktree (`git worktree add`) has a `.git` FILE whose gitdir is
// `<common>/worktrees/<name>`. Info.Root (shared by Resolve, FindRoot and
// ResolveIdentity) is the PROJECT the checkout belongs to: the main
// repository's top level, so every worktree of a repository lands on the
// same project, remote and root commit as the main checkout. For a bare
// common directory there is no main top level and Root is the checkout.
// Info.CheckoutRoot (and FindCheckoutRoot) is the directory whose files and
// HEAD the caller is looking at: the worktree's own top level. The two are
// equal for every repository that is not a linked worktree. Before F0-14 a
// linked worktree resolved to `<main>/.git/worktrees`, with no branch and no
// remote.
//
// Relative-path worktrees (lane shr-worktree2, PT-39): git 2.48 with
// `worktree.useRelativePaths` (or `git worktree add --relative-paths`)
// writes the worktree's gitdir and the admin directory's back pointer
// relative to their own directories. Each pointer is resolved against the
// directory holding it and must then pass the same layout checks as an
// absolute one (commondir exists, the admin directory sits in
// `<common>/worktrees`, the back pointer names this `.git` file, compared
// as files); a pointer that climbs above the filesystem root, dangles, or
// carries a drive-letter, UNC or rooted spelling that is not absolute on
// this OS is refused. An absolute pointer still may not hold a `..`
// segment. Before this lane a relative-path worktree stayed a project of
// its own, rooted at its checkout.
//
// Callers by need (today's value for a linked worktree, then the fixed one):
//
//   - identity (attribution, wire hashes, posture and exception keys) use
//     Root, `<main>/.git/worktrees` before, the main top level now: every
//     adapter's ResolveIdentity/Resolve call, backfill (backfill.go,
//     backfill_antigravity.go), attach_standalone.go, handoff_hook.go,
//     internal/mcprelay/projectid.go, antigravity's project_root_metadata,
//     the security posture and findings keys (hook_security.go hookRootOf,
//     statusline_security.go, security_mcp.go, security_exceptions.go,
//     security_phasec.go allowRoot), guard's
//     project-scoped approvals and its dry-run and lint roots (guard.go,
//     guard_enforce.go, guard_prompt.go), and the skills snapshot's
//     recorded project.
//   - checkout (reads the worktree's files, index or HEAD) use CheckoutRoot,
//     `<main>/.git/worktrees` before, the worktree's top level now: the
//     repository trust check (launch_trust.go, dashboard security_trust.go),
//     custom scanners (security_custom_cmd.go), the code intelligence CLI
//     (codeintel_core.go), the launch hook switches (toolgate_node.go), the
//     skills snapshot's file reads (hook_skillsnap.go), and the commit
//     gate's quick scan, which answers unknown when the event's checkout is
//     not the project root's (hook_security.go securityQuickScanPlanFor and
//     securityLeavesRoot).
//   - both: the dashboard editor feed (security_editor.go) and the MCP
//     findings tool (secmcp.NewFindingsReader) list findings kept under
//     Root and, in a worktree, under its CheckoutRoot; guard's in-repo
//     project policy file is a checkout file, so the per-project engine
//     (keyed by Root) folds the main checkout's copy and each linked
//     worktree's own (guard.ProjectPolicyPaths, escalate-only, strictest
//     wins), while the trusted per-project file stays keyed on Root; the
//     repository trust baseline snapshots each baselined root and then
//     each of its linked worktrees as checkouts of their own
//     (LinkedWorktreeCheckouts, within the same 200-root cap).
//
// File targets (lane shr-worktree2, PT-39): every adapter stores a file
// target through CheckoutRelativePath, which makes a target inside a
// linked worktree of the project relative to that worktree's checkout, so
// one file has one stored path in every checkout (`pkg/a.go`, never
// `.worktrees/x/pkg/a.go` or `[external]/...`). Readers that open the
// file on disk (freshness hashing, the post-write scan feed) recover the
// checkout from the tool's own absolute path (internal/store
// worktreetarget.go); file_state stays keyed by the real absolute path, so
// each checkout keeps its own row.
//
// LegacyWorktreeRootTarget maps a pre-F0-14 `<main>/.git/worktrees` root
// back to `<main>`, and CheckoutRootTarget a root at a linked worktree's
// own checkout (what a relative-path worktree got before lane
// shr-worktree2) to its main project, for `observer backfill
// --worktree-roots`.
package git
