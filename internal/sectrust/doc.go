// Package sectrust is the repository trust check of the security pillar
// (security pillar plan section 5.1 item 2, security Phase B; component
// security.trust). Before an agent launches in a repository it reads only a
// fixed path table (agentconfig.TrustPaths, the one owner of that table) at
// two roots, the repository root and the launch directory, plus the
// directories between them, and returns a verdict of clean, flagged or
// untrusted with reason codes. There is no repository walk.
//
// The rules are the JSP-7 spike's reason-code table
// (docs/plans/spikes/JSP-7-repository-trust-2026-10.md) with the plan's
// revision 2.4 changes:
//
//   - A command the repository makes the agent run without the user asking
//     (a project hook, an MCP stdio server, a credential helper, a status
//     line command, a folder-open task, a plugin or custom tool, a crushrc)
//     is untrusted until the developer accepts that exact content digest,
//     then flagged. Indicator matching (curl, a pipe into a shell and the
//     rest) only words the reason; it never decides the level.
//   - The VS Code terminal-profile rule is gone; terminal.integrated.env.*
//     is judged only through the injection-env name table.
//   - A remote https MCP server is information, not flagged.
//   - The .git/config rules can fire only on a tree that arrived by archive,
//     copy or an agent's edit: a fresh git clone writes its own .git/config.
//
// The package is pure: every filesystem read goes through the FS seam,
// whose one operating-system implementation is fs_os.go (pinned by
// imports_test.go). It imports no database, network or process package and
// stores nothing; the accepted digests come in as a function.
package sectrust
