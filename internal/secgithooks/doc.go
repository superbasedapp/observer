// Package secgithooks is the pure core of the security pillar's opt-in
// local git hooks (component security.githooks; security pillar plan
// section 5.8, ruling Q12, ledger SECP-14; lane sec-c3).
//
// With the developer's per-repository consent (the CLI or the dashboard,
// never an agent), Observer writes a small marked block into the
// repository's pre-commit and pre-push hooks that runs `observer security
// precommit` or `prepush` and then lets the rest of the hook run: an
// existing shell hook is kept and chained, a hook that is not a shell
// script is refused (Observer never rewrites a binary or another
// interpreter's hook). Removal is byte-exact: the block comes out and the
// file is what it was before; a file Observer created is removed whole.
//
// The block is advisory for a human (`git commit --no-verify` still skips
// it, PR8) and fails open: only a blocking finding (exit 1) stops the
// commit or push; a missing observer, an inactive module, a timeout or any
// other error lets it through.
//
// The package renders and edits hook TEXT and decides where hooks may go;
// the file reads and writes, and git, are the caller's (cmd/observer).
package secgithooks
