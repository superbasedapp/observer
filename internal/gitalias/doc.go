// Package gitalias is the on-disk contract between the daemon and the
// short-lived `observer hook` process for the git alias table the guard's
// hook-bypass rules read (R-112 to R-114, D-761).
//
// An agent can hide `git commit --no-verify` behind an alias the
// repository or the user already defined (`git ci`). Resolving it needs
// the alias table, and the hook must never run git on its reply path, so
// the daemon precomputes the aliases of every observed project (with
// internal/gitview's read-only envelope) and publishes them in
// guard-git-aliases.json beside the database. ONE writer, the daemon; the
// hook and the daemon's own guard only read it.
//
// The file is a convenience table, not an authority: a missing, stale or
// unreadable file means "no table covers this directory", so an alias the
// table does not know is not resolved (the R-112 docs name that residual),
// while an alias defined on the command line itself (`git -c alias.x=...`,
// `git config alias.x ...`) is judged without it. The file lives under
// ~/.observer, where R-160 denies agent writes under enforcement.
//
// stdlib plus internal/fsatomic only, because it is read on the hook path
// (the guardposture precedent).
package gitalias
