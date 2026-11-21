// Package gitroute decides which git reads a repository for the commit
// quick scan, and how that git names it (R3-86).
//
// A WSL daemon reading a checkout on a Windows drive (a DrvFs mount, seen as
// /mnt/<drive>/...) pays about a millisecond per lstat across the 9P bridge,
// and the index it reads was written by Windows git, whose stat fields never
// match a Linux lstat. A working-tree diff (`git commit -a`, a pathspec)
// from the WSL git therefore takes tens of seconds on a large repository
// even with core.checkStat=minimal (R3-66), over the quick scan's 2 s
// budget, and the WSL git cannot open a linked worktree Windows git made at
// all (its `.git` pointer is spelled D:/...). The Windows git.exe, run
// through WSL interop with the same fixed argv, reads the same diff in a
// few hundred milliseconds and follows that pointer natively.
//
// The package is pure: it parses /proc/self/mountinfo bytes, maps a DrvFs
// path to its Windows spelling, lists the git.exe candidates, chooses a
// plan from an ordered rule table, and classifies a failed run as
// environmental (fall back to the WSL git) or a git answer (keep it).
// Every read of the host (the mount table, the interop registration, the
// PATH, a file's existence, `git.exe --version`) is injected through Env;
// the one git exec envelope stays internal/gitview, and the daemon's seam
// is cmd/observer/security_phasec.go securityQuickScanGit.
package gitroute
