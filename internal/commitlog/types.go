package commitlog

import "time"

// Commit is one HEAD-reachable commit as decoded by ParseLog.
//
// AuthorHash replaces the author's display name at parse time (doc.go) —
// the raw name is never carried past this package, so a downstream
// consumer cannot accidentally treat it as a display value.
type Commit struct {
	SHA         string
	Parents     []string
	AuthorHash  string
	AuthoredAt  time.Time
	CommittedAt time.Time
	Subject     string
	IsMerge     bool
	Files       []CommitFile
}

// CommitFile is one changed path within a Commit, from --numstat.
//
// Status is intentionally left zero (best-effort) in v1: deriving a real
// A/M/D/R code cheaply would need a second `--name-status` git
// invocation correlated by position with the --numstat output, and two
// passes over the same commit range is fragile (plan §3.1 rejected it
// explicitly). A future wave may add it if a real need shows up; until
// then no caller should treat Status as populated.
type CommitFile struct {
	RelPath  string
	PathHash string
	Added    int
	Deleted  int
	Binary   bool
	Status   byte
}
