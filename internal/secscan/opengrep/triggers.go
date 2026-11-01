package opengrep

import (
	"sort"
	"time"
)

// triggers.go is the pure half of the code rules' daemon triggers (security
// pillar plan section 5.5, lane SEC-G2 milestone 3): the post-write
// debouncer over the changed files of recorded agent writes, the schedule's
// due rule and the new-HEAD rule. None of it runs in a hook or in the
// commit gate's quick scan; the cmd layer's loop owns the state and the
// runs, one run per project at a time.

// Debounce bounds.
const (
	// PostWriteQuiet is how long a project's writes must pause before its
	// changed files are scanned.
	PostWriteQuiet = 30 * time.Second
	// PostWriteMaxDelay scans a project that keeps being written to at
	// least this often.
	PostWriteMaxDelay = 5 * time.Minute
	// maxPendingProjects bounds the projects the debouncer tracks.
	maxPendingProjects = 64
)

// Batch is one project's changed files, due for a files-mode scan.
type Batch struct {
	Root  string
	Paths []string
	// Dropped counts files beyond MaxFiles left out of this batch (the
	// commit-diff and scheduled scans still cover them).
	Dropped int
}

// pending is one project's accumulated writes.
type pending struct {
	paths       map[string]time.Time
	first, last time.Time
}

// Debouncer accumulates written files per project. It is not safe for
// concurrent use; the cmd loop owns it.
type Debouncer struct {
	projects map[string]*pending
}

// Add records a write of path (project-relative, forward slashes) in root
// at now. A path the files mode would refuse is ignored; past the project
// bound, a new project is ignored until a batch drains.
func (d *Debouncer) Add(root, path string, now time.Time) {
	if root == "" || !ValidPaths([]string{path}) {
		return
	}
	if d.projects == nil {
		d.projects = map[string]*pending{}
	}
	p, ok := d.projects[root]
	if !ok {
		if len(d.projects) >= maxPendingProjects {
			return
		}
		p = &pending{paths: map[string]time.Time{}, first: now}
		d.projects[root] = p
	}
	p.paths[path] = now
	p.last = now
}

// Due removes and returns every project whose writes paused for
// PostWriteQuiet or whose first pending write is PostWriteMaxDelay old,
// newest files first, at most MaxFiles each. Projects come in root order.
func (d *Debouncer) Due(now time.Time) []Batch {
	var roots []string
	for root, p := range d.projects {
		if now.Sub(p.last) >= PostWriteQuiet || now.Sub(p.first) >= PostWriteMaxDelay {
			roots = append(roots, root)
		}
	}
	sort.Strings(roots)
	out := make([]Batch, 0, len(roots))
	for _, root := range roots {
		p := d.projects[root]
		delete(d.projects, root)
		paths := make([]string, 0, len(p.paths))
		for path := range p.paths {
			paths = append(paths, path)
		}
		sort.Slice(paths, func(i, j int) bool {
			ti, tj := p.paths[paths[i]], p.paths[paths[j]]
			if !ti.Equal(tj) {
				return ti.After(tj)
			}
			return paths[i] < paths[j]
		})
		b := Batch{Root: root, Paths: paths}
		if len(paths) > MaxFiles {
			b.Paths, b.Dropped = paths[:MaxFiles], len(paths)-MaxFiles
		}
		sort.Strings(b.Paths)
		out = append(out, b)
	}
	return out
}

// Requeue puts a batch back (a run that could not start: another scan held
// the machine's lease), keeping its files due at the next pass.
func (d *Debouncer) Requeue(b Batch, now time.Time) {
	for _, p := range b.Paths {
		d.Add(b.Root, p, now.Add(-PostWriteQuiet))
	}
}

// Pending reports how many projects have writes waiting.
func (d *Debouncer) Pending() int { return len(d.projects) }

// ScheduleDue reports whether a scheduled full scan is due: the schedule is
// on (every > 0) and the last scheduled run is at least every old (never
// run counts as due).
func ScheduleDue(last time.Time, every time.Duration, now time.Time) bool {
	return every > 0 && (last.IsZero() || now.Sub(last) >= every)
}

// HeadStep is what the new-HEAD rule says to do for one project.
type HeadStep string

// The HeadStep values.
const (
	// HeadRemember: the first sighting of a project's HEAD; remember it,
	// scan nothing (a daemon start never begins with a scan).
	HeadRemember HeadStep = "remember"
	// HeadNone: HEAD did not move.
	HeadNone HeadStep = "none"
	// HeadScan: HEAD moved; scan what changed since the previous one.
	HeadScan HeadStep = "scan"
	// HeadUnreadable: the current HEAD could not be read; keep the
	// previous one.
	HeadUnreadable HeadStep = "unreadable"
)

// HeadRule is the new-HEAD rule over the remembered and the current HEAD
// (commit ids, "" for none).
func HeadRule(prev, cur string) HeadStep {
	switch {
	case !ValidBase(cur):
		return HeadUnreadable
	case prev == "":
		return HeadRemember
	case prev == cur:
		return HeadNone
	}
	return HeadScan
}
