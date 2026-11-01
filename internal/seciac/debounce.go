package seciac

import (
	"sort"
	"time"
)

// PostWriteQuiet is how long a project must see no IaC write before its
// post-write scan starts.
const PostWriteQuiet = 30 * time.Second

// Debouncer collects agent writes to IaC files per project and hands a
// project back once its writes went quiet (one owner: the daemon loop).
// Writes to any other path are not queued (the path class table).
type Debouncer struct {
	last map[string]time.Time
}

// Add records a write; it reports whether the path is an IaC file.
func (d *Debouncer) Add(root, rel string, now time.Time) bool {
	if ClassOf(rel) == "" || root == "" {
		return false
	}
	if d.last == nil {
		d.last = map[string]time.Time{}
	}
	d.last[root] = now
	return true
}

// Due returns, sorted, the projects quiet for PostWriteQuiet and forgets
// them.
func (d *Debouncer) Due(now time.Time) []string {
	var out []string
	for root, at := range d.last {
		if now.Sub(at) >= PostWriteQuiet {
			out = append(out, root)
			delete(d.last, root)
		}
	}
	sort.Strings(out)
	return out
}

// Requeue puts a project back (its scan could not start).
func (d *Debouncer) Requeue(root string, now time.Time) {
	if d.last == nil {
		d.last = map[string]time.Time{}
	}
	d.last[root] = now
}
