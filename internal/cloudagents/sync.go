package cloudagents

import (
	"sort"
	"time"
)

// Discovery checkpoints. The durable checkpoint of a discovery stream is the
// HIGH-WATER MARK of the vendor's updated_at, not the provider's pagination
// cursor: the reference warns a provider cursor may be short-lived or page-
// specific ("do not call it a durable incremental synchronization cursor
// unless the contract says so"), and neither CLI documents one as durable.
// Each pass re-reads an overlap window behind the mark and deduplicates it
// (ingest is idempotent on its event ids).

// Gap is an interval a discovery pass knows it did not cover.
type Gap struct {
	From time.Time
	To   time.Time
}

// MaxGaps bounds the gaps a checkpoint keeps (oldest dropped first).
const MaxGaps = 50

// MaxFutureSkew is how far past the pass's own clock a vendor updated_at may
// sit and still move the high-water mark. A vendor timestamp further ahead
// is not trusted: one task stamped years in the future would otherwise lift
// the mark past every real update, and each later pass would filter real
// tasks out as older than its window, silently and with no gap recorded.
const MaxFutureSkew = 5 * time.Minute

// Checkpoint is the pure view of a discovery checkpoint.
type Checkpoint struct {
	HighWater   time.Time
	Overlap     time.Duration
	Gaps        []Gap
	LastSuccess time.Time
}

// EncodeHighWater is the checkpoint cursor text for a high-water mark.
func EncodeHighWater(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// DecodeHighWater reads a checkpoint cursor; "" or junk is the zero time
// (a full re-discovery, which ingest dedups).
func DecodeHighWater(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

// Since is the oldest updated_at a pass must re-read: the high-water mark
// minus the overlap window; zero on the first pass.
func Since(cp Checkpoint) time.Time {
	if cp.HighWater.IsZero() {
		return time.Time{}
	}
	return cp.HighWater.Add(-cp.Overlap)
}

// Discovery accumulates one discovery pass over list pages (newest first).
type Discovery struct {
	c          Connector
	since      time.Time
	pages      int
	seen       map[string]bool
	tasks      []Task
	older      map[string]Task
	want       map[string]bool
	reachedOld bool
	truncated  bool
}

// NewDiscovery starts a pass for connector c that must reach back to since.
func NewDiscovery(c Connector, since time.Time) *Discovery {
	return &Discovery{c: c, since: since, seen: map[string]bool{}, older: map[string]Task{}, want: map[string]bool{}}
}

// Want names sessions a checkpoint says are still owed a read. A list
// documented newest first then keeps paging past the window's start until
// every one of them was listed (or the page budget or the list ends), so an
// owed session older than the window is found through Older and re-read.
func (d *Discovery) Want(ids []string) {
	for _, id := range ids {
		if id != "" && !d.seen[id] {
			if _, ok := d.older[id]; !ok {
				d.want[id] = true
			}
		}
	}
}

// Add folds one page in and reports whether the next page should be read.
func (d *Discovery) Add(p Page) bool {
	d.pages++
	for _, t := range p.Tasks {
		delete(d.want, t.ID)
		if d.seen[t.ID] {
			continue
		}
		if !d.since.IsZero() && !t.UpdatedAt.IsZero() && t.UpdatedAt.Before(d.since) {
			d.reachedOld = true
			d.older[t.ID] = t
			continue
		}
		d.seen[t.ID] = true
		d.tasks = append(d.tasks, t)
	}
	// A list documented newest first may stop at the first entry older
	// than the window (once no owed session is still unlisted); any other
	// list is read to its end (or the page budget), the older entries
	// filtered out above.
	newestFirstDone := d.reachedOld && d.c.NewestFirst
	if newestFirstDone && len(d.want) == 0 {
		d.truncated = false
		return false
	}
	more := d.c.Paged && p.Cursor != ""
	if more && d.pages < d.c.MaxPages {
		return true
	}
	// Stopped without reaching the window's start: either the page budget
	// ran out with a cursor still pending, or an unpaged list came back
	// full. Older updates may exist that this pass did not see. A newest
	// first list that already passed its window's start misses nothing new.
	d.truncated = !newestFirstDone && (more || (!d.c.Paged && len(p.Tasks) >= d.c.PageLimit))
	return false
}

// Older returns a listed task that was older than the window (unchanged
// since the last pass), for a session a later pass still owes a re-read.
func (d *Discovery) Older(id string) (Task, bool) {
	t, ok := d.older[id]
	return t, ok
}

// Tasks returns the tasks the pass kept (inside the window), newest first
// as listed.
func (d *Discovery) Tasks() []Task { return d.tasks }

// Pages is how many pages the pass read.
func (d *Discovery) Pages() int { return d.pages }

// Truncated reports whether the pass stopped before reaching its window's
// start (older updates may be missing).
func (d *Discovery) Truncated() bool { return d.truncated }

// Next returns the checkpoint after a successful pass and whether the pass
// left history uncovered (a recorded gap, or a first pass that could not
// reach the start of the vendor's history).
//
// The mark never moves past now plus MaxFutureSkew: a task whose updated_at
// lies further ahead is still kept by the pass (it is ingested) but its
// timestamp is ignored for the mark and for gap bounds. A previous mark
// already beyond that bound (a checkpoint written before the clamp existed)
// is discarded: the window it seeded may have hidden real tasks, so the pass
// reports partial history and the mark restarts from this pass's trusted
// timestamps (zero means the next pass re-discovers from the start, which
// ingest deduplicates).
func (d *Discovery) Next(prev Checkpoint, now time.Time) (Checkpoint, bool) {
	limit := now.Add(MaxFutureSkew)
	next := Checkpoint{
		HighWater: prev.HighWater, Overlap: d.c.Overlap,
		Gaps: append([]Gap(nil), prev.Gaps...), LastSuccess: now,
	}
	poisoned := !now.IsZero() && prev.HighWater.After(limit)
	if poisoned {
		next.HighWater = time.Time{}
	}
	var oldest time.Time
	for _, t := range d.tasks {
		if t.UpdatedAt.IsZero() || (!now.IsZero() && t.UpdatedAt.After(limit)) {
			continue
		}
		if t.UpdatedAt.After(next.HighWater) {
			next.HighWater = t.UpdatedAt
		}
		if oldest.IsZero() || t.UpdatedAt.Before(oldest) {
			oldest = t.UpdatedAt
		}
	}
	partial := poisoned
	if d.truncated {
		partial = true
		if !poisoned && !prev.HighWater.IsZero() && !oldest.IsZero() && oldest.After(prev.HighWater) {
			next.Gaps = append(next.Gaps, Gap{From: prev.HighWater, To: oldest})
		}
	}
	sort.SliceStable(next.Gaps, func(i, j int) bool { return next.Gaps[i].From.Before(next.Gaps[j].From) })
	if len(next.Gaps) > MaxGaps {
		next.Gaps = next.Gaps[len(next.Gaps)-MaxGaps:]
	}
	return next, partial
}

// RefreshCandidates returns the open tasks a viewable connector should
// re-read by id: those not seen in this pass, at most c.MaxViews, in a
// stable order.
func RefreshCandidates(c Connector, open []string, seen map[string]bool) []string {
	if !c.Viewable || c.MaxViews <= 0 {
		return nil
	}
	var out []string
	sorted := append([]string(nil), open...)
	sort.Strings(sorted)
	for _, id := range sorted {
		if seen[id] || !ValidSessionID(id) {
			continue
		}
		out = append(out, id)
		if len(out) >= c.MaxViews {
			break
		}
	}
	return out
}
