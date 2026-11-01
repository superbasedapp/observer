package secpostwrite

import (
	"context"
	"errors"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/secdetect"
)

// Write is one reported write (internal/store.PostWrite's fields, copied at
// the cmd seam so this package does not import the store).
type Write struct {
	SessionID   string
	ActionID    int64
	ProjectRoot string
	// Path is project-relative and slash-separated.
	Path string
	// CopyWorkspace marks a sandbox run with a copy workspace; WorkspaceRoot
	// is its tree when visible on the host ("" when it is not).
	CopyWorkspace bool
	WorkspaceRoot string
	// Checkout and CheckoutPath place a write in an out-of-tree linked
	// worktree (lane LEFT-SEC): the file is read at CheckoutPath under
	// Checkout, while Path stays the per-checkout sighting key the findings
	// are recorded at. Both "" for a write under ProjectRoot.
	Checkout     string
	CheckoutPath string
}

// NotScanned says why a write was not scanned.
type NotScanned string

const (
	NotScannedNone          NotScanned = ""
	NotScannedCopyWorkspace NotScanned = "copy_workspace"
	NotScannedGone          NotScanned = "gone"
	NotScannedRefused       NotScanned = "refused"
	NotScannedTooLarge      NotScanned = "too_large"
)

// Result is one write's scan outcome. It carries no content.
type Result struct {
	Write      Write
	NotScanned NotScanned
	// Refusal names the read refusal for NotScannedRefused.
	Refusal string
	Scan    secdetect.Result
}

// Sink receives results (the findings store, through the cmd seam).
type Sink func(context.Context, Result)

// Queue is the bounded, deduplicating post-write queue. One worker scans
// writes in arrival order; a path already queued is not queued twice.
type Queue struct {
	// Sink receives each result. Required.
	Sink Sink
	// CapKiB is the post-write cap picker value (64 or 256).
	CapKiB int
	// CapNow, when set, is read for every write instead of CapKiB: the cap
	// in force, so a managed node's refusal of the smaller cap applies as
	// soon as the daemon knows it is managed (lane LEFT-SEC).
	CapNow func() int
	// Max bounds the queue; a write past it is dropped and counted.
	Max int
	// Read and Scanner are injectable for tests (nil: ReadFile and the
	// default secdetect scanner).
	Read    func(root, rel string, maxBytes int) ([]byte, error)
	Scanner secdetect.Scanner

	mu      sync.Mutex
	pending []Write
	queued  map[string]bool
	dropped int
	wake    chan struct{}
}

// DefaultMax is the default queue bound.
const DefaultMax = 1024

// Submit queues w; it never blocks. It reports false when w was a
// duplicate of a queued path or the queue was full.
func (q *Queue) Submit(w Write) bool {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.init()
	// The tree is part of the key: a copy only inside a box (no
	// WorkspaceRoot) is never folded into the live tree's write.
	key := w.ProjectRoot + "\x00" + w.WorkspaceRoot + "\x00" + w.Path
	if w.CopyWorkspace {
		key += "\x00copy"
	}
	if q.queued[key] {
		return false
	}
	max := q.Max
	if max <= 0 {
		max = DefaultMax
	}
	if len(q.pending) >= max {
		q.dropped++
		return false
	}
	q.queued[key] = true
	q.pending = append(q.pending, w)
	select {
	case q.wake <- struct{}{}:
	default:
	}
	return true
}

// Dropped returns the count of writes dropped because the queue was full.
func (q *Queue) Dropped() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return q.dropped
}

func (q *Queue) init() {
	if q.queued == nil {
		q.queued = map[string]bool{}
	}
	if q.wake == nil {
		q.wake = make(chan struct{}, 1)
	}
}

// Run scans queued writes until ctx ends.
func (q *Queue) Run(ctx context.Context) {
	q.mu.Lock()
	q.init()
	wake := q.wake
	q.mu.Unlock()
	for {
		for q.Drain(ctx) > 0 {
		}
		select {
		case <-ctx.Done():
			return
		case <-wake:
		}
	}
}

// Drain scans every write queued now and returns how many it scanned.
func (q *Queue) Drain(ctx context.Context) int {
	q.mu.Lock()
	batch := q.pending
	q.pending = nil
	q.queued = map[string]bool{}
	q.mu.Unlock()
	for _, w := range batch {
		if ctx.Err() != nil {
			return 0
		}
		if q.Sink != nil {
			q.Sink(ctx, q.scanOne(w))
		}
	}
	return len(batch)
}

// scanOne reads and scans one write.
func (q *Queue) scanOne(w Write) Result {
	root, rel := w.ProjectRoot, w.Path
	if w.CopyWorkspace {
		if w.WorkspaceRoot == "" {
			return Result{Write: w, NotScanned: NotScannedCopyWorkspace}
		}
		root = w.WorkspaceRoot
	} else if w.Checkout != "" {
		root, rel = w.Checkout, w.CheckoutPath
	}
	capKiB := q.CapKiB
	if q.CapNow != nil {
		capKiB = q.CapNow()
	}
	lim := secdetect.PostWriteLimits(capKiB)
	read := q.Read
	if read == nil {
		read = ReadFile
	}
	b, err := read(root, rel, lim.MaxBytes)
	switch {
	case err == nil:
	case errors.Is(err, ErrTooLarge):
		return Result{Write: w, NotScanned: NotScannedTooLarge}
	case errors.Is(err, ErrOutsideRoot), errors.Is(err, ErrSymlink), errors.Is(err, ErrNotRegular), errors.Is(err, ErrReplaced):
		return Result{Write: w, NotScanned: NotScannedRefused, Refusal: err.Error()}
	default:
		return Result{Write: w, NotScanned: NotScannedGone}
	}
	return Result{Write: w, Scan: q.Scanner.Scan(string(b), rel, lim)}
}
