package secfeedback

import (
	"encoding/json"
	"sort"
	"sync"
	"time"
)

// LeaseFor is how long an offered, unacknowledged finding stays out of
// other offers (lane sec-polish, audit finding F3). The daemon waits for
// the hook's acknowledgement for less than this (internal/secipc
// FeedbackAckWait), so an acknowledgement never lands after the lease has
// lapsed and the line was offered again.
const LeaseFor = 3 * time.Second

// Leases is the daemon's table of findings it offered to a post-tool reply
// and that no hook has acknowledged yet. A finding under an unexpired
// lease is offered to no other reply (never twice at once); one whose
// lease lapsed unacknowledged is offered again on the next post hook. The
// table is memory only: after a daemon restart every unacknowledged
// finding is offered again, the at-least-once side of the trade. The zero
// value is ready to use and safe for concurrent use.
type Leases struct {
	mu    sync.Mutex
	until map[string]time.Time
}

// Held returns the findings under an unexpired lease at now, sorted, and
// forgets the lapsed ones.
func (l *Leases) Held(now time.Time) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for id, until := range l.until {
		if !now.Before(until) {
			delete(l.until, id)
			continue
		}
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Hold leases ids from now for LeaseFor.
func (l *Leases) Hold(ids []string, now time.Time) {
	if len(ids) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.until == nil {
		l.until = map[string]time.Time{}
	}
	for _, id := range ids {
		l.until[id] = now.Add(LeaseFor)
	}
}

// Settle drops ids from the table once their acknowledgement is recorded
// (the store then never offers them again).
func (l *Leases) Settle(ids []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, id := range ids {
		delete(l.until, id)
	}
}

// HoldUntil leases ids until the given time (lane SEC-H2: an offer whose
// answer was written is held for its pending window, PendingFor).
func (l *Leases) HoldUntil(ids []string, until time.Time) {
	if len(ids) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.until == nil {
		l.until = map[string]time.Time{}
	}
	for _, id := range ids {
		if cur, ok := l.until[id]; !ok || until.After(cur) {
			l.until[id] = until
		}
	}
}

// PendingFor is how long an offer whose answer was written to a hook that
// will acknowledge it stays out of other replies (lane SEC-H2, audit
// finding F3): long enough for a host slow to write its reply to
// acknowledge late on a fresh connection, and for a daemon restart, before
// the lines are offered again.
const PendingFor = 2 * time.Minute

// MaxPending caps the pending offers kept (and written to disk).
const MaxPending = 256

// PendingOffer is one offer whose answer was written and whose
// acknowledgement has not been recorded yet: the findings it carried,
// grouped by project root hash, its session and when its window ends.
type PendingOffer struct {
	Token   string              `json:"token"`
	Session string              `json:"session"`
	Groups  map[string][]string `json:"groups"`
	Until   time.Time           `json:"until"`
}

// IDs is every finding the offer carried, sorted.
func (p PendingOffer) IDs() []string {
	var out []string
	for _, g := range p.Groups {
		out = append(out, g...)
	}
	sort.Strings(out)
	return out
}

// PendingFile is the on-disk shape of the daemon's pending offers.
type PendingFile struct {
	V      int            `json:"v"`
	Offers []PendingOffer `json:"offers"`
}

// pendingFileVersion is PendingFile's version.
const pendingFileVersion = 1

// LivePending keeps the offers whose window has not ended at now, newest
// window last, at most MaxPending (pure).
func LivePending(in []PendingOffer, now time.Time) []PendingOffer {
	var out []PendingOffer
	for _, p := range in {
		if now.Before(p.Until) && p.Token != "" && len(p.Groups) > 0 {
			out = append(out, p)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Until.Before(out[j].Until) })
	if len(out) > MaxPending {
		out = out[len(out)-MaxPending:]
	}
	return out
}

// EncodePending is the file's bytes for offers.
func EncodePending(offers []PendingOffer) ([]byte, error) {
	return json.Marshal(PendingFile{V: pendingFileVersion, Offers: offers})
}

// DecodePending reads the file's bytes; anything unreadable is no offer
// (the lines are then offered again after their lease, never lost).
func DecodePending(b []byte) []PendingOffer {
	var f PendingFile
	if json.Unmarshal(b, &f) != nil || f.V != pendingFileVersion {
		return nil
	}
	return f.Offers
}
