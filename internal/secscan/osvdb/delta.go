package osvdb

import (
	"archive/zip"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// The incremental update's limits (static feed mirroring plan section 4,
// Layer A).
const (
	// MaxDeltaRecords is the most changed records one incremental update
	// applies; more (or more than a tenth of the base's entries) and the
	// full export is downloaded instead.
	MaxDeltaRecords = 2000
	// MaxBaseAge rebases weekly regardless: the per-record listing cannot
	// express an upstream deletion, a fresh full export can.
	MaxBaseAge = 7 * 24 * time.Hour
	// MaxWatermarkAge: a watermark older than this is not trusted to be
	// reachable through the listing; the full export is downloaded.
	MaxWatermarkAge = 7 * 24 * time.Hour
	// MaxDeltaFailures consecutive failed incremental updates make the next
	// refresh download the full export.
	MaxDeltaFailures = 3
	// DefaultDeltaTotal bounds one ecosystem's incremental update (listing,
	// every record, merge and install), as the body deadlines bound a full
	// download, so a slow server cannot hold the store lock.
	DefaultDeltaTotal = 10 * time.Minute
	// WatermarkMargin is taken off a full export's watermark: a watermark
	// too new would miss records forever, one too old only fetches a few
	// records again (a replacement is idempotent).
	WatermarkMargin = 2 * time.Hour
)

// ErrRecordGone is a DeltaRemote's answer for a record the source no
// longer holds (HTTP 404): the record is dropped from the local export.
var ErrRecordGone = errors.New("the OSV record is gone")

// Modified is one line of an ecosystem's modified_id.csv: a record id and
// the time the record last changed.
type Modified struct {
	// ID is the OSV record id.
	ID string
	// At is the record's modification time.
	At time.Time
}

// DeltaRemote is a Remote that can also list the records changed since a
// time and fetch one record (production: internal/secscan/osvnet over the
// bucket's <Ecosystem>/modified_id.csv and <Ecosystem>/<ID>.json). Refresh
// takes the incremental path only through a type assertion, so a plain
// Remote keeps the full-export behaviour.
type DeltaRemote interface {
	Remote
	// ModifiedSince lists, newest first, the records modified strictly
	// after since; more than limit of them reports overflow (with the first
	// limit) instead.
	ModifiedSince(ctx context.Context, eco string, since time.Time, limit int) (ids []Modified, overflow bool, err error)
	// Record fetches one record's JSON; a record the source no longer
	// holds is ErrRecordGone.
	Record(ctx context.Context, eco, id string) ([]byte, error)
}

// LocalRemote is a Remote whose exports are already files on this disk
// (production: the org mirror's installed security.osv_export artifacts,
// design B3). The full-export path hard-links path into the store (a copy
// only where the link is refused) instead of streaming Get, then applies
// the same size, CRC32C and zip checks against meta.
type LocalRemote interface {
	Remote
	// LocalExport returns one export's file and its metadata.
	LocalExport(ctx context.Context, eco string) (path string, meta Meta, err error)
}

// rebaseFacts is what the rebase rules read.
type rebaseFacts struct {
	Epoch
	// Now is the refresh time.
	Now time.Time
	// FileOK: the SCALIBR export is on disk.
	FileOK bool
}

// rebaseRule is one row of rebaseRules: when full holds, the full export
// is checked (and downloaded when it changed) instead of a delta.
type rebaseRule struct {
	reason string
	full   func(rebaseFacts) bool
}

// rebaseRules decide full download versus incremental update, walked top
// down; the first row that holds names the reason, and no row holding
// means an incremental update. Overflow of the change listing is decided
// after the listing (refreshDelta), not here.
var rebaseRules = []rebaseRule{
	{"no_export", func(f rebaseFacts) bool { return !f.Installed() || !f.FileOK }},
	{"no_watermark", func(f rebaseFacts) bool { return f.Watermark.IsZero() }},
	{"base_stale", func(f rebaseFacts) bool { return f.BaseFetchedAt.IsZero() || f.Now.Sub(f.BaseFetchedAt) > MaxBaseAge }},
	{"watermark_stale", func(f rebaseFacts) bool { return f.Now.Sub(f.Watermark) > MaxWatermarkAge }},
	{"delta_failing", func(f rebaseFacts) bool { return f.DeltaFailures >= MaxDeltaFailures }},
}

// rebaseReason is the first rebase rule that holds, "" for a delta.
func rebaseReason(f rebaseFacts) string {
	for _, r := range rebaseRules {
		if r.full(f) {
			return r.reason
		}
	}
	return ""
}

// deltaLimit is the most records a delta may apply to a base of entries
// records: MaxDeltaRecords or a tenth of the base, the smaller, at least 1.
func deltaLimit(entries int) int {
	n := MaxDeltaRecords
	if entries >= 0 && entries/10 < n {
		n = entries / 10
	}
	if n < 1 {
		n = 1
	}
	return n
}

// ecoOutcome is what one ecosystem's refresh did.
type ecoOutcome struct {
	// changed: the full export was replaced.
	changed bool
	// applied: records applied by an incremental update.
	applied int
}

// refreshEco refreshes one ecosystem: incrementally when the remote can
// and the rebase rules allow (no HEAD of the full export then: its CRC32C
// changes upstream all day, which is the point), else the full path. On
// error the returned epoch is the one to record (the last-known-good one,
// with a delta failure counted).
func (s Store) refreshEco(ctx context.Context, remote Remote, eco string, cur Epoch, now time.Time) (ecoOutcome, Epoch, error) {
	if dr, ok := remote.(DeltaRemote); ok {
		_, statErr := os.Stat(s.zipPath("osv-scalibr", eco))
		if rebaseReason(rebaseFacts{Epoch: cur, Now: now, FileOK: statErr == nil}) == "" {
			n, next, rebase, err := s.refreshDelta(ctx, dr, eco, cur, now)
			if !rebase {
				return ecoOutcome{applied: n}, next, err
			}
		}
	}
	changed, next, err := s.refreshFull(ctx, remote, eco, cur, now)
	return ecoOutcome{changed: changed}, next, err
}

// refreshDelta applies the records changed since cur.Watermark to the
// installed export: list them, fetch each (a gone record is dropped),
// merge into a new file beside the old one, check it, and install it with
// the same two renames as a full download, so a crash leaves the old file
// and the old epoch. rebase reports a change set too large for a delta
// (the caller downloads the full export); err is a delta failure, and the
// returned epoch then is the last-known-good one with DeltaFailures
// counted.
func (s Store) refreshDelta(ctx context.Context, dr DeltaRemote, eco string, cur Epoch, now time.Time) (applied int, next Epoch, rebase bool, err error) {
	ctx, cancel := context.WithTimeout(ctx, s.deltaTotal)
	defer cancel()
	failed := cur
	failed.DeltaFailures++
	fail := func(err error) (int, Epoch, bool, error) {
		return 0, failed, false, fmt.Errorf("incremental update: %w", err)
	}
	final := s.zipPath("osv-scalibr", eco)
	zr, err := zip.OpenReader(final)
	if err != nil {
		return fail(fmt.Errorf("the installed export: %w", err))
	}
	open := true
	closeBase := func() {
		if open {
			_ = zr.Close()
			open = false
		}
	}
	defer closeBase()
	baseCount := len(zr.File)
	mods, overflow, err := dr.ModifiedSince(ctx, eco, cur.Watermark, deltaLimit(baseCount))
	if err != nil {
		return fail(err)
	}
	if overflow {
		return 0, cur, true, nil
	}
	if len(mods) == 0 {
		cur.CheckedAt, cur.LastError, cur.DeltaFailures = now, "", 0
		return 0, cur, false, nil
	}
	replace, drop := map[string][]byte{}, map[string]bool{}
	newest := cur.Watermark
	for _, m := range mods {
		if !ValidID(m.ID) {
			return fail(fmt.Errorf("bad record id %q", m.ID))
		}
		if m.At.After(newest) {
			newest = m.At
		}
		if _, seen := replace[m.ID]; seen || drop[m.ID] {
			continue
		}
		b, err := dr.Record(ctx, eco, m.ID)
		if errors.Is(err, ErrRecordGone) {
			drop[m.ID] = true
			continue
		}
		if err != nil {
			return fail(fmt.Errorf("record %s: %w", m.ID, err))
		}
		replace[m.ID] = b
	}
	tmp, err := os.CreateTemp(filepath.Dir(final), "all.zip.*.part")
	if err != nil {
		return fail(err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	st, err := MergeExport(&zr.Reader, replace, drop, tmp)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	// The base is closed before the renames: Windows refuses to replace a
	// file that is open.
	closeBase()
	if err != nil {
		return fail(err)
	}
	if err := ctx.Err(); err != nil {
		return fail(err)
	}
	if st.Total < baseCount-st.Dropped {
		return fail(fmt.Errorf("the merged export holds %d entries, fewer than the %d kept from the base", st.Total, baseCount-st.Dropped))
	}
	if err := checkZip(tmpName, st.Total); err != nil {
		return fail(err)
	}
	note, err := s.install(tmpName, eco)
	if err != nil {
		return fail(err)
	}
	n := len(replace) + len(drop)
	next = cur
	next.Watermark = newest
	next.DeltaRecords += n
	next.DeltaFailures = 0
	next.FetchedAt, next.CheckedAt = now, now
	next.LastError = note
	return n, next, false, nil
}

// baseWatermark is the watermark of a full export just installed (or
// found identical to the upstream object): the earlier of the object's
// Last-Modified and the newest record in the change listing, less
// WatermarkMargin. Either source alone serves when the other is
// unavailable; neither leaves it zero (the next refresh is a full one).
func baseWatermark(ctx context.Context, dr DeltaRemote, eco, lastModified string) time.Time {
	at := parseHTTPTime(lastModified)
	if mods, _, err := dr.ModifiedSince(ctx, eco, time.Time{}, 1); err == nil && len(mods) > 0 {
		if at.IsZero() || mods[0].At.Before(at) {
			at = mods[0].At
		}
	}
	if at.IsZero() {
		return at
	}
	return at.Add(-WatermarkMargin).UTC()
}

// httpTimeLayouts are the Last-Modified spellings accepted (RFC 9110's
// three, and RFC 3339 for a mirror's issue time).
var httpTimeLayouts = []string{time.RFC1123, "Monday, 02-Jan-06 15:04:05 MST", time.ANSIC, time.RFC3339Nano}

func parseHTTPTime(s string) time.Time {
	for _, l := range httpTimeLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}
