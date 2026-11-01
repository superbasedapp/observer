//go:build !sbo_omit_security

package secsvc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secexcept"
	"github.com/marmutapp/superbased-observer/internal/secfinding"
	"github.com/marmutapp/superbased-observer/internal/secposture"
	"github.com/marmutapp/superbased-observer/internal/secpostwrite"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// Local finding exceptions (security pillar plan section 6.3, lane
// sec-c3): the grant and the expiry sweep over the store's one seam
// (internal/store/secexceptions.go), with the decisions in the pure
// internal/secexcept tables.

// ExceptionStore is the part of the findings store the exceptions use.
type ExceptionStore interface {
	SecFindingByID(ctx context.Context, id string) (secfinding.Finding, bool, error)
	GrantSecException(ctx context.Context, e store.SecException, status secfinding.Status) (int64, error)
	EndSecException(ctx context.Context, id int64, reason string, now time.Time) error
	EndSecExceptionGone(ctx context.Context, id int64, reason string, now time.Time) error
	ListSecExceptions(ctx context.Context, f store.SecExceptionFilter) ([]store.SecException, error)
}

// PresenceCheck rescans the files a finding is sighted in and reports
// whether its content is still there; known is false when it cannot tell
// (a file unreadable or over the cap, no node key): then the finding
// reopens, never closes on a guess.
type PresenceCheck func(ctx context.Context, f secfinding.Finding) (present, known bool)

// FileHasher returns the sha256 hex of a project file (root and a
// project-relative path), false when it cannot be read: gone, a symlink,
// outside the root or over the cap.
type FileHasher func(root, rel string) (string, bool)

// RootResolver returns the project root whose hash is rootHash, false
// when the project is not on this machine.
type RootResolver func(ctx context.Context, rootHash string) (string, bool)

// ExceptionDeps are the injected I/O of the grant and the sweep.
type ExceptionDeps struct {
	Store    ExceptionStore
	HashFile FileHasher
	RootFor  RootResolver
	// StillPresent, when set, is asked before an ended exception reopens a
	// secret finding (lane sec-gate2, decision log P-025): a secret the
	// rescan no longer finds closes as not reproduced instead.
	StillPresent PresenceCheck
	// UntilChangeCursor, when set, is the sweep's place in the
	// until-change exceptions (the last id it read), kept by the caller
	// across passes so more than one page of them is still walked whole
	// (lane sec-gate3 milestone 2d); nil starts at the first every pass.
	UntilChangeCursor *int64
	// Now is the clock (default time.Now).
	Now func() time.Time
}

// sweepPage is how many exceptions of each kind one sweep reads.
const sweepPage = 1000

func (d ExceptionDeps) now() time.Time {
	if d.Now != nil {
		return d.Now()
	}
	return time.Now()
}

// fileHash is the finding's file fingerprint now, "" when it cannot be
// read.
func (d ExceptionDeps) fileHash(ctx context.Context, f secfinding.Finding) (string, bool) {
	if d.RootFor == nil || d.HashFile == nil || f.Location.RelPath == "" {
		return "", false
	}
	root, ok := d.RootFor(ctx, f.Project.RootHash)
	if !ok {
		return "", false
	}
	h, ok := d.HashFile(root, f.Location.RelPath)
	if !ok {
		return "", true
	}
	return h, true
}

// GrantException plans and records one exception: secexcept.Plan's
// refusal table, then one store transaction that also moves the finding
// out of open. A refusal is a *secexcept.RefusalError.
func GrantException(ctx context.Context, d ExceptionDeps, req secexcept.Request) (store.SecException, error) {
	if d.Store == nil {
		return store.SecException{}, errors.New("secsvc.GrantException: no store")
	}
	f, found, err := d.Store.SecFindingByID(ctx, req.FindingID)
	if err != nil {
		return store.SecException{}, fmt.Errorf("secsvc.GrantException: %w", err)
	}
	facts := secexcept.FindingFacts{Found: found, Status: f.Status}
	if e, ok := secexcept.ExpiryFor(req.Expiry); ok && e.UntilChange && found {
		facts.FileHash, _ = d.fileHash(ctx, f)
	}
	now := d.now()
	g, err := secexcept.Plan(req, facts, now)
	if err != nil {
		return store.SecException{}, err
	}
	row := store.SecException{
		FindingID: f.ID, ProjectRootHash: f.Project.RootHash, RuleID: f.Rule.ID, Reason: string(g.Reason.ID),
		Expiry: string(g.Expiry.ID), ExpiresAt: g.ExpiresAt, FileHash: g.FileHash, GrantedBy: string(req.Origin),
		GrantedAt: now.UTC(), RelPath: f.Location.RelPath,
	}
	id, err := d.Store.GrantSecException(ctx, row, g.Reason.Status)
	if errors.Is(err, store.ErrSecFindingNotOpen) {
		return store.SecException{}, &secexcept.RefusalError{Refusal: secexcept.RefuseNotOpen, Message: "only an open finding can be excepted; this one is not open"}
	}
	if err != nil {
		return store.SecException{}, fmt.Errorf("secsvc.GrantException: %w", err)
	}
	row.ID = id
	return row, nil
}

// RevokeException ends one exception now and reopens its finding.
func RevokeException(ctx context.Context, d ExceptionDeps, id int64) error {
	if d.Store == nil {
		return errors.New("secsvc.RevokeException: no store")
	}
	return d.Store.EndSecException(ctx, id, store.SecExceptionRevoked, d.now())
}

// SweepResult counts what one sweep ended. Gone counts the ended
// exceptions whose finding closed (its secret no longer there) instead of
// reopening; they are also counted as Expired or FileChanged.
type SweepResult struct {
	Expired     int
	FileChanged int
	Gone        int
}

// sweepEnd maps a judged outcome to the store's end reason.
var sweepEnd = map[secexcept.Outcome]string{
	secexcept.OutcomeExpired:     store.SecExceptionExpired,
	secexcept.OutcomeFileChanged: store.SecExceptionFileChanged,
}

// SweepExceptions ends every open exception whose expiry passed or whose
// file changed (secexcept.Judge), reopening its finding, or, for a secret
// the rescan no longer finds (StillPresent), closing it. Each pass reads
// at most 1000 open timed exceptions, the soonest to expire first, and on
// a budget of its own one page of 1000 until-change exceptions, the page
// after the one the last pass read (UntilChangeCursor), so every one of
// them gets its file check however many are open.
func SweepExceptions(ctx context.Context, d ExceptionDeps) (SweepResult, error) {
	var out SweepResult
	if d.Store == nil {
		return out, errors.New("secsvc.SweepExceptions: no store")
	}
	open, err := d.Store.ListSecExceptions(ctx, store.SecExceptionFilter{OpenOnly: true, Timed: true, SoonestFirst: true, Limit: sweepPage})
	if err != nil {
		return out, fmt.Errorf("secsvc.SweepExceptions: %w", err)
	}
	var after int64
	if d.UntilChangeCursor != nil {
		after = *d.UntilChangeCursor
	}
	until, err := d.Store.ListSecExceptions(ctx, store.SecExceptionFilter{OpenOnly: true, UntilChange: true, OldestFirst: true, AfterID: after, Limit: sweepPage})
	if err != nil {
		return out, fmt.Errorf("secsvc.SweepExceptions: %w", err)
	}
	if d.UntilChangeCursor != nil {
		*d.UntilChangeCursor = 0
		if len(until) == sweepPage {
			*d.UntilChangeCursor = until[len(until)-1].ID
		}
	}
	open = append(open, until...)
	now := d.now()
	roots := map[string]string{}
	for _, e := range open {
		var obs secexcept.Observed
		if e.Expiry == string(secexcept.ExpiryUntilChange) && d.RootFor != nil && d.HashFile != nil {
			root, cached := roots[e.ProjectRootHash]
			if !cached {
				root, _ = d.RootFor(ctx, e.ProjectRootHash)
				roots[e.ProjectRootHash] = root
			}
			if root != "" && e.RelPath != "" {
				obs.FileKnown = true
				obs.FileHash, _ = d.HashFile(root, e.RelPath)
			}
		}
		outcome := secexcept.Judge(secexcept.Exception{Expiry: secexcept.Expiry(e.Expiry), ExpiresAt: e.ExpiresAt, FileHash: e.FileHash}, now, obs)
		reason, ends := sweepEnd[outcome]
		if !ends {
			continue
		}
		end := d.Store.EndSecException
		if d.stillGone(ctx, e) {
			end = d.Store.EndSecExceptionGone
			out.Gone++
		}
		if err := end(ctx, e.ID, reason, now); err != nil && !errors.Is(err, store.ErrSecExceptionNotFound) {
			return out, fmt.Errorf("secsvc.SweepExceptions: %w", err)
		}
		if outcome == secexcept.OutcomeFileChanged {
			out.FileChanged++
		} else {
			out.Expired++
		}
	}
	return out, nil
}

// stillGone reports whether an ending exception's finding is a secret the
// rescan positively no longer finds; any doubt (no check, an unreadable
// finding, an unknown answer) is false, so the finding reopens.
func (d ExceptionDeps) stillGone(ctx context.Context, e store.SecException) bool {
	if d.StillPresent == nil {
		return false
	}
	f, found, err := d.Store.SecFindingByID(ctx, e.FindingID)
	if err != nil || !found || f.Category != policy.FindingSecret {
		return false
	}
	present, known := d.StillPresent(ctx, f)
	return known && !present
}

// RootsResolver builds a RootResolver over a list of project roots (the
// store's projects), hashing each the way the posture does.
func RootsResolver(list func(ctx context.Context) ([]string, error)) RootResolver {
	return func(ctx context.Context, rootHash string) (string, bool) {
		roots, err := list(ctx)
		if err != nil {
			return "", false
		}
		for _, r := range roots {
			if secposture.ProjectRootHash(r) == rootHash {
				return r, true
			}
		}
		return "", false
	}
}

// maxHashBytes caps the file an "until the file changes" exception
// fingerprints.
const maxHashBytes = 4 << 20

// HashProjectFile is the exceptions' file fingerprint: the sha256 hex of
// root/rel read through the post-write seam's defensive reader (no
// symlink, nothing outside the root, a regular file, at most 4 MiB),
// false when it cannot be read. Only the hash is kept.
func HashProjectFile(root, rel string) (string, bool) {
	b, err := secpostwrite.ReadFile(root, rel, maxHashBytes)
	if err != nil {
		return "", false
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), true
}
