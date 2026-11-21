package store

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/marmutapp/superbased-observer/internal/platformcontract"
)

// docfloor.go is the store seam of the signed-document version floors (cloud
// 0097; managed-SaaS plan 07 wave 16 lane control-plane, lead decision
// W16-D6; docs/security.md CPSIGN-6): the only SQL over
// signed_doc_version_floors. A floor is the version the document signer's
// own record says it already signed for a stream; after a database restore
// to a point before that record, the operator verb `observer-cloud signer
// document raise-floor` appends it here, so the worker asks for
// max(latest stored version, floor) + 1 and the store refuses to store a
// version at or below it. The table is class S, append-only; every write
// and read of a stream's floor runs under that stream's document lock
// (documentLockKey), the lock every document insert of the stream takes.

// DocumentFloorEntry is one (kind, scope) entry of the signer's record and
// the last version the signer committed for it.
type DocumentFloorEntry struct {
	Kind    platformcontract.DocumentKind
	Scope   string
	Version int64
}

// FloorAction is what raise-floor does (or would do) for one entry.
type FloorAction string

// Floor actions.
const (
	// FloorRaise: the record is ahead of both the stored documents and the
	// current floor; a floor row with the record's version is appended.
	FloorRaise FloorAction = "raise"
	// FloorDatabaseAhead: the database already stores a document at or
	// above the record's version; nothing to raise.
	FloorDatabaseAhead FloorAction = "database_ahead"
	// FloorAlreadyRaised: a floor at or above the record's version is
	// already in force; nothing to raise (a repeated run).
	FloorAlreadyRaised FloorAction = "already_raised"
)

// floorRules decide one entry, walked top-down, first match wins; one test
// case per row (docfloor_internal_test.go). A floor never lowers: only the
// first row writes, and only above both the stored maximum and the floor.
var floorRules = []struct {
	action FloorAction
	match  func(record, stored, floor int64) bool
}{
	{FloorDatabaseAhead, func(record, stored, _ int64) bool { return stored >= record }},
	{FloorAlreadyRaised, func(record, _, floor int64) bool { return floor >= record }},
	{FloorRaise, func(int64, int64, int64) bool { return true }},
}

// decideFloor walks floorRules.
func decideFloor(record, stored, floor int64) FloorAction {
	for _, r := range floorRules {
		if r.match(record, stored, floor) {
			return r.action
		}
	}
	return FloorRaise // unreachable: the last row matches everything
}

// DocumentFloorResult is one entry's outcome.
type DocumentFloorResult struct {
	Entry DocumentFloorEntry
	// Stored is the stream's highest stored version (0: none).
	Stored int64
	// Floor is the stream's floor before this run (0: none).
	Floor int64
	// Action is what was done (apply) or would be done (dry run).
	Action FloorAction
}

// RaiseDocumentFloorsInput is one raise-floor run.
type RaiseDocumentFloorsInput struct {
	// Entries are the record's entries; each (kind, scope) at most once.
	Entries []DocumentFloorEntry
	// RecordSHA256 is the lowercase hex sha256 of the record file read.
	RecordSHA256 string
	// Operator names who ran the verb (1 to 64 of [A-Za-z0-9._@-]).
	Operator string
	// Apply writes the floor rows; false is a dry run that writes nothing.
	Apply bool
}

// ErrDocumentFloorInput means a raise-floor input failed its checks before
// any SQL: an empty or repeated entry, a bad kind, scope or version, a bad
// record digest or operator name.
var ErrDocumentFloorInput = errors.New("cloudserver/store: raise-floor input refused")

var (
	recordSHA256RE  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	floorOperatorRE = regexp.MustCompile(`^[A-Za-z0-9._@-]{1,64}$`)
)

// checkRaiseInput applies the input rules before any SQL and returns the
// entries in lock order (kind, then scope), so two runs never take the
// stream locks in opposite orders.
func checkRaiseInput(in RaiseDocumentFloorsInput) ([]DocumentFloorEntry, error) {
	if !recordSHA256RE.MatchString(in.RecordSHA256) {
		return nil, fmt.Errorf("%w: the record digest must be 64 lowercase hex characters", ErrDocumentFloorInput)
	}
	if !floorOperatorRE.MatchString(in.Operator) {
		return nil, fmt.Errorf("%w: the operator name must be 1 to 64 of [A-Za-z0-9._@-]", ErrDocumentFloorInput)
	}
	if len(in.Entries) == 0 {
		return nil, fmt.Errorf("%w: the record has no entries", ErrDocumentFloorInput)
	}
	out := slices.Clone(in.Entries)
	slices.SortFunc(out, func(a, b DocumentFloorEntry) int {
		if c := strings.Compare(string(a.Kind), string(b.Kind)); c != 0 {
			return c
		}
		return strings.Compare(a.Scope, b.Scope)
	})
	for i, e := range out {
		if err := platformcontract.ValidateDocumentScope(e.Kind, e.Scope); err != nil {
			return nil, fmt.Errorf("%w: %s/%s: %w", ErrDocumentFloorInput, e.Kind, e.Scope, err)
		}
		if e.Version <= 0 {
			return nil, fmt.Errorf("%w: %s/%s: version %d is not positive", ErrDocumentFloorInput, e.Kind, e.Scope, e.Version)
		}
		if i > 0 && out[i-1].Kind == e.Kind && out[i-1].Scope == e.Scope {
			return nil, fmt.Errorf("%w: %s/%s appears twice", ErrDocumentFloorInput, e.Kind, e.Scope)
		}
	}
	return out, nil
}

// storedMaxTx is the stream's highest stored version (0: none). An
// entitlements scope is compared as text, so a scope that is not a UUID
// finds nothing rather than failing the cast.
func storedMaxTx(ctx context.Context, tx pgx.Tx, kind platformcontract.DocumentKind, scope string) (int64, error) {
	var q string
	var args []any
	switch kind {
	case platformcontract.KindEntitlements:
		q, args = `SELECT COALESCE(max(version), 0) FROM org_entitlement_docs WHERE org_id::text = $1`, []any{scope}
	case platformcontract.KindAvailability:
		q = `SELECT COALESCE(max(version), 0) FROM availability_docs`
	default:
		return 0, fmt.Errorf("unknown document kind %q", kind)
	}
	var v int64
	err := tx.QueryRow(ctx, q, args...).Scan(&v)
	return v, err
}

// floorTx is the stream's floor (0: none).
func floorTx(ctx context.Context, tx pgx.Tx, kind platformcontract.DocumentKind, scope string) (int64, error) {
	var v int64
	err := tx.QueryRow(ctx,
		`SELECT COALESCE(max(floor_version), 0) FROM signed_doc_version_floors WHERE kind = $1 AND scope = $2`,
		string(kind), scope).Scan(&v)
	return v, err
}

// lastVersionTx is the version a new document of the stream must exceed:
// the higher of the stored maximum and the floor. The caller holds the
// stream's document lock.
func lastVersionTx(ctx context.Context, tx pgx.Tx, kind platformcontract.DocumentKind, scope string) (int64, error) {
	stored, err := storedMaxTx(ctx, tx, kind, scope)
	if err != nil {
		return 0, err
	}
	floor, err := floorTx(ctx, tx, kind, scope)
	if err != nil {
		return 0, err
	}
	return max(stored, floor), nil
}

// lockDocumentStreamTx takes the stream's document lock for the rest of tx.
func lockDocumentStreamTx(ctx context.Context, tx pgx.Tx, kind platformcontract.DocumentKind, scope string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, documentLockKey(kind, scope))
	return err
}

// RaiseDocumentFloors decides every entry of a signer record against the
// database and, with Apply, appends a floor row for each entry whose action
// is FloorRaise, all in one transaction (sbci_app, the operator verb). Each
// decision is made under the stream's document lock, so a concurrent
// document insert either lands first (and the entry reads FloorDatabaseAhead)
// or waits and then sees the floor. A dry run takes the same locks and
// writes nothing. Running it twice with the same record raises nothing the
// second time.
func (s *Store) RaiseDocumentFloors(ctx context.Context, in RaiseDocumentFloorsInput, now time.Time) ([]DocumentFloorResult, error) {
	entries, err := checkRaiseInput(in)
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.RaiseDocumentFloors: %w", err)
	}
	var out []DocumentFloorResult
	err = s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		out = out[:0]
		for _, e := range entries {
			if err := lockDocumentStreamTx(ctx, tx, e.Kind, e.Scope); err != nil {
				return err
			}
			stored, err := storedMaxTx(ctx, tx, e.Kind, e.Scope)
			if err != nil {
				return err
			}
			floor, err := floorTx(ctx, tx, e.Kind, e.Scope)
			if err != nil {
				return err
			}
			r := DocumentFloorResult{Entry: e, Stored: stored, Floor: floor, Action: decideFloor(e.Version, stored, floor)}
			if in.Apply && r.Action == FloorRaise {
				if _, err := tx.Exec(ctx,
					`INSERT INTO signed_doc_version_floors (kind, scope, floor_version, record_sha256, operator, at)
					 VALUES ($1, $2, $3, $4, $5, $6)`,
					string(e.Kind), e.Scope, e.Version, in.RecordSHA256, in.Operator, now.UTC()); err != nil {
					return err
				}
			}
			out = append(out, r)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.RaiseDocumentFloors: %w", err)
	}
	return out, nil
}

// DocumentVersionFloor returns the floor of one stream (0: none). The
// entitlements issuer reads it before it asks the signer for a version
// (sbci_worker holds SELECT).
func (s *Store) DocumentVersionFloor(ctx context.Context, kind platformcontract.DocumentKind, scope string) (int64, error) {
	if err := platformcontract.ValidateDocumentScope(kind, scope); err != nil {
		return 0, fmt.Errorf("cloudserver/store.DocumentVersionFloor: %w", err)
	}
	var v int64
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		var err error
		v, err = floorTx(ctx, tx, kind, scope)
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("cloudserver/store.DocumentVersionFloor: %w", err)
	}
	return v, nil
}

// DocumentFloorRow is one appended floor row (the history the verb prints).
type DocumentFloorRow struct {
	Kind         platformcontract.DocumentKind
	Scope        string
	FloorVersion int64
	RecordSHA256 string
	Operator     string
	At           time.Time
}

// DocumentFloorHistory returns every floor row, newest first (sbci_app).
func (s *Store) DocumentFloorHistory(ctx context.Context) ([]DocumentFloorRow, error) {
	var out []DocumentFloorRow
	err := s.WithSystem(ctx, func(ctx context.Context, tx pgx.Tx) error {
		rows, err := tx.Query(ctx,
			`SELECT kind, scope, floor_version, record_sha256, operator, at
			   FROM signed_doc_version_floors ORDER BY seq DESC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r DocumentFloorRow
			var kind string
			if err := rows.Scan(&kind, &r.Scope, &r.FloorVersion, &r.RecordSHA256, &r.Operator, &r.At); err != nil {
				return err
			}
			r.Kind = platformcontract.DocumentKind(kind)
			out = append(out, r)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("cloudserver/store.DocumentFloorHistory: %w", err)
	}
	return out, nil
}
