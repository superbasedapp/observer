package store

// sessiontags.go — the ONE store seam for session classification: tags
// (session_tags) plus the favorite/note annotation (session_annotations),
// migration 075. See docs/plans/session-classification-tags-plan-2026-07-31.md
// §3.
//
// Deliberately NOT part of UpsertSession (the lineage-fields precedent,
// models.go:654-661): classification is user-authored review metadata written
// on its own cadence, never something an adapter's parse loop produces.
//
// NODE-LOCAL: neither table ever enters internal/store/orgpush.go —
// tag names and notes are the sessions.git_branch privacy class (they encode
// client names, codenames, ticket ids). Pinned by
// tests/invariant/privacy_test.go.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MaxTagLen bounds a single normalized tag. Long enough for
// "compression-regression-2026" and short enough that the vocabulary stays a
// vocabulary rather than a sentence store.
const MaxTagLen = 40

// MaxTagsPerSession caps how many tags one session may carry. The cap is the
// taxonomy's guardrail: past ~16 the tag set stops being a classification and
// becomes free text (which is what the note field is for).
const MaxTagsPerSession = 16

// MaxNoteLen bounds the per-session note (plan §0: "optional free text").
const MaxNoteLen = 500

// MaxRating is the top of the 1..MaxRating overall-session-rating scale
// (migration 080). 0 is the reserved "unrated" sentinel, not a score.
const MaxRating = 10

// MaxTitleLen bounds the developer's own session title (migration 116). It is
// a single-line label, not a note — short enough to sit beside a session id
// in a table row or a detail header.
const MaxTitleLen = 200

// ErrInvalidTag rejects a tag that does not normalize to 1..MaxTagLen
// characters drawn from [a-z0-9._-] — notably any unicode letter, emoji, or
// punctuation outside that set.
var ErrInvalidTag = errors.New("store: tag must normalize to 1-40 characters of [a-z0-9._-]")

// ErrTooManyTags rejects an add that would push a session past
// MaxTagsPerSession.
var ErrTooManyTags = errors.New("store: session already carries the maximum number of tags")

// ErrNoteTooLong rejects a note longer than MaxNoteLen characters.
var ErrNoteTooLong = errors.New("store: session note exceeds the maximum length")

// ErrInvalidRating rejects a rating outside 0..MaxRating (0 = clear/unrated).
var ErrInvalidRating = errors.New("store: session rating must be 0 (unrated) or 1-10")

// ErrTitleTooLong rejects a title longer than MaxTitleLen characters (after
// TrimSpace).
var ErrTitleTooLong = errors.New("store: session title exceeds the maximum length")

// ErrInvalidTitle rejects a title containing a newline. The title is a
// single-line label rendered inline (Sessions list row, detail header); a
// multi-line title belongs in the note instead.
var ErrInvalidTitle = errors.New("store: session title must not contain a newline")

// Annotation is the per-session bookmark record: the favorite star, the
// optional note explaining why, the optional 1..MaxRating overall rating, and
// the developer's own title (migration 116). The zero value is the
// "unannotated" state — SetSessionAnnotation deletes the row when a mutation
// lands back on it, so an absent row and a zero Annotation mean the same thing
// everywhere. Rating 0 is the "unrated" sentinel; Title "" means no
// developer-authored title (an AI-generated title, if any, lives elsewhere —
// see cloud_results — and Title always wins over it when both exist).
type Annotation struct {
	Favorite  bool   `json:"favorite"`
	Note      string `json:"note,omitempty"`
	Rating    int    `json:"rating,omitempty"`
	Title     string `json:"title,omitempty"`
	UpdatedAt string `json:"updated_at,omitempty"`
}

// TagCount is one vocabulary entry: a tag and how many sessions carry it.
type TagCount struct {
	Tag      string `json:"tag"`
	Sessions int    `json:"sessions"`
}

// NormalizeTag applies the plan §0 normalization to a raw user-entered tag:
// trim surrounding whitespace, lowercase, collapse each internal whitespace run
// to a single '-', trim leading/trailing '-', then validate the result against
// the [a-z0-9._-] charset and the 1..MaxTagLen length bound.
//
// Rejection (rather than silent stripping/truncation) is deliberate: a tag that
// quietly loses characters would split one intended label across two vocabulary
// entries, which is exactly the ambiguity the single-namespace design exists to
// avoid.
func NormalizeTag(raw string) (string, error) {
	var b strings.Builder
	b.Grow(len(raw))
	prevDash := false
	for _, r := range strings.TrimSpace(strings.ToLower(raw)) {
		if unicode.IsSpace(r) {
			if !prevDash {
				b.WriteByte('-')
				prevDash = true
			}
			continue
		}
		prevDash = false
		b.WriteRune(r)
	}
	tag := strings.Trim(b.String(), "-")
	if tag == "" || len(tag) > MaxTagLen {
		return "", fmt.Errorf("%w: %q", ErrInvalidTag, raw)
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '.', c == '_', c == '-':
		default:
			return "", fmt.Errorf("%w: %q", ErrInvalidTag, raw)
		}
	}
	return tag, nil
}

// normalizeTagSet normalizes every entry and de-duplicates, preserving first-
// seen order. An empty input yields a nil slice (not an error).
func normalizeTagSet(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	seen := make(map[string]struct{}, len(raw))
	out := make([]string, 0, len(raw))
	for _, r := range raw {
		tag, err := NormalizeTag(r)
		if err != nil {
			return nil, err
		}
		if _, dup := seen[tag]; dup {
			continue
		}
		seen[tag] = struct{}{}
		out = append(out, tag)
	}
	return out, nil
}

// ValidateClassificationInput pre-flights an ENTIRE classification mutation —
// the tag add/remove sets AND the note — before any of it is written.
//
// The two writes a combined request drives (MutateSessionTags then
// SetSessionAnnotation) cannot share one transaction across the store seam's
// two entry points, so a request whose tags are valid but whose note is too
// long used to commit the tags and THEN 400 — a partial write the caller has no
// way to distinguish from a total failure. Callers (the POST
// /api/session/<id>/tags handler and `observer tag`) run this first and abort
// before touching the store, which makes the combined mutation all-or-nothing
// for every REJECTION class: invalid tag, over-cap add list, over-long note.
//
// What it cannot pre-check is the per-session cap against tags the session
// ALREADY carries — that count is only knowable inside MutateSessionTags'
// transaction. That residue is harmless: tags are written first, so an
// ErrTooManyTags there aborts before the annotation write, leaving nothing
// partially applied.
func ValidateClassificationInput(add, remove []string, note *string, rating *int, title *string) error {
	addTags, err := normalizeTagSet(add)
	if err != nil {
		return fmt.Errorf("store.ValidateClassificationInput: %w", err)
	}
	if _, err := normalizeTagSet(remove); err != nil {
		return fmt.Errorf("store.ValidateClassificationInput: %w", err)
	}
	if len(addTags) > MaxTagsPerSession {
		return fmt.Errorf("store.ValidateClassificationInput: %w (%d tags requested, max %d)",
			ErrTooManyTags, len(addTags), MaxTagsPerSession)
	}
	if note != nil && len([]rune(*note)) > MaxNoteLen {
		return fmt.Errorf("store.ValidateClassificationInput: %w (max %d characters)", ErrNoteTooLong, MaxNoteLen)
	}
	if err := validateRating(rating); err != nil {
		return fmt.Errorf("store.ValidateClassificationInput: %w", err)
	}
	if err := validateTitle(title); err != nil {
		return fmt.Errorf("store.ValidateClassificationInput: %w", err)
	}
	return nil
}

// validateRating accepts nil ("leave unchanged"), 0 ("clear / unrated"), or a
// score in 1..MaxRating. Anything else is ErrInvalidRating. Shared by the
// pre-flight and by SetSessionAnnotation's own defensive check.
func validateRating(rating *int) error {
	if rating == nil {
		return nil
	}
	if *rating < 0 || *rating > MaxRating {
		return fmt.Errorf("%w (got %d)", ErrInvalidRating, *rating)
	}
	return nil
}

// validateTitle accepts nil ("leave unchanged") or a title that, after
// TrimSpace, carries no newline and is at most MaxTitleLen characters. An
// empty string (after trim) is valid — it clears the title. Shared by the
// pre-flight and by SetSessionAnnotation's own defensive check.
func validateTitle(title *string) error {
	if title == nil {
		return nil
	}
	t := strings.TrimSpace(*title)
	if strings.ContainsAny(t, "\n\r") {
		return ErrInvalidTitle
	}
	if len([]rune(t)) > MaxTitleLen {
		return fmt.Errorf("%w (max %d characters)", ErrTitleTooLong, MaxTitleLen)
	}
	return nil
}

// MutateSessionTags adds and removes tags on one session in a single
// transaction. Both lists are normalized (NormalizeTag) and de-duplicated
// first; an invalid tag fails the whole call rather than silently applying the
// valid remainder.
//
// Idempotent in both directions: adding a tag the session already carries and
// removing one it never had are both no-ops. Removals apply BEFORE additions,
// so a swap ("-junk +keep") can't trip the MaxTagsPerSession cap on a full
// session. Exceeding the cap returns ErrTooManyTags and writes nothing.
func (s *Store) MutateSessionTags(ctx context.Context, sessionID string, add, remove []string) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("store.MutateSessionTags: empty session id")
	}
	addTags, err := normalizeTagSet(add)
	if err != nil {
		return fmt.Errorf("store.MutateSessionTags: %w", err)
	}
	removeTags, err := normalizeTagSet(remove)
	if err != nil {
		return fmt.Errorf("store.MutateSessionTags: %w", err)
	}
	if len(addTags) == 0 && len(removeTags) == 0 {
		return nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.MutateSessionTags: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, tag := range removeTags {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM session_tags WHERE session_id = ? AND tag = ?`, sessionID, tag); err != nil {
			return fmt.Errorf("store.MutateSessionTags: %w", err)
		}
	}
	if len(addTags) > 0 {
		// Cap check inside the transaction, after removals, so the count
		// reflects exactly what the write is about to produce.
		existing := map[string]struct{}{}
		rows, err := tx.QueryContext(ctx, `SELECT tag FROM session_tags WHERE session_id = ?`, sessionID)
		if err != nil {
			return fmt.Errorf("store.MutateSessionTags: %w", err)
		}
		for rows.Next() {
			var tag string
			if err := rows.Scan(&tag); err != nil {
				_ = rows.Close()
				return fmt.Errorf("store.MutateSessionTags: %w", err)
			}
			existing[tag] = struct{}{}
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return fmt.Errorf("store.MutateSessionTags: %w", err)
		}
		_ = rows.Close()

		final := len(existing)
		for _, tag := range addTags {
			if _, ok := existing[tag]; !ok {
				final++
			}
		}
		if final > MaxTagsPerSession {
			return fmt.Errorf("store.MutateSessionTags: %w (%d tags, max %d)",
				ErrTooManyTags, final, MaxTagsPerSession)
		}
		now := time.Now().UTC().Format(time.RFC3339Nano)
		for _, tag := range addTags {
			if _, err := tx.ExecContext(ctx,
				`INSERT OR IGNORE INTO session_tags (session_id, tag, created_at) VALUES (?, ?, ?)`,
				sessionID, tag, now); err != nil {
				return fmt.Errorf("store.MutateSessionTags: %w", err)
			}
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.MutateSessionTags: %w", err)
	}
	return nil
}

// SetSessionAnnotation applies a PARTIAL update to a session's
// favorite/note/rating/title annotation: a nil pointer leaves that field
// untouched, so the star toggle, the note editor, the rating control and the
// title editor can each write independently. A pointer to "" clears the
// field (title included) — that is how a developer-authored title falls back
// to the AI title on every rendering surface.
//
// The row is garbage-collected when the resulting state is the zero value
// (favorite=false AND note="" AND rating=0 AND title=""): an unstarred,
// un-noted, unrated, untitled session carries no row, so "absent" and "empty"
// never diverge.
func (s *Store) SetSessionAnnotation(ctx context.Context, sessionID string, favorite *bool, note *string, rating *int, title *string) error {
	if strings.TrimSpace(sessionID) == "" {
		return fmt.Errorf("store.SetSessionAnnotation: empty session id")
	}
	if note != nil && len([]rune(*note)) > MaxNoteLen {
		return fmt.Errorf("store.SetSessionAnnotation: %w (max %d characters)", ErrNoteTooLong, MaxNoteLen)
	}
	if err := validateRating(rating); err != nil {
		return fmt.Errorf("store.SetSessionAnnotation: %w", err)
	}
	if err := validateTitle(title); err != nil {
		return fmt.Errorf("store.SetSessionAnnotation: %w", err)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.SetSessionAnnotation: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var cur Annotation
	var fav int
	switch err := tx.QueryRowContext(ctx,
		`SELECT favorite, note, rating, title FROM session_annotations WHERE session_id = ?`, sessionID).
		Scan(&fav, &cur.Note, &cur.Rating, &cur.Title); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return fmt.Errorf("store.SetSessionAnnotation: %w", err)
	default:
		cur.Favorite = fav != 0
	}
	if favorite != nil {
		cur.Favorite = *favorite
	}
	if note != nil {
		cur.Note = strings.TrimSpace(*note)
	}
	if rating != nil {
		cur.Rating = *rating
	}
	if title != nil {
		cur.Title = strings.TrimSpace(*title)
	}

	if !cur.Favorite && cur.Note == "" && cur.Rating == 0 && cur.Title == "" {
		if _, err := tx.ExecContext(ctx,
			`DELETE FROM session_annotations WHERE session_id = ?`, sessionID); err != nil {
			return fmt.Errorf("store.SetSessionAnnotation: %w", err)
		}
	} else {
		favInt := 0
		if cur.Favorite {
			favInt = 1
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO session_annotations (session_id, favorite, note, rating, title, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?)
			 ON CONFLICT(session_id) DO UPDATE SET
			   favorite   = excluded.favorite,
			   note       = excluded.note,
			   rating     = excluded.rating,
			   title      = excluded.title,
			   updated_at = excluded.updated_at`,
			sessionID, favInt, cur.Note, cur.Rating, cur.Title, time.Now().UTC().Format(time.RFC3339Nano)); err != nil {
			return fmt.Errorf("store.SetSessionAnnotation: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.SetSessionAnnotation: %w", err)
	}
	return nil
}

// GetSessionAnnotation returns one session's annotation. The zero Annotation
// (no error) is returned when the session carries none.
func (s *Store) GetSessionAnnotation(ctx context.Context, sessionID string) (Annotation, error) {
	var a Annotation
	var fav int
	var updated sql.NullString
	switch err := s.db.QueryRowContext(ctx,
		`SELECT favorite, note, rating, title, updated_at FROM session_annotations WHERE session_id = ?`, sessionID).
		Scan(&fav, &a.Note, &a.Rating, &a.Title, &updated); {
	case errors.Is(err, sql.ErrNoRows):
		return Annotation{}, nil
	case err != nil:
		return Annotation{}, fmt.Errorf("store.GetSessionAnnotation: %w", err)
	}
	a.Favorite = fav != 0
	a.UpdatedAt = updated.String
	return a, nil
}

// SessionTags returns one session's tags, sorted.
func (s *Store) SessionTags(ctx context.Context, sessionID string) ([]string, error) {
	byID, err := s.ListSessionTags(ctx, []string{sessionID})
	if err != nil {
		return nil, err
	}
	return byID[sessionID], nil
}

// ListSessionTags loads the tags for a PAGE of sessions in ONE batched
// `IN (...)` query (the FTS5 batch-load lesson — never one query per row).
// Sessions with no tags are simply absent from the map; per-session slices are
// sorted so the rendered pill order is stable.
func (s *Store) ListSessionTags(ctx context.Context, sessionIDs []string) (map[string][]string, error) {
	out := map[string][]string{}
	if len(sessionIDs) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		args = append(args, id)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	rows, err := s.db.QueryContext(ctx,
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value is bound.
		`SELECT session_id, tag FROM session_tags WHERE session_id IN (`+placeholders+`)
		 ORDER BY session_id, tag`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListSessionTags: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, tag string
		if err := rows.Scan(&id, &tag); err != nil {
			return nil, fmt.Errorf("store.ListSessionTags: %w", err)
		}
		out[id] = append(out[id], tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListSessionTags: %w", err)
	}
	return out, nil
}

// ListAnnotations loads the favorite/note annotations for a PAGE of sessions in
// ONE batched `IN (...)` query. Unannotated sessions are absent from the map
// (equivalent to the zero Annotation).
func (s *Store) ListAnnotations(ctx context.Context, sessionIDs []string) (map[string]Annotation, error) {
	out := map[string]Annotation{}
	if len(sessionIDs) == 0 {
		return out, nil
	}
	args := make([]any, 0, len(sessionIDs))
	for _, id := range sessionIDs {
		args = append(args, id)
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(args)), ",")
	rows, err := s.db.QueryContext(ctx,
		//nolint:gosec // G202: only the ?-placeholder list is concatenated; every value is bound.
		`SELECT session_id, favorite, note, rating, title, updated_at FROM session_annotations
		 WHERE session_id IN (`+placeholders+`)`, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListAnnotations: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var fav int
		var a Annotation
		var updated sql.NullString
		if err := rows.Scan(&id, &fav, &a.Note, &a.Rating, &a.Title, &updated); err != nil {
			return nil, fmt.Errorf("store.ListAnnotations: %w", err)
		}
		a.Favorite = fav != 0
		a.UpdatedAt = updated.String
		out[id] = a
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.ListAnnotations: %w", err)
	}
	return out, nil
}

// TagAssignments returns every (session_id → tags) pair in ONE query. It is the
// substrate for the per-tag rollup: the caller unions the keys into a single
// cost.Options{SessionIDs, GroupBySession} pass and folds the resulting rows
// tag-wise in Go, rather than issuing one cost query per tag.
//
// Sibling of ListSessionTags — kept separate rather than overloading an empty
// sessionIDs slice with "means everything", which would make an empty page
// silently load the whole table.
func (s *Store) TagAssignments(ctx context.Context) (map[string][]string, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT session_id, tag FROM session_tags ORDER BY session_id, tag`)
	if err != nil {
		return nil, fmt.Errorf("store.TagAssignments: %w", err)
	}
	defer rows.Close()
	out := map[string][]string{}
	for rows.Next() {
		var id, tag string
		if err := rows.Scan(&id, &tag); err != nil {
			return nil, fmt.Errorf("store.TagAssignments: %w", err)
		}
		out[id] = append(out[id], tag)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.TagAssignments: %w", err)
	}
	return out, nil
}

// TagVocabulary returns the distinct tag vocabulary with per-tag session
// counts, ordered by count desc then tag asc. v1 derives the vocabulary from
// the assignments themselves — there is deliberately no tag_defs table.
func (s *Store) TagVocabulary(ctx context.Context) ([]TagCount, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tag, COUNT(*) AS n FROM session_tags GROUP BY tag ORDER BY n DESC, tag ASC`)
	if err != nil {
		return nil, fmt.Errorf("store.TagVocabulary: %w", err)
	}
	defer rows.Close()
	out := []TagCount{}
	for rows.Next() {
		var tc TagCount
		if err := rows.Scan(&tc.Tag, &tc.Sessions); err != nil {
			return nil, fmt.Errorf("store.TagVocabulary: %w", err)
		}
		out = append(out, tc)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.TagVocabulary: %w", err)
	}
	return out, nil
}

// SessionIDsForTag returns the session ids carrying a tag, newest assignment
// first. limit <= 0 means no limit. Feeds cost.Options.SessionIDs for a
// single-tag analysis pass.
func (s *Store) SessionIDsForTag(ctx context.Context, tag string, limit int) ([]string, error) {
	norm, err := NormalizeTag(tag)
	if err != nil {
		return nil, fmt.Errorf("store.SessionIDsForTag: %w", err)
	}
	query := `SELECT session_id FROM session_tags WHERE tag = ? ORDER BY created_at DESC, session_id ASC`
	args := []any{norm}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("store.SessionIDsForTag: %w", err)
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("store.SessionIDsForTag: %w", err)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.SessionIDsForTag: %w", err)
	}
	return out, nil
}

// RenameTag renames a tag across every session, MERGING into the destination
// when a session already carries both (INSERT OR IGNORE then delete the
// source — the composite primary key makes the collision a no-op rather than a
// constraint error). Returns how many assignment rows carried the old name.
//
// A merge can only ever shrink a session's tag count, so MaxTagsPerSession
// needs no re-check here.
func (s *Store) RenameTag(ctx context.Context, from, to string) (int64, error) {
	fromTag, err := NormalizeTag(from)
	if err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	toTag, err := NormalizeTag(to)
	if err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	if fromTag == toTag {
		return 0, nil
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx,
		`INSERT OR IGNORE INTO session_tags (session_id, tag, created_at)
		 SELECT session_id, ?, created_at FROM session_tags WHERE tag = ?`,
		toTag, fromTag); err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM session_tags WHERE tag = ?`, fromTag)
	if err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.RenameTag: %w", err)
	}
	return n, nil
}

// DeleteTag removes a tag from every session it is assigned to and returns how
// many assignment rows were dropped. Vocabulary management without a defs
// table: a tag exists exactly as long as something carries it.
func (s *Store) DeleteTag(ctx context.Context, tag string) (int64, error) {
	norm, err := NormalizeTag(tag)
	if err != nil {
		return 0, fmt.Errorf("store.DeleteTag: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `DELETE FROM session_tags WHERE tag = ?`, norm)
	if err != nil {
		return 0, fmt.Errorf("store.DeleteTag: %w", err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("store.DeleteTag: %w", err)
	}
	return n, nil
}

// ErrSessionPrefixAmbiguous reports that a session-id prefix matched more than
// one session; the candidate ids travel with the error so the CLI can list
// them.
type ErrSessionPrefixAmbiguous struct {
	Prefix     string
	Candidates []string
	// Truncated reports that MORE sessions matched than Candidates lists: the
	// resolver stops reading at maxList+1 rows, so the exact total is unknown
	// and must be rendered as "N+" rather than as a count the store never
	// established. Reporting len(Candidates) as the total would UNDER-state the
	// ambiguity to the very operator being asked to disambiguate.
	Truncated bool
}

// Error implements error.
func (e *ErrSessionPrefixAmbiguous) Error() string {
	return fmt.Sprintf("session id prefix %q is ambiguous (%s matches)", e.Prefix, e.MatchCountLabel())
}

// MatchCountLabel renders the match count honestly: "3" when the candidate list
// is complete, "10+" when the resolver stopped counting at the list cap.
func (e *ErrSessionPrefixAmbiguous) MatchCountLabel() string {
	if e.Truncated {
		return fmt.Sprintf("%d+", len(e.Candidates))
	}
	return fmt.Sprintf("%d", len(e.Candidates))
}

// ErrSessionNotFound reports that a session-id prefix matched nothing.
var ErrSessionNotFound = errors.New("store: no session matches that id prefix")

// sessionPrefixRangeQuery builds the INDEX-FRIENDLY prefix lookup: the half-
// open range [prefix, prefixSucc) over sessions.id, where prefixSucc is the
// prefix with its last byte incremented. sessions.id is a TEXT PRIMARY KEY, so
// the range seeks the PK index (BINARY collation) instead of scanning every row
// to evaluate substr(id, 1, N) — the difference between an index SEARCH and a
// full-table SCAN on a store with hundreds of thousands of sessions.
//
// ok=false means the prefix has no representable successor and the caller must
// fall back to the substr scan. That covers two cases at once: an empty prefix,
// and any prefix whose last byte is not plain ASCII below 0x7F (a 0xFF byte, or
// a UTF-8 continuation byte whose increment would produce an invalid string to
// hand the driver). Session ids are ASCII (UUIDs, hex, slugs) in every adapter,
// so the fallback is the rare path — correctness first, speed for the shape
// that actually occurs.
//
// Ordering is by id (the index's own order), NOT by started_at: an
// ORDER BY started_at would push the planner onto idx_sessions_started and
// re-introduce the scan. Candidate ordering is cosmetic — ResolveSessionIDPrefix
// sorts the list before returning it either way.
func sessionPrefixRangeQuery(prefix string, limit int) (query string, args []any, ok bool) {
	if prefix == "" {
		return "", nil, false
	}
	last := prefix[len(prefix)-1]
	if last >= 0x7F {
		return "", nil, false
	}
	succ := prefix[:len(prefix)-1] + string(rune(last+1))
	return `SELECT id FROM sessions WHERE id >= ? AND id < ? ORDER BY id ASC LIMIT ?`,
		[]any{prefix, succ, limit}, true
}

// ResolveSessionIDPrefix resolves a (possibly abbreviated) session id to
// exactly one session. An EXACT id match always wins — it is a single indexed
// primary-key lookup issued FIRST, so a full id can never lose to newer
// sessions that merely share it as a prefix (the pre-fix code fetched
// maxList+1 prefix matches ordered by started_at and only then looked for the
// exact one, so an id with 11 newer prefix-collisions resolved as "ambiguous"
// even though the operator had typed it in full).
//
// Otherwise the prefix must be unique, or *ErrSessionPrefixAmbiguous is
// returned carrying up to `maxList` candidate ids (sorted) plus Truncated when
// more matched than are listed.
//
// Matching never uses LIKE, so a prefix containing SQL wildcards ('%', '_')
// can't silently widen the match: the fast path is a byte range over the PK
// index and the fallback compares substr(id, 1, N) literally.
func (s *Store) ResolveSessionIDPrefix(ctx context.Context, prefix string, maxList int) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return "", fmt.Errorf("store.ResolveSessionIDPrefix: empty prefix")
	}
	if maxList <= 0 {
		maxList = 10
	}

	// (a) Exact id first — indexed, unconditional winner.
	var exact string
	switch err := s.db.QueryRowContext(ctx, `SELECT id FROM sessions WHERE id = ?`, prefix).Scan(&exact); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return "", fmt.Errorf("store.ResolveSessionIDPrefix: %w", err)
	default:
		return exact, nil
	}

	// (b) Prefix match over the PK index, with the substr scan as fallback.
	query, args, ok := sessionPrefixRangeQuery(prefix, maxList+1)
	if !ok {
		query = `SELECT id FROM sessions WHERE substr(id, 1, ?) = ? ORDER BY id ASC LIMIT ?`
		args = []any{utf8.RuneCountInString(prefix), prefix, maxList + 1}
	}
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return "", fmt.Errorf("store.ResolveSessionIDPrefix: %w", err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return "", fmt.Errorf("store.ResolveSessionIDPrefix: %w", err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return "", fmt.Errorf("store.ResolveSessionIDPrefix: %w", err)
	}
	switch {
	case len(ids) == 0:
		return "", fmt.Errorf("store.ResolveSessionIDPrefix: %w: %q", ErrSessionNotFound, prefix)
	case len(ids) == 1:
		return ids[0], nil
	}
	sort.Strings(ids)
	// (c) More matches than the list cap: keep maxList and SAY so, rather than
	// reporting the truncated length as if it were the total.
	truncated := len(ids) > maxList
	if truncated {
		ids = ids[:maxList]
	}
	return "", &ErrSessionPrefixAmbiguous{Prefix: prefix, Candidates: ids, Truncated: truncated}
}
