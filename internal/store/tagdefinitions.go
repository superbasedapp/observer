package store

// tagdefinitions.go — the store seam for tag_definitions (migration 101):
// an optional human-readable explanation + category attached to a tag name
// in the session_tags vocabulary (internal/store/sessiontags.go). A sibling
// seam, not a merge into sessiontags.go, because the two tables answer
// different questions ("which sessions carry this tag" vs "what does this
// tag mean") and have independent lifecycles — a definition can be authored
// before any session carries the tag, and outlives a tag whose last
// assignment was removed.
//
// NODE-LOCAL: never pushed. Same privacy class as session_tags/
// session_annotations (docs/plans/session-classification-tags-plan-2026-07-31.md
// §1) — pinned in tests/invariant/privacy_test.go's forbiddenCacheTables
// sentinel.

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// TagDefinition is one tag_definitions row: the tag itself plus its optional
// definition and category.
type TagDefinition struct {
	Tag        string `json:"tag"`
	Definition string `json:"definition"`
	Category   string `json:"category"`
}

// UpsertTagDefinition sets (or clears) the definition/category for a tag. The
// tag is normalized with NormalizeTag first, so the definitions vocabulary
// stays keyed on exactly the same strings session_tags uses.
//
// An empty definition (after TrimSpace) CLEARS the row rather than storing an
// empty string: a custom definition is either present or it isn't, and
// deleting the row (rather than writing an empty one) means a tag with no
// definition and a tag never looked up both read back the same zero value.
// Category rides along with whatever definition is being written; it is not
// independently clearable while a non-empty definition remains — clear both
// via an empty definition and re-set them together.
func (s *Store) UpsertTagDefinition(ctx context.Context, tag, definition, category string) error {
	norm, err := NormalizeTag(tag)
	if err != nil {
		return fmt.Errorf("store.UpsertTagDefinition: %w", err)
	}
	def := strings.TrimSpace(definition)
	if def == "" {
		if _, err := s.db.ExecContext(ctx,
			`DELETE FROM tag_definitions WHERE tag = ?`, norm); err != nil {
			return fmt.Errorf("store.UpsertTagDefinition: %w", err)
		}
		return nil
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx,
		`INSERT INTO tag_definitions (tag, definition, category, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(tag) DO UPDATE SET
		   definition = excluded.definition,
		   category   = excluded.category,
		   updated_at = excluded.updated_at`,
		norm, def, strings.TrimSpace(category), now, now); err != nil {
		return fmt.Errorf("store.UpsertTagDefinition: %w", err)
	}
	return nil
}

// DeleteTagDefinition removes a tag's definition/category row, if any. The tag
// is normalized first, same as UpsertTagDefinition; an invalid tag is
// rejected rather than silently treated as a no-op, since a name that fails
// NormalizeTag could never have been stored in the first place.
func (s *Store) DeleteTagDefinition(ctx context.Context, tag string) error {
	norm, err := NormalizeTag(tag)
	if err != nil {
		return fmt.Errorf("store.DeleteTagDefinition: %w", err)
	}
	if _, err := s.db.ExecContext(ctx,
		`DELETE FROM tag_definitions WHERE tag = ?`, norm); err != nil {
		return fmt.Errorf("store.DeleteTagDefinition: %w", err)
	}
	return nil
}

// TagDefinitions returns every tag_definitions row, keyed by tag.
func (s *Store) TagDefinitions(ctx context.Context) (map[string]TagDefinition, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT tag, definition, category FROM tag_definitions ORDER BY tag ASC`)
	if err != nil {
		return nil, fmt.Errorf("store.TagDefinitions: %w", err)
	}
	defer rows.Close()
	out := map[string]TagDefinition{}
	for rows.Next() {
		var d TagDefinition
		if err := rows.Scan(&d.Tag, &d.Definition, &d.Category); err != nil {
			return nil, fmt.Errorf("store.TagDefinitions: %w", err)
		}
		out[d.Tag] = d
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store.TagDefinitions: %w", err)
	}
	return out, nil
}
