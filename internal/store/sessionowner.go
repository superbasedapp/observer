package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// sessionowner.go is the store seam the watcher's sandbox projection root
// asks before it lets a box-written transcript merge into a session id
// (lane SBX-P3C audit finding 3, internal/watcher bindToRun).

// SessionOwnerFacts is what the store holds for a session id: whether it
// exists, its project root, and whether any of its actions or token rows
// came from a source file outside sourceRoot (the projection root).
type SessionOwnerFacts struct {
	Exists        bool
	ProjectRoot   string
	ForeignSource bool
}

// SessionOwnerFacts reads a session's owner facts (see the type).
func (s *Store) SessionOwnerFacts(ctx context.Context, sessionID, sourceRoot string) (SessionOwnerFacts, error) {
	var f SessionOwnerFacts
	var root sql.NullString
	err := s.db.QueryRowContext(ctx, `
		SELECT p.root_path FROM sessions s
		JOIN projects p ON p.id = s.project_id
		WHERE s.id = ?`, sessionID).Scan(&root)
	if errors.Is(err, sql.ErrNoRows) {
		return f, nil
	}
	if err != nil {
		return f, fmt.Errorf("store.SessionOwnerFacts: %w", err)
	}
	f.Exists, f.ProjectRoot = true, root.String
	prefix := strings.TrimRight(sourceRoot, "/") + "/"
	var foreign int
	err = s.db.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM actions WHERE session_id = ? AND COALESCE(source_file, '') <> ''
			  AND substr(source_file, 1, ?) <> ?
		) OR EXISTS (
			SELECT 1 FROM token_usage WHERE session_id = ? AND COALESCE(source_file, '') <> ''
			  AND substr(source_file, 1, ?) <> ?
		)`, sessionID, len(prefix), prefix, sessionID, len(prefix), prefix).Scan(&foreign)
	if err != nil {
		return f, fmt.Errorf("store.SessionOwnerFacts: sources: %w", err)
	}
	f.ForeignSource = foreign != 0
	return f, nil
}
