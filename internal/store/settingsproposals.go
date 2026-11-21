package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// settingsproposals.go is the one owner of settings_proposals (agent
// migration 259, Plane A build-out lane B6, ruling D19): a security-sensitive
// settings change an AI agent asked for through MCP set_setting, waiting for
// the user's approval. The agent only files a row; approving writes the value
// through the one config write owner (cmd/observer) and then marks the row.
// Node-local; never on the push wire.

// Settings proposal statuses.
const (
	SettingsProposalPending    = "pending"
	SettingsProposalApproved   = "approved"
	SettingsProposalRejected   = "rejected"
	SettingsProposalSuperseded = "superseded"
)

// Bounds on the free-text columns.
const (
	maxProposalValue = 4096
	maxProposalNote  = 500
	maxProposalWho   = 120
)

// ErrSettingsProposalNotFound is returned for an unknown proposal id.
var ErrSettingsProposalNotFound = errors.New("store: settings proposal not found")

// ErrSettingsProposalDecided is returned when a proposal is no longer
// pending.
var ErrSettingsProposalDecided = errors.New("store: settings proposal already decided")

// SettingsProposal is one row.
type SettingsProposal struct {
	ID          int64     `json:"id"`
	Key         string    `json:"key"`
	Value       string    `json:"value"`
	PrevValue   string    `json:"prev_value"`
	Category    string    `json:"category"`
	Reason      string    `json:"reason"`
	RequestedBy string    `json:"requested_by"`
	Note        string    `json:"note"`
	Status      string    `json:"status"`
	CreatedAt   time.Time `json:"created_at"`
	DecidedAt   time.Time `json:"decided_at,omitzero"`
	DecidedBy   string    `json:"decided_by,omitempty"`
}

// NewSettingsProposal is what the agent's request files.
type NewSettingsProposal struct {
	Key, Value, PrevValue, Category, Reason, RequestedBy, Note string
}

func clipProposalText(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n])
	}
	return s
}

// FileSettingsProposal records a pending proposal and supersedes any older
// pending proposal for the same key, in one transaction. It returns the new
// row's id.
func (s *Store) FileSettingsProposal(ctx context.Context, p NewSettingsProposal, now time.Time) (int64, error) {
	key := strings.TrimSpace(p.Key)
	if key == "" {
		return 0, errors.New("store.FileSettingsProposal: empty key")
	}
	if len(p.Value) > maxProposalValue {
		return 0, fmt.Errorf("store.FileSettingsProposal: value is longer than %d bytes", maxProposalValue)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("store.FileSettingsProposal: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	ts := timestamp(now)
	if _, err := tx.ExecContext(ctx,
		`UPDATE settings_proposals SET status = ?, decided_at = ?, decided_by = 'superseded by a newer request'
		 WHERE key = ? AND status = ?`,
		SettingsProposalSuperseded, ts, key, SettingsProposalPending); err != nil {
		return 0, fmt.Errorf("store.FileSettingsProposal: supersede: %w", err)
	}
	res, err := tx.ExecContext(ctx,
		`INSERT INTO settings_proposals (key, value, prev_value, category, reason, requested_by, note, status, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		key, p.Value, clipProposalText(p.PrevValue, maxProposalValue), clipProposalText(p.Category, 64), clipProposalText(p.Reason, maxProposalNote),
		clipProposalText(p.RequestedBy, maxProposalWho), clipProposalText(p.Note, maxProposalNote), SettingsProposalPending, ts)
	if err != nil {
		return 0, fmt.Errorf("store.FileSettingsProposal: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store.FileSettingsProposal: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("store.FileSettingsProposal: %w", err)
	}
	return id, nil
}

const settingsProposalCols = `id, key, value, prev_value, category, reason, requested_by, note, status, created_at, decided_at, decided_by`

func scanSettingsProposal(row interface{ Scan(...any) error }) (SettingsProposal, error) {
	var p SettingsProposal
	var created, decided string
	if err := row.Scan(&p.ID, &p.Key, &p.Value, &p.PrevValue, &p.Category, &p.Reason, &p.RequestedBy,
		&p.Note, &p.Status, &created, &decided, &p.DecidedBy); err != nil {
		return p, err
	}
	p.CreatedAt, _ = time.Parse(time.RFC3339Nano, created)
	if decided != "" {
		p.DecidedAt, _ = time.Parse(time.RFC3339Nano, decided)
	}
	return p, nil
}

// ListSettingsProposals returns proposals newest first. pendingOnly limits
// the list to pending rows; limit <= 0 means 100.
func (s *Store) ListSettingsProposals(ctx context.Context, pendingOnly bool, limit int) ([]SettingsProposal, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + settingsProposalCols + ` FROM settings_proposals`
	args := []any{}
	if pendingOnly {
		q += ` WHERE status = ?`
		args = append(args, SettingsProposalPending)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListSettingsProposals: %w", err)
	}
	defer rows.Close()
	out := []SettingsProposal{}
	for rows.Next() {
		p, err := scanSettingsProposal(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ListSettingsProposals: %w", err)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// GetSettingsProposal returns one proposal.
func (s *Store) GetSettingsProposal(ctx context.Context, id int64) (SettingsProposal, error) {
	p, err := scanSettingsProposal(s.db.QueryRowContext(ctx,
		`SELECT `+settingsProposalCols+` FROM settings_proposals WHERE id = ?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return p, ErrSettingsProposalNotFound
	}
	if err != nil {
		return p, fmt.Errorf("store.GetSettingsProposal: %w", err)
	}
	return p, nil
}

// DecideSettingsProposal moves a pending proposal to approved or rejected.
// The compare-and-set on status means two deciders cannot both win; a
// proposal that is no longer pending answers ErrSettingsProposalDecided.
func (s *Store) DecideSettingsProposal(ctx context.Context, id int64, status, decidedBy string, now time.Time) error {
	if status != SettingsProposalApproved && status != SettingsProposalRejected {
		return fmt.Errorf("store.DecideSettingsProposal: status %q is not approved or rejected", status)
	}
	res, err := s.db.ExecContext(ctx,
		`UPDATE settings_proposals SET status = ?, decided_at = ?, decided_by = ? WHERE id = ? AND status = ?`,
		status, timestamp(now), clipProposalText(decidedBy, maxProposalWho), id, SettingsProposalPending)
	if err != nil {
		return fmt.Errorf("store.DecideSettingsProposal: %w", err)
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	if _, err := s.GetSettingsProposal(ctx, id); err != nil {
		return err
	}
	return ErrSettingsProposalDecided
}
