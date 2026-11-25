package store

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// TerminalCommand is one command/turn boundary on a terminal run
// (terminal-product-exploitation plan §7 / F3, migration 065). Metadata /
// coordinates only — NO command text or output. Trust marks the provenance:
// "oob" (the trusted out-of-band launcher channel) or "hint" (an untrusted OSC
// hint parsed off the PTY stream, internal/termscan). This is the ONE store
// seam for terminal_commands; the table is sentinel-pinned out of the org-push
// wire (tests/invariant/privacy_test.go). No paired orgserver migration exists.
type TerminalCommand struct {
	// RunID is the durable terminal_run this boundary belongs to.
	RunID string
	// TurnSeq is a monotonic boundary index within the run.
	TurnSeq int
	// StartedAt / EndedAt are the boundary times (UTC); zero omits the column.
	StartedAt time.Time
	EndedAt   time.Time
	// ExitCode is the command's exit code; nil when unknown/running.
	ExitCode *int
	// Buffer* / MarkerOffset are the F2 mirror coordinates; nil until F2.
	BufferEpoch  *int64
	BufferStart  *int64
	BufferEnd    *int64
	MarkerOffset *int64
	// Trust is "oob" (trusted) or "hint" (untrusted PTY-stream hint).
	Trust string
	// CmdHash is a domain-separated correlation hash; never command text. "".
	CmdHash string
}

// InsertTerminalCommand appends one command/turn boundary. The sole writer of
// terminal_commands (one-owner rule). A duplicate (run_id, turn_seq) is upserted
// so a re-observed boundary (e.g. an OOB confirmation of a prior hint) is
// idempotent; a trusted "oob" row always wins over a "hint" for the same slot.
func (s *Store) InsertTerminalCommand(ctx context.Context, c TerminalCommand) error {
	if c.Trust == "" {
		return fmt.Errorf("store.InsertTerminalCommand: trust is required")
	}
	_, err := s.db.ExecContext(ctx,
		`INSERT INTO terminal_commands
		   (run_id, turn_seq, started_at, ended_at, exit_code,
		    buffer_epoch, buffer_start, buffer_end, marker_offset, trust, cmd_hash)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(run_id, turn_seq) DO UPDATE SET
		   started_at    = COALESCE(excluded.started_at, terminal_commands.started_at),
		   ended_at      = COALESCE(excluded.ended_at, terminal_commands.ended_at),
		   exit_code     = COALESCE(excluded.exit_code, terminal_commands.exit_code),
		   buffer_epoch  = COALESCE(excluded.buffer_epoch, terminal_commands.buffer_epoch),
		   buffer_start  = COALESCE(excluded.buffer_start, terminal_commands.buffer_start),
		   buffer_end    = COALESCE(excluded.buffer_end, terminal_commands.buffer_end),
		   marker_offset = COALESCE(excluded.marker_offset, terminal_commands.marker_offset),
		   cmd_hash      = COALESCE(NULLIF(excluded.cmd_hash, ''), terminal_commands.cmd_hash),
		   -- A trusted OOB boundary upgrades a prior untrusted hint; never the reverse.
		   trust         = CASE WHEN excluded.trust = 'oob' THEN 'oob' ELSE terminal_commands.trust END`,
		c.RunID, c.TurnSeq, nullableTimestamp(c.StartedAt), nullableTimestamp(c.EndedAt), nullableIntPtr(c.ExitCode),
		nullableInt64Ptr(c.BufferEpoch), nullableInt64Ptr(c.BufferStart), nullableInt64Ptr(c.BufferEnd),
		nullableInt64Ptr(c.MarkerOffset), c.Trust, c.CmdHash)
	if err != nil {
		return fmt.Errorf("store.InsertTerminalCommand: %w", err)
	}
	return nil
}

// LoadTerminalCommands returns a run's command/turn boundaries in order.
func (s *Store) LoadTerminalCommands(ctx context.Context, runID string) ([]TerminalCommand, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT run_id, turn_seq, started_at, ended_at, exit_code,
		        buffer_epoch, buffer_start, buffer_end, marker_offset, trust, cmd_hash
		   FROM terminal_commands WHERE run_id = ? ORDER BY turn_seq ASC`, runID)
	if err != nil {
		return nil, fmt.Errorf("store.LoadTerminalCommands: %w", err)
	}
	defer rows.Close()
	var out []TerminalCommand
	for rows.Next() {
		var c TerminalCommand
		var started, ended sql.NullString
		var exit, be, bs, bend, mo sql.NullInt64
		var cmdHash sql.NullString
		if err := rows.Scan(&c.RunID, &c.TurnSeq, &started, &ended, &exit,
			&be, &bs, &bend, &mo, &c.Trust, &cmdHash); err != nil {
			return nil, fmt.Errorf("store.LoadTerminalCommands scan: %w", err)
		}
		if started.Valid {
			c.StartedAt, _ = time.Parse(time.RFC3339Nano, started.String)
		}
		if ended.Valid {
			c.EndedAt, _ = time.Parse(time.RFC3339Nano, ended.String)
		}
		if exit.Valid {
			v := int(exit.Int64)
			c.ExitCode = &v
		}
		c.BufferEpoch = int64PtrFromNull(be)
		c.BufferStart = int64PtrFromNull(bs)
		c.BufferEnd = int64PtrFromNull(bend)
		c.MarkerOffset = int64PtrFromNull(mo)
		if cmdHash.Valid {
			c.CmdHash = cmdHash.String
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// int64PtrFromNull lifts a sql.NullInt64 to *int64.
func int64PtrFromNull(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}
