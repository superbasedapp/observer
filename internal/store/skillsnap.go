package store

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// THIS FILE IS THE ONE OWNER of skill_snapshot_members and
// session_skill_snapshots (agent migration 135, S10-SKILLS; CLAUDE.md
// module-boundary rule #4). The only caller is the Claude Code hook seam
// (cmd/observer/hook_skillsnap.go), which hashes each SKILL.md at
// SessionStart and PostToolUse(Skill) and hands the result here.
//
// NODE-LOCAL: neither table is ever named in internal/store/orgpush.go
// (forbidden-name sentinel + TestSkillHistoryTablesPinnedOutOfPush).

// skillTimeLayout is the FIXED-WIDTH UTC layout every migration-135 table
// stores, so a TEXT comparison orders correctly (RFC3339Nano is variable
// width and misorders sub-second pairs).
const skillTimeLayout = "2006-01-02T15:04:05.000000000Z"

func formatSkillTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(skillTimeLayout)
}

func parseSkillTime(s string) time.Time {
	if s == "" {
		return time.Time{}
	}
	if t, err := time.Parse(skillTimeLayout, s); err == nil {
		return t
	}
	return parseCommitTime(s)
}

// SkillSnapshotMember is one SKILL.md a hook snapshot saw.
type SkillSnapshotMember struct {
	Scope       string
	RelPath     string
	DirKey      string
	Name        string
	State       string
	ContentHash string
	BlobOID     string
	BlobOIDLF   string
	SizeBytes   int64
}

// SkillSnapshot is one hook snapshot: the event that fired, when, and
// every member. Complete=false means the hook's budget or file cap was
// hit, so a skill missing from Members is UNKNOWN, not absent;
// HomeResolved=false means the tool's home .claude could not be resolved.
type SkillSnapshot struct {
	SessionID    string
	Tool         string
	Event        string
	Source       string
	ToolUseID    string
	InvokedName  string
	ProjectRoot  string
	ObservedAt   time.Time
	Complete     bool
	HomeResolved bool
	Members      []SkillSnapshotMember
}

// skillSetHash is the content address of a member set: sha256 over the
// sorted member tuples. Identical snapshots (the same skills at every
// session start) share one set, so the member table grows with distinct
// skill states, not with sessions.
func skillSetHash(members []SkillSnapshotMember) string {
	lines := make([]string, 0, len(members))
	for _, m := range members {
		lines = append(lines, strings.Join([]string{
			m.Scope, m.RelPath, m.DirKey, m.Name, m.State,
			m.ContentHash, m.BlobOID, m.BlobOIDLF, strconv.FormatInt(m.SizeBytes, 10),
		}, "\x00"))
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// InsertSkillSnapshot records one hook snapshot in a single transaction.
// It is idempotent: a re-fired hook with the same (session, event,
// tool_use_id, observed_at) is a no-op, and a member set already stored
// is not duplicated.
func (s *Store) InsertSkillSnapshot(ctx context.Context, snap SkillSnapshot) error {
	if strings.TrimSpace(snap.SessionID) == "" {
		return errors.New("store.InsertSkillSnapshot: empty session id")
	}
	if snap.Event == "" {
		return errors.New("store.InsertSkillSnapshot: empty event")
	}
	if snap.ObservedAt.IsZero() {
		snap.ObservedAt = time.Now()
	}
	setHash := skillSetHash(snap.Members)

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.InsertSkillSnapshot: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	for _, m := range snap.Members {
		if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO skill_snapshot_members
    (set_hash, scope, rel_path, dir_key, name, state, content_hash, blob_oid, blob_oid_lf, size_bytes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			setHash, m.Scope, m.RelPath, m.DirKey, m.Name, m.State,
			m.ContentHash, m.BlobOID, m.BlobOIDLF, m.SizeBytes); err != nil {
			return fmt.Errorf("store.InsertSkillSnapshot: member %s: %w", m.RelPath, err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
INSERT OR IGNORE INTO session_skill_snapshots
    (session_id, tool, event, source, tool_use_id, invoked_name, observed_at,
     project_root, set_hash, complete, home_resolved)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		snap.SessionID, snap.Tool, snap.Event, snap.Source, snap.ToolUseID, snap.InvokedName,
		formatSkillTime(snap.ObservedAt), snap.ProjectRoot, setHash,
		boolToInt(snap.Complete), boolToInt(snap.HomeResolved)); err != nil {
		return fmt.Errorf("store.InsertSkillSnapshot: snapshot: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.InsertSkillSnapshot: commit: %w", err)
	}
	return nil
}
