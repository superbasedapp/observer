package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// authorityorgkey.go owns sessions.authority_org_key (agent migration 250;
// managed SaaS plan 07 row M8.1, plan 06 section 5.6; operator rulings D-43
// and I-8: data captured under one organization never reaches another).
//
// It is the ONE place that:
//
//   - computes the key a capture is stamped with (resolveAuthorityOrgKeyFrom,
//     read by UpsertSession inside its own transaction, next to the
//     dataauthority stamp);
//   - resolves the migration's transient 'pending-250' rows to the key of the
//     enrolment that was in force when the migration ran
//     (resolvePendingAuthorityOrgKeys);
//   - decides the destination an org-bound selection may serve
//     (orgDestinationFor) and which rows of a composed push batch belong to it
//     (applyOrgAttribution, PushEligibleCounts' predicate,
//     ListOrgIntelSubmitCandidates, EnqueueOrgIntelSubmission).
//
// The column is NODE-LOCAL: it is a selection predicate, never a wire field.

// AuthorityOrgKeyPersonal is the authority_org_key of a session captured with
// no enrolment in force. It never equals an org key. Operator answer
// 2026-11-13 (M8.1 follow-up): personal sessions are CLAIMED by the first
// organization this machine selects rows for while enrolled
// (claimPersonalSessions) - a session already running when the machine
// enrolled, and history captured before it first enrolled, go to that org.
// Once claimed the key is an org key and never moves again, so a personal
// session reaches at most one organization.
const AuthorityOrgKeyPersonal = "personal"

// authorityOrgKeyPending is the transient key migration 250 stamps on the
// existing rows of an enrolled node; resolvePendingAuthorityOrgKeys replaces
// it before any org-bound selection reads the column.
const authorityOrgKeyPending = "pending-250"

// The schema_meta keys migration 250 writes: the pre-image of the enrolment in
// force when it ran.
const (
	authorityOrgKeyPendingOrgIDKey = "authority_org_key_250_org_id"
	authorityOrgKeyPendingURLKey   = "authority_org_key_250_org_server_url"
)

// errOrgDestinationChanged is returned when the org the caller is about to
// push to is not the org the node is enrolled in now (an enrolment switch
// landed between the caller's read and the selection). Nothing is composed.
var errOrgDestinationChanged = errors.New("the enrolment changed while the push was being composed")

// authorityOrgKey is the enrolment identity key a session is stamped with:
// hex(SHA256(normalized org server URL || 0x00 || org id)). It is the same
// value orgclient.OrgKey computes (pinned by
// TestAuthorityOrgKeyMatchesOrgclient); the store cannot import orgclient,
// which imports the store.
func authorityOrgKey(orgServerURL, orgID string) string {
	normalized := strings.TrimRight(strings.TrimSpace(orgServerURL), "/")
	sum := sha256.Sum256([]byte(normalized + "\x00" + orgID))
	return hex.EncodeToString(sum[:])
}

// resolveAuthorityOrgKeyFrom is the at-capture key for a session written now,
// from the LIVE enrolment read through q (UpsertSession passes its own
// transaction, so the read and the write are atomic). It follows
// resolveEnrolmentFrom's fail-closed rules:
//
//	enrolment row with an org id -> that enrolment's org key
//	no row, or an empty org id   -> 'personal'
//	read error                   -> nil (unknown; never matches a destination)
func resolveAuthorityOrgKeyFrom(ctx context.Context, q queryRower) any {
	if q == nil {
		return nil
	}
	var orgID, url string
	err := q.QueryRowContext(ctx,
		`SELECT org_id, org_server_url FROM org_enrolment WHERE id = 1`).Scan(&orgID, &url)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		return AuthorityOrgKeyPersonal
	case err != nil:
		return nil
	case orgID == "":
		return AuthorityOrgKeyPersonal
	default:
		return authorityOrgKey(url, orgID)
	}
}

// resolvePendingAuthorityOrgKeys replaces migration 250's 'pending-250' stamp
// with the key of the enrolment that was in force when the migration ran (its
// pre-image in schema_meta), then deletes the pre-image. It is cheap once done
// (one point read), and every org-bound selection runs it first, so a pending
// row is never compared against a destination. Until it has run a pending row
// matches nothing (fail closed).
func (s *Store) resolvePendingAuthorityOrgKeys(ctx context.Context) error {
	orgID, err := s.readMeta(ctx, authorityOrgKeyPendingOrgIDKey)
	if err != nil {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: %w", err)
	}
	if orgID == "" {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// Re-read inside the write transaction: another process may have
	// resolved the rows between the probe above and this BEGIN IMMEDIATE.
	var url string
	err = tx.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, authorityOrgKeyPendingOrgIDKey).Scan(&orgID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: read org id: %w", err)
	}
	err = tx.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = ?`, authorityOrgKeyPendingURLKey).Scan(&url)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: read org server url: %w", err)
	}
	if _, err := tx.ExecContext(ctx,
		`UPDATE sessions SET authority_org_key = ? WHERE authority_org_key = ?`,
		authorityOrgKey(url, orgID), authorityOrgKeyPending); err != nil {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: stamp: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM schema_meta WHERE key IN (?, ?)`,
		authorityOrgKeyPendingOrgIDKey, authorityOrgKeyPendingURLKey); err != nil {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: clear pre-image: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("store.resolvePendingAuthorityOrgKeys: commit: %w", err)
	}
	return nil
}

// orgDestination is the organization an org-bound selection serves.
type orgDestination struct {
	// open is true when the node is not enrolled: no organization can
	// receive what is composed (orgclient refuses to push without an
	// enrolment), so nothing is filtered. The unenrolled lanes (the cloud
	// session flush) keep their behaviour.
	open bool
	// key is the enrolled org's authority_org_key; only rows whose session
	// carries it may be selected.
	key string
}

// destinationInput is what orgDestinationRules decide on.
type destinationInput struct {
	enrolled    bool   // an enrolment row with a non-empty org id
	liveOrgID   string // its org id
	liveURL     string // its org server url
	callerOrgID string // the org the caller is composing for ("" = whatever is enrolled)
}

// orgDestinationRules decide the destination of an org-bound selection,
// top-down, first match wins.
var orgDestinationRules = []struct {
	name  string
	match func(destinationInput) bool
	out   func(destinationInput) (orgDestination, error)
}{
	{
		name:  "not enrolled: nothing can be sent to an org",
		match: func(in destinationInput) bool { return !in.enrolled },
		out:   func(destinationInput) (orgDestination, error) { return orgDestination{open: true}, nil },
	},
	{
		name:  "caller composes for an org the node is no longer enrolled in",
		match: func(in destinationInput) bool { return in.callerOrgID != "" && in.callerOrgID != in.liveOrgID },
		out: func(destinationInput) (orgDestination, error) {
			return orgDestination{}, errOrgDestinationChanged
		},
	},
	{
		name:  "enrolled: the enrolment's org key",
		match: func(destinationInput) bool { return true },
		out: func(in destinationInput) (orgDestination, error) {
			return orgDestination{key: authorityOrgKey(in.liveURL, in.liveOrgID)}, nil
		},
	},
}

// decideOrgDestination walks orgDestinationRules.
func decideOrgDestination(in destinationInput) (orgDestination, error) {
	for _, r := range orgDestinationRules {
		if r.match(in) {
			return r.out(in)
		}
	}
	return orgDestination{}, errOrgDestinationChanged
}

// orgDestinationFor resolves migration 250's pending rows, then the
// destination for a selection composed for callerOrgID ("" = the org enrolled
// now), from the LIVE enrolment.
func (s *Store) orgDestinationFor(ctx context.Context, callerOrgID string) (orgDestination, error) {
	if err := s.resolvePendingAuthorityOrgKeys(ctx); err != nil {
		return orgDestination{}, err
	}
	in := destinationInput{callerOrgID: callerOrgID}
	err := s.db.QueryRowContext(ctx,
		`SELECT org_id, org_server_url FROM org_enrolment WHERE id = 1`).Scan(&in.liveOrgID, &in.liveURL)
	switch {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return orgDestination{}, fmt.Errorf("store.orgDestinationFor: %w", err)
	default:
		in.enrolled = in.liveOrgID != ""
	}
	dest, err := decideOrgDestination(in)
	if err != nil || dest.open {
		return dest, err
	}
	if err := s.claimPersonalSessions(ctx, dest.key); err != nil {
		return orgDestination{}, err
	}
	return dest, nil
}

// claimPersonalSessions stamps every session still keyed 'personal' with the
// enrolled org's key (operator answer 2026-11-13: a session running when the
// machine enrolled, and pre-enrolment history, belong to the first org it is
// enrolled in). It runs at the start of every org-bound selection, after the
// destination is known, so it only ever claims for the org enrolled now. Rows
// keyed to another org, NULL (unknown) and pending rows are untouched.
func (s *Store) claimPersonalSessions(ctx context.Context, orgKey string) error {
	if orgKey == "" {
		return nil
	}
	if _, err := s.db.ExecContext(ctx,
		`UPDATE sessions SET authority_org_key = ? WHERE authority_org_key = ?`,
		orgKey, AuthorityOrgKeyPersonal); err != nil {
		return fmt.Errorf("store.claimPersonalSessions: %w", err)
	}
	return nil
}

// sessionKeyLookupChunk bounds one IN-list of session ids.
const sessionKeyLookupChunk = 400

// sessionOrgKeys reads authority_org_key for each id. An id with no session
// row is absent from the map; a NULL key maps to Valid=false.
func (s *Store) sessionOrgKeys(ctx context.Context, ids []string) (map[string]sql.NullString, error) {
	out := make(map[string]sql.NullString, len(ids))
	for start := 0; start < len(ids); start += sessionKeyLookupChunk {
		end := min(start+sessionKeyLookupChunk, len(ids))
		chunk := ids[start:end]
		args := make([]any, len(chunk))
		for i, id := range chunk {
			args[i] = id
		}
		//nolint:gosec // G202: the fragment is only "?" placeholders; values bind as args
		q := `SELECT id, authority_org_key FROM sessions WHERE id IN (` +
			strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",") + `)`
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return nil, fmt.Errorf("store.sessionOrgKeys: %w", err)
		}
		for rows.Next() {
			var id string
			var key sql.NullString
			if err := rows.Scan(&id, &key); err != nil {
				_ = rows.Close()
				return nil, fmt.Errorf("store.sessionOrgKeys: scan: %w", err)
			}
			out[id] = key
		}
		if err := closeRows(rows); err != nil {
			return nil, fmt.Errorf("store.sessionOrgKeys: %w", err)
		}
	}
	return out, nil
}

// rowAttributionRules decide whether one session-linked row may reach the
// destination, top-down, first match wins. found reports whether the row's
// session exists; key is its authority_org_key.
var rowAttributionRules = []struct {
	name  string
	match func(sessionID string, found bool, key sql.NullString, dest orgDestination) bool
	keep  bool
}{
	{"not enrolled: nothing is filtered", func(_ string, _ bool, _ sql.NullString, d orgDestination) bool { return d.open }, true},
	{"session-less row: it carries no attribution", func(id string, _ bool, _ sql.NullString, _ orgDestination) bool { return id == "" }, true},
	{"session not captured yet: it is being captured under the enrolment in force", func(_ string, found bool, _ sql.NullString, _ orgDestination) bool { return !found }, true},
	{"session of the destination org", func(_ string, _ bool, k sql.NullString, d orgDestination) bool { return k.Valid && k.String == d.key }, true},
	{"any other session (another org, personal, unknown, pending)", func(string, bool, sql.NullString, orgDestination) bool { return true }, false},
}

// keepAttributedRow walks rowAttributionRules.
func keepAttributedRow(sessionID string, found bool, key sql.NullString, dest orgDestination) bool {
	for _, r := range rowAttributionRules {
		if r.match(sessionID, found, key, dest) {
			return r.keep
		}
	}
	return false
}

// keepSessionRows filters rows in place by the session id sid reads from each.
// An emptied slice is returned as nil, like a family that composed nothing.
func keepSessionRows[T any](rows []T, sid func(*T) string, keep func(string) bool) []T {
	if len(rows) == 0 {
		return rows
	}
	out := rows[:0]
	for i := range rows {
		if keep(sid(&rows[i])) {
			out = append(out, rows[i])
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// attributedFamilies is every push-batch family whose rows belong to one
// captured session (the field named here is a sessions.id). Each is filtered
// to the destination org after the batch is composed: the cursor and re-send
// lanes have already moved past a dropped row, which can never ship to this
// org. name is the PushBatch field. The identity-only correction lanes
// (Deletions, SessionManifests) and the aggregate, posture and Plane A
// families carry no captured session and are not listed;
// TestAttributedFamiliesCoverEverySessionFamily fails on a new family that
// carries a session id until it is listed here or excluded there.
var attributedFamilies = []struct {
	name   string
	filter func(b *PushBatch, keep func(string) bool)
}{
	{"Sessions", func(b *PushBatch, k func(string) bool) {
		b.Sessions = keepSessionRows(b.Sessions, func(r *orgcontract.SessionRow) string { return r.ID }, k)
	}},
	{"Actions", func(b *PushBatch, k func(string) bool) {
		b.Actions = keepSessionRows(b.Actions, func(r *orgcontract.ActionRow) string { return r.SessionID }, k)
	}},
	{"APITurns", func(b *PushBatch, k func(string) bool) {
		b.APITurns = keepSessionRows(b.APITurns, func(r *orgcontract.APITurnRow) string { return r.SessionID }, k)
	}},
	{"TokenUsage", func(b *PushBatch, k func(string) bool) {
		b.TokenUsage = keepSessionRows(b.TokenUsage, func(r *orgcontract.TokenUsageRow) string { return r.SessionID }, k)
	}},
	{"GuardEvents", func(b *PushBatch, k func(string) bool) {
		b.GuardEvents = keepSessionRows(b.GuardEvents, func(r *orgcontract.GuardEventRow) string { return r.SessionID }, k)
	}},
	{"OTelContent", func(b *PushBatch, k func(string) bool) {
		b.OTelContent = keepSessionRows(b.OTelContent, func(r *orgcontract.OTelContentRow) string { return r.SessionID }, k)
	}},
	{"MCPRelayEvents", func(b *PushBatch, k func(string) bool) {
		b.MCPRelayEvents = keepSessionRows(b.MCPRelayEvents, func(r *orgcontract.MCPRelayEventRow) string { return r.CodingSessionID }, k)
	}},
	{"SessionLimitSnapshots", func(b *PushBatch, k func(string) bool) {
		b.SessionLimitSnapshots = keepSessionRows(b.SessionLimitSnapshots, func(r *orgcontract.SessionLimitSnapshotRow) string { return r.SessionID }, k)
	}},
	{"SessionVerbositySummaries", func(b *PushBatch, k func(string) bool) {
		b.SessionVerbositySummaries = keepSessionRows(b.SessionVerbositySummaries, func(r *orgcontract.SessionVerbosityRow) string { return r.SessionID }, k)
	}},
	{"SessionCacheSummaries", func(b *PushBatch, k func(string) bool) {
		b.SessionCacheSummaries = keepSessionRows(b.SessionCacheSummaries, func(r *orgcontract.SessionCacheRow) string { return r.SessionID }, k)
	}},
	{"SessionCacheEvents", func(b *PushBatch, k func(string) bool) {
		b.SessionCacheEvents = keepSessionRows(b.SessionCacheEvents, func(r *orgcontract.SessionCacheEventRow) string { return r.SessionID }, k)
	}},
	{"SessionProcesses", func(b *PushBatch, k func(string) bool) {
		b.SessionProcesses = keepSessionRows(b.SessionProcesses, func(r *orgcontract.SessionProcessRow) string { return r.SessionID }, k)
	}},
	{"SessionNetworkEvents", func(b *PushBatch, k func(string) bool) {
		b.SessionNetworkEvents = keepSessionRows(b.SessionNetworkEvents, func(r *orgcontract.SessionNetworkEventRow) string { return r.SessionID }, k)
	}},
	{"SessionProcessRollups", func(b *PushBatch, k func(string) bool) {
		b.SessionProcessRollups = keepSessionRows(b.SessionProcessRollups, func(r *orgcontract.SessionProcessRollupRow) string { return r.SessionID }, k)
	}},
	{"SessionProcessCaptureStats", func(b *PushBatch, k func(string) bool) {
		b.SessionProcessCaptureStats = keepSessionRows(b.SessionProcessCaptureStats, func(r *orgcontract.SessionProcessCaptureStatsRow) string { return r.SessionID }, k)
	}},
	{"SessionTaskItems", func(b *PushBatch, k func(string) bool) {
		b.SessionTaskItems = keepSessionRows(b.SessionTaskItems, func(r *orgcontract.SessionTaskItemRow) string { return r.SessionID }, k)
	}},
	{"SessionTaskTransitions", func(b *PushBatch, k func(string) bool) {
		b.SessionTaskTransitions = keepSessionRows(b.SessionTaskTransitions, func(r *orgcontract.SessionTaskTransitionRow) string { return r.SessionID }, k)
	}},
	{"SessionToolAccounts", func(b *PushBatch, k func(string) bool) {
		b.SessionToolAccounts = keepSessionRows(b.SessionToolAccounts, func(r *orgcontract.SessionToolAccountRow) string { return r.SessionID }, k)
	}},
	{"SessionHookActivity", func(b *PushBatch, k func(string) bool) {
		b.SessionHookActivity = keepSessionRows(b.SessionHookActivity, func(r *orgcontract.HookActivitySessionRow) string { return r.SessionID }, k)
	}},
	{"SessionLOC", func(b *PushBatch, k func(string) bool) {
		b.SessionLOC = keepSessionRows(b.SessionLOC, func(r *orgcontract.SessionLOCRow) string { return r.SessionID }, k)
	}},
	{"SessionQuality", func(b *PushBatch, k func(string) bool) {
		b.SessionQuality = keepSessionRows(b.SessionQuality, func(r *orgcontract.SessionQualityRow) string { return r.SessionID }, k)
	}},
	{"CommitOwnership", func(b *PushBatch, k func(string) bool) {
		b.CommitOwnership = keepSessionRows(b.CommitOwnership, func(r *orgcontract.CommitOwnershipRow) string { return r.OwnerSessionID }, k)
	}},
	{"SecurityFindings", func(b *PushBatch, k func(string) bool) {
		b.SecurityFindings = keepSessionRows(b.SecurityFindings, func(r *orgcontract.SecurityFindingRow) string { return r.SessionID }, k)
	}},
	{"GuardApprovals", func(b *PushBatch, k func(string) bool) {
		b.GuardApprovals = keepSessionRows(b.GuardApprovals, func(r *orgcontract.GuardApprovalRow) string { return r.SessionID }, k)
	}},
}

// applyOrgAttribution drops every row of an attributed family whose session
// does not belong to dest (D-43). It reads each referenced session's key once.
func (s *Store) applyOrgAttribution(ctx context.Context, b *PushBatch, dest orgDestination) error {
	if dest.open {
		return nil
	}
	seen := map[string]bool{}
	var ids []string
	collect := func(id string) bool {
		if id != "" && !seen[id] {
			seen[id] = true
			ids = append(ids, id)
		}
		return true
	}
	for _, f := range attributedFamilies {
		f.filter(b, collect)
	}
	keys, err := s.sessionOrgKeys(ctx, ids)
	if err != nil {
		return fmt.Errorf("store.applyOrgAttribution: %w", err)
	}
	keep := func(id string) bool {
		key, found := keys[id]
		return keepAttributedRow(id, found, key, dest)
	}
	for _, f := range attributedFamilies {
		f.filter(b, keep)
	}
	return nil
}

// attributedCountPredicate is the SQL twin of keepAttributedRow for a table
// whose rows carry session_id (alias t), used by PushEligibleCounts: a row
// counts unless its session exists and is keyed to anything but dest. Bind
// dest.key once.
const attributedCountPredicate = ` AND NOT EXISTS (SELECT 1 FROM sessions ks
	  WHERE ks.id = t.session_id AND COALESCE(ks.authority_org_key, '') <> ?)`
