//go:build !sbo_omit_security

package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/scrub"
)

// secchange.go is the ONE owner of the signed AI change record tables
// (agent migration 191; security plan 7.10; component security.provenance,
// lane SEC-F2A): sec_change_records, sec_change_keys (public halves only)
// and sec_change_consent. All three are NODE-LOCAL and in the privacy
// sentinel; the change records reach the org only through
// SelectChangeRecordRows, which the cmd layer binds into
// SecurityOrgProviders.ChangeRecords.

// changeRecordWireWindow keeps a record on the wire this long after it was
// recorded; the org keys a re-push on the commit identity hash.
const changeRecordWireWindow = 30 * 24 * time.Hour

// ChangeRecordRow is one stored change record.
type ChangeRecordRow struct {
	ID               int64
	ProjectID        int64
	ProjectRootHash  string
	CommitSHA        string
	TreeSHA          string
	PatchFP          string
	KeyID            string
	AttestationLevel string
	KeyStorage       string
	RecordDigest     string
	// Envelope is the DSSE envelope as signed (canonical JSON).
	Envelope         []byte
	Files            int64
	AILines          int64
	HumanLines       int64
	UnknownLines     int64
	HumanCapture     string
	Sessions         []string
	Models           []string
	Tools            []string
	Scanners         []string
	Packs            []string
	Exceptions       []string
	Paths            []string
	FindingsOpen     int64
	FindingsBlocking int64
	EvidenceDigest   string
	CommittedAt      string
	RecordedAt       string
	NoteWrittenAt    string
}

// ListChangeRecordsBefore pages one repository's change records newest
// first, in (recorded_at, id) order: the records strictly older than the
// cursor (beforeRecordedAt, beforeID); a zero beforeID starts at the
// newest. limit is capped like ListChangeRecords (audit finding F8: the
// export reads past one page).
func (s *Store) ListChangeRecordsBefore(ctx context.Context, rootHash, beforeRecordedAt string, beforeID int64, limit int) ([]ChangeRecordRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + changeRecordCols + ` FROM sec_change_records WHERE project_root_hash = ?`
	args := []any{rootHash}
	if beforeID > 0 {
		q += ` AND (recorded_at < ? OR (recorded_at = ? AND id < ?))`
		args = append(args, beforeRecordedAt, beforeRecordedAt, beforeID)
	}
	q += ` ORDER BY recorded_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListChangeRecordsBefore: %w", err)
	}
	defer rows.Close()
	var out []ChangeRecordRow
	for rows.Next() {
		r, err := scanChangeRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ListChangeRecordsBefore: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ChangeKey is one signing key's public half.
type ChangeKey struct {
	KeyID        string
	PublicKey    string
	Storage      string
	Attestation  string
	Enrolment    string
	CreatedAt    string
	RetiredAt    string
	RetireReason string
}

// ChangeConsent is one repository's writer consent.
type ChangeConsent struct {
	ProjectRootHash string
	RootPath        string
	Notes           bool
	Trailer         bool
	Surface         string
	GivenAt         string
	RevokedAt       string
}

func changeJSONList(v []string) string {
	if len(v) == 0 {
		return "[]"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func changeParseList(s string) []string {
	var out []string
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// InsertChangeRecord stores a record; inserted=false when the same
// project, commit and key already have one (the builder records a commit
// once).
func (s *Store) InsertChangeRecord(ctx context.Context, r ChangeRecordRow) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO sec_change_records (
		project_id, project_root_hash, commit_sha, tree_sha, patch_fp, key_id, attestation_level, key_storage,
		record_digest, envelope, files, ai_lines, human_lines, unknown_lines, human_capture,
		sessions_json, models_json, tools_json, scanners_json, packs_json, exceptions_json, paths_json,
		findings_open, findings_blocking, evidence_digest, committed_at, recorded_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT (project_root_hash, commit_sha, key_id) DO NOTHING`,
		r.ProjectID, r.ProjectRootHash, r.CommitSHA, r.TreeSHA, r.PatchFP, r.KeyID, r.AttestationLevel, r.KeyStorage,
		r.RecordDigest, string(r.Envelope), r.Files, r.AILines, r.HumanLines, r.UnknownLines, r.HumanCapture,
		changeJSONList(r.Sessions), changeJSONList(r.Models), changeJSONList(r.Tools), changeJSONList(r.Scanners), changeJSONList(r.Packs),
		changeJSONList(r.Exceptions), changeJSONList(r.Paths),
		r.FindingsOpen, r.FindingsBlocking, r.EvidenceDigest, r.CommittedAt, r.RecordedAt)
	if err != nil {
		return false, fmt.Errorf("store.InsertChangeRecord: %w", err)
	}
	n, _ := res.RowsAffected()
	return n == 1, nil
}

// HasChangeRecord reports whether a project's commit has any record.
func (s *Store) HasChangeRecord(ctx context.Context, rootHash, sha string) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sec_change_records WHERE project_root_hash = ? AND commit_sha = ?`, rootHash, sha).Scan(&n)
	if err != nil {
		return false, fmt.Errorf("store.HasChangeRecord: %w", err)
	}
	return n > 0, nil
}

const changeRecordCols = `id, project_id, project_root_hash, commit_sha, tree_sha, patch_fp, key_id, attestation_level, key_storage,
	record_digest, envelope, files, ai_lines, human_lines, unknown_lines, human_capture,
	sessions_json, models_json, tools_json, scanners_json, packs_json, exceptions_json, paths_json,
	findings_open, findings_blocking, evidence_digest, committed_at, recorded_at, note_written_at`

func scanChangeRecord(sc interface{ Scan(...any) error }) (ChangeRecordRow, error) {
	var r ChangeRecordRow
	var env, ses, mod, tools, scan, packs, exc, paths string
	err := sc.Scan(&r.ID, &r.ProjectID, &r.ProjectRootHash, &r.CommitSHA, &r.TreeSHA, &r.PatchFP, &r.KeyID, &r.AttestationLevel, &r.KeyStorage,
		&r.RecordDigest, &env, &r.Files, &r.AILines, &r.HumanLines, &r.UnknownLines, &r.HumanCapture,
		&ses, &mod, &tools, &scan, &packs, &exc, &paths,
		&r.FindingsOpen, &r.FindingsBlocking, &r.EvidenceDigest, &r.CommittedAt, &r.RecordedAt, &r.NoteWrittenAt)
	if err != nil {
		return r, err
	}
	r.Envelope = []byte(env)
	r.Sessions, r.Models, r.Tools, r.Scanners = changeParseList(ses), changeParseList(mod), changeParseList(tools), changeParseList(scan)
	r.Packs, r.Exceptions, r.Paths = changeParseList(packs), changeParseList(exc), changeParseList(paths)
	return r, nil
}

// ListChangeRecords returns a project's records (every project when
// rootHash is ""), newest first, at most limit.
func (s *Store) ListChangeRecords(ctx context.Context, rootHash string, limit int) ([]ChangeRecordRow, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	q := `SELECT ` + changeRecordCols + ` FROM sec_change_records`
	var args []any
	if rootHash != "" {
		q += ` WHERE project_root_hash = ?`
		args = append(args, rootHash)
	}
	q += ` ORDER BY recorded_at DESC, id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, fmt.Errorf("store.ListChangeRecords: %w", err)
	}
	defer rows.Close()
	var out []ChangeRecordRow
	for rows.Next() {
		r, err := scanChangeRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ListChangeRecords: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// ChangeRecordsWithoutNote returns a project's records whose git note has
// not been written yet, oldest first.
func (s *Store) ChangeRecordsWithoutNote(ctx context.Context, rootHash string, limit int) ([]ChangeRecordRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+changeRecordCols+` FROM sec_change_records
		WHERE project_root_hash = ? AND note_written_at = '' ORDER BY id LIMIT ?`, rootHash, limit)
	if err != nil {
		return nil, fmt.Errorf("store.ChangeRecordsWithoutNote: %w", err)
	}
	defer rows.Close()
	var out []ChangeRecordRow
	for rows.Next() {
		r, err := scanChangeRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store.ChangeRecordsWithoutNote: %w", err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// MarkChangeNoteWritten stamps a record's note as written.
func (s *Store) MarkChangeNoteWritten(ctx context.Context, id int64, at time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE sec_change_records SET note_written_at = ? WHERE id = ?`, at.UTC().Format(time.RFC3339), id); err != nil {
		return fmt.Errorf("store.MarkChangeNoteWritten: %w", err)
	}
	return nil
}

// ChangeRecordStats is the status line's counts.
type ChangeRecordStats struct {
	Records      int64
	Projects     int64
	NotesWritten int64
	Newest       string
}

// ChangeRecordStatsNow counts the stored records.
func (s *Store) ChangeRecordStatsNow(ctx context.Context) (ChangeRecordStats, error) {
	var st ChangeRecordStats
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*), COUNT(DISTINCT project_root_hash),
		COALESCE(SUM(CASE WHEN note_written_at != '' THEN 1 ELSE 0 END), 0), COALESCE(MAX(recorded_at), '')
		FROM sec_change_records`).Scan(&st.Records, &st.Projects, &st.NotesWritten, &st.Newest)
	if err != nil {
		return st, fmt.Errorf("store.ChangeRecordStatsNow: %w", err)
	}
	return st, nil
}

// SaveChangeKey stores a new key's public half.
func (s *Store) SaveChangeKey(ctx context.Context, k ChangeKey) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO sec_change_keys (key_id, public_key, storage, attestation, enrolment, created_at)
		VALUES (?,?,?,?,?,?) ON CONFLICT (key_id) DO NOTHING`, k.KeyID, k.PublicKey, k.Storage, k.Attestation, k.Enrolment, k.CreatedAt)
	if err != nil {
		return fmt.Errorf("store.SaveChangeKey: %w", err)
	}
	return nil
}

// SetChangeKeyAttestation records how a key is vouched for: org_certified
// once the org signed its certificate (lane SEC-F2B). Records signed after
// carry it; a verifier still decides what it trusts.
func (s *Store) SetChangeKeyAttestation(ctx context.Context, keyID, attestation string) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE sec_change_keys SET attestation = ? WHERE key_id = ?`, attestation, keyID); err != nil {
		return fmt.Errorf("store.SetChangeKeyAttestation: %w", err)
	}
	return nil
}

// ActiveChangeKey returns the newest key that is not retired.
func (s *Store) ActiveChangeKey(ctx context.Context) (ChangeKey, bool, error) {
	var k ChangeKey
	err := s.db.QueryRowContext(ctx, `SELECT key_id, public_key, storage, attestation, enrolment, created_at, retired_at, retire_reason
		FROM sec_change_keys WHERE retired_at = '' ORDER BY created_at DESC, key_id LIMIT 1`).
		Scan(&k.KeyID, &k.PublicKey, &k.Storage, &k.Attestation, &k.Enrolment, &k.CreatedAt, &k.RetiredAt, &k.RetireReason)
	if errors.Is(err, sql.ErrNoRows) {
		return k, false, nil
	}
	if err != nil {
		return k, false, fmt.Errorf("store.ActiveChangeKey: %w", err)
	}
	return k, true, nil
}

// ChangeKeys returns every key, newest first (retired ones too, so their
// records stay verifiable).
func (s *Store) ChangeKeys(ctx context.Context) ([]ChangeKey, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key_id, public_key, storage, attestation, enrolment, created_at, retired_at, retire_reason
		FROM sec_change_keys ORDER BY created_at DESC, key_id`)
	if err != nil {
		return nil, fmt.Errorf("store.ChangeKeys: %w", err)
	}
	defer rows.Close()
	var out []ChangeKey
	for rows.Next() {
		var k ChangeKey
		if err := rows.Scan(&k.KeyID, &k.PublicKey, &k.Storage, &k.Attestation, &k.Enrolment, &k.CreatedAt, &k.RetiredAt, &k.RetireReason); err != nil {
			return nil, fmt.Errorf("store.ChangeKeys: %w", err)
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// RetireChangeKey retires a key (never deletes it).
func (s *Store) RetireChangeKey(ctx context.Context, keyID, reason string, at time.Time) error {
	if _, err := s.db.ExecContext(ctx, `UPDATE sec_change_keys SET retired_at = ?, retire_reason = ? WHERE key_id = ? AND retired_at = ''`,
		at.UTC().Format(time.RFC3339), reason, keyID); err != nil {
		return fmt.Errorf("store.RetireChangeKey: %w", err)
	}
	return nil
}

// SetChangeConsent records a person's consent (or its withdrawal, with
// both flags false) for one repository.
func (s *Store) SetChangeConsent(ctx context.Context, c ChangeConsent, at time.Time) error {
	now := at.UTC().Format(time.RFC3339)
	given, revoked := now, ""
	if !c.Notes && !c.Trailer {
		given, revoked = "", now
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO sec_change_consent (project_root_hash, root_path, notes, trailer, surface, given_at, revoked_at)
		VALUES (?,?,?,?,?,?,?)
		ON CONFLICT (project_root_hash) DO UPDATE SET root_path = excluded.root_path, notes = excluded.notes, trailer = excluded.trailer,
		surface = excluded.surface,
		given_at = CASE WHEN excluded.given_at = '' THEN sec_change_consent.given_at ELSE excluded.given_at END,
		revoked_at = excluded.revoked_at`,
		c.ProjectRootHash, c.RootPath, boolInt(c.Notes), boolInt(c.Trailer), c.Surface, given, revoked)
	if err != nil {
		return fmt.Errorf("store.SetChangeConsent: %w", err)
	}
	return nil
}

// ChangeConsentFor returns one repository's consent (the zero value, no
// consent, when none was ever given).
func (s *Store) ChangeConsentFor(ctx context.Context, rootHash string) (ChangeConsent, error) {
	c := ChangeConsent{ProjectRootHash: rootHash}
	var notes, trailer int
	err := s.db.QueryRowContext(ctx, `SELECT root_path, notes, trailer, surface, given_at, revoked_at FROM sec_change_consent WHERE project_root_hash = ?`, rootHash).
		Scan(&c.RootPath, &notes, &trailer, &c.Surface, &c.GivenAt, &c.RevokedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, nil
	}
	if err != nil {
		return c, fmt.Errorf("store.ChangeConsentFor: %w", err)
	}
	c.Notes, c.Trailer = notes == 1, trailer == 1
	return c, nil
}

// ChangeConsents returns every repository with a consent row.
func (s *Store) ChangeConsents(ctx context.Context) ([]ChangeConsent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT project_root_hash, root_path, notes, trailer, surface, given_at, revoked_at FROM sec_change_consent ORDER BY root_path`)
	if err != nil {
		return nil, fmt.Errorf("store.ChangeConsents: %w", err)
	}
	defer rows.Close()
	var out []ChangeConsent
	for rows.Next() {
		var c ChangeConsent
		var notes, trailer int
		if err := rows.Scan(&c.ProjectRootHash, &c.RootPath, &notes, &trailer, &c.Surface, &c.GivenAt, &c.RevokedAt); err != nil {
			return nil, fmt.Errorf("store.ChangeConsents: %w", err)
		}
		c.Notes, c.Trailer = notes == 1, trailer == 1
		out = append(out, c)
	}
	return out, rows.Err()
}

// ChangeCommitIdentityHash is the wire's opaque commit identity: a
// domain-separated digest of the project hash and the commit sha.
func ChangeCommitIdentityHash(rootHash, sha string) string {
	sum := sha256.Sum256([]byte("sbo-change-commit-v1\x00" + rootHash + "\x00" + sha))
	return hex.EncodeToString(sum[:])
}

// changePatchHash is the wire's opaque patch fingerprint, the one a CI
// job computes too (orgcontract.ChangePatchFPHash).
func changePatchHash(fp string) string { return orgcontract.ChangePatchFPHash(fp) }

// changeWireAttestation maps a node key's attestation onto the wire's
// closed vocabulary: a node signature is "local" until the org
// countersigns it (lane SEC-F2B).
func changeWireAttestation(string) string { return "local" }

// SelectChangeRecordRows reads the change record wire rows of the
// projects inside scope, newest first, at most max: unstripped (the
// composer strips raw fields and runs the secret gate).
func (s *Store) SelectChangeRecordRows(ctx context.Context, max int, scope SecurityScope) ([]orgcontract.AIChangeRecordRow, error) {
	where, args := scope.where("project_root_hash")
	since := time.Now().UTC().Add(-changeRecordWireWindow).Format(time.RFC3339)
	//nolint:gosec // G202: only fixed column lists and the scope's placeholder clause are concatenated; every value is bound.
	q := `SELECT ` + changeRecordCols + ` FROM sec_change_records WHERE recorded_at >= ?` + where + ` ORDER BY recorded_at DESC, id DESC LIMIT ?`
	all := append([]any{since}, args...)
	all = append(all, max)
	rows, err := s.db.QueryContext(ctx, q, all...)
	if err != nil {
		return nil, fmt.Errorf("store.SelectChangeRecordRows: %w", err)
	}
	defer rows.Close()
	var out []orgcontract.AIChangeRecordRow
	for rows.Next() {
		r, err := scanChangeRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store.SelectChangeRecordRows: %w", err)
		}
		out = append(out, orgcontract.AIChangeRecordRow{
			CommitIdentityHash: ChangeCommitIdentityHash(r.ProjectRootHash, r.CommitSHA),
			PatchFPHash:        changePatchHash(r.PatchFP),
			RecordDigest:       r.RecordDigest,
			KeyID:              r.KeyID,
			AttestationLevel:   changeWireAttestation(r.AttestationLevel),
			Files:              r.Files,
			AILines:            r.AILines,
			HumanLines:         r.HumanLines,
			UnknownLines:       r.UnknownLines,
			HumanCapture:       changeWireHumanCapture(r.HumanCapture),
			Sessions:           r.Sessions,
			Models:             r.Models,
			Tools:              r.Tools,
			Scanners:           r.Scanners,
			PackVersions:       r.Packs,
			FindingsOpen:       r.FindingsOpen,
			FindingsBlocking:   r.FindingsBlocking,
			ExceptionIDs:       r.Exceptions,
			CommittedAt:        r.CommittedAt,
			CommitSHA:          r.CommitSHA,
			Paths:              r.Paths,
			// The signed envelope rides with the raw columns (lane
			// SEC-F2B): the composer's strip clears it unless raw content
			// ships, and an envelope over the cap is left out.
			Envelope: changeWireEnvelope(r.Envelope),
		})
	}
	return out, rows.Err()
}

// changeWireEnvelope is the envelope a change record ships (lane SEC-F2B):
// the stored DSSE line within its cap, unless its decoded payload holds a
// shape-certain secret. The secret gate (orgcontract.GateSecuritySecrets)
// reads the row's text fields, not the base64 inside an envelope, so the
// payload is checked here: the envelope is left out rather than masked
// (masking would break its signature).
func changeWireEnvelope(raw []byte) string {
	env := orgcontract.NormalizeChangeEnvelope(string(raw))
	if env == "" {
		return ""
	}
	var e struct {
		Payload string `json:"payload"`
	}
	if json.Unmarshal([]byte(env), &e) != nil {
		return ""
	}
	payload, err := base64.StdEncoding.DecodeString(e.Payload)
	if err != nil || len(scrub.CertainSecretTypes(string(payload))) > 0 {
		return ""
	}
	return env
}

// changeWireHumanCapture maps LOC's capture state onto the wire's closed
// vocabulary (none, partial, full): VS Code capture is partial (one
// editor), and none stays none, never zero.
func changeWireHumanCapture(v string) string {
	if strings.TrimSpace(v) == "" || v == "none" {
		return "none"
	}
	return "partial"
}

// probeSecChangeRecords fingerprints the change records for the snapshot
// gate.
func (s *Store) probeSecChangeRecords(ctx context.Context) (string, error) {
	base, err := s.snapProbeScalar(ctx, `SELECT (SELECT COUNT(*) FROM sec_change_records) || ':' ||
		(SELECT COALESCE(MAX(id), 0) FROM sec_change_records)`)
	if err != nil {
		return "", err
	}
	return base + "#" + time.Now().UTC().Format("2006-01-02") + "#" + s.secSalt.get(), nil
}

// SessionModel returns a session's model, "" when unknown (the trailer's
// AGENT:MODEL value).
func (s *Store) SessionModel(ctx context.Context, sessionID string) string {
	var m sql.NullString
	if err := s.db.QueryRowContext(ctx, `SELECT model FROM sessions WHERE id = ?`, sessionID).Scan(&m); err != nil {
		return ""
	}
	return m.String
}
