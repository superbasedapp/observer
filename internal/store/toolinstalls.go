package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Dashboard-installed tools (agent migration 149).
//
// THIS FILE IS THE ONE OWNER of tool_installs (CLAUDE.md module-boundary rule
// #4). The lifecycle vocabulary and the uninstall derivation live in the pure
// internal/toolinstall package; the caller (cmd/observer's install ledger)
// resolves every transition there and hands this seam plain strings. Every
// status change here is a compare-and-set on the row's CURRENT status, so two
// racing confirms (or a confirm racing an exit) can never both win.
//
// NODE-LOCAL: tool_installs is never named in internal/store/orgpush.go —
// pinned in the forbidden-table sentinel (tests/invariant/privacy_test.go).
//
// Since agent migration 222 the table holds two SUBJECTS (subject_kind):
// AI tools the New Terminal dialog installed (SubjectTool, every row from
// before 222) and sandbox setup steps (SubjectSandbox, where tool holds the
// prerequisite id). Every read and every compare-and-set below is scoped to
// one subject, the latest-record guard included, so a sandbox record can
// never supersede, be listed as, or be uninstalled through a tool record
// and the reverse. The original Tool* methods are the SubjectTool scope and
// behave exactly as before; the *InstallRecord methods take the subject.

// The closed subject_kind vocabulary.
const (
	// SubjectTool: an AI tool's guided install (the default).
	SubjectTool = "tool"
	// SubjectSandbox: one step of a sandbox backend's setup.
	SubjectSandbox = "sandbox"
)

// validSubject reports whether s is a subject_kind value.
func validSubject(s string) bool { return s == SubjectTool || s == SubjectSandbox }

// ToolInstallRow is one tool_installs row.
type ToolInstallRow struct {
	ID int64
	// SubjectKind is SubjectTool or SubjectSandbox; "" on insert means
	// SubjectTool.
	SubjectKind string
	// Tool is the AI tool's name, or a sandbox step's prerequisite id.
	Tool        string
	Channel     string
	Package     string
	Argv        []string
	Display     string
	Version     string
	Status      string
	ExitCode    *int
	StartedAt   time.Time
	FinishedAt  *time.Time
	ResolvedBin string

	UninstallArgv       []string
	UninstallDisplay    string
	UninstallStartedAt  *time.Time
	UninstallFinishedAt *time.Time
	UninstallExitCode   *int

	// Backend is the sandbox backend a sandbox record was set up for.
	Backend string
	// Source is where a pinned download came from (vendor_release,
	// org_mirror, from_file).
	Source string
	// Digest is the sha256 of the file Observer placed.
	Digest string
	// PlacedPath is the file Observer placed (a pinned download).
	PlacedPath string
	// Elevated: the step ran under sudo or UAC.
	Elevated bool
}

// ToolInstallFinish is the outcome a settled PTY (or a finished in-process
// operation) writes.
type ToolInstallFinish struct {
	Status      string
	ExitCode    int
	ResolvedBin string
	At          time.Time
	// Digest and PlacedPath, when set, record what a pinned download placed
	// (empty keeps the row's value).
	Digest     string
	PlacedPath string
}

// tiNotSuperseded is the latest-record guard every operator-confirmed
// transition (uninstall claim, forget) carries IN its compare-and-set: the
// row must still be its tool's newest not-forgotten record. The ledger checks
// that first, but a new install can land between the check and the update
// (Sol A3-08), so the check alone would let an uninstall run against machine
// state a newer install now owns. Folding it into the UPDATE makes the
// validation and the transition one atomic statement.
// The guard is per subject: a newer record of another subject under the same
// name never supersedes this one.
const tiNotSuperseded = `NOT EXISTS (SELECT 1 FROM tool_installs n
		WHERE n.subject_kind = tool_installs.subject_kind AND n.tool = tool_installs.tool
		  AND n.id > tool_installs.id AND n.forgotten_at IS NULL)`

const toolInstallCols = `id, tool, channel, package, argv_json, display, version, status,
	exit_code, started_at, finished_at, resolved_bin, uninstall_argv_json,
	uninstall_display, uninstall_started_at, uninstall_finished_at,
	uninstall_exit_code, subject_kind, backend, source, digest, placed_path,
	elevated`

// InsertToolInstall records a just-spawned dashboard install and returns its
// id. row.Status is the initial status (the caller passes "installing").
// row.SubjectKind "" records an AI tool (SubjectTool).
func (s *Store) InsertToolInstall(ctx context.Context, row ToolInstallRow) (int64, error) {
	if strings.TrimSpace(row.Tool) == "" || strings.TrimSpace(row.Channel) == "" || len(row.Argv) == 0 || row.Status == "" {
		return 0, errors.New("store.InsertToolInstall: tool, channel, argv and status are required")
	}
	subject := row.SubjectKind
	if subject == "" {
		subject = SubjectTool
	}
	if !validSubject(subject) {
		return 0, fmt.Errorf("store.InsertToolInstall: unknown subject_kind %q", subject)
	}
	argv, err := json.Marshal(row.Argv)
	if err != nil {
		return 0, fmt.Errorf("store.InsertToolInstall: %w", err)
	}
	at := row.StartedAt
	if at.IsZero() {
		at = time.Now()
	}
	res, err := s.db.ExecContext(ctx, `
		INSERT INTO tool_installs (tool, channel, package, argv_json, display, version, status, started_at,
		                           subject_kind, backend, source, digest, placed_path, elevated)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		row.Tool, row.Channel, row.Package, string(argv), row.Display, row.Version, row.Status, tiFmtTS(at),
		subject, row.Backend, row.Source, row.Digest, row.PlacedPath, row.Elevated)
	if err != nil {
		return 0, fmt.Errorf("store.InsertToolInstall: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("store.InsertToolInstall: %w", err)
	}
	return id, nil
}

// LatestToolInstall returns the newest not-forgotten AI-tool record for tool.
func (s *Store) LatestToolInstall(ctx context.Context, tool string) (ToolInstallRow, bool, error) {
	return s.LatestInstallRecord(ctx, SubjectTool, tool)
}

// LatestInstallRecord returns the newest not-forgotten record of subject
// for name (an AI tool, or a sandbox prerequisite id).
func (s *Store) LatestInstallRecord(ctx context.Context, subject, name string) (ToolInstallRow, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+toolInstallCols+`
		FROM tool_installs WHERE subject_kind = ? AND tool = ? AND forgotten_at IS NULL
		ORDER BY id DESC LIMIT 1`, subject, name)
	if err != nil {
		return ToolInstallRow{}, false, fmt.Errorf("store.LatestInstallRecord: %w", err)
	}
	out, err := scanToolInstalls(rows)
	if err != nil {
		return ToolInstallRow{}, false, fmt.Errorf("store.LatestInstallRecord: %w", err)
	}
	if len(out) == 0 {
		return ToolInstallRow{}, false, nil
	}
	return out[0], true, nil
}

// GetToolInstall returns one AI-tool record by id (forgotten rows included);
// ok is false for a sandbox record's id.
func (s *Store) GetToolInstall(ctx context.Context, id int64) (ToolInstallRow, bool, error) {
	return s.GetInstallRecord(ctx, SubjectTool, id)
}

// GetInstallRecord returns one record of subject by id (forgotten rows
// included).
func (s *Store) GetInstallRecord(ctx context.Context, subject string, id int64) (ToolInstallRow, bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+toolInstallCols+`
		FROM tool_installs WHERE id = ? AND subject_kind = ?`, id, subject)
	if err != nil {
		return ToolInstallRow{}, false, fmt.Errorf("store.GetInstallRecord: %w", err)
	}
	out, err := scanToolInstalls(rows)
	if err != nil {
		return ToolInstallRow{}, false, fmt.Errorf("store.GetInstallRecord: %w", err)
	}
	if len(out) == 0 {
		return ToolInstallRow{}, false, nil
	}
	return out[0], true, nil
}

// ListLatestToolInstalls returns the newest not-forgotten AI-tool record per
// tool, newest first.
func (s *Store) ListLatestToolInstalls(ctx context.Context) ([]ToolInstallRow, error) {
	return s.ListLatestInstallRecords(ctx, SubjectTool)
}

// ListLatestInstallRecords returns the newest not-forgotten record of
// subject per name, newest first.
func (s *Store) ListLatestInstallRecords(ctx context.Context, subject string) ([]ToolInstallRow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+toolInstallCols+`
		FROM tool_installs t
		WHERE subject_kind = ? AND forgotten_at IS NULL
		  AND id = (SELECT MAX(id) FROM tool_installs t2
		            WHERE t2.subject_kind = t.subject_kind AND t2.tool = t.tool AND t2.forgotten_at IS NULL)
		ORDER BY id DESC`, subject)
	if err != nil {
		return nil, fmt.Errorf("store.ListLatestInstallRecords: %w", err)
	}
	out, err := scanToolInstalls(rows)
	if err != nil {
		return nil, fmt.Errorf("store.ListLatestInstallRecords: %w", err)
	}
	return out, nil
}

// FinishToolInstall settles an in-flight AI-tool INSTALL: CAS from `from` to
// f.Status, stamping the exit code, finish time and the post-install
// resolution. ok=false when the row was not in `from` (already settled).
func (s *Store) FinishToolInstall(ctx context.Context, id int64, from string, f ToolInstallFinish) (bool, error) {
	return s.FinishInstallRecord(ctx, SubjectTool, id, from, f)
}

// FinishInstallRecord is FinishToolInstall for a record of subject; a
// non-empty f.Digest or f.PlacedPath is stamped too.
func (s *Store) FinishInstallRecord(ctx context.Context, subject string, id int64, from string, f ToolInstallFinish) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tool_installs
		   SET status = ?, exit_code = ?, finished_at = ?, resolved_bin = ?,
		       digest = CASE WHEN ? = '' THEN digest ELSE ? END,
		       placed_path = CASE WHEN ? = '' THEN placed_path ELSE ? END
		 WHERE id = ? AND subject_kind = ? AND status = ?`,
		f.Status, f.ExitCode, tiFmtTS(f.At), f.ResolvedBin, f.Digest, f.Digest, f.PlacedPath, f.PlacedPath, id, subject, from)
	return tiAffectedOne(res, err, "store.FinishInstallRecord")
}

// ClaimToolUninstall moves an AI-tool record into "uninstalling" iff its
// current status is one of from and no newer not-forgotten record of the
// same tool exists, recording the exact uninstall argv about to run. It
// returns the status it moved FROM (so a spawn failure can put it back).
func (s *Store) ClaimToolUninstall(ctx context.Context, id int64, from []string, to string, argv []string, display string, at time.Time) (string, bool, error) {
	return s.ClaimUninstallRecord(ctx, SubjectTool, id, from, to, argv, display, at)
}

// ClaimUninstallRecord is ClaimToolUninstall for a record of subject.
func (s *Store) ClaimUninstallRecord(ctx context.Context, subject string, id int64, from []string, to string, argv []string, display string, at time.Time) (string, bool, error) {
	if len(from) == 0 {
		return "", false, errors.New("store.ClaimUninstallRecord: empty from-set")
	}
	argvJSON, err := json.Marshal(argv)
	if err != nil {
		return "", false, fmt.Errorf("store.ClaimUninstallRecord: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", false, fmt.Errorf("store.ClaimUninstallRecord: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var prev string
	if err := tx.QueryRowContext(ctx, `SELECT status FROM tool_installs WHERE id = ? AND subject_kind = ? AND forgotten_at IS NULL`, id, subject).Scan(&prev); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", false, nil
		}
		return "", false, fmt.Errorf("store.ClaimUninstallRecord: %w", err)
	}
	if !tiContains(from, prev) {
		return prev, false, nil
	}
	res, err := tx.ExecContext(ctx, `
		UPDATE tool_installs
		   SET status = ?, uninstall_argv_json = ?, uninstall_display = ?,
		       uninstall_started_at = ?, uninstall_finished_at = NULL,
		       uninstall_exit_code = NULL
		 WHERE id = ? AND subject_kind = ? AND status = ? AND `+tiNotSuperseded,
		to, string(argvJSON), display, tiFmtTS(at), id, subject, prev)
	ok, err := tiAffectedOne(res, err, "store.ClaimUninstallRecord")
	if err != nil || !ok {
		return prev, false, err
	}
	if err := tx.Commit(); err != nil {
		return prev, false, fmt.Errorf("store.ClaimUninstallRecord: %w", err)
	}
	return prev, true, nil
}

// RevertToolUninstall undoes an AI-tool claim whose spawn failed: CAS from
// `from` ("uninstalling") back to prev, clearing the uninstall start stamp.
func (s *Store) RevertToolUninstall(ctx context.Context, id int64, from, prev string) (bool, error) {
	return s.RevertUninstallRecord(ctx, SubjectTool, id, from, prev)
}

// RevertUninstallRecord is RevertToolUninstall for a record of subject.
func (s *Store) RevertUninstallRecord(ctx context.Context, subject string, id int64, from, prev string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tool_installs
		   SET status = ?, uninstall_started_at = NULL
		 WHERE id = ? AND subject_kind = ? AND status = ?`, prev, id, subject, from)
	return tiAffectedOne(res, err, "store.RevertUninstallRecord")
}

// FinishToolUninstall settles an in-flight AI-tool UNINSTALL: CAS from
// `from` to f.Status with the uninstall exit code, finish time and the
// post-uninstall resolution (a binary still found means another install
// shadows it).
func (s *Store) FinishToolUninstall(ctx context.Context, id int64, from string, f ToolInstallFinish) (bool, error) {
	return s.FinishUninstallRecord(ctx, SubjectTool, id, from, f)
}

// FinishUninstallRecord is FinishToolUninstall for a record of subject.
func (s *Store) FinishUninstallRecord(ctx context.Context, subject string, id int64, from string, f ToolInstallFinish) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE tool_installs
		   SET status = ?, uninstall_exit_code = ?, uninstall_finished_at = ?, resolved_bin = ?
		 WHERE id = ? AND subject_kind = ? AND status = ?`,
		f.Status, f.ExitCode, tiFmtTS(f.At), f.ResolvedBin, id, subject, from)
	return tiAffectedOne(res, err, "store.FinishUninstallRecord")
}

// SetToolInstallStatus is the bare CAS used for the orphan sweep of an
// AI-tool record (an in-flight row no live process tracks).
func (s *Store) SetToolInstallStatus(ctx context.Context, id int64, from, to string) (bool, error) {
	return s.SetInstallRecordStatus(ctx, SubjectTool, id, from, to)
}

// SetInstallRecordStatus is SetToolInstallStatus for a record of subject.
func (s *Store) SetInstallRecordStatus(ctx context.Context, subject string, id int64, from, to string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE tool_installs SET status = ? WHERE id = ? AND subject_kind = ? AND status = ?`, to, id, subject, from)
	return tiAffectedOne(res, err, "store.SetInstallRecordStatus")
}

// ForgetToolInstall hides an AI-tool record (never deletes it) iff its
// status is in from and no newer not-forgotten record of the same tool
// exists. ok=false when it was not (in flight, already forgotten, or
// superseded).
func (s *Store) ForgetToolInstall(ctx context.Context, id int64, from []string, at time.Time) (bool, error) {
	return s.ForgetInstallRecord(ctx, SubjectTool, id, from, at)
}

// ForgetInstallRecord is ForgetToolInstall for a record of subject.
func (s *Store) ForgetInstallRecord(ctx context.Context, subject string, id int64, from []string, at time.Time) (bool, error) {
	if len(from) == 0 {
		return false, errors.New("store.ForgetInstallRecord: empty from-set")
	}
	fromJSON, err := json.Marshal(from)
	if err != nil {
		return false, fmt.Errorf("store.ForgetInstallRecord: %w", err)
	}
	res, err := s.db.ExecContext(ctx, `
		UPDATE tool_installs SET forgotten_at = ?
		 WHERE id = ? AND subject_kind = ? AND forgotten_at IS NULL
		   AND status IN (SELECT value FROM json_each(?))
		   AND `+tiNotSuperseded, tiFmtTS(at), id, subject, string(fromJSON))
	return tiAffectedOne(res, err, "store.ForgetInstallRecord")
}

func scanToolInstalls(rows *sql.Rows) ([]ToolInstallRow, error) {
	defer rows.Close()
	var out []ToolInstallRow
	for rows.Next() {
		var (
			r                             ToolInstallRow
			argvJSON, uargvJSON, started  string
			finished, ustarted, ufinished sql.NullString
			exitCode, uexitCode           sql.NullInt64
			elevated                      int64
		)
		if err := rows.Scan(&r.ID, &r.Tool, &r.Channel, &r.Package, &argvJSON, &r.Display,
			&r.Version, &r.Status, &exitCode, &started, &finished, &r.ResolvedBin,
			&uargvJSON, &r.UninstallDisplay, &ustarted, &ufinished, &uexitCode,
			&r.SubjectKind, &r.Backend, &r.Source, &r.Digest, &r.PlacedPath, &elevated); err != nil {
			return nil, err
		}
		r.Elevated = elevated != 0
		if err := json.Unmarshal([]byte(argvJSON), &r.Argv); err != nil {
			return nil, fmt.Errorf("decode argv of tool_installs %d: %w", r.ID, err)
		}
		if uargvJSON != "" {
			if err := json.Unmarshal([]byte(uargvJSON), &r.UninstallArgv); err != nil {
				return nil, fmt.Errorf("decode uninstall argv of tool_installs %d: %w", r.ID, err)
			}
		}
		r.StartedAt = tiParseTS(started)
		r.FinishedAt = tiParseNullTS(finished)
		r.UninstallStartedAt = tiParseNullTS(ustarted)
		r.UninstallFinishedAt = tiParseNullTS(ufinished)
		r.ExitCode = tiIntPtr(exitCode)
		r.UninstallExitCode = tiIntPtr(uexitCode)
		out = append(out, r)
	}
	return out, rows.Err()
}

func tiAffectedOne(res sql.Result, err error, op string) (bool, error) {
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("%s: %w", op, err)
	}
	return n == 1, nil
}

func tiFmtTS(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func tiParseTS(s string) time.Time {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return time.Time{}
	}
	return t
}

func tiParseNullTS(s sql.NullString) *time.Time {
	if !s.Valid || s.String == "" {
		return nil
	}
	t := tiParseTS(s.String)
	if t.IsZero() {
		return nil
	}
	return &t
}

func tiIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func tiContains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}
