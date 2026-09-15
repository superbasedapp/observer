package freebuff

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	_ "modernc.org/sqlite" // pure-Go driver (no CGO), per CLAUDE.md

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// desktopThread is one `threads` row: the unit that becomes a session.
type desktopThread struct {
	ID          string
	ProjectPath string // threads.project_path (primary cwd statement)
	RootPath    string // projects.root_path (fallback, joined on project_id)
	Model       string // threads.model — a gateway id ("deepseek/deepseek-v4-flash")
	Branch      string
	CreatedAt   int64 // epoch MILLISECONDS
	UpdatedAt   int64 // epoch MILLISECONDS
	// TurnState is threads.turn_state ("idle" between turns; anything
	// else while a turn streams). "" on a schema without the column.
	TurnState string
}

// desktopMainDBPath maps a `-wal` / `-shm` sidecar path onto its main
// store; any other path is returned unchanged.
func desktopMainDBPath(path string) string {
	switch {
	case strings.HasSuffix(path, "-wal"):
		return strings.TrimSuffix(path, "-wal")
	case strings.HasSuffix(path, "-shm"):
		return strings.TrimSuffix(path, "-shm")
	}
	return path
}

// columnExists reports whether table has a column named col (PRAGMA
// table_info), so a query can adapt to an older schema.
func columnExists(ctx context.Context, db *sql.DB, table, col string) bool {
	rows, err := db.QueryContext(ctx, `PRAGMA table_info("`+table+`")`) //nolint:gosec // table is a package constant
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid     int
			name    string
			ctype   string
			notnull int
			dflt    sql.NullString
			pk      int
		)
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			return false
		}
		if strings.EqualFold(name, col) {
			return true
		}
	}
	return false
}

// desktopMessage is one `messages` row. parts_json holds the ENTIRE turn as
// an ordered array of parts; metrics_json holds the per-turn usage envelope.
type desktopMessage struct {
	Seq         int64
	Role        string // "user" | "assistant"
	PartsJSON   string
	MetricsJSON string
	TS          int64 // epoch MILLISECONDS
}

// openDesktopDB opens a desktop-v2.db read-only, staging a local mirror
// first when the source lives on a foreign mount. Same DSN + mirror shape
// as goose / crush / devin / kiro-cli: modernc.org/sqlite hits SQLITE_IOERR
// against /mnt/c paths while the app holds the WAL open, so the trio
// (.db + -wal + -shm) is byte-copied once and the in-tmp copy is opened.
func openDesktopDB(path string) (*sql.DB, error) {
	actual, err := stageDesktopMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("freebuff.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)",
		sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// stageDesktopMirrorIfForeign returns srcDB unchanged when it is native,
// and otherwise the path of a freshly-staged local mirror.
func stageDesktopMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	base, err := mirrorbase.Base()
	if err != nil || base == "" {
		base = filepath.Join(os.TempDir(), "superbased-observer")
	}
	sum := sha256.Sum256([]byte(srcDB))
	mirrorDir := filepath.Join(base, "freebuff-desktop-mirror", hex.EncodeToString(sum[:8]))
	if err := os.MkdirAll(mirrorDir, 0o700); err != nil {
		return "", fmt.Errorf("mkdir mirror: %w", err)
	}
	dstDB := filepath.Join(mirrorDir, desktopDBName)
	if desktopMirrorUpToDate(srcDB, dstDB) {
		return dstDB, nil
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		src, dst := srcDB+suffix, dstDB+suffix
		data, err := os.ReadFile(src) //nolint:gosec // the watched store + its own WAL siblings
		if err != nil {
			if os.IsNotExist(err) {
				_ = os.Remove(dst)
				continue
			}
			return "", fmt.Errorf("read %s: %w", src, err)
		}
		if err := os.WriteFile(dst, data, 0o600); err != nil {
			return "", fmt.Errorf("write %s: %w", dst, err)
		}
	}
	return dstDB, nil
}

func desktopMirrorUpToDate(srcDB, dstDB string) bool {
	if !desktopFilesMatch(srcDB, dstDB) {
		return false
	}
	if sw, err := os.Stat(srcDB + "-wal"); err == nil {
		if !desktopFilesMatchInfo(sw, dstDB+"-wal") {
			return false
		}
	}
	return true
}

func desktopFilesMatch(src, dst string) bool {
	s, err := os.Stat(src)
	if err != nil {
		return false
	}
	return desktopFilesMatchInfo(s, dst)
}

func desktopFilesMatchInfo(srcInfo os.FileInfo, dst string) bool {
	d, err := os.Stat(dst)
	if err != nil {
		return false
	}
	if srcInfo.Size() != d.Size() {
		return false
	}
	return !srcInfo.ModTime().After(d.ModTime())
}

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home (both bridge directions: /mnt/c on WSL2, \\wsl.localhost
// on Windows).
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" || h.Path == "" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

// allHomesFunc is the test seam over crossmount.AllHomes, mirroring the
// goose / devin / crush convention.
var allHomesFunc = crossmount.AllHomes

// desktopWatermark returns the store's high-water mark: the newest
// epoch-millis timestamp visible anywhere in the conversation tables.
//
// It deliberately is NOT MAX(messages.seq). Freebuff Desktop persists ONE
// assistant `messages` row per turn and REWRITES its parts_json in place as
// the turn streams, so seq stops advancing while the turn is still growing
// and a seq watermark would freeze mid-turn. MAX(threads.updated_at) and
// MAX(messages.ts) both move on every rewrite, so their max is the honest
// "has anything changed?" signal.
func desktopWatermark(ctx context.Context, db *sql.DB) (int64, error) {
	var latest int64
	for _, q := range []struct{ table, col string }{
		{"threads", "updated_at"},
		{"messages", "ts"},
	} {
		if !tableExists(ctx, db, q.table) {
			continue
		}
		var v sql.NullInt64
		if err := db.QueryRowContext(ctx,
			"SELECT MAX("+q.col+") FROM "+q.table).Scan(&v); err != nil { //nolint:gosec // literal table/column names from the fixed struct above
			return 0, err
		}
		if v.Valid && v.Int64 > latest {
			latest = v.Int64
		}
	}
	return latest, nil
}

// loadTouchedThreads returns every thread that changed at or after
// fromOffset, joined to its projects row for the root_path fallback.
//
// The comparison is `>= fromOffset`, not `>`: the thread whose rewrite
// produced the previous watermark may still have been mid-stream when it
// was read, so it is re-covered once. SourceEventIDs are deterministic, so
// re-emitting already-seen parts is a store-level no-op.
func loadTouchedThreads(ctx context.Context, db *sql.DB, fromOffset int64) ([]desktopThread, error) {
	if !tableExists(ctx, db, "threads") {
		return nil, nil
	}
	joinProjects := tableExists(ctx, db, "projects")
	rootExpr, join := "''", ""
	if joinProjects {
		rootExpr = "COALESCE(p.root_path, '')"
		join = " LEFT JOIN projects p ON p.id = t.project_id"
	}
	messageClause := ""
	if tableExists(ctx, db, "messages") {
		messageClause = " OR EXISTS (SELECT 1 FROM messages m WHERE m.thread_id = t.id AND m.ts >= ?)"
	}
	turnExpr := "''"
	if columnExists(ctx, db, "threads", "turn_state") {
		turnExpr = "COALESCE(t.turn_state,'')"
	}
	//nolint:gosec // every interpolated fragment is a literal chosen above
	q := `SELECT t.id, COALESCE(t.project_path,''), ` + rootExpr + `,
		       COALESCE(t.model,''), COALESCE(t.branch,''),
		       COALESCE(t.created_at,0), COALESCE(t.updated_at,0), ` + turnExpr + `
		  FROM threads t` + join + `
		 WHERE COALESCE(t.updated_at,0) >= ?` + messageClause + `
		 ORDER BY COALESCE(t.created_at,0) ASC, t.id ASC`
	args := []any{fromOffset}
	if messageClause != "" {
		args = append(args, fromOffset)
	}
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []desktopThread
	for rows.Next() {
		var t desktopThread
		if err := rows.Scan(&t.ID, &t.ProjectPath, &t.RootPath, &t.Model, &t.Branch,
			&t.CreatedAt, &t.UpdatedAt, &t.TurnState); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// loadDesktopMessages returns a thread's messages in seq order.
func loadDesktopMessages(ctx context.Context, db *sql.DB, threadID string) ([]desktopMessage, error) {
	if !tableExists(ctx, db, "messages") {
		return nil, nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT seq, role, COALESCE(parts_json,'[]'), COALESCE(metrics_json,'{}'), COALESCE(ts,0)
		  FROM messages
		 WHERE thread_id = ?
		 ORDER BY seq ASC`, threadID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []desktopMessage
	for rows.Next() {
		var m desktopMessage
		if err := rows.Scan(&m.Seq, &m.Role, &m.PartsJSON, &m.MetricsJSON, &m.TS); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// tableExists lets a foreign or older schema degrade gracefully instead of
// erroring the whole parse.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}

// projectPathFromSidecar reads `projectPath` out of the project.json that
// sits next to a desktop-v2.db. It is the LAST project-root fallback (after
// threads.project_path and projects.root_path) and the only sibling file
// this layout ever opens — `state.json` (auth token + operator identity)
// and `state.json.orchestrator-lock.sqlite` are never touched.
func projectPathFromSidecar(dbPath string) string {
	data, err := os.ReadFile(filepath.Join(filepath.Dir(dbPath), desktopProjectJSONName)) //nolint:gosec // sibling of a watched file
	if err != nil {
		return ""
	}
	var pj struct {
		ProjectPath string `json:"projectPath"`
	}
	if err := json.Unmarshal(data, &pj); err != nil {
		return ""
	}
	return strings.TrimSpace(pj.ProjectPath)
}
