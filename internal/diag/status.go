package diag

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/db"
)

// StatusSnapshot is a point-in-time view of the observer's state. Exposed so
// callers can format it for both humans (CLI) and machines (JSON export).
type StatusSnapshot struct {
	// Version is the build-stamped binary version (e.g. "1.8.2"). The
	// dashboard surfaces it in the topbar and compares against the npm
	// registry to flag a stale install. Empty in unit tests and on dev
	// builds where main.version is still "dev".
	Version          string         `json:"version,omitempty"`
	DBPath           string         `json:"db_path"`
	DBSizeBytes      int64          `json:"db_size_bytes"`
	SchemaVersion    int            `json:"schema_version"`
	Counts           SnapshotCounts `json:"counts"`
	LastActionAt     time.Time      `json:"last_action_at,omitempty"`
	LastActionTool   string         `json:"last_action_tool,omitempty"`
	PerToolLastSeen  []ToolActivity `json:"per_tool_last_seen"`
	RecentFailures24 int            `json:"recent_failures_24h"`

	// StartedAt / UptimeSeconds describe the serving process (stamped
	// by the dashboard handler, like Version — diag.Snapshot itself
	// leaves them zero). The dashboard's restart-pending banner
	// compares a config-save timestamp against StartedAt to detect
	// that the operator has restarted the daemon since the save.
	StartedAt     time.Time `json:"started_at,omitempty"`
	UptimeSeconds int64     `json:"uptime_seconds,omitempty"`

	// HostOS is runtime.GOOS of the process that produced this
	// snapshot ("darwin" / "linux" / "windows") — i.e. the machine
	// whose PTYs the dashboard's terminals are attached to. Stamped
	// by Snapshot itself (unlike Version/StartedAt) because it is a
	// build-time constant of the running binary, so the CLI's JSON
	// status carries it too.
	//
	// The dashboard's on-screen terminal key bar reads it to choose
	// the modifier VOCABULARY it prints (⌃/⌥ on darwin, Ctrl/Alt
	// elsewhere). That decision belongs to the HOST, not the browser:
	// the browser is very often a phone that is not the machine being
	// typed into. Labels only — the bytes a key emits are identical
	// on every OS. Not omitempty: an absent field is the wire signal
	// for "daemon too old to know", which the client handles.
	HostOS string `json:"host_os"`

	// QueryErrors counts the individual lookups in Snapshot that FAILED and
	// were swallowed into a zero value. Snapshot is deliberately tolerant —
	// a partial schema, a table that pre-dates its migration, or a scan cut
	// short must still yield whatever else is readable rather than an
	// all-or-nothing error — but that tolerance is indistinguishable, at the
	// wire, from a genuinely empty database. This field is the distinction:
	// 0 means every lookup answered, N>0 means N of the numbers in this
	// snapshot are fabricated zeros rather than measurements.
	//
	// It exists so a CONSUMER can refuse to treat a degraded snapshot as
	// fact — the dashboard's /api/status cache declines to memoize any
	// snapshot with QueryErrors > 0, since a cached partial would keep
	// serving fabricated zeros for the whole TTL, long after the transient
	// condition that caused them had cleared.
	//
	// omitempty: the wire shape only grows when something actually went
	// wrong, so a healthy daemon's response is byte-identical to before this
	// field existed and no client is required to know about it.
	QueryErrors int `json:"query_errors,omitempty"`

	// Integrity is the persisted verdict of the daemon's background
	// `PRAGMA quick_check` (RES-3, codebase audit 2026-09-16). nil means the
	// probe has NOT run on this database yet — a fresh install, or one where
	// [observer.db].integrity_check_max_gb size-gated it off. nil is NOT a
	// failure and must never be rendered as one.
	//
	// It is here rather than in a new table or a new endpoint because this is
	// already the struct `observer status` prints and the dashboard's
	// /api/status serves: before this, a corrupt database produced exactly one
	// ERROR log line and nothing else, so it degraded capture silently until
	// somebody thought to run `observer doctor`.
	//
	// omitempty + pointer: a daemon that has never probed emits the same bytes
	// as before this field existed.
	Integrity *IntegrityStatus `json:"integrity,omitempty"`
}

// IntegrityStatus is the status-surface projection of db.IntegrityVerdict.
// Duplicated as its own type rather than embedding the db one so the wire shape
// this package owns cannot drift when the db type grows a field.
type IntegrityStatus struct {
	// CheckedAt is when the probe finished (UTC).
	CheckedAt time.Time `json:"checked_at"`
	// Status is db.IntegrityOK / db.IntegrityCorrupt / db.IntegrityError —
	// a closed vocabulary. "error" means the probe could not COMPLETE
	// (timeout, locked file); it says nothing about the data.
	Status string `json:"status"`
	// Message is the pragma's own text, or the error's. Empty when ok.
	Message string `json:"message,omitempty"`
}

// OK reports whether the last probe completed cleanly.
func (s IntegrityStatus) OK() bool { return s.Status == db.IntegrityOK }

// MarshalJSON preserves StatusSnapshot's public wire shape while actually
// honoring the optional contract for time.Time fields. encoding/json's
// `omitempty` does not consider a zero struct empty, so without this projection
// a fresh database emits `0001-01-01T00:00:00Z` as last_action_at. Dashboard
// relative-time formatters then honestly-but-uselessly render roughly 17.7
// million hours of "activity". Internal callers keep ordinary time.Time values
// and their IsZero checks; only the JSON boundary uses nullable timestamps.
func (s StatusSnapshot) MarshalJSON() ([]byte, error) {
	type snapshotAlias StatusSnapshot
	type snapshotWire struct {
		snapshotAlias
		LastActionAt *time.Time `json:"last_action_at,omitempty"`
		StartedAt    *time.Time `json:"started_at,omitempty"`
	}

	w := snapshotWire{snapshotAlias: snapshotAlias(s)}
	if !s.LastActionAt.IsZero() {
		last := s.LastActionAt
		w.LastActionAt = &last
	}
	if !s.StartedAt.IsZero() {
		started := s.StartedAt
		w.StartedAt = &started
	}
	return json.Marshal(w)
}

// SnapshotCounts holds the row counts for each table the user cares about.
type SnapshotCounts struct {
	Projects       int `json:"projects"`
	Sessions       int `json:"sessions"`
	Actions        int `json:"actions"`
	APITurns       int `json:"api_turns"`
	FileState      int `json:"file_state"`
	FailureContext int `json:"failure_context"`
	ActionExcerpts int `json:"action_excerpts"`
	TokenUsageRows int `json:"token_usage"`
	// CacheEvents counts rows in the cachetrack cache_events table
	// (migration 036). Drives the dashboard sidebar "Cache" badge so
	// the operator sees at a glance how much prompt-cache activity has
	// been captured. Stays zero on DBs that pre-date migration 036 or
	// on installs that have disabled [cachetrack].enabled — the table
	// count is read tolerantly.
	CacheEvents int `json:"cache_events"`
	// Suggestions is the advisor's active suggestion count, point-read
	// from the daemon-refreshed advisor_digest snapshot (migration 039)
	// via json_extract — no advisor import, no engine run. Drives the
	// sidebar "Suggestions" badge. Zero when the digest hasn't been
	// written yet (daemon just started / advisor disabled).
	Suggestions int `json:"suggestions"`
	// GuardEvents counts rows in the guard_events verdict table
	// (migration 040). Drives the sidebar "Security" badge. Read
	// tolerantly like cache_events — zero on pre-040 DBs.
	GuardEvents int `json:"guard_events"`
	// RouterDecisions counts rows in the router_decisions table
	// (migration 041). Drives the sidebar "Routing" badge. Read
	// tolerantly — zero on pre-041 DBs and while [routing] is off.
	RouterDecisions int `json:"router_decisions"`
	// LiveSessions counts sessions with any activity (actions,
	// api_turns, or token_usage rows) in the last 15 minutes — the
	// same activity definition and default window as the dashboard's
	// /api/live endpoint, without its 8-session display cap. Drives
	// the sidebar "Live" badge.
	LiveSessions int `json:"live_sessions"`
}

// ToolActivity is one tool's most recent action.
type ToolActivity struct {
	Tool        string    `json:"tool"`
	LastSeenAt  time.Time `json:"last_seen_at"`
	ActionCount int       `json:"action_count"`
}

// Snapshot returns a status snapshot of the observer DB. Errors loading
// individual fields surface as zero values; the caller can render whatever's
// available.
func Snapshot(ctx context.Context, database *sql.DB, dbPath string) (StatusSnapshot, error) {
	if database == nil {
		return StatusSnapshot{}, errors.New("diag.Snapshot: nil DB")
	}
	snap := StatusSnapshot{DBPath: dbPath, HostOS: runtime.GOOS}
	if fi, err := os.Stat(expandTilde(dbPath)); err == nil {
		snap.DBSizeBytes = fi.Size()
	}

	// note records a lookup that failed and was swallowed into a zero value,
	// so the caller can tell a partial snapshot from an empty database (see
	// StatusSnapshot.QueryErrors).
	//
	// sql.ErrNoRows is deliberately NOT counted: "no row" is a legitimate
	// ANSWER — an empty actions table, a fresh install with no advisor
	// digest — not a failure to read. Counting it would mark every new
	// install permanently degraded, which is the precise opposite of what
	// this signal is for.
	note := func(err error) {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			snap.QueryErrors++
		}
	}

	// Schema version — tolerated on error (schema may be partial); the
	// destination stays zero-valued, so only the failure is recorded.
	note(database.QueryRowContext(
		ctx,
		`SELECT CAST(value AS INTEGER) FROM schema_meta WHERE key='version'`,
	).Scan(&snap.SchemaVersion))

	// Last integrity verdict (RES-3). Absent is the common, healthy case on a
	// fresh install and is NOT counted as a query error — same rule as
	// sql.ErrNoRows above. A malformed/unreadable record IS counted, because
	// then the snapshot genuinely could not answer.
	if v, ok, err := db.LastIntegrityVerdict(ctx, database); err != nil {
		note(err)
	} else if ok {
		snap.Integrity = &IntegrityStatus{
			CheckedAt: v.CheckedAt, Status: v.Status, Message: v.Message,
		}
	}

	tableCounts := []struct {
		table string
		dest  *int
	}{
		{"projects", &snap.Counts.Projects},
		{"sessions", &snap.Counts.Sessions},
		{"actions", &snap.Counts.Actions},
		{"api_turns", &snap.Counts.APITurns},
		{"file_state", &snap.Counts.FileState},
		{"failure_context", &snap.Counts.FailureContext},
		{"action_excerpts", &snap.Counts.ActionExcerpts},
		{"token_usage", &snap.Counts.TokenUsageRows},
		{"cache_events", &snap.Counts.CacheEvents},
		{"guard_events", &snap.Counts.GuardEvents},
		{"router_decisions", &snap.Counts.RouterDecisions},
	}
	for _, tc := range tableCounts {
		note(database.QueryRowContext(ctx, "SELECT COUNT(*) FROM "+tc.table).Scan(tc.dest))
	}

	// Live sessions: distinct sessions with activity in the last 15
	// minutes across the three activity tables — the /api/live
	// definition (its default window), as a count instead of a feed.
	liveSince := time.Now().UTC().Add(-15 * time.Minute).Format(time.RFC3339Nano)
	note(database.QueryRowContext(
		ctx, `
		SELECT COUNT(DISTINCT session_id) FROM (
			SELECT session_id FROM actions WHERE timestamp >= ?
			UNION ALL
			SELECT session_id FROM api_turns WHERE timestamp >= ?
			UNION ALL
			SELECT session_id FROM token_usage WHERE timestamp >= ?
		) WHERE session_id IS NOT NULL AND session_id <> ''`,
		liveSince, liveSince, liveSince,
	).Scan(&snap.Counts.LiveSessions))

	// Advisor active-suggestion count from the digest snapshot (tolerant:
	// table may not exist pre-migration-039, payload may lack the field).
	note(database.QueryRowContext(
		ctx,
		`SELECT CAST(COALESCE(json_extract(payload, '$.total_count'), 0) AS INTEGER)
		 FROM advisor_digest WHERE id = 1`,
	).Scan(&snap.Counts.Suggestions))

	// Last action overall.
	var lastTS, lastTool sql.NullString
	note(database.QueryRowContext(
		ctx,
		`SELECT timestamp, tool FROM actions ORDER BY timestamp DESC LIMIT 1`,
	).Scan(&lastTS, &lastTool))
	if lastTS.Valid {
		if t, err := time.Parse(time.RFC3339Nano, lastTS.String); err == nil {
			snap.LastActionAt = t
		}
	}
	if lastTool.Valid {
		snap.LastActionTool = lastTool.String
	}

	// Per-tool last seen.
	rows, err := database.QueryContext(ctx,
		`SELECT tool, MAX(timestamp), COUNT(*) FROM actions GROUP BY tool ORDER BY tool`)
	note(err)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var ta ToolActivity
			var ts string
			if err := rows.Scan(&ta.Tool, &ts, &ta.ActionCount); err != nil {
				note(err)
				continue
			}
			if t, err := time.Parse(time.RFC3339Nano, ts); err == nil {
				ta.LastSeenAt = t
			}
			snap.PerToolLastSeen = append(snap.PerToolLastSeen, ta)
		}
		// A cursor that dies mid-walk (a cancelled scan, a closing DB) leaves
		// a SHORT list that looks exactly like a small install. Only rows.Err
		// tells the two apart.
		note(rows.Err())
	}

	// Failures in the last 24 hours.
	cutoff := time.Now().UTC().Add(-24 * time.Hour).Format(time.RFC3339Nano)
	note(database.QueryRowContext(
		ctx,
		`SELECT COUNT(*) FROM failure_context WHERE timestamp >= ?`, cutoff,
	).Scan(&snap.RecentFailures24))

	return snap, nil
}

// expandTilde turns "~/foo" into "$HOME/foo" so os.Stat resolves correctly.
func expandTilde(p string) string {
	if !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}

// FormatStatus renders a StatusSnapshot as a human-readable multi-line
// string suitable for CLI display. The JSON representation comes for free
// via json.Marshal(snap).
func FormatStatus(s StatusSnapshot) string {
	var b strings.Builder
	fmt.Fprintf(&b, "DB:               %s (%s, schema v%d)\n",
		s.DBPath, humanBytes(s.DBSizeBytes), s.SchemaVersion)
	fmt.Fprintf(&b, "Projects:         %d\n", s.Counts.Projects)
	fmt.Fprintf(&b, "Sessions:         %d\n", s.Counts.Sessions)
	fmt.Fprintf(&b, "Actions:          %d\n", s.Counts.Actions)
	fmt.Fprintf(&b, "API turns:        %d\n", s.Counts.APITurns)
	fmt.Fprintf(&b, "File state:       %d\n", s.Counts.FileState)
	fmt.Fprintf(&b, "Failures (total): %d\n", s.Counts.FailureContext)
	fmt.Fprintf(&b, "Failures (24h):   %d\n", s.RecentFailures24)
	fmt.Fprintf(&b, "Excerpts (FTS5):  %d\n", s.Counts.ActionExcerpts)
	fmt.Fprintf(&b, "Token rows:       %d\n", s.Counts.TokenUsageRows)
	fmt.Fprintf(&b, "Cache events:     %d\n", s.Counts.CacheEvents)
	fmt.Fprintf(&b, "Guard events:     %d\n", s.Counts.GuardEvents)
	fmt.Fprintf(&b, "Router decisions: %d\n", s.Counts.RouterDecisions)
	fmt.Fprintf(&b, "Live sessions:    %d\n", s.Counts.LiveSessions)
	// Integrity (RES-3): silent when the probe has not run (a fresh install
	// must not read as damaged) and when it last came back clean — a healthy
	// status stays noise-free. Loud, with the remedy, otherwise.
	if s.Integrity != nil && !s.Integrity.OK() {
		label := "DB INTEGRITY:     CORRUPT"
		if s.Integrity.Status == db.IntegrityError {
			label = "DB INTEGRITY:     UNVERIFIED"
		}
		fmt.Fprintf(&b, "%s (checked %s)\n", label, s.Integrity.CheckedAt.Format(time.RFC3339))
		if s.Integrity.Message != "" {
			fmt.Fprintf(&b, "                  %s\n", s.Integrity.Message)
		}
		fmt.Fprintf(&b, "                  run `observer doctor db` — capture may be degraded\n")
	}
	if !s.LastActionAt.IsZero() {
		fmt.Fprintf(&b, "Last action:      %s by %s\n",
			s.LastActionAt.Format(time.RFC3339), s.LastActionTool)
	}
	if len(s.PerToolLastSeen) > 0 {
		fmt.Fprintln(&b, "Per-tool activity:")
		for _, ta := range s.PerToolLastSeen {
			fmt.Fprintf(&b, "  %-12s %d actions, last %s\n",
				ta.Tool, ta.ActionCount, ta.LastSeenAt.Format(time.RFC3339))
		}
	}
	// QueryErrors is the completeness signal (see its doc comment): silent
	// when 0 so a healthy status stays noise-free, loud when non-zero so
	// the reader can't mistake a degraded read for a genuinely empty DB.
	if s.QueryErrors > 0 {
		word := "query"
		if s.QueryErrors != 1 {
			word = "queries"
		}
		fmt.Fprintf(&b, "WARNING:          %d %s failed — the counts above are INCOMPLETE, do not trust them as exact\n",
			s.QueryErrors, word)
	}
	return b.String()
}

// humanBytes formats a byte count as KB/MB/GB.
func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for n2 := n / unit; n2 >= unit; n2 /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(n)/float64(div), "KMGTPE"[exp])
}
