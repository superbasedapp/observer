package deepagents

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/marmutapp/superbased-observer/internal/adapter/mirrorbase"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/platform/sqlitedsn"
)

// allHomesFunc is the test seam over crossmount.AllHomes (same shape as
// goose.allHomesFunc / devin.allHomesFunc).
var allHomesFunc = crossmount.AllHomes

// homeEnv is the Deep Agents Code profile-root override. dcode resolves its
// home as $DEEPAGENTS_HOME (absolute, or `~/`-prefixed) else ~/.deepagents
// (deepagents_code/_paths.py::get_deepagents_home); the state dir is always
// `<home>/.state`.
const homeEnv = "DEEPAGENTS_HOME"

// stateDirParts is the path of dcode's state directory below a home. The
// layout is identical on Linux, macOS and Windows (grounded 2026-10-21: the
// same `.deepagents/.state/sessions.db` on a WSL Ubuntu home and a Windows
// home), so one relative path serves every cross-mount home.
var stateDirParts = []string{".deepagents", ".state"}

// stateDirName is the immutable last segment IsSessionFile pins the store's
// parent directory to.
const stateDirName = ".state"

// defaultRoots returns one watch root per cross-mount-resolved home (the
// `.deepagents/.state` directory), plus the native $DEEPAGENTS_HOME state
// directory when that override is set to an absolute path. Roots are
// canonical regardless of installed state — a missing directory is inert
// (the watcher skips it at registry time).
func defaultRoots() []string {
	var roots []string
	seen := map[string]struct{}{}
	add := func(p string) {
		if p == "" {
			return
		}
		p = filepath.Clean(p)
		if _, ok := seen[p]; ok {
			return
		}
		seen[p] = struct{}{}
		roots = append(roots, p)
	}
	for _, h := range allHomesFunc() {
		if h.Path == "" {
			continue
		}
		add(filepath.Join(append([]string{h.Path}, stateDirParts...)...))
	}
	if env := strings.TrimSpace(os.Getenv(homeEnv)); env != "" {
		switch {
		case strings.HasPrefix(env, "~/"):
			if home, err := os.UserHomeDir(); err == nil {
				add(filepath.Join(home, filepath.FromSlash(strings.TrimLeft(env[2:], "/")), stateDirName))
			}
		case filepath.IsAbs(env):
			add(filepath.Join(env, stateDirName))
		}
		// A relative or `~user` value is rejected by dcode itself, so no
		// store exists there to watch.
	}
	return roots
}

// resolveDBPath maps a -wal/-shm sibling event back to the main sessions.db.
func resolveDBPath(path string) string {
	base := strings.ToLower(filepath.Base(path))
	if base == "sessions.db-wal" || base == "sessions.db-shm" {
		return filepath.Join(filepath.Dir(path), "sessions.db")
	}
	return path
}

// openReadOnlyDB opens the sessions.db read-only, staging a local mirror
// first when the source is a foreign mount.
func openReadOnlyDB(path string) (*sql.DB, error) {
	actual, err := stageMirrorIfForeign(path)
	if err != nil {
		return nil, fmt.Errorf("deepagents.stageMirror: %w", err)
	}
	dsn := fmt.Sprintf("file:%s?mode=ro&_pragma=query_only(1)&_pragma=busy_timeout(2000)", sqlitedsn.Escape(actual))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	return db, nil
}

// stageMirrorIfForeign returns srcDB unchanged when it is native. A
// foreign-mount store (a Windows-side store read by a WSL observer over
// /mnt/c, or the reverse), which modernc.org/sqlite cannot open in place
// while the vendor process writes its WAL, is read through a filtered local
// mirror built by mirrorbase.Stage: only the tables in mirrorSpec are kept,
// so the store's other tables never leave the vendor's file (T-927,
// MIRROR-CRED-1; this adapter's private byte copy was RB1 sweep finding A2).
func stageMirrorIfForeign(srcDB string) (string, error) {
	if !isForeignMountPath(srcDB) {
		return srcDB, nil
	}
	return mirrorbase.Stage(context.Background(), srcDB, mirrorSpec)
}

// mirrorSpec is the allow-list mirror of the store: every table this
// package queries and nothing else. A query on a new table must add it
// here, or the foreign-mount mirror silently lacks it;
// mirrortest.AssertSpecCoversQueries pins that.
var mirrorSpec = mirrorbase.Spec{
	Dir:    "deepagents-mirror",
	File:   "sessions.db",
	Tables: []string{"checkpoints", "writes", "dcode_btw_costs", "dcode_thread_workspaces"},
}

// isForeignMountPath reports whether path lives under a crossmount-detected
// non-native home (both bridge directions).
func isForeignMountPath(path string) bool {
	for _, h := range allHomesFunc() {
		if h.Origin == "native" {
			continue
		}
		sep := string(filepath.Separator)
		if strings.HasPrefix(path, h.Path+sep) || strings.HasPrefix(path, h.Path+"/") {
			return true
		}
	}
	return false
}

// tableExists reports whether a table is present, so an empty or foreign
// store (the Windows install's 0-byte sessions.db) degrades to "nothing to
// do" instead of erroring.
func tableExists(ctx context.Context, db *sql.DB, name string) bool {
	var got string
	err := db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, name).Scan(&got)
	return err == nil && got == name
}

// threadRow is one conversation thread (a dcode session) that gained a
// checkpoint after the persisted cursor.
type threadRow struct {
	ID string
	// LatestCheckpointID is the highest checkpoint id of the thread's root
	// namespace (UUIDv6 ids sort chronologically).
	LatestCheckpointID string
}

// checkpointMeta is the subset of a checkpoint's JSON metadata the adapter
// reads. dcode stamps these on every checkpoint (grounded 2026-10-21 against
// deepagents-code 0.1.87).
type checkpointMeta struct {
	Cwd             string `json:"cwd"`
	GitBranch       string `json:"git_branch"`
	ApprovalMode    string `json:"approval_mode"`
	AgentName       string `json:"agent_name"`
	IntegrationVers string `json:"ls_integration_version"`
	LCVersions      struct {
		DeepAgentsCode string `json:"deepagents-code"`
	} `json:"lc_versions"`
	// TurnID / TurnNumber identify the user turn the checkpoint belongs to:
	// turn_id equals the human message's deepagents_code_user_prompt.turn_id
	// (and the hook prompt_id); turn_number is its 1-based ordinal in the
	// thread. A sub-agent's checkpoints carry the PARENT turn's values.
	TurnID     string `json:"turn_id"`
	TurnNumber int    `json:"turn_number"`
	// AgentType is "subagent" on a sub-agent's child-namespace checkpoints;
	// LCAgentName is that sub-agent's type ("general-purpose", ...).
	AgentType   string `json:"ls_agent_type"`
	LCAgentName string `json:"lc_agent_name"`
}

// version returns the dcode build recorded on the checkpoint.
func (m checkpointMeta) version() string {
	if m.LCVersions.DeepAgentsCode != "" {
		return m.LCVersions.DeepAgentsCode
	}
	return m.IntegrationVers
}

// decodeMeta parses a checkpoint metadata blob (JSON text stored in a BLOB
// column). A malformed blob yields the zero value.
func decodeMeta(raw []byte) checkpointMeta {
	var m checkpointMeta
	_ = json.Unmarshal(raw, &m)
	return m
}

// latestCursor returns the store's incremental cursor: the 100ns-ticks-since-
// Unix-epoch clock embedded in the newest checkpoint id (every checkpoint of
// every thread is a UUIDv6, so the lexicographic max is the chronological
// max). 0 for an empty / foreign store or an unparseable id.
func latestCursor(ctx context.Context, db *sql.DB) (int64, error) {
	if !tableExists(ctx, db, "checkpoints") {
		return 0, nil
	}
	var id sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT MAX(checkpoint_id) FROM checkpoints`).Scan(&id); err != nil {
		return 0, err
	}
	return cursorOf(id.String), nil
}

// uuidV6Epoch is the Gregorian epoch (1582-10-15) in 100ns ticks before the
// Unix epoch: the offset between a UUID timestamp and Unix time.
const uuidV6Epoch = 0x01b21dd213814000

// uuidTime parses the embedded clock of a UUIDv6 or UUIDv7 and returns it
// (UTC). ok is false for any other shape. LangGraph checkpoint ids are
// UUIDv6 (grounded: `1f1cd134-b5fe-6405-...` — version nibble 6); the time
// agrees with the checkpoint blob's own `ts` to within microseconds.
func uuidTime(id string) (time.Time, bool) {
	h := strings.ReplaceAll(id, "-", "")
	if len(h) != 32 {
		return time.Time{}, false
	}
	b, err := hex.DecodeString(h)
	if err != nil {
		return time.Time{}, false
	}
	switch b[6] >> 4 {
	case 6:
		// time_high(32) | time_mid(16) | version(4) time_low(12)
		ticks := uint64(b[0])<<52 | uint64(b[1])<<44 | uint64(b[2])<<36 | uint64(b[3])<<28 |
			uint64(b[4])<<20 | uint64(b[5])<<12 | uint64(b[6]&0x0f)<<8 | uint64(b[7])
		unixTicks := int64(ticks) - uuidV6Epoch
		return time.Unix(0, unixTicks*100).UTC(), true
	case 7:
		ms := uint64(b[0])<<40 | uint64(b[1])<<32 | uint64(b[2])<<24 | uint64(b[3])<<16 |
			uint64(b[4])<<8 | uint64(b[5])
		return time.UnixMilli(int64(ms)).UTC(), true
	}
	return time.Time{}, false
}

// cursorOf converts a checkpoint id to the incremental cursor value: Unix
// 100ns ticks. 0 when the id carries no clock.
func cursorOf(id string) int64 {
	t, ok := uuidTime(id)
	if !ok {
		return 0
	}
	return t.UnixNano() / 100
}

// sideCost is a thread's out-of-graph spend: the thread-naming request and
// any `/btw` side questions. dcode keeps it OUTSIDE the graph's checkpoints
// (deepagents_code/btw_cost.py): a cumulative per-thread subtotal in
// dcode_btw_costs, with no per-call detail and no model name. Input is GROSS
// (cache reads included) and output includes reasoning, the same convention
// as the graph's own `_session_cost_breakdown`.
type sideCost struct {
	Input         int64
	Output        int64
	CacheCreation int64
	CacheRead     int64
	Reasoning     int64
	CostUSD       float64
}

// loadSideCost reads dcode_btw_costs for a thread. ok is false when the table
// or row is absent, the row is the `null` tombstone dcode writes when a
// thread is deleted, or the subtotal carries no tokens.
func loadSideCost(ctx context.Context, db *sql.DB, threadID string) (sideCost, bool) {
	if !tableExists(ctx, db, "dcode_btw_costs") {
		return sideCost{}, false
	}
	var raw string
	if err := db.QueryRowContext(ctx,
		`SELECT breakdown FROM dcode_btw_costs WHERE thread_id = ?`, threadID).Scan(&raw); err != nil {
		return sideCost{}, false
	}
	var b struct {
		Input         int64   `json:"input_tokens"`
		Output        int64   `json:"output_tokens"`
		CacheCreation int64   `json:"cache_creation_tokens"`
		CacheRead     int64   `json:"cache_read_tokens"`
		Reasoning     int64   `json:"reasoning_tokens"`
		TotalCostUSD  float64 `json:"total_cost_usd"`
	}
	if err := json.Unmarshal([]byte(raw), &b); err != nil {
		return sideCost{}, false
	}
	c := sideCost{b.Input, b.Output, b.CacheCreation, b.CacheRead, b.Reasoning, b.TotalCostUSD}
	if c.Input == 0 && c.Output == 0 && c.CacheCreation == 0 && c.CacheRead == 0 {
		return sideCost{}, false
	}
	return c, true
}
