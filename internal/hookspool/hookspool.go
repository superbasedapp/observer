package hookspool

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/models"
	"github.com/marmutapp/superbased-observer/internal/testwriteguard"
)

// Filename is the live spool's name beside the global config file.
const Filename = "hook-lifecycle.jsonl"

// asideMarker separates the live spool's name from an aside file's unix-nano
// stamp: hook-lifecycle.jsonl.aside-<unixnano>.
const asideMarker = ".aside-"

// MaxRecordBytes bounds one spooled line. A record past it is refused at
// append time (the hook logs and drops it) and skipped at drain time.
const MaxRecordBytes = 256 << 10

// MaxActivitySpoolBytes is the live spool size past which an activity record
// is skipped instead of appended (R-188 F5). A running daemon sets the live
// spool aside every few seconds, so it never comes near this; the cap only
// bites while hooks stay registered and nothing drains, where every hook call
// would otherwise add an activity line (a few MB a day) without bound.
// 8 MiB is roughly 25,000 activity lines, several days of heavy use, and an
// aside file of that size still decodes in one drain pass. Only liveness
// counts are lost past it: tool-event and compaction records are never
// capped (capsAtSpoolLimit), and the skips are counted (SkippedActivity).
const MaxActivitySpoolBytes = 8 << 20

// MaxSkippedCount bounds the skip counter file (one byte per skipped record),
// so a spool that stays full for months cannot grow the counter without
// bound either. Past it the count reads as "at least MaxSkippedCount".
const MaxSkippedCount = 1 << 20

// skippedSuffix names the skip counter beside the live spool. It does not
// share the aside marker, so the drainer's glob never reads it as a spool.
const skippedSuffix = ".activity-skipped"

// ErrActivitySkipped is Append's answer for an activity record it skipped
// because the live spool is past MaxActivitySpoolBytes. The skip is counted;
// a hook treats it as success (nothing to report on the hook's stderr).
var ErrActivitySkipped = errors.New("hookspool.Append: activity record skipped, the spool is past its cap")

// spoolCapRule says, per record kind, whether Append skips the record once
// the live spool is past MaxActivitySpoolBytes. A kind not listed is never
// capped: losing an action or a compaction phase is a data loss, losing an
// activity line is a lost count.
var spoolCapRule = map[string]bool{
	"":             false, // a tool-event row (an action)
	KindCompaction: false,
	KindActivity:   true,
}

// capsAtSpoolLimit reports whether a record of kind is skipped past the cap.
func capsAtSpoolLimit(kind string) bool { return spoolCapRule[kind] }

// SkippedPath is the skip counter beside the live spool ("" for "").
func SkippedPath(path string) string {
	if path == "" {
		return ""
	}
	return path + skippedSuffix
}

// Grace is how long an aside file waits before it is processed: far longer
// than one hook's open-then-append, so an append that raced the rename has
// landed in the aside file before the drainer reads it.
const Grace = 2 * time.Second

// version is the newest record schema version this package reads; a drainer
// skips a newer one. Version 1 is a tool-event row; version 2 adds the
// non-event kinds (KindCompaction), so a released drainer that knows only
// version 1 drops such a line as "newer schema" instead of ingesting it as
// an action with no action type. Version 3 adds KindActivity, whose session
// id may be empty, so a drainer that knows only version 2 drops it the same
// way instead of reading it as a malformed compaction.
const version = 3

// versionCompaction is the version a compaction record is written with.
const versionCompaction = 2

// versionToolEvent is the version a plain tool-event row is written with,
// unchanged from the first release so every released drainer still reads it.
const versionToolEvent = 1

// KindCompaction marks a held compaction hook (T-320): a pre or post phase
// of a compact_lifecycle binding whose session the watcher had not ingested
// yet. The zero Kind is a tool-event row.
const KindCompaction = "compaction"

// KindActivity marks one hook invocation's liveness record (surface-gap
// review OBS-7 / CC-2): the tool, the event, the session id the payload
// carried ("" when none: the unattributed bucket) and the route-relevant env
// classes the hook saw (internal/hookliveness.EnvClasses, names and coarse
// classes only). The drainer hands it to store.UpsertHookActivity; it never
// needs a session row and is never held.
const KindActivity = "activity"

// recordVersion is the schema version a record is written with.
func recordVersion(r Record) int {
	switch r.Kind {
	case "":
		return versionToolEvent
	case KindCompaction:
		return versionCompaction
	}
	return version
}

// validRecord is the one shape check Append and the drain share: a tool
// always; a session, and an action type, for a tool-event row; a session and
// a phase for a compaction row; an event (and no session requirement) for an
// activity row; and no kind this package does not know.
func validRecord(r Record) bool {
	if r.Tool == "" {
		return false
	}
	switch r.Kind {
	case "":
		return r.SessionID != "" && r.ActionType != ""
	case KindCompaction:
		return r.SessionID != "" && r.Phase != ""
	case KindActivity:
		return r.HookEvent != ""
	default:
		return false
	}
}

// Record is one spooled lifecycle row: the subset of models.ToolEvent a
// lifecycle hook produces. It is a plain value; FromEvent / Event convert.
type Record struct {
	V                  int       `json:"v"`
	Tool               string    `json:"tool"`
	SourceFile         string    `json:"source_file"`
	SourceEventID      string    `json:"source_event_id"`
	SessionID          string    `json:"session_id"`
	ProjectRoot        string    `json:"project_root,omitempty"`
	Timestamp          time.Time `json:"ts"`
	ActionType         string    `json:"action_type"`
	Target             string    `json:"target,omitempty"`
	MessageID          string    `json:"message_id,omitempty"`
	RawToolName        string    `json:"raw_tool_name,omitempty"`
	RawToolInput       string    `json:"raw_tool_input,omitempty"`
	ToolOutput         string    `json:"tool_output,omitempty"`
	PrecedingReasoning string    `json:"preceding_reasoning,omitempty"`
	IsSidechain        bool      `json:"is_sidechain,omitempty"`
	Success            bool      `json:"success"`
	// Metadata is the action metadata as JSON (models.ActionMetadata).
	Metadata *models.ActionMetadata `json:"metadata,omitempty"`
	// Kind is "" for a tool-event row, KindCompaction for a held compaction
	// hook. Phase and Trigger belong to a compaction row: the binding's phase
	// ("pre" captures, "post" reconciles) and the host's trigger text.
	Kind    string `json:"kind,omitempty"`
	Phase   string `json:"phase,omitempty"`
	Trigger string `json:"trigger,omitempty"`
	// Attempts counts the drain passes that held this record because its
	// session did not exist yet (T-320). It bounds the hold with MaxHoldAge.
	Attempts int `json:"attempts,omitempty"`
	// HookEvent and Env belong to an activity row: the hook event (the
	// registry binding's native name when the invocation resolved to one)
	// and the env names the hook saw mapped to coarse classes, never values.
	HookEvent string            `json:"event,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
}

// FromEvent captures ev as a spool record.
func FromEvent(ev models.ToolEvent) Record {
	return Record{
		V:                  version,
		Tool:               ev.Tool,
		SourceFile:         ev.SourceFile,
		SourceEventID:      ev.SourceEventID,
		SessionID:          ev.SessionID,
		ProjectRoot:        ev.ProjectRoot,
		Timestamp:          ev.Timestamp.UTC(),
		ActionType:         ev.ActionType,
		Target:             ev.Target,
		MessageID:          ev.MessageID,
		RawToolName:        ev.RawToolName,
		RawToolInput:       ev.RawToolInput,
		ToolOutput:         ev.ToolOutput,
		PrecedingReasoning: ev.PrecedingReasoning,
		IsSidechain:        ev.IsSidechain,
		Success:            ev.Success,
		Metadata:           ev.Metadata,
	}
}

// Event rebuilds the models.ToolEvent the hook produced.
func (r Record) Event() models.ToolEvent {
	return models.ToolEvent{
		Tool:               r.Tool,
		SourceFile:         r.SourceFile,
		SourceEventID:      r.SourceEventID,
		SessionID:          r.SessionID,
		ProjectRoot:        r.ProjectRoot,
		Timestamp:          r.Timestamp,
		ActionType:         r.ActionType,
		Target:             r.Target,
		MessageID:          r.MessageID,
		RawToolName:        r.RawToolName,
		RawToolInput:       r.RawToolInput,
		ToolOutput:         r.ToolOutput,
		PrecedingReasoning: r.PrecedingReasoning,
		IsSidechain:        r.IsSidechain,
		Success:            r.Success,
		Metadata:           r.Metadata,
	}
}

// Path returns the live spool beside the resolved global config path ("" when
// configPath is empty).
func Path(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), Filename)
}

// Append adds one record with a single O_APPEND write. It never waits on the
// drainer and takes no lock: a failed append returns the error and the hook
// moves on (the row is lost, which the lifecycle ladder tolerates: the
// transcript still carries the session). A kind capsAtSpoolLimit names (an
// activity record) is skipped once the live spool is past
// MaxActivitySpoolBytes, counted in the skip counter, and answered with
// ErrActivitySkipped; the size is read from the opened file, so the check
// costs one fstat.
func Append(path string, r Record) error {
	if path == "" {
		return errors.New("hookspool.Append: empty path")
	}
	if !validRecord(r) {
		return errors.New("hookspool.Append: tool and the kind's required fields (session_id and action_type, a phase, or an event) are required")
	}
	r.V = recordVersion(r)
	if r.Timestamp.IsZero() {
		r.Timestamp = time.Now().UTC()
	}
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("hookspool.Append: %w", err)
	}
	line = append(line, '\n')
	if len(line) > MaxRecordBytes {
		return errors.New("hookspool.Append: record too large")
	}
	if err := testwriteguard.Check("append", path); err != nil {
		return fmt.Errorf("hookspool.Append: %w", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("hookspool.Append: %w", err)
	}
	if capsAtSpoolLimit(r.Kind) {
		if st, serr := f.Stat(); serr == nil && st.Size() >= MaxActivitySpoolBytes {
			_ = f.Close()
			countSkipped(SkippedPath(path))
			return ErrActivitySkipped
		}
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("hookspool.Append: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("hookspool.Append: %w", err)
	}
	return nil
}

// countSkipped adds one to the skip counter: a single one-byte O_APPEND
// write, so concurrent hooks never lose an increment, stopped at
// MaxSkippedCount. Best effort: a counter that cannot be written loses the
// count, never the hook's answer.
func countSkipped(counter string) {
	if testwriteguard.Check("append", counter) != nil {
		return
	}
	f, err := os.OpenFile(counter, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || st.Size() >= MaxSkippedCount {
		return
	}
	_, _ = f.Write([]byte{'.'})
}

// SkippedActivity is the number of activity records skipped since the
// counter was last taken (0 when there is none). Read-only: the doctor reads
// it while the daemon is down. A count of MaxSkippedCount means at least
// that many.
func SkippedActivity(path string) (int64, error) {
	counter := SkippedPath(path)
	if counter == "" {
		return 0, nil
	}
	st, err := os.Stat(counter)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, fmt.Errorf("hookspool.SkippedActivity: %w", err)
	}
	return st.Size(), nil
}

// TakeSkippedActivity returns the skip count and clears the counter (the
// drainer, after it set the full spool aside, logs it once). The counter is
// renamed away before it is read, so a skip that lands meanwhile starts a
// new counter instead of being cleared unread.
func TakeSkippedActivity(path string, now time.Time) (int64, error) {
	counter := SkippedPath(path)
	if counter == "" {
		return 0, nil
	}
	taken := counter + ".taken-" + strconv.FormatInt(now.UnixNano(), 10)
	if err := testwriteguard.Check("rename", counter); err != nil {
		return 0, fmt.Errorf("hookspool.TakeSkippedActivity: %w", err)
	}
	if err := os.Rename(counter, taken); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("hookspool.TakeSkippedActivity: %w", err)
	}
	st, err := os.Stat(taken)
	if err != nil {
		return 0, fmt.Errorf("hookspool.TakeSkippedActivity: %w", err)
	}
	if err := os.Remove(taken); err != nil {
		return st.Size(), fmt.Errorf("hookspool.TakeSkippedActivity: %w", err)
	}
	return st.Size(), nil
}

// Aside is one set-aside spool file ready to be processed.
type Aside struct {
	Path string
	// Records are the decodable lines, in file order.
	Records []Record
	// Dropped counts lines that were malformed, oversized or from a newer
	// schema.
	Dropped int
}

// Ready returns the aside files set aside at least Grace before now, oldest
// first, decoded. A file that cannot be read is skipped (it is retried on the
// next pass).
func Ready(path string, now time.Time) ([]Aside, error) {
	if path == "" {
		return nil, nil
	}
	matches, err := filepath.Glob(path + asideMarker + "*")
	if err != nil {
		return nil, fmt.Errorf("hookspool.Ready: %w", err)
	}
	type stamped struct {
		path string
		at   int64
	}
	var files []stamped
	for _, m := range matches {
		n, perr := strconv.ParseInt(strings.TrimPrefix(m, path+asideMarker), 10, 64)
		if perr != nil {
			continue
		}
		if now.Sub(time.Unix(0, n)) < Grace {
			continue
		}
		files = append(files, stamped{m, n})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].at < files[j].at })
	out := make([]Aside, 0, len(files))
	for _, f := range files {
		a, rerr := readAside(f.path)
		if rerr != nil {
			continue
		}
		out = append(out, a)
	}
	return out, nil
}

func readAside(p string) (Aside, error) {
	f, err := os.Open(p)
	if err != nil {
		return Aside{}, err
	}
	defer func() { _ = f.Close() }()
	a := Aside{Path: p}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), MaxRecordBytes+1)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var r Record
		if json.Unmarshal([]byte(line), &r) != nil || r.V > version || !validRecord(r) {
			a.Dropped++
			continue
		}
		a.Records = append(a.Records, r)
	}
	if err := sc.Err(); err != nil {
		// An over-long line ends the scan; count it and keep what decoded.
		a.Dropped++
	}
	return a, nil
}

// HoldsKind reports whether any spool file (the live spool or an aside file,
// whatever its age) still holds a record of kind for sessionID. A recorder
// uses it to keep a session's records in order (P3-37): a later record of a
// session whose earlier record is still held must be held behind it, or the
// drainer would apply the earlier one after the later one. A file that cannot
// be read is skipped; an error is returned only when the spool cannot be
// listed.
func HoldsKind(path, kind, sessionID string) (bool, error) {
	if path == "" || sessionID == "" {
		return false, nil
	}
	matches, err := filepath.Glob(path + asideMarker + "*")
	if err != nil {
		return false, fmt.Errorf("hookspool.HoldsKind: %w", err)
	}
	for _, p := range append([]string{path}, matches...) {
		a, rerr := readAside(p)
		if rerr != nil {
			continue
		}
		for _, r := range a.Records {
			if r.Kind == kind && r.SessionID == sessionID {
				return true, nil
			}
		}
	}
	return false, nil
}

// Done removes a processed aside file.
func Done(a Aside) error {
	if err := os.Remove(a.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("hookspool.Done: %w", err)
	}
	return nil
}

// SetAside renames the live spool aside (stamped now) when it exists and is
// non-empty. It returns false when there was nothing to set aside.
func SetAside(path string, now time.Time) (bool, error) {
	if path == "" {
		return false, nil
	}
	st, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("hookspool.SetAside: %w", err)
	}
	if st.Size() == 0 {
		return false, nil
	}
	dst := path + asideMarker + strconv.FormatInt(now.UnixNano(), 10)
	if err := testwriteguard.Check("rename", path); err != nil {
		return false, fmt.Errorf("hookspool.SetAside: %w", err)
	}
	if err := os.Rename(path, dst); err != nil {
		return false, fmt.Errorf("hookspool.SetAside: %w", err)
	}
	return true, nil
}
