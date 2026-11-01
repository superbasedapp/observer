package guardposture

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// PostureFilename / SpoolFilename are the basenames, placed beside the
// global config file.
const (
	PostureFilename = "guard-posture.json"
	SpoolFilename   = "guard-hookfail.jsonl"
)

// Schema is the posture file's schema version.
const Schema = 1

// Source values for Posture.Source.
const (
	SourceOrg   = "org"
	SourceLocal = "local"
)

// Failure kinds a spool record carries (Record.Kind). Closed set.
const (
	KindTimeout     = "timeout"
	KindCrash       = "crash"
	KindConfig      = "config"
	KindGuardInit   = "guard_init"
	KindUnparseable = "unparseable"
	// KindUserPolicyFailClosed is not a hook FAILURE: the hook ran, but the
	// organization chose fail_closed (D-221 / T-327) and the user
	// guard-policy.toml does not load, so an enforced gate was closed with a
	// reason naming the file and line.
	KindUserPolicyFailClosed = "user_policy_fail_closed"
	// KindUnclassified is not a hook FAILURE either: the hook ran, but the
	// wired tool gate could not classify the call (a tool name no taxonomy
	// knows, or a judged tool whose operand is missing), so it went through
	// unjudged (review M2-12). Rate-limited per (tool, event, native tool)
	// by AllowOnce; Record.Native names the tool.
	KindUnclassified = "unclassified"
)

// FailureKinds returns the closed set of failure kinds, the degraded_from
// values that mark a guard_error row as a hook failure (the node Security
// page and the org Control coverage count them).
func FailureKinds() []string {
	return []string{KindTimeout, KindCrash, KindConfig, KindGuardInit, KindUnparseable}
}

// maxPostureBytes bounds a posture read: the file is a few fields.
const maxPostureBytes = 16 << 10

// MaxRecordBytes is the hard cap on one spool line (newline included). A
// single small O_APPEND write to a local regular file lands whole, so lines
// from concurrent hook processes never interleave; the cap keeps every line
// far below the 4 KiB page size. Append clips fields to fit.
const MaxRecordBytes = 2048

// DefaultDrainCap bounds one drain pass: a runaway spool is read up to this
// many bytes, the rest is dropped (and counted) rather than loaded whole.
const DefaultDrainCap = 1 << 20

// Posture is guard-posture.json.
type Posture struct {
	Schema int `json:"schema"`
	// Enforced is true when guard enforcement is in force: the guard is
	// enabled and either the global mode is "enforce" or at least one rule
	// is per-rule enforced.
	Enforced bool `json:"enforced"`
	// Source is "org" when an org policy layer is loaded, else "local".
	Source string `json:"source"`
	// Generation is the org policy version in force ("" when none).
	Generation string `json:"generation,omitempty"`
	// GateCaps are the gate capabilities (internal/integration HookCap
	// values) whose hook must fail CLOSED on a failure while Enforced. Empty
	// when not enforced.
	GateCaps []string `json:"gate_caps,omitempty"`
	// UserPolicyFailClosed is the organization's T-327 choice as it applies
	// on this node (guard.GateEnforcement.UserPolicyFailClosed): while the
	// user guard-policy.toml does not load, the hooks of GateCaps fail
	// closed. The hook re-checks the file itself, so this is a mode, not a
	// verdict. Only meaningful while Enforced.
	UserPolicyFailClosed bool `json:"user_policy_fail_closed,omitempty"`
	// OrgLock says the daemon that wrote this posture also writes
	// guard-org-lock.json (orglock.go). It is the anchor that makes a MISSING
	// lock read as tampered rather than as "an older daemon": a posture from
	// a daemon that predates the lock never carries it.
	OrgLock bool `json:"org_lock,omitempty"`
	// Managed is the tenancy the daemon resolved (T-864 gap 1). It is the
	// anchor a reader falls back to when the org lock itself is gone: a
	// MAC'd posture that says "managed, org layer in force" keeps the
	// organization's floor (and its locked rules) in force while the daemon
	// repairs the lock, and an individual node's posture keeps local control.
	Managed bool `json:"managed,omitempty"`
	// TenancyRecorded says this daemon records its tenancy in Managed (so a
	// false Managed means "individual", not "an older daemon that never
	// said").
	TenancyRecorded bool `json:"tenancy_recorded,omitempty"`
	// SecurityActive is whether the security pillar's module (component
	// `security`) is active on this node, and SecurityRecorded says this
	// daemon records it (so a false SecurityActive means "inactive", not
	// "an older daemon that never said"). The hook reads a missing security
	// posture file as unknown only while this says active (security pillar
	// plan section 4.3: the module's inactive state is signed into the
	// guard posture). Both are covered by the MAC.
	SecurityActive   bool `json:"security_active,omitempty"`
	SecurityRecorded bool `json:"security_recorded,omitempty"`
	// SecurityPacks is the node's active security pack set (the component
	// ids of the security tree that are active, the root included) while
	// SecurityActive. The hook uses it whenever a project's own posture
	// file cannot be used (missing, unverified, expired, over the cap, or
	// the read failed), so the commit gate and the content rows keep
	// firing on an unknown state (lane SEC-GATEFIX, P-014 item 1). Sorted,
	// deduplicated and covered by the MAC; empty while not active.
	SecurityPacks []string `json:"security_packs,omitempty"`
	// CommitGateFloorHeld says a managed node holds the security.scanning
	// family in effect with a commit gate floor (require.commit_gate =
	// quick_scan) in force org-wide or in at least one project section it
	// holds (audit SEC-P4 F2). The hook reads it only when a project's own
	// posture file cannot answer for the floor (missing, unverifiable, or a
	// read that overran): the floor then fails closed instead of reading as
	// no floor. Covered by the MAC; false while the module is not active or
	// the node is not managed.
	CommitGateFloorHeld bool `json:"commit_gate_floor_held,omitempty"`
	// WrittenAt is when the daemon wrote the file.
	WrittenAt time.Time `json:"written_at"`
	// MAC is the daemon's HMAC-SHA256 over every other field (auth.go,
	// Sol A2-02). A posture without a valid MAC is tampered.
	MAC string `json:"mac,omitempty"`
}

// Posture freshness (T-050). The daemon re-signs the posture at least every
// RefreshInterval while it runs; a reader treats a posture older than MaxAge
// as STALE (the daemon is stopped, suspended or wedged) and so does a
// posture written before the config file last changed (the inputs moved
// after the daemon computed it). A stale posture is ignored exactly like an
// absent one: the reader re-derives enforcement from the config and the
// signed org bundle (D-193/D-194), so a node whose enforcement was turned
// off while the daemon was down stops failing closed, and one that is still
// enforced keeps failing closed.
const (
	RefreshInterval = time.Minute
	MaxAge          = 3 * time.Minute
	// MaxFutureSkew tolerates a small clock step backwards (a posture dated up to this far in the future is still fresh).
	MaxFutureSkew = time.Minute
)

// Stale reports why p cannot be trusted at now ("" when it is fresh).
// configModified is the global config file's modification time (zero when
// unknown or absent).
func (p *Posture) Stale(now, configModified time.Time) string {
	if p == nil {
		return "no posture"
	}
	age := now.Sub(p.WrittenAt)
	switch {
	case age > MaxAge:
		return fmt.Sprintf("written %s ago, past the %s freshness window (the daemon is not refreshing it)", age.Round(time.Second), MaxAge)
	case age < -MaxFutureSkew:
		return "written in the future (clock skew)"
	case !configModified.IsZero() && configModified.After(p.WrittenAt):
		return "config.toml changed after it was written"
	}
	return ""
}

// StaleOnlyByConfig reports whether p is stale at now for exactly one reason:
// the config file changed after the daemon wrote it, while the posture is
// otherwise fresh (inside MaxAge, no clock skew). On a managed node that is
// the window between a local config edit and the daemon's next re-sign; a
// reader there keeps the posture's answer as well as the config's (T-864 gap
// 2), so a local edit cannot open a gate the organization holds closed.
func (p *Posture) StaleOnlyByConfig(now, configModified time.Time) bool {
	if p == nil || configModified.IsZero() || !configModified.After(p.WrittenAt) {
		return false
	}
	age := now.Sub(p.WrittenAt)
	return age <= MaxAge && age >= -MaxFutureSkew
}

// UserPolicyClosesGate reports whether, under the organization's fail_closed
// choice, a gate hook of capability cap must be closed while the user policy
// does not load: the choice is on and cap is one of the fail-closed gates.
func (p *Posture) UserPolicyClosesGate(cap string) bool {
	return p != nil && p.UserPolicyFailClosed && p.FailsClosed(cap)
}

// FailsClosed reports whether a failure on a hook of capability cap must be
// answered with a block. A nil posture (no file) never fails closed.
func (p *Posture) FailsClosed(cap string) bool {
	if p == nil || !p.Enforced {
		return false
	}
	for _, c := range p.GateCaps {
		if c == cap {
			return true
		}
	}
	return false
}

// PosturePath returns the posture file beside the resolved global config
// path ("" when configPath is empty).
func PosturePath(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), PostureFilename)
}

// SpoolPath returns the failure spool beside the resolved global config path
// ("" when configPath is empty).
func SpoolPath(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), SpoolFilename)
}

// Read loads a posture file. A missing file is (nil, nil): no daemon has
// published a posture, and the caller falls back to its own config. A
// malformed or foreign-schema file is an error; the caller treats it as
// unknown.
func Read(path string) (*Posture, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("guardposture.Read: %w", err)
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxPostureBytes+1))
	if err != nil {
		return nil, fmt.Errorf("guardposture.Read: %w", err)
	}
	if len(data) > maxPostureBytes {
		return nil, errors.New("guardposture.Read: posture file too large")
	}
	var out Posture
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("guardposture.Read: %w", err)
	}
	if out.Schema != Schema {
		return nil, errors.New("guardposture.Read: unsupported schema")
	}
	return &out, nil
}

// normalize stamps the schema and drops gate caps from a non-enforced
// posture: the one shape Encode, Sign and the MAC agree on.
func normalize(p Posture) Posture {
	p.Schema = Schema
	if !p.Enforced || len(p.GateCaps) == 0 {
		p.GateCaps = nil
		p.UserPolicyFailClosed = false
	}
	if !p.SecurityActive || !p.Managed {
		p.CommitGateFloorHeld = false
	}
	if !p.SecurityActive {
		p.SecurityPacks = nil
	} else {
		p.SecurityPacks = sortedPacks(p.SecurityPacks)
	}
	p.WrittenAt = p.WrittenAt.UTC()
	return p
}

// sortedPacks returns packs sorted, deduplicated and without empty ids
// (nil when none remain): the one spelling Encode and the MAC agree on.
func sortedPacks(packs []string) []string {
	var out []string
	for _, id := range packs {
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	slices.Sort(out)
	return out
}

// Encode renders p (normalized, MAC as given) as the bytes Write stores.
func Encode(p Posture) ([]byte, error) {
	p = normalize(p)
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("guardposture.Encode: %w", err)
	}
	return data, nil
}

// Write signs p under key and replaces the posture file atomically
// (temp + rename, 0600). It returns the exact bytes written so the one
// writer can later tell its own file from a replaced one.
func Write(path string, p Posture, key []byte) ([]byte, error) {
	if path == "" {
		return nil, errors.New("guardposture.Write: empty path")
	}
	if len(key) == 0 {
		return nil, errors.New("guardposture.Write: no key")
	}
	data, err := Encode(Sign(p, key))
	if err != nil {
		return nil, err
	}
	if err := writeAtomic(path, data, ".guard-posture-*.tmp"); err != nil {
		return nil, fmt.Errorf("guardposture.Write: %w", err)
	}
	// A posture now exists: from here on a missing one is a tamper, so the
	// key's not-yet-published marker goes (auth.go, UnpublishedFilename).
	if err := os.Remove(unpublishedPath(filepath.Dir(path))); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("guardposture.Write: clear the unpublished marker: %w", err)
	}
	return data, nil
}

func writeAtomic(path string, data []byte, pattern string) error {
	return fsatomic.WriteFile(path, data, fsatomic.Options{TempPattern: pattern})
}

// Outcomes a spool record carries (Record.Outcome). Closed set.
const (
	// OutcomeFailClosed: the failure was answered with the dialect's block
	// (a gate hook while guard enforcement is on).
	OutcomeFailClosed = "fail_closed"
	// OutcomeFailOpen: the failure let the call through unevaluated (a gate
	// hook while enforcement is off for its capability), T-049.
	OutcomeFailOpen = "fail_open"
)

// Record is one spool line: a gate hook that could not evaluate a call, and
// whether it blocked (fail closed) or let the call through (fail open).
type Record struct {
	Tool      string    `json:"tool"`
	Event     string    `json:"event"`
	Cap       string    `json:"cap"`
	SessionID string    `json:"session_id,omitempty"`
	Kind      string    `json:"kind"`
	At        time.Time `json:"at"`
	// Outcome is OutcomeFailClosed or OutcomeFailOpen. Empty on a line a
	// pre-T-049 hook wrote, which only ever spooled fail-closed blocks
	// (FailedOpen reads it that way).
	Outcome string `json:"outcome,omitempty"`
	// Native is the vendor's tool name a KindUnclassified record is about
	// ("" on every other kind, and when the payload named no tool).
	Native string `json:"native,omitempty"`
}

// FailedOpen reports whether the record is a fail-open failure (an empty
// Outcome is a legacy fail-closed line).
func (r Record) FailedOpen() bool { return r.Outcome == OutcomeFailOpen }

// fieldCap bounds each free-form field so a line always fits
// MaxRecordBytes.
const fieldCap = 256

func clip(s string) string {
	if len(s) <= fieldCap {
		return s
	}
	s = s[:fieldCap]
	for !utf8.ValidString(s) && s != "" {
		s = s[:len(s)-1]
	}
	return s
}

// Append adds one record to the spool with a single O_APPEND write. It never
// waits on the drainer and never blocks on a lock: a failed append returns
// the error and the caller (the hook) moves on.
func Append(path string, r Record) error {
	if path == "" {
		return errors.New("guardposture.Append: empty path")
	}
	r.Tool, r.Event, r.Cap, r.SessionID, r.Kind, r.Outcome = clip(r.Tool), clip(r.Event), clip(r.Cap), clip(r.SessionID), clip(r.Kind), clip(r.Outcome)
	r.Native = clip(r.Native)
	if r.At.IsZero() {
		r.At = time.Now().UTC()
	}
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("guardposture.Append: %w", err)
	}
	line = append(line, '\n')
	if len(line) > MaxRecordBytes {
		return errors.New("guardposture.Append: record too large")
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("guardposture.Append: %w", err)
	}
	if _, err := f.Write(line); err != nil {
		_ = f.Close()
		return fmt.Errorf("guardposture.Append: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("guardposture.Append: %w", err)
	}
	return nil
}

// rateLimitSuffix names the marker directory beside the spool.
const rateLimitSuffix = ".limits"

// RateLimitDir is the marker directory AllowOnce uses for spoolPath ("" when
// spoolPath is empty).
func RateLimitDir(spoolPath string) string {
	if spoolPath == "" {
		return ""
	}
	return spoolPath + rateLimitSuffix
}

// AllowOnce reports whether a rate-limited record for key may be written at
// now: at most once per window per key, across hook processes. The marker
// is a file in dir named by a hash of key (never the key itself), whose
// modification time is the last allowed record. A marker it cannot create
// or refresh denies (no record rather than an unbounded flood); a marker
// dated in the future by more than window is treated as expired. Two hooks
// racing on one key may both be allowed once: the bound is per window, not
// exact.
func AllowOnce(dir, key string, window time.Duration, now time.Time) bool {
	if dir == "" {
		return false
	}
	sum := sha256.Sum256([]byte(key))
	name := filepath.Join(dir, hex.EncodeToString(sum[:8]))
	if fi, err := os.Stat(name); err == nil {
		if age := now.Sub(fi.ModTime()); age < window && age > -window {
			return false
		}
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return false
	}
	f, err := os.OpenFile(name, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return false
	}
	if err := f.Close(); err != nil {
		return false
	}
	return os.Chtimes(name, now, now) == nil
}

// drainingSuffix names the sealed (renamed-aside) spool a drain is
// processing; drainStateSuffix its read offset and seal time.
const (
	drainingSuffix   = ".draining"
	drainStateSuffix = ".state"
)

// SpoolQuiesce is how long a sealed spool is kept after its last byte was
// read before it may be removed (T-051).
//
// The drain seals the spool with a rename, so a hook that opens the spool
// AFTER the rename creates a fresh one. A hook that opened it BEFORE the
// rename still holds the old inode (POSIX keeps an open file descriptor
// across a rename) and its write lands in the sealed file, possibly after
// the drain read it. Deleting or rewriting the sealed file at that point
// lost the line. So the sealed file is never rewritten: the drain keeps a
// read offset beside it and reads any straggler on a later pass, and it
// removes the file only once it is fully read AND older than SpoolQuiesce.
// A hook holds the spool open for one Append, and its process lifetime is
// bounded by the hook watchdog (30 s default plus a 2 s lock grace), far
// below this window; a hook run with the watchdog disabled
// (`--max-runtime 0`, a diagnostics escape hatch) is the documented
// residual. On Windows a rename of an open file fails, so the drain simply
// retries on its next pass.
const SpoolQuiesce = 2 * time.Minute

// nowFn is the drain's clock (tests advance it past SpoolQuiesce).
var nowFn = time.Now

// drainState is the sealed spool's sidecar: how far it was read, and when
// it was sealed.
type drainState struct {
	Offset   int64     `json:"offset"`
	SealedAt time.Time `json:"sealed_at"`
}

func readDrainState(path string) (drainState, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return drainState{}, false
	}
	var s drainState
	if json.Unmarshal(data, &s) != nil || s.Offset < 0 || s.SealedAt.IsZero() {
		return drainState{}, false
	}
	return s, true
}

func writeDrainState(path string, s drainState) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return writeAtomic(path, data, ".guard-hookfail-state-*.tmp")
}

// Batch is one drain pass's result: the complete lines of one bounded chunk
// of the sealed spool, read from the saved offset. Commit records that the
// chunk was consumed and must be called only after every record was
// persisted; when it is not called the next Drain reads the same chunk
// again (at-least-once). Bytes past the chunk, including lines a straggling
// hook appended to the sealed file after this read, are never dropped: the
// next Drain continues from the committed offset (Sol A2-07, T-051).
type Batch struct {
	Records []Record
	// Dropped counts lines that were malformed or longer than a record
	// can be, one per line.
	Dropped int
	// More is true when the sealed file holds bytes past this chunk.
	More bool
	path string
	// consumed is the byte offset just past the chunk's last line.
	consumed int64
	sealedAt time.Time
}

// Commit consumes the chunk by saving the new offset. The sealed file is
// removed only when it is fully read and has been sealed for at least
// SpoolQuiesce (no hook can still write into it); otherwise it stays, and
// the next Drain reads whatever was appended past the offset.
func (b *Batch) Commit() error {
	if b == nil || b.path == "" {
		return nil
	}
	if retired, err := retireIfDone(b.path, b.consumed, b.sealedAt); err != nil || retired {
		return err
	}
	if err := writeDrainState(b.path+drainStateSuffix, drainState{Offset: b.consumed, SealedAt: b.sealedAt}); err != nil {
		return fmt.Errorf("guardposture.Commit: %w", err)
	}
	return nil
}

// retireIfDone removes the sealed file and its state when offset reaches its
// size and the seal is older than SpoolQuiesce.
func retireIfDone(aside string, offset int64, sealedAt time.Time) (bool, error) {
	if nowFn().Sub(sealedAt) < SpoolQuiesce {
		return false, nil
	}
	st, err := os.Stat(aside)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			_ = os.Remove(aside + drainStateSuffix)
			return true, nil
		}
		return false, fmt.Errorf("guardposture.retire: %w", err)
	}
	if st.Size() > offset {
		return false, nil
	}
	if err := os.Remove(aside); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("guardposture.retire: %w", err)
	}
	if err := os.Remove(aside + drainStateSuffix); err != nil && !errors.Is(err, os.ErrNotExist) {
		return true, fmt.Errorf("guardposture.retire: %w", err)
	}
	return true, nil
}

// Drain parses one bounded chunk of the sealed spool from its saved offset.
// With no sealed spool it first seals the live one (rename aside, so a hook
// appending during the drain writes a fresh spool). A sealed spool that is
// fully read and older than SpoolQuiesce is retired first, and the live
// spool sealed in its place; one that is fully read but younger waits (the
// live spool keeps collecting meanwhile). A chunk is the complete lines
// starting within maxBytes past the offset (DefaultDrainCap when <= 0); a
// line is never split, and an unterminated tail is left for a later pass
// until the seal is quiet. (nil, nil) when there is nothing to drain now.
func Drain(path string, maxBytes int64) (*Batch, error) {
	if path == "" {
		return nil, nil
	}
	if maxBytes <= 0 {
		maxBytes = DefaultDrainCap
	}
	aside := path + drainingSuffix
	statePath := aside + drainStateSuffix
	state, haveState := readDrainState(statePath)
	switch _, err := os.Stat(aside); {
	case err == nil:
		if !haveState {
			// A sealed file without its state: a crash between seal and
			// state write, or one sealed by an older daemon. Read it from
			// the start (at-least-once) and start its quiet window now.
			state = drainState{SealedAt: nowFn().UTC()}
			if err := writeDrainState(statePath, state); err != nil {
				return nil, fmt.Errorf("guardposture.Drain: %w", err)
			}
		}
		retired, err := retireIfDone(aside, state.Offset, state.SealedAt)
		if err != nil {
			return nil, fmt.Errorf("guardposture.Drain: %w", err)
		}
		if !retired {
			break
		}
		fallthrough
	case errors.Is(err, os.ErrNotExist):
		if err := os.Rename(path, aside); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return nil, nil
			}
			return nil, fmt.Errorf("guardposture.Drain: %w", err)
		}
		state = drainState{SealedAt: nowFn().UTC()}
		if err := writeDrainState(statePath, state); err != nil {
			return nil, fmt.Errorf("guardposture.Drain: %w", err)
		}
	default:
		return nil, fmt.Errorf("guardposture.Drain: %w", err)
	}
	f, err := os.Open(aside)
	if err != nil {
		return nil, fmt.Errorf("guardposture.Drain: %w", err)
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("guardposture.Drain: %w", err)
	}
	if st.Size() <= state.Offset {
		return nil, nil
	}
	if _, err := f.Seek(state.Offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("guardposture.Drain: %w", err)
	}
	quiet := nowFn().Sub(state.SealedAt) >= SpoolQuiesce
	b := &Batch{path: aside, consumed: state.Offset, sealedAt: state.SealedAt}
	rd := bufio.NewReaderSize(f, 2*MaxRecordBytes)
	for b.consumed-state.Offset < maxBytes {
		line, n, rerr := readSpoolLine(rd)
		if errors.Is(rerr, io.EOF) && n > 0 && line != nil && !bytes.HasSuffix(line, []byte{'\n'}) && !quiet {
			// An unterminated tail: a straggler may still be writing it.
			break
		}
		b.consumed += n
		switch {
		case line == nil && n > 0:
			b.Dropped++ // longer than any record: skipped whole
		case len(bytes.TrimSpace(line)) > 0:
			var r Record
			if err := json.Unmarshal(bytes.TrimSpace(line), &r); err != nil || r.Kind == "" {
				b.Dropped++
			} else {
				b.Records = append(b.Records, r)
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			return nil, fmt.Errorf("guardposture.Drain: %w", rerr)
		}
	}
	if b.consumed == state.Offset {
		return nil, nil
	}
	b.More = st.Size() > b.consumed
	return b, nil
}

// readSpoolLine reads one line (newline included in n). A line longer than
// the reader's buffer is consumed to its newline and returned as nil with
// its full length, so the caller counts it as dropped without holding it.
func readSpoolLine(rd *bufio.Reader) (line []byte, n int64, err error) {
	chunk, err := rd.ReadSlice('\n')
	if !errors.Is(err, bufio.ErrBufferFull) {
		out := append([]byte(nil), chunk...)
		return out, int64(len(chunk)), err
	}
	n = int64(len(chunk))
	for errors.Is(err, bufio.ErrBufferFull) {
		chunk, err = rd.ReadSlice('\n')
		n += int64(len(chunk))
	}
	return nil, n, err
}
