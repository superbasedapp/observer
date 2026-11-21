package sandboxrelayd

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxrelay"
)

// RecordVersion is the run and box record version.
const RecordVersion = 1

// Delivery is how a run's workspace reaches the box (sandbox plan section
// 6, M7): the agent edits the live tree, or a copy.
type Delivery string

// The closed Delivery vocabulary.
const (
	DeliveryLive Delivery = "live"
	DeliveryCopy Delivery = "copy"
)

// RunRecord is the HOST copy of a run's launch facts and secrets. It lives
// under the observer directory, which no box can read, and is read by the
// host helper (for both secrets) and by the daemon (for the link secret and
// the facts). Its fields are what the run's channel supplies.
type RunRecord struct {
	V     int    `json:"v"`
	RunID string `json:"run_id"`
	Tool  string `json:"tool"`
	// ProjectRoot is the host's attribution of the run (never a path the
	// box reports).
	ProjectRoot string `json:"project_root"`
	// WorkspaceDir is the workspace the run edits.
	WorkspaceDir string `json:"workspace_dir"`
	// Roots are the directories a relayed payload path may be read under
	// (the workspace and the tool's bound state).
	Roots []string `json:"roots"`
	// Delivery and CopyHostPath are the workspace delivery launch fact.
	Delivery     Delivery `json:"delivery"`
	CopyHostPath string   `json:"copy_host_path,omitempty"`
	// BoxSecret keys the box channel; LinkSecret keys the helper-to-daemon
	// link. They are different so a key read inside the box cannot speak
	// on the link.
	BoxSecret  []byte    `json:"box_secret"`
	LinkSecret []byte    `json:"link_secret"`
	CreatedAt  time.Time `json:"created_at"`
	// TerminalRunID is the stored terminal run this relay run belongs to
	// (the terminal_run row its capture health is recorded on), bound when
	// the launcher spawns it (BindTerminalRun), a dashboard launch or a CLI
	// sandboxed launch alike; "" when the row could not be written.
	TerminalRunID string `json:"terminal_run_id,omitempty"`
	// ConfigPath is the daemon's config file, so the host helper reads the
	// hook registration the daemon wrote ("" is the default config).
	ConfigPath string `json:"config_path,omitempty"`
	// RefusalAuditRequired records that the org's require_refusal_audit
	// floor was in force when the run was composed (tracker F-012, audit
	// finding N4-A4). The host helper reads it: while it is set, a run
	// whose link to the daemon is lost closes its egress gateway rather
	// than let refusals go unrecorded; while it is not, the run keeps its
	// egress and the lost refusals are counted when the link comes back.
	// Additive: a record without it reads false.
	RefusalAuditRequired bool `json:"refusal_audit_required,omitempty"`
	// PathMap maps a box's own path prefixes onto host directories (a
	// hosted box that works in a fixed path of its own, lane G4 fix round
	// 2, G4-R2; pathmap.go). The relay rewrites a payload's mapped paths
	// before binding and reading; a box prefix is never a root. Additive:
	// a record without it maps nothing.
	PathMap []PathPrefix `json:"path_map,omitempty"`
	// RemoteBox records that the run's box is on another machine (a hosted
	// row, FX4-A1): this machine's home is not the box's, so a payload's
	// "~/" file value names nothing of this machine and the binding refuses
	// it instead of expanding it here (expandHome), and the record's roots
	// never list this machine's tool state. Additive: a record without it
	// reads false (a local box, which sees this machine's home).
	RemoteBox bool `json:"remote_box,omitempty"`
}

// HomeIsThisMachines reports whether a payload's "~/" names this machine's
// home for the run: a local box only. A record that is remote, or that maps
// box paths (a box with paths of its own), does not (FX4-A1).
func (r RunRecord) HomeIsThisMachines() bool { return !r.RemoteBox && len(r.PathMap) == 0 }

// ReadRoots are the directories a relayed payload's files may be read under
// for this record, at bind time and in the confined reader alike. For a
// record whose home is not this machine's (HomeIsThisMachines false) they
// are its WorkspaceDir and its PathMap hosts only, whatever the stored
// Roots say: a hosted record written before FX4 that stays live across the
// upgrade (never re-keyed) still lists this machine's tool state there
// (FX4 fix round 2, FX4-R1). Otherwise the stored Roots.
func (r RunRecord) ReadRoots() []string {
	if r.HomeIsThisMachines() {
		return r.Roots
	}
	return RemoteBoxRoots(r.WorkspaceDir, r.PathMap)
}

// RemoteBoxRoots is the one owner of the read-roots rule for a box whose
// home is not this machine's (FX4-A1; fold delta audit N3): the run's
// workspace and its mapped host directories only, never this machine's
// tool state. ReadRoots, the record writer and the hosted re-key all call
// it.
func RemoteBoxRoots(workspace string, pathMap []PathPrefix) []string {
	var out []string
	if workspace != "" {
		out = append(out, workspace)
	}
	for _, pm := range pathMap {
		if pm.Host != "" && !slices.Contains(out, pm.Host) {
			out = append(out, pm.Host)
		}
	}
	return out
}

// BoxRecord is the BOX copy of the launch record (sandbox plan section 5.2,
// Opus M8): written by the host helper into the per-run socket dir, which
// the box sees read-only. `observer hook` reads it first; when it says the
// relay is required the hook never opens a database.
type BoxRecord struct {
	V int `json:"v"`
	// Relay is always "required" in a written record.
	Relay     string   `json:"relay"`
	RunID     string   `json:"run_id"`
	Socket    string   `json:"socket"`
	BoxSecret []byte   `json:"box_secret"`
	Delivery  Delivery `json:"delivery"`
}

// RelayRequired is BoxRecord.Relay's one value.
const RelayRequired = "required"

// File and directory names.
const (
	// RelayDirName is the relay's directory under the observer directory.
	RelayDirName = "sandbox-relay"
	runsDirName  = "runs"
	// BoxRecordName is the box record in a per-run socket dir.
	BoxRecordName = "launch.json"
	// RelaySocketName is the box-facing socket in a per-run socket dir.
	RelaySocketName = "relay.sock"
	// maxRecord caps a record read.
	maxRecord = 64 << 10
)

// Errors.
var (
	ErrNoRecord  = errors.New("sandboxrelayd: no run record")
	ErrBadRecord = errors.New("sandboxrelayd: run record refused")
)

// RunsDir is where run records live under observerDir.
func RunsDir(observerDir string) string { return filepath.Join(observerDir, RelayDirName, runsDirName) }

// NewSecret mints a per-run secret.
func NewSecret() ([]byte, error) {
	b := make([]byte, sandboxrelay.SecretSize)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, fmt.Errorf("sandboxrelayd.NewSecret: %w", err)
	}
	return b, nil
}

// NewRunRecord fills the secrets and stamps of a record whose facts the
// caller set.
func NewRunRecord(r RunRecord) (RunRecord, error) {
	if !sandboxrelay.ValidRunID(r.RunID) {
		return RunRecord{}, fmt.Errorf("%w: run id", ErrBadRecord)
	}
	var err error
	if r.BoxSecret, err = NewSecret(); err != nil {
		return RunRecord{}, err
	}
	if r.LinkSecret, err = NewSecret(); err != nil {
		return RunRecord{}, err
	}
	if r.Delivery == "" {
		r.Delivery = DeliveryLive
	}
	if err := validPathMap(r.PathMap); err != nil {
		return RunRecord{}, err
	}
	r.V, r.CreatedAt = RecordVersion, time.Now().UTC()
	return r, nil
}

// WriteRun writes rec under observerDir (dirs 0700, the file 0600, created
// exclusively and never through a link).
func WriteRun(observerDir string, rec RunRecord) error {
	dir := RunsDir(observerDir)
	// An elevated Windows daemon creates objects owned by Administrators;
	// the record and the directories this call created are given to the
	// token user, the owner the reader requires (owned.go; a directory that
	// already exists keeps its owner, SBX-UPD audit finding 7).
	if err := MkdirAllOwned(dir); err != nil {
		return fmt.Errorf("sandboxrelayd.WriteRun: %w", err)
	}
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("sandboxrelayd.WriteRun: %w", err)
	}
	return writeExclusive(filepath.Join(dir, rec.RunID+".json"), b)
}

// ReadRun reads the record of runID under observerDir.
func ReadRun(observerDir, runID string) (RunRecord, error) {
	if !sandboxrelay.ValidRunID(runID) {
		return RunRecord{}, fmt.Errorf("%w: run id", ErrBadRecord)
	}
	b, err := readOwned(filepath.Join(RunsDir(observerDir), runID+".json"))
	if err != nil {
		return RunRecord{}, err
	}
	var rec RunRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return RunRecord{}, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	if rec.V != RecordVersion || rec.RunID != runID || len(rec.BoxSecret) != sandboxrelay.SecretSize || len(rec.LinkSecret) != sandboxrelay.SecretSize {
		return RunRecord{}, fmt.Errorf("%w: fields", ErrBadRecord)
	}
	if err := validPathMap(rec.PathMap); err != nil {
		return RunRecord{}, err
	}
	return rec, nil
}

// maxTerminalRunID bounds a bound terminal run id.
const maxTerminalRunID = 128

// BindTerminalRun records in runID's record the stored terminal run it
// belongs to. The record is replaced whole (a fresh 0600 file renamed over
// it), so a reader sees the old record or the new one, never a half. It
// refuses a record already bound to another terminal run.
func BindTerminalRun(observerDir, runID, terminalRunID string) error {
	if terminalRunID == "" || len(terminalRunID) > maxTerminalRunID || strings.ContainsAny(terminalRunID, "\x00\n/") {
		return fmt.Errorf("%w: terminal run id", ErrBadRecord)
	}
	rec, err := ReadRun(observerDir, runID)
	if err != nil {
		return err
	}
	if rec.TerminalRunID == terminalRunID {
		return nil
	}
	if rec.TerminalRunID != "" {
		return fmt.Errorf("%w: run %s is already bound", ErrBadRecord, runID)
	}
	rec.TerminalRunID = terminalRunID
	b, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("sandboxrelayd.BindTerminalRun: %w", err)
	}
	dir := RunsDir(observerDir)
	tmp := filepath.Join(dir, "."+runID+".bind")
	_ = os.Remove(tmp)
	if err := writeExclusive(tmp, b); err != nil {
		return err
	}
	if err := os.Rename(tmp, filepath.Join(dir, runID+".json")); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("sandboxrelayd.BindTerminalRun: %w", err)
	}
	return nil
}

// RemoveRun deletes the record of runID (a missing one is not an error).
func RemoveRun(observerDir, runID string) error {
	if !sandboxrelay.ValidRunID(runID) {
		return fmt.Errorf("%w: run id", ErrBadRecord)
	}
	err := os.Remove(filepath.Join(RunsDir(observerDir), runID+".json"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("sandboxrelayd.RemoveRun: %w", err)
	}
	return nil
}

// WriteBoxRecord writes the box record into the per-run socket dir.
func WriteBoxRecord(sockDir string, rec RunRecord) error {
	b, err := json.Marshal(BoxRecord{
		V: RecordVersion, Relay: RelayRequired, RunID: rec.RunID, Socket: RelaySocketName,
		BoxSecret: rec.BoxSecret, Delivery: rec.Delivery,
	})
	if err != nil {
		return fmt.Errorf("sandboxrelayd.WriteBoxRecord: %w", err)
	}
	// The box reads its record only from a directory its user owns.
	if err := claimOwnership(sockDir); err != nil {
		return fmt.Errorf("sandboxrelayd.WriteBoxRecord: own the socket dir: %w", err)
	}
	return writeExclusive(filepath.Join(sockDir, BoxRecordName), b)
}

// ReadBoxRecord reads a box record at path. ok=false (with a nil error)
// means there is no record at all: the hook is outside any sandbox. A
// record that exists but is refused (another owner, a link, a
// group-writable file or directory, a bad field) is an error: a hook that
// finds one treats it as a fault and blocks gate events.
func ReadBoxRecord(path string) (BoxRecord, bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return BoxRecord{}, false, nil
	}
	if err := checkOwnedDir(filepath.Dir(path)); err != nil {
		return BoxRecord{}, true, err
	}
	b, err := readOwned(path)
	if err != nil {
		return BoxRecord{}, true, err
	}
	var rec BoxRecord
	if err := json.Unmarshal(b, &rec); err != nil {
		return BoxRecord{}, true, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	if rec.V != RecordVersion || rec.Relay != RelayRequired || !sandboxrelay.ValidRunID(rec.RunID) ||
		rec.Socket != RelaySocketName || len(rec.BoxSecret) != sandboxrelay.SecretSize {
		return BoxRecord{}, true, fmt.Errorf("%w: fields", ErrBadRecord)
	}
	return rec, true, nil
}

// claimOwned is claimOwnership, a variable so a test sees which objects a
// write claims.
var claimOwned = claimOwnership

// writeExclusive creates path (O_EXCL, O_NOFOLLOW, 0600) and writes b.
func writeExclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL|oNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("sandboxrelayd: create %s: %w", filepath.Base(path), err)
	}
	_, werr := f.Write(b)
	cerr := f.Close()
	oerr := claimOwned(path)
	if err := errors.Join(werr, cerr, oerr); err != nil {
		_ = os.Remove(path)
		return fmt.Errorf("sandboxrelayd: write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// readOwned reads a small regular file that this user owns, never through
// a link, and that no group or other may write.
func readOwned(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoRecord
		}
		return nil, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	defer func() { _ = f.Close() }()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	if !fi.Mode().IsRegular() || fi.Size() > maxRecord || !privateFile(path, f, fi) {
		return nil, fmt.Errorf("%w: not a private regular file", ErrBadRecord)
	}
	return io.ReadAll(io.LimitReader(f, maxRecord))
}

// checkOwnedDir refuses a directory another user owns or others may write.
func checkOwnedDir(dir string) error {
	fi, err := os.Lstat(dir) //nolint:gosec // G703: the sandbox's own record dir, checked here
	if err != nil {
		return fmt.Errorf("%w: %w", ErrBadRecord, err)
	}
	if !fi.IsDir() || !privateDir(dir, fi) {
		return fmt.Errorf("%w: the record's directory is not private", ErrBadRecord)
	}
	return nil
}

// PruneRuns removes run records older than maxAge (a helper killed with
// SIGKILL cannot remove its own) and reports how many it removed. Only
// regular record files are touched.
func PruneRuns(observerDir string, maxAge time.Duration, now time.Time) (int, error) {
	dir := RunsDir(observerDir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, fmt.Errorf("sandboxrelayd.PruneRuns: %w", err)
	}
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !e.Type().IsRegular() || filepath.Ext(name) != ".json" || !sandboxrelay.ValidRunID(name[:len(name)-len(".json")]) {
			continue
		}
		fi, err := e.Info()
		if err != nil || now.Sub(fi.ModTime()) < maxAge {
			continue
		}
		if os.Remove(filepath.Join(dir, name)) == nil {
			n++
		}
	}
	return n, nil
}
