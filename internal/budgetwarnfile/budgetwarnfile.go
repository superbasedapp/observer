package budgetwarnfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// StatusFilename / ShownFilename are the basenames, placed beside the DB.
const (
	StatusFilename = "budget-status.json"
	ShownFilename  = "budget-notices-shown.json"
)

// Schema is the status file's schema version.
const Schema = 1

// maxStatusBytes bounds a read: the file is a handful of windows.
const maxStatusBytes = 256 << 10

// Notice mirrors budgetwarn.Notice on disk.
type Notice struct {
	ID          string    `json:"id"`
	Window      string    `json:"window"`
	Unit        string    `json:"unit"`
	Subject     string    `json:"subject,omitempty"` // "tool:<id>" / "model:<id>"; empty = whole caller
	Period      string    `json:"period"`
	Threshold   float64   `json:"threshold"`
	Ratio       float64   `json:"ratio"`
	Spent       float64   `json:"spent"`
	Cap         float64   `json:"cap"`
	Scope       string    `json:"scope"`
	Enforcement string    `json:"enforcement"`
	CrossedAt   time.Time `json:"crossed_at"`
	Level       string    `json:"level"`
	Message     string    `json:"message"`
	// Effect / Blocked / DeniesOnLocal say what the cap does on THIS
	// machine (budgetwarn.EffectOf): a file from an older daemon has none,
	// and a reader then must not claim a block it cannot see.
	Effect        string `json:"effect,omitempty"`
	Blocked       bool   `json:"blocked,omitempty"`
	DeniesOnLocal bool   `json:"denies_on_local_spend,omitempty"`
}

// Window mirrors budgetwarn.WindowStatus on disk.
type Window struct {
	Window  string `json:"window"`
	Unit    string `json:"unit"`
	Subject string `json:"subject,omitempty"` // "tool:<id>" / "model:<id>"; empty = whole caller
	Period  string `json:"period"`
	// Timezone is the IANA zone Period is named in (the cap's own calendar),
	// written as "UTC" for a UTC cap. Empty means a file from a daemon that
	// predates the field: a reader then has to assume UTC and say so.
	Timezone    string  `json:"timezone,omitempty"`
	Cap         float64 `json:"cap"`
	Spent       float64 `json:"spent"`
	Ratio       float64 `json:"ratio"`
	Scope       string  `json:"scope"`
	Enforcement string  `json:"enforcement"`
	Level       string  `json:"level"`
	Crossed     float64 `json:"crossed"`
	// Effect / Blocked / DeniesOnLocal: see Notice.
	Effect        string `json:"effect,omitempty"`
	Blocked       bool   `json:"blocked,omitempty"`
	DeniesOnLocal bool   `json:"denies_on_local_spend,omitempty"`
}

// Notified mirrors one budgetwarn.State entry.
type Notified struct {
	Threshold float64 `json:"threshold"`
	Notice    Notice  `json:"notice"`
}

// File is budget-status.json.
type File struct {
	Schema    int       `json:"schema"`
	WrittenAt time.Time `json:"written_at"`
	// Display is the developer cost display the Messages were rendered in
	// ("usd" or "tokens", store.ResolveDeveloperCostDisplay). Empty (a file
	// from an older daemon) means "usd". Readers that render their own text
	// from the numbers (the statusline) honour it too.
	Display string `json:"display,omitempty"`
	// Windows is every org-authored window's current reading.
	Windows []Window `json:"windows"`
	// Active is the highest announced notice per window this period.
	Active []Notice `json:"active,omitempty"`
	// State is the daemon's persisted ladder memory (which rung each window
	// already announced this period), so a restart does not re-announce.
	State map[string]Notified `json:"state,omitempty"`
	// Fetch is the last pull of this machine's organization budget (GET
	// /api/agent/budget), so the local dashboard can say when it fails
	// (budget enforce consistency, 2026-11-19: a failed pull was visible
	// nowhere on the machine). nil from an older daemon or a machine with no
	// organization budget rail.
	Fetch *Fetch `json:"fetch,omitempty"`
}

// Fetch is one machine's organization budget pull, as the daemon last saw it.
type Fetch struct {
	// State is the closed orgcontract.BudgetFetch* value.
	State string `json:"state"`
	// LastOKAt is the last pull that got a verified answer; zero when none
	// has in this daemon's life.
	LastOKAt time.Time `json:"last_ok_at,omitempty"`
	// FailingSince is when the current run of failed pulls began; zero while
	// the pull works.
	FailingSince time.Time `json:"failing_since,omitempty"`
}

// StatusPath returns the status file path beside dbPath ("" when dbPath is
// empty).
func StatusPath(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), StatusFilename)
}

// ShownPath returns the hook-owned shown-marker path beside dbPath.
func ShownPath(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), ShownFilename)
}

// Read loads a status file. A missing file is (nil, nil): no org budget
// warnings on this node. A malformed or foreign-schema file is an error and
// callers treat it as "nothing to show".
func Read(path string) (*File, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("budgetwarnfile.Read: %w", err)
	}
	defer func() { _ = f.Close() }()
	var out File
	dec := json.NewDecoder(&limitedReader{r: f, n: maxStatusBytes})
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("budgetwarnfile.Read: %w", err)
	}
	if out.Schema != Schema {
		return nil, errors.New("budgetwarnfile: unsupported schema")
	}
	return &out, nil
}

// Write replaces the status file atomically (temp + rename), mode 0600.
func Write(path string, file File) error {
	if path == "" {
		return errors.New("budgetwarnfile: empty path")
	}
	file.Schema = Schema
	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("budgetwarnfile.Write: %w", err)
	}
	return writeAtomic(path, data)
}

// Shown is the hook-owned marker: notice ids already shown in-band.
type Shown struct {
	IDs []string `json:"ids"`
}

// maxShownIDs bounds the marker (ids carry their period, so old ones are dead
// weight once the period passed).
const maxShownIDs = 64

// ReadShown loads the marker (missing or malformed = empty).
func ReadShown(path string) Shown {
	var s Shown
	if path == "" {
		return s
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > maxStatusBytes {
		return s
	}
	_ = json.Unmarshal(data, &s)
	return s
}

// Has reports whether id was already shown.
func (s Shown) Has(id string) bool {
	for _, v := range s.IDs {
		if v == id {
			return true
		}
	}
	return false
}

// MarkShown records ids as shown (keeping the newest maxShownIDs) and
// writes the marker atomically. Best-effort: a lost race between two hook
// processes can at worst show one notice twice.
func MarkShown(path string, ids ...string) error {
	if path == "" || len(ids) == 0 {
		return nil
	}
	s := ReadShown(path)
	for _, id := range ids {
		if !s.Has(id) {
			s.IDs = append(s.IDs, id)
		}
	}
	if len(s.IDs) > maxShownIDs {
		s.IDs = s.IDs[len(s.IDs)-maxShownIDs:]
	}
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("budgetwarnfile.MarkShown: %w", err)
	}
	return writeAtomic(path, data)
}

// PendingInBand returns the active notices of a status file that have not
// been shown in-band yet, highest rung first. A notice older than maxAge is
// skipped (a crossing from long ago is not "news" for the next prompt; the
// banner and statusline still show it).
func PendingInBand(file *File, shown Shown, now time.Time, maxAge time.Duration) []Notice {
	if file == nil {
		return nil
	}
	var out []Notice
	for _, n := range file.Active {
		if n.ID == "" || shown.Has(n.ID) {
			continue
		}
		if maxAge > 0 && !n.CrossedAt.IsZero() && now.Sub(n.CrossedAt) > maxAge {
			continue
		}
		out = append(out, n)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Threshold > out[j].Threshold })
	return out
}

// TouchActivity stamps the node-activity marker beside the DB (see
// ActivityFilename). It is the hook lane's "a prompt happened" signal to the
// daemon's policy-freshness checker: an mtime only, no content, no fsync.
func TouchActivity(dbPath string) error {
	if dbPath == "" {
		return nil
	}
	p := filepath.Join(filepath.Dir(dbPath), ActivityFilename)
	now := time.Now()
	if err := os.Chtimes(p, now, now); err == nil {
		return nil
	}
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE, 0o600)
	if err != nil {
		return fmt.Errorf("budgetwarnfile.TouchActivity: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("budgetwarnfile.TouchActivity: %w", err)
	}
	return nil
}

// ActivityFilename is the node-activity marker the hooks touch and the
// daemon stats (2026-10-02 budget-latency arc, policy freshness).
const ActivityFilename = "activity.stamp"

// ActivityPath returns the activity marker path beside dbPath.
func ActivityPath(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), ActivityFilename)
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, ".budgetwarn-*.tmp")
	if err != nil {
		return fmt.Errorf("budgetwarnfile.writeAtomic: %w", err)
	}
	name := tmp.Name()
	cleanup := func() { _ = os.Remove(name) }
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("budgetwarnfile.writeAtomic: %w", err)
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("budgetwarnfile.writeAtomic: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("budgetwarnfile.writeAtomic: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		cleanup()
		return fmt.Errorf("budgetwarnfile.writeAtomic: %w", err)
	}
	return nil
}

type limitedReader struct {
	r interface{ Read([]byte) (int, error) }
	n int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("budgetwarnfile: status file too large")
	}
	if int64(len(p)) > l.n {
		p = p[:l.n]
	}
	n, err := l.r.Read(p)
	l.n -= int64(n)
	return n, err
}
