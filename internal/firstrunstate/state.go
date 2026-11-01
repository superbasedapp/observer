package firstrunstate

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// Filename is the state file's name beside the node database.
const Filename = "firstrun-state.json"

// Schema is the file's schema version.
const Schema = 1

const maxBytes = 64 << 10

// Install is what the install looked like when it was first recorded.
type Install string

// The install kinds.
const (
	// InstallUnknown: nothing recorded yet.
	InstallUnknown Install = ""
	// InstallFresh: the database held no sessions at the first record.
	InstallFresh Install = "fresh"
	// InstallExisting: the database already held sessions (an upgrade).
	InstallExisting Install = "existing"
)

// State is the persisted first-run state.
type State struct {
	Schema     int        `json:"schema"`
	Install    Install    `json:"install,omitempty"`
	RecordedAt *time.Time `json:"recorded_at,omitempty"`
	// SeenAt is when the owner closed the view for good; nil while unseen.
	SeenAt *time.Time `json:"seen_at,omitempty"`
	// Dismissed records, per dashboard notice key, when the owner dismissed
	// it for good (WINNODE2 16b: the product tour, the "Review components"
	// card). Kept on the daemon so a dismissal holds when the browser's
	// own storage does not (a profile whose storage is not persisted, a
	// second browser). The dashboard owns the closed set of keys.
	Dismissed map[string]time.Time `json:"dismissed,omitempty"`
}

// DismissedKeys returns the dismissed notice keys, sorted.
func (s State) DismissedKeys() []string {
	out := make([]string, 0, len(s.Dismissed))
	for k := range s.Dismissed {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Seen reports whether the owner has closed the view for good.
func (s State) Seen() bool { return s.SeenAt != nil }

// AutoOpen reports whether the dashboard should open the first-run view by
// itself: only on a fresh install that has not been marked seen.
func AutoOpen(s State) bool { return s.Install == InstallFresh && !s.Seen() }

// Path returns the state file beside dbPath ("" when dbPath is empty).
func Path(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), Filename)
}

// Store serializes this process's reads and writes of one state file.
type Store struct {
	path string
	mu   sync.Mutex
}

// New returns the store for path. An empty path keeps nothing: Load returns
// the zero State and every write is a no-op, which is what a dashboard with
// no database path (tests, demo) wants.
func New(path string) *Store { return &Store{path: path} }

// Load returns the persisted state. A missing, oversized or unreadable file
// is "nothing recorded yet", never an error.
func (s *Store) Load() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}

// RecordInstall records the install kind once. fresh reports whether the
// database held no sessions; it is only consulted when nothing is recorded
// yet, so a later start never turns an existing install fresh or back.
func (s *Store) RecordInstall(fresh bool, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if st.Install != InstallUnknown || s.path == "" {
		return st, nil
	}
	st.Install = InstallExisting
	if fresh {
		st.Install = InstallFresh
	}
	at := now.UTC()
	st.RecordedAt = &at
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.RecordInstall: %w", err)
	}
	return st, nil
}

// SetSeen marks the view seen (true) or clears the mark (false).
func (s *Store) SetSeen(seen bool, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" {
		return st, nil
	}
	if seen {
		at := now.UTC()
		st.SeenAt = &at
	} else {
		st.SeenAt = nil
	}
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.SetSeen: %w", err)
	}
	return st, nil
}

// Dismiss records key as dismissed for good. Dismissing a key twice keeps
// the first time.
func (s *Store) Dismiss(key string, now time.Time) (State, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.read()
	if s.path == "" || key == "" {
		return st, nil
	}
	if _, ok := st.Dismissed[key]; ok {
		return st, nil
	}
	if st.Dismissed == nil {
		st.Dismissed = map[string]time.Time{}
	}
	st.Dismissed[key] = now.UTC()
	if err := s.write(st); err != nil {
		return st, fmt.Errorf("firstrunstate.Dismiss: %w", err)
	}
	return st, nil
}

func (s *Store) read() State {
	out := State{Schema: Schema}
	if s.path == "" {
		return out
	}
	fh, err := os.Open(s.path)
	if err != nil {
		return out
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return out
	}
	var st State
	if json.Unmarshal(data, &st) != nil || st.Schema != Schema {
		return out
	}
	switch st.Install {
	case InstallUnknown, InstallFresh, InstallExisting:
	default:
		st.Install = InstallUnknown
	}
	return st
}

func (s *Store) write(st State) error {
	st.Schema = Schema
	data, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(s.path, data, fsatomic.Options{TempPattern: ".firstrun-*.tmp"})
}
