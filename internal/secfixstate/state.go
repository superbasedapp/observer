package secfixstate

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// Filename is the state file's name beside the node database.
const Filename = "secfix-attempts.json"

// Schema is the file's schema version.
const Schema = 1

// Bounds.
const (
	// MaxAttempts is how many attempts the file keeps (oldest dropped).
	MaxAttempts = 200
	// MaxFindingIDs is how many finding ids one attempt keeps.
	MaxFindingIDs = 100
	maxBytes      = 2 << 20
	maxField      = 256
)

// Attempt is one "Fix with an agent" launch.
type Attempt struct {
	ID              string    `json:"id"`
	CreatedAt       time.Time `json:"created_at"`
	Tool            string    `json:"tool"`
	ProjectRootHash string    `json:"project_root_hash"`
	ProjectName     string    `json:"project_name,omitempty"`
	// Handle is the dashboard terminal's handle.
	Handle string `json:"handle,omitempty"`
	// Seeded says the task was passed on the agent's argv (false: the
	// developer was shown it to paste).
	Seeded     bool     `json:"seeded"`
	FindingIDs []string `json:"finding_ids"`
}

type file struct {
	Schema   int       `json:"schema"`
	Attempts []Attempt `json:"attempts"`
}

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

// New returns the store for path. An empty path keeps nothing: Recent is
// empty and Record only returns the attempt (tests, demo).
func New(path string) *Store { return &Store{path: path} }

// Record appends a, minting its id when empty, stamping CreatedAt from now
// when zero, and capping its fields; the file keeps the newest MaxAttempts.
func (s *Store) Record(a Attempt, now time.Time) (Attempt, error) {
	if a.ID == "" {
		a.ID = newID()
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.CreatedAt = a.CreatedAt.UTC()
	a = capAttempt(a)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.path == "" {
		return a, nil
	}
	f := s.read()
	f.Attempts = append(f.Attempts, a)
	if n := len(f.Attempts) - MaxAttempts; n > 0 {
		f.Attempts = append([]Attempt(nil), f.Attempts[n:]...)
	}
	if err := s.write(f); err != nil {
		return a, fmt.Errorf("secfixstate.Record: %w", err)
	}
	return a, nil
}

// Recent returns at most n attempts, newest first. A missing, oversized or
// unreadable file holds none.
func (s *Store) Recent(n int) []Attempt {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := s.read().Attempts
	out := make([]Attempt, 0, min(n, len(all)))
	for i := len(all) - 1; i >= 0 && len(out) < n; i-- {
		out = append(out, all[i])
	}
	return out
}

func capAttempt(a Attempt) Attempt {
	for _, p := range []*string{&a.ID, &a.Tool, &a.ProjectRootHash, &a.ProjectName, &a.Handle} {
		if len(*p) > maxField {
			*p = (*p)[:maxField]
		}
	}
	ids := make([]string, 0, min(len(a.FindingIDs), MaxFindingIDs))
	for _, id := range a.FindingIDs {
		if id == "" || len(id) > maxField {
			continue
		}
		if len(ids) == MaxFindingIDs {
			break
		}
		ids = append(ids, id)
	}
	a.FindingIDs = ids
	return a
}

func (s *Store) read() file {
	out := file{Schema: Schema}
	fh, err := os.Open(s.path)
	if err != nil {
		return out
	}
	defer func() { _ = fh.Close() }()
	data, err := io.ReadAll(io.LimitReader(fh, maxBytes+1))
	if err != nil || len(data) > maxBytes {
		return out
	}
	var f file
	if json.Unmarshal(data, &f) != nil || f.Schema != Schema {
		return out
	}
	return f
}

func (s *Store) write(f file) error {
	f.Schema = Schema
	data, err := json.Marshal(f)
	if err != nil {
		return err
	}
	return fsatomic.WriteFile(s.path, data, fsatomic.Options{TempPattern: ".secfix-*.tmp"})
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
