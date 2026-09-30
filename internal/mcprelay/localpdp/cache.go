package localpdp

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// CacheFileName is the compiled node table's file name, written BESIDE the
// guard org-bundle cache ([guard.rules].org_bundle, default ~/.observer/):
// the same directory the guard's org layer and the policy-resource tree
// already live in, so one directory holds every org-delivered policy
// artefact on the node.
const CacheFileName = "mcp-node-table.json"

// SiblingPath returns the table cache path beside orgBundlePath (the
// resolved [guard.rules].org_bundle); with an empty orgBundlePath it falls
// back beside dbPath, mirroring cmd/observer's policyResourceCacheDir.
func SiblingPath(orgBundlePath, dbPath string) string {
	if orgBundlePath != "" {
		return filepath.Join(filepath.Dir(orgBundlePath), CacheFileName)
	}
	return filepath.Join(filepath.Dir(dbPath), CacheFileName)
}

// cacheFile is the on-disk shape. It is a DERIVED hot-start artefact: the
// verified envelope in the policy-resource tree stays the source of truth,
// and a loader that finds a BodyHash differing from the currently verified
// resource must recompile rather than trust the file.
type cacheFile struct {
	Format  int       `json:"format"`
	SavedAt time.Time `json:"saved_at"`
	Table   Table     `json:"table"`
}

const cacheFormat = 1

// ErrCacheAbsent reports no cache file.
var ErrCacheAbsent = errors.New("localpdp: no cached table")

// Cache is the ONE owner of the sibling file.
type Cache struct {
	Path string
}

// Save atomically writes t to the cache path (0600, fsync).
func (c Cache) Save(t *Table) error {
	if t == nil {
		return errors.New("localpdp.Cache.Save: nil table")
	}
	raw, err := json.Marshal(cacheFile{Format: cacheFormat, SavedAt: time.Now().UTC(), Table: *t})
	if err != nil {
		return fmt.Errorf("localpdp.Cache.Save: marshal: %w", err)
	}
	if err := fsatomic.WriteFile(c.Path, raw, fsatomic.Options{TempPattern: ".mcp-node-table-*.tmp", Fsync: true}); err != nil {
		return fmt.Errorf("localpdp.Cache.Save: %w", err)
	}
	return nil
}

// Load reads the cache. ErrCacheAbsent when the file does not exist; a
// corrupt or foreign-format file is an error (the caller recompiles from
// the verified envelope - never a fabricated table).
func (c Cache) Load() (*Table, error) {
	raw, err := os.ReadFile(c.Path)
	if os.IsNotExist(err) {
		return nil, ErrCacheAbsent
	}
	if err != nil {
		return nil, fmt.Errorf("localpdp.Cache.Load: %w", err)
	}
	var f cacheFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("localpdp.Cache.Load: corrupt cache: %w", err)
	}
	if f.Format != cacheFormat {
		return nil, fmt.Errorf("localpdp.Cache.Load: cache format %d, want %d", f.Format, cacheFormat)
	}
	if f.Table.Mode != ModeObserve && f.Table.Mode != ModeEnforce {
		return nil, fmt.Errorf("localpdp.Cache.Load: cache mode %q is not observe/enforce", f.Table.Mode)
	}
	t := newTable(f.Table.Node, f.Table.Mode, f.Table.Meta)
	t.AuditStrict = f.Table.AuditStrict
	return t, nil
}

// Remove deletes the cache file (idempotent).
func (c Cache) Remove() error {
	if err := os.Remove(c.Path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("localpdp.Cache.Remove: %w", err)
	}
	return nil
}
