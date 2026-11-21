package secinventory

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// Snapshot format and caps.
const (
	// Version is the snapshot format version; another version reads as
	// absent.
	Version = 1
	// MaxPackages caps the packages one snapshot keeps (Truncated beyond).
	MaxPackages = 50_000
	// maxFileBytes caps the file Load reads.
	maxFileBytes = 64 << 20
	// StaleAfter is how old a stored snapshot from a stronger driver must
	// be before a weaker driver's replaces it.
	StaleAfter = 7 * 24 * time.Hour
)

// Driver strengths, the precedence table: a higher strength's inventory is
// replaced only by one of at least its strength, or once it is stale.
var driverStrength = map[string]int{
	"scalibr": 2, // the linked SCALIBR driver: dependency files, artifacts, workflows
	"osv":     1, // osv-scanner: dependency files only
}

// Package is one inventory row.
type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	// Path is the dependency file, project-relative, forward slashes.
	Path      string `json:"path,omitempty"`
	Extractor string `json:"extractor,omitempty"`
}

// Snapshot is one project's stored inventory.
type Snapshot struct {
	Version   int       `json:"version"`
	Driver    string    `json:"driver"`
	ScanTime  time.Time `json:"scan_time"`
	Truncated bool      `json:"truncated,omitempty"`
	Packages  []Package `json:"packages"`
}

// Supersedes reports whether incoming replaces stored (nil: none stored),
// walked as an ordered table: nothing stored; incoming at least as strong;
// stored stale; else keep.
func Supersedes(stored *Snapshot, incoming Snapshot, now time.Time) bool {
	switch {
	case stored == nil:
		return true
	case driverStrength[incoming.Driver] >= driverStrength[stored.Driver]:
		return true
	case now.Sub(stored.ScanTime) > StaleAfter:
		return true
	}
	return false
}

// Path returns the snapshot file of a project.
func Path(securityDir, rootHash string) string {
	return filepath.Join(securityDir, "inventory", rootHash+".json")
}

// Load reads a project's snapshot; ok is false when there is none or it
// cannot be read as this format.
func Load(securityDir, rootHash string) (Snapshot, bool) {
	if rootHash == "" {
		return Snapshot{}, false
	}
	p := Path(securityDir, rootHash)
	info, err := os.Stat(p)
	if err != nil || !info.Mode().IsRegular() || info.Size() > maxFileBytes {
		return Snapshot{}, false
	}
	b, err := os.ReadFile(p) //nolint:gosec // G304: our own snapshot under the security directory.
	if err != nil {
		return Snapshot{}, false
	}
	var s Snapshot
	if json.Unmarshal(b, &s) != nil || s.Version != Version {
		return Snapshot{}, false
	}
	return s, true
}

// Replace stores incoming as the project's snapshot when Supersedes says
// so, and reports whether it did. Packages are sorted and deduplicated and
// capped at MaxPackages.
func Replace(securityDir, rootHash string, incoming Snapshot, now time.Time) (bool, error) {
	if rootHash == "" || securityDir == "" {
		return false, errors.New("secinventory.Replace: no project or directory")
	}
	if stored, ok := Load(securityDir, rootHash); ok && !Supersedes(&stored, incoming, now) {
		return false, nil
	}
	incoming.Version = Version
	incoming.Packages = normalize(incoming.Packages)
	if len(incoming.Packages) > MaxPackages {
		incoming.Packages, incoming.Truncated = incoming.Packages[:MaxPackages], true
	}
	if incoming.Packages == nil {
		incoming.Packages = []Package{}
	}
	b, err := json.Marshal(incoming)
	if err != nil {
		return false, fmt.Errorf("secinventory.Replace: %w", err)
	}
	p := Path(securityDir, rootHash)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return false, fmt.Errorf("secinventory.Replace: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(p), ".inventory-*.json")
	if err != nil {
		return false, fmt.Errorf("secinventory.Replace: %w", err)
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return false, fmt.Errorf("secinventory.Replace: %w", err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmp.Name())
		return false, fmt.Errorf("secinventory.Replace: %w", err)
	}
	if err := os.Rename(tmp.Name(), p); err != nil {
		_ = os.Remove(tmp.Name())
		return false, fmt.Errorf("secinventory.Replace: %w", err)
	}
	return true, nil
}

// Remove deletes a project's snapshot (absent is not an error).
func Remove(securityDir, rootHash string) error {
	if err := os.Remove(Path(securityDir, rootHash)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("secinventory.Remove: %w", err)
	}
	return nil
}

// normalize sorts rows and drops exact duplicates and nameless rows.
func normalize(in []Package) []Package {
	out := make([]Package, 0, len(in))
	for _, p := range in {
		if p.Name != "" && p.Ecosystem != "" {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Ecosystem != b.Ecosystem {
			return a.Ecosystem < b.Ecosystem
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Version != b.Version {
			return a.Version < b.Version
		}
		return a.Path < b.Path
	})
	k := 0
	for i, p := range out {
		if i > 0 && p == out[k-1] {
			continue
		}
		out[k] = p
		k++
	}
	return out[:k]
}
