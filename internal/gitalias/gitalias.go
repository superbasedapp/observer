package gitalias

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/fsatomic"
)

// Filename is the table's basename, placed beside the database.
const Filename = "guard-git-aliases.json"

// Schema is the table file's schema version.
const Schema = 1

// Bounds on what one table carries, so a pathological repository cannot
// grow the file the hook reads on its reply path.
const (
	// MaxProjects caps the projects in one table.
	MaxProjects = 512
	// MaxAliases caps the aliases kept per project.
	MaxAliases = 256
	// MaxValueBytes caps one alias expansion.
	MaxValueBytes = 1024
	// maxFileBytes bounds a table read.
	maxFileBytes = 4 << 20
)

// Project is the alias set in force in one project root.
type Project struct {
	// Root is the project root, in the daemon's path flavor.
	Root string `json:"root"`
	// Aliases maps an alias name, lowercased, to its expansion.
	Aliases map[string]string `json:"aliases,omitempty"`
}

// Table is guard-git-aliases.json.
type Table struct {
	Schema    int       `json:"schema"`
	WrittenAt time.Time `json:"written_at"`
	Projects  []Project `json:"projects"`
}

// Path returns the table file beside the database path ("" when dbPath is
// empty).
func Path(dbPath string) string {
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), Filename)
}

// ParseConfigList reads the output of `git config -z --get-regexp
// '^alias\.'`: NUL-terminated records, each the key, a newline, then the
// value. Keys are lowercased with their "alias." prefix removed; a later
// definition of the same alias wins, as it does in git. Records past
// MaxAliases and values past MaxValueBytes are dropped.
func ParseConfigList(out []byte) map[string]string {
	aliases := map[string]string{}
	for _, rec := range bytes.Split(out, []byte{0}) {
		if len(rec) == 0 {
			continue
		}
		key, value, _ := strings.Cut(string(rec), "\n")
		name, ok := strings.CutPrefix(strings.ToLower(key), "alias.")
		if !ok || name == "" || len(value) > MaxValueBytes {
			continue
		}
		if _, seen := aliases[name]; !seen && len(aliases) >= MaxAliases {
			continue
		}
		aliases[name] = value
	}
	return aliases
}

// Encode renders a table in its canonical form (projects sorted by root),
// so an unchanged table encodes to the same bytes.
func Encode(t Table) ([]byte, error) {
	t.Schema = Schema
	sort.Slice(t.Projects, func(i, j int) bool { return t.Projects[i].Root < t.Projects[j].Root })
	if len(t.Projects) > MaxProjects {
		t.Projects = t.Projects[:MaxProjects]
	}
	b, err := json.Marshal(t)
	if err != nil {
		return nil, fmt.Errorf("gitalias.Encode: %w", err)
	}
	return b, nil
}

// Write writes the table atomically.
func Write(path string, t Table) error {
	if path == "" {
		return errors.New("gitalias.Write: empty path")
	}
	b, err := Encode(t)
	if err != nil {
		return err
	}
	if err := fsatomic.WriteFile(path, b, fsatomic.Options{TempPattern: ".guard-git-aliases-*.tmp"}); err != nil {
		return fmt.Errorf("gitalias.Write: %w", err)
	}
	return nil
}

// Load reads the table. A missing file is (nil, nil); an over-size, unreadable
// or malformed one, or one of another schema, is an error.
func Load(path string) (*Table, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("gitalias.Load: %w", err)
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("gitalias.Load: %w", err)
	}
	if len(b) > maxFileBytes {
		return nil, errors.New("gitalias.Load: table over size")
	}
	var t Table
	if err := json.Unmarshal(b, &t); err != nil {
		return nil, fmt.Errorf("gitalias.Load: %w", err)
	}
	if t.Schema != Schema {
		return nil, fmt.Errorf("gitalias.Load: schema %d, want %d", t.Schema, Schema)
	}
	return &t, nil
}

// Lookup returns the aliases of the project whose root holds dir (the
// deepest such root), and whether any project does. Paths compare with
// either separator, and without case when either side is a Windows path.
func (t *Table) Lookup(dir string) (map[string]string, bool) {
	if t == nil || dir == "" {
		return nil, false
	}
	d := norm(dir)
	best, bestLen := -1, -1
	for i, p := range t.Projects {
		r := norm(p.Root)
		if r == "" || !under(d, r) || len(r) <= bestLen {
			continue
		}
		best, bestLen = i, len(r)
	}
	if best < 0 {
		return nil, false
	}
	return t.Projects[best].Aliases, true
}

// norm turns a path into forward slashes without a trailing separator.
func norm(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if len(p) > 1 {
		p = strings.TrimRight(p, "/")
	}
	return p
}

// windowsShaped reports a drive-letter path.
func windowsShaped(p string) bool {
	return len(p) >= 2 && p[1] == ':'
}

// under reports whether d is r or lies beneath it.
func under(d, r string) bool {
	if windowsShaped(d) || windowsShaped(r) {
		d, r = strings.ToLower(d), strings.ToLower(r)
	}
	if d == r {
		return true
	}
	if r == "/" {
		return strings.HasPrefix(d, "/")
	}
	return strings.HasPrefix(d, r+"/")
}
