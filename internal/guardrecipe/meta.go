package guardrecipe

import (
	"bufio"
	"bytes"
	"encoding/json"
	"strings"
)

// MetaFormat is the header format version this binary writes.
const MetaFormat = 1

// metaPrefix starts the one machine-readable header line of an applied
// recipe file.
const metaPrefix = "# observer-guard-recipe: "

// metaScanLines bounds how far into a file the header is looked for.
const metaScanLines = 16

// Scope is where an applied recipe lives.
type Scope string

// Scopes.
const (
	// ScopeGlobal folds the recipe into the user policy layer and writes
	// the level's mode machine-wide.
	ScopeGlobal Scope = "global"
	// ScopeProject folds the recipe into one project's trusted layer.
	ScopeProject Scope = "project"
)

// ValidScope reports whether s names a scope.
func ValidScope(s Scope) bool { return s == ScopeGlobal || s == ScopeProject }

// Ref names one applied recipe and the revision that was applied.
type Ref struct {
	Name    string `json:"name"`
	Version int    `json:"version"`
}

// Previous records what a global apply replaced, so remove can put it back.
type Previous struct {
	// Level, Mode and PromptMode are [guard] level, [guard] mode and
	// [guard.prompt] mode as they were before the apply.
	Level      string `json:"level"`
	Mode       string `json:"mode"`
	PromptMode string `json:"prompt_mode"`
}

// Meta is the header of an applied recipe file.
type Meta struct {
	Format      int    `json:"format"`
	Scope       Scope  `json:"scope"`
	ProjectRoot string `json:"project_root,omitempty"`
	// Level is the applied level (nil when the selection had none).
	Level *Ref `json:"level,omitempty"`
	// Packs are the applied packs in apply order.
	Packs []Ref `json:"packs,omitempty"`
	// Mode and PromptMode are what the level set at global scope ("" when
	// the apply set none).
	Mode       string `json:"mode,omitempty"`
	PromptMode string `json:"prompt_mode,omitempty"`
	// AppliedAt is the RFC 3339 UTC time of the apply.
	AppliedAt string `json:"applied_at,omitempty"`
	// AppliedVia is the surface that applied it ("cli" or "dashboard").
	AppliedVia string `json:"applied_via,omitempty"`
	// Previous is what a global apply replaced (nil at project scope).
	Previous *Previous `json:"previous,omitempty"`
}

// LevelName returns the applied level's name, "" when none.
func (m Meta) LevelName() string {
	if m.Level == nil {
		return ""
	}
	return m.Level.Name
}

// PackNames returns the applied packs' names in order.
func (m Meta) PackNames() []string {
	out := make([]string, 0, len(m.Packs))
	for _, p := range m.Packs {
		out = append(out, p.Name)
	}
	return out
}

// headerLine renders the header line for m.
func (m Meta) headerLine() string {
	m.Format = MetaFormat
	b, err := json.Marshal(m)
	if err != nil {
		// Meta holds only strings, ints and slices of them; Marshal cannot
		// fail. Keep a parseable line regardless.
		b = []byte(`{"format":1}`)
	}
	return metaPrefix + string(b)
}

// ParseMeta reads the header of an applied recipe file. ok is false when the
// file carries no header this binary can read (a hand-written file in the
// recipe slot, or a newer format).
func ParseMeta(raw []byte) (Meta, bool) {
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	for i := 0; i < metaScanLines && sc.Scan(); i++ {
		line := strings.TrimRight(sc.Text(), "\r")
		rest, ok := strings.CutPrefix(line, metaPrefix)
		if !ok {
			continue
		}
		var m Meta
		if err := json.Unmarshal([]byte(rest), &m); err != nil || m.Format < 1 || m.Format > MetaFormat || !ValidScope(m.Scope) {
			return Meta{}, false
		}
		return m, true
	}
	return Meta{}, false
}
