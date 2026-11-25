package shell

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

// FilterSpec is a TOML-loaded per-command filter chain.
type FilterSpec struct {
	// Command matches the basename of argv[0]; "git" matches "/usr/bin/git".
	Command string `toml:"command"`
	// Subcommands optionally narrows the match to specific argv[1] values.
	// An empty list matches any subcommand.
	Subcommands []string `toml:"subcommands"`
	// Description is surfaced by diagnostics tooling.
	Description string `toml:"description"`
	// Rules are applied in order as a chain.
	Rules []RuleSpec `toml:"rule"`
}

// RuleSpec is a single step in a filter chain. Field semantics depend on Type.
type RuleSpec struct {
	// Type selects the rule implementation. One of: line_drop, line_keep,
	// dedup_consecutive, truncate, squash_whitespace, hook.
	Type string `toml:"type"`

	// Pattern is the regex for line_drop / line_keep.
	Pattern string `toml:"pattern"`

	// Head and Tail are line counts kept by truncate.
	Head int `toml:"head"`
	Tail int `toml:"tail"`

	// Marker is the printf template truncate uses to replace the elided
	// middle; must contain exactly one %d for the dropped-line count.
	Marker string `toml:"marker"`

	// Hook names a previously-registered Go rule factory when Type is "hook".
	Hook string `toml:"hook"`

	// Format selects the structured parser when Type is "format_parse".
	// Currently supported: "cargo_test_json".
	Format string `toml:"format"`

	// FailureOnly, when true on a format_parse rule, suppresses passing-
	// test detail in the summary — only failures and their context are
	// emitted. The aggregate counts (`<N> passed, <M> failed`) are still
	// reported so the model knows the test run's overall shape.
	FailureOnly bool `toml:"failure_only"`

	// Comment is informational and ignored at runtime.
	Comment string `toml:"comment"`
}

// HookFactory produces a fresh Rule per stream, letting hooks hold per-invocation
// state without sharing it across concurrent streams.
type HookFactory func() Rule

// Engine dispatches shell output through per-command filter chains.
//
// The zero value is unusable — call NewEngine.
type Engine struct {
	specs []FilterSpec
	hooks map[string]HookFactory
}

// NewEngine returns an empty engine.
func NewEngine() *Engine {
	return &Engine{hooks: make(map[string]HookFactory)}
}

// RegisterHook installs a named hook referenced by RuleSpec{Type:"hook", Hook:name}.
// Replaces any prior registration with the same name.
//
// It is an extension point only: no production code registers a hook and
// no embedded default filter uses type = "hook", so today a filter that
// names one fails to compile with "hook ... not registered". Only the
// engine tests call it.
func (e *Engine) RegisterHook(name string, factory HookFactory) {
	e.hooks[name] = factory
}

// AddSpec appends or replaces a filter spec. Specs with the same
// (command, subcommands) key replace earlier entries — user TOML overrides
// embedded defaults this way.
func (e *Engine) AddSpec(spec FilterSpec) {
	for i, existing := range e.specs {
		if existing.Command == spec.Command && sameStrings(existing.Subcommands, spec.Subcommands) {
			e.specs[i] = spec
			return
		}
	}
	e.specs = append(e.specs, spec)
}

// Specs returns a snapshot of the registered filter specs in registration order.
func (e *Engine) Specs() []FilterSpec {
	out := make([]FilterSpec, len(e.specs))
	copy(out, e.specs)
	return out
}

// Lookup returns the filter spec matching argv, or nil when none applies.
// Preference is exact (command, subcommand) over (command, any). argv[0] is
// matched by its filepath.Base so "/usr/bin/git" and "git" resolve identically.
func (e *Engine) Lookup(argv []string) *FilterSpec {
	if len(argv) == 0 {
		return nil
	}
	cmd := filepath.Base(argv[0])
	sub := ""
	if len(argv) > 1 {
		sub = argv[1]
	}
	var generic *FilterSpec
	for i := range e.specs {
		s := &e.specs[i]
		if s.Command != cmd {
			continue
		}
		if len(s.Subcommands) == 0 {
			if generic == nil {
				generic = s
			}
			continue
		}
		for _, sc := range s.Subcommands {
			if sc == sub {
				return s
			}
		}
	}
	return generic
}

// Filter returns a Stream that wraps w and transforms lines from a command
// matching argv. When no spec matches, the returned stream is a line-buffered
// pass-through; callers can check Stream.Spec() == nil to detect that case.
//
// Callers MUST call Stream.Close to flush any buffered state.
func (e *Engine) Filter(argv []string, w io.Writer) (*Stream, error) {
	spec := e.Lookup(argv)
	s := newStream(w, spec)
	if spec == nil {
		return s, nil
	}
	for idx, rs := range spec.Rules {
		r, err := e.buildRule(rs)
		if err != nil {
			return nil, fmt.Errorf("shell.Engine.Filter: rule[%d] (%s): %w", idx, rs.Type, err)
		}
		s.rules = append(s.rules, r)
	}
	return s, nil
}

// LoadFS parses every *.toml file in fsys (non-recursive) as filter specs.
// Files may contain either a top-level single-spec shape (command + [[rule]])
// or multi-spec shape (repeated [[filter]] tables).
func (e *Engine) LoadFS(fsys fs.FS) error {
	return loadFSRecursive(e, fsys, ".")
}

// LoadDir loads every *.toml file from a filesystem directory. A missing
// directory returns nil (no-op) rather than an error, so user-override dirs
// are optional.
func (e *Engine) LoadDir(dir string) error {
	entries, err := filepath.Glob(filepath.Join(dir, "*.toml"))
	if err != nil {
		return fmt.Errorf("shell.Engine.LoadDir: glob: %w", err)
	}
	if len(entries) == 0 {
		if _, statErr := os.Stat(dir); os.IsNotExist(statErr) {
			return nil
		}
	}
	for _, path := range entries {
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("shell.Engine.LoadDir: read %s: %w", path, err)
		}
		if err := e.parseSpecBytes(path, data); err != nil {
			return err
		}
	}
	return nil
}

func loadFSRecursive(e *Engine, fsys fs.FS, dir string) error {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return fmt.Errorf("shell.Engine.LoadFS: readdir %s: %w", dir, err)
	}
	for _, entry := range entries {
		name := entry.Name()
		path := name
		if dir != "." {
			path = dir + "/" + name
		}
		if entry.IsDir() {
			if err := loadFSRecursive(e, fsys, path); err != nil {
				return err
			}
			continue
		}
		if filepath.Ext(name) != ".toml" {
			continue
		}
		data, err := fs.ReadFile(fsys, path)
		if err != nil {
			return fmt.Errorf("shell.Engine.LoadFS: read %s: %w", path, err)
		}
		if err := e.parseSpecBytes(path, data); err != nil {
			return err
		}
	}
	return nil
}

// specFile carries both single-spec and multi-spec TOML shapes so either
// layout parses cleanly.
type specFile struct {
	Command     string       `toml:"command"`
	Subcommands []string     `toml:"subcommands"`
	Description string       `toml:"description"`
	Rules       []RuleSpec   `toml:"rule"`
	Filter      []FilterSpec `toml:"filter"`
}

func (e *Engine) parseSpecBytes(src string, data []byte) error {
	var doc specFile
	if _, err := toml.Decode(string(data), &doc); err != nil {
		return fmt.Errorf("shell.Engine: parse %s: %w", src, err)
	}
	if doc.Command != "" {
		spec := FilterSpec{
			Command:     doc.Command,
			Subcommands: doc.Subcommands,
			Description: doc.Description,
			Rules:       doc.Rules,
		}
		if err := validateSpec(spec); err != nil {
			return fmt.Errorf("shell.Engine: %s: %w", src, err)
		}
		e.AddSpec(spec)
	}
	for _, s := range doc.Filter {
		if err := validateSpec(s); err != nil {
			return fmt.Errorf("shell.Engine: %s: %w", src, err)
		}
		e.AddSpec(s)
	}
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ErrNoFilter is returned by callers that need to distinguish "no spec matched"
// from other Filter errors. Engine.Filter itself returns a pass-through stream
// in that case rather than this sentinel; it's exported for diagnostics code.
var ErrNoFilter = errors.New("no filter matched")
