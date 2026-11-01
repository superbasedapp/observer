package shipped

import (
	"bytes"
	"crypto/sha1" //nolint:gosec // git's blob id is SHA-1 by definition; this is an identity, not a security hash.
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// SchemaVersion is the record format version. Bump it only with a reader that
// still accepts the old one.
const SchemaVersion = 1

// RecordPath is the committed record, relative to the repository root. It is
// the one owner of "what shipped".
const RecordPath = "tests/invariant/testdata/shipped-migrations.json"

// RuleDoc names the document that explains the rule, for failure messages.
const RuleDoc = `docs/migration-numbering.md, "The released-step rule"`

// LineageDef is one numbered migration lineage: a stable name and the
// directory (relative to the repository root) whose NNN_*.sql files are its
// steps.
type LineageDef struct {
	Name string
	Dir  string
}

// lineages is every lineage the rule covers, sorted by name. A new lineage is
// one row here plus one generator run.
var lineages = []LineageDef{
	{Name: "archive", Dir: "internal/archivestore/migrations"},
	{Name: "cloud", Dir: "internal/cloudserver/db/migrations"},
	{Name: "edge-wal", Dir: "internal/edge/wal/migrations"},
	{Name: "node", Dir: "internal/db/migrations"},
	{Name: "org-pg", Dir: "internal/orgserver/db/pgmigrations"},
	{Name: "org-sqlite", Dir: "internal/orgserver/db/migrations"},
}

// Lineages returns a copy of every lineage the rule covers, sorted by name.
func Lineages() []LineageDef {
	out := make([]LineageDef, len(lineages))
	copy(out, lineages)
	return out
}

// LookupLineage returns the lineage named name.
func LookupLineage(name string) (LineageDef, bool) {
	for _, l := range lineages {
		if l.Name == name {
			return l, true
		}
	}
	return LineageDef{}, false
}

// Record is the committed record of shipped migration steps.
type Record struct {
	Schema   int       `json:"schema"`
	Lineages []Lineage `json:"lineages"`
}

// Lineage is what shipped in one lineage: the head (highest shipped step
// number), the ref the head was taken from (a release tag, or the build sha
// deployed to a hosted production service) with its resolved commit, and
// every shipped step file with its git blob id.
type Lineage struct {
	Name   string `json:"name"`
	Dir    string `json:"dir"`
	Head   int    `json:"head"`
	Ref    string `json:"ref"`
	Commit string `json:"commit"`
	Steps  []Step `json:"steps"`
}

// Step is one migration step file: its base name and its git blob id.
type Step struct {
	File string `json:"file"`
	Blob string `json:"blob"`
}

// StepNumber returns the step number of a migration file name of the form
// NNN_name.sql. ok is false for any other file (Go sources, subdirectories).
func StepNumber(file string) (n int, ok bool) {
	if !strings.HasSuffix(file, ".sql") || strings.ContainsAny(file, `/\`) {
		return 0, false
	}
	prefix, rest, found := strings.Cut(file, "_")
	if !found || prefix == "" || rest == ".sql" {
		return 0, false
	}
	for _, r := range prefix {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	n, err := strconv.Atoi(prefix)
	if err != nil {
		return 0, false
	}
	return n, true
}

// BlobID returns the git blob id of content (what `git hash-object` prints),
// so a working-tree file compares directly with `git ls-tree` output.
func BlobID(content []byte) string {
	h := sha1.New() //nolint:gosec // see the import comment.
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write(content)
	return hex.EncodeToString(h.Sum(nil))
}

// Parse decodes and validates a record. Unknown fields are refused so a typo
// cannot silently drop a lineage's protection.
func Parse(data []byte) (Record, error) {
	var r Record
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&r); err != nil {
		return Record{}, fmt.Errorf("shipped.Parse: %w", err)
	}
	if dec.More() {
		return Record{}, errors.New("shipped.Parse: trailing data after the record")
	}
	if err := r.Validate(); err != nil {
		return Record{}, err
	}
	return r, nil
}

// Validate reports every way the record is malformed: a wrong schema, a
// lineage missing, duplicated, unknown or pointing at the wrong directory, a
// head that is not the highest step, an empty ref or commit, and a step with
// a bad name, a bad blob id or a number used twice.
func (r Record) Validate() error {
	var errs []error
	if r.Schema != SchemaVersion {
		errs = append(errs, fmt.Errorf("schema is %d, want %d", r.Schema, SchemaVersion))
	}
	seen := map[string]bool{}
	for _, l := range r.Lineages {
		if seen[l.Name] {
			errs = append(errs, fmt.Errorf("lineage %q appears twice", l.Name))
			continue
		}
		seen[l.Name] = true
		if err := l.Validate(); err != nil {
			errs = append(errs, err)
		}
	}
	for _, def := range lineages {
		if !seen[def.Name] {
			errs = append(errs, fmt.Errorf("lineage %q is missing", def.Name))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("shipped: malformed record: %w", errors.Join(errs...))
	}
	return nil
}

// Validate reports every way one lineage entry is malformed.
func (l Lineage) Validate() error {
	var errs []error
	def, ok := LookupLineage(l.Name)
	switch {
	case !ok:
		errs = append(errs, fmt.Errorf("lineage %q is not a known lineage", l.Name))
	case l.Dir != def.Dir:
		errs = append(errs, fmt.Errorf("lineage %q: dir is %q, want %q", l.Name, l.Dir, def.Dir))
	}
	if strings.TrimSpace(l.Ref) == "" {
		errs = append(errs, fmt.Errorf("lineage %q: ref is empty", l.Name))
	}
	if !isHex(l.Commit, 40) {
		errs = append(errs, fmt.Errorf("lineage %q: commit %q is not a 40-hex commit id", l.Name, l.Commit))
	}
	if len(l.Steps) == 0 {
		errs = append(errs, fmt.Errorf("lineage %q: no steps", l.Name))
	}
	numbers := map[int]string{}
	files := map[string]bool{}
	maxN := 0
	for _, s := range l.Steps {
		n, ok := StepNumber(s.File)
		if !ok {
			errs = append(errs, fmt.Errorf("lineage %q: %q is not a NNN_name.sql step file", l.Name, s.File))
			continue
		}
		if files[s.File] {
			errs = append(errs, fmt.Errorf("lineage %q: step %s appears twice", l.Name, s.File))
			continue
		}
		files[s.File] = true
		if other, dup := numbers[n]; dup {
			errs = append(errs, fmt.Errorf("lineage %q: number %d is used by both %s and %s", l.Name, n, other, s.File))
		}
		numbers[n] = s.File
		if !isHex(s.Blob, 40) {
			errs = append(errs, fmt.Errorf("lineage %q: step %s: blob %q is not a 40-hex blob id", l.Name, s.File, s.Blob))
		}
		if n > maxN {
			maxN = n
		}
	}
	if len(l.Steps) > 0 && l.Head != maxN {
		errs = append(errs, fmt.Errorf("lineage %q: head is %d but the highest step is %d", l.Name, l.Head, maxN))
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

func isHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// Encode renders the record deterministically: lineages sorted by name, steps
// by number then file name, two-space indent, trailing newline.
func Encode(r Record) ([]byte, error) {
	out := Record{Schema: r.Schema, Lineages: make([]Lineage, len(r.Lineages))}
	for i, l := range r.Lineages {
		l.Steps = sortedSteps(l.Steps)
		out.Lineages[i] = l
	}
	sort.Slice(out.Lineages, func(i, j int) bool { return out.Lineages[i].Name < out.Lineages[j].Name })
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("shipped.Encode: %w", err)
	}
	return append(b, '\n'), nil
}

func sortedSteps(in []Step) []Step {
	out := make([]Step, len(in))
	copy(out, in)
	sort.Slice(out, func(i, j int) bool {
		ni, _ := StepNumber(out[i].File)
		nj, _ := StepNumber(out[j].File)
		if ni != nj {
			return ni < nj
		}
		return out[i].File < out[j].File
	})
	return out
}

// ViolationKind names how a tree breaks the rule.
type ViolationKind string

// The three ways a tree breaks the released-step rule.
const (
	// Late: a step that did not ship is numbered at or below the head.
	Late ViolationKind = "late"
	// Changed: a shipped step's file has a different blob.
	Changed ViolationKind = "changed"
	// Vanished: a shipped step's file is gone (removed or renamed).
	Vanished ViolationKind = "vanished"
)

// Violation is one break of the rule, with what it takes to fix it.
type Violation struct {
	Kind     ViolationKind
	Lineage  string
	Dir      string
	File     string
	Number   int
	Head     int
	Ref      string
	WantBlob string
	GotBlob  string
	// NextFree is the lowest number a late step may take (above the head and
	// above every step in the tree), zero-padded like the file's prefix.
	NextFree string
}

// String is the plain-language failure message, naming the file and the fix.
func (v Violation) String() string {
	path := v.Dir + "/" + v.File
	switch v.Kind {
	case Late:
		return fmt.Sprintf("%s is numbered %d, at or below the shipped head %d of the %s lineage (shipped in %s), and it is not a shipped step. "+
			"A database that already ran step %d would never run it on an older runner, and an install that updated past %d would receive it late. "+
			"It is unshipped, so renumbering is safe: renumber the new step above %d (next free number: %s). Never edit a shipped step.",
			path, v.Number, v.Head, v.Lineage, v.Ref, v.Head, v.Head, v.Head, v.NextFree)
	case Changed:
		return fmt.Sprintf("%s shipped in %s of the %s lineage with blob %s, but the tree has blob %s. "+
			"Never edit a shipped step: restore it (git checkout %s -- %s) and put the change in a new step above %d.",
			path, v.Ref, v.Lineage, v.WantBlob, v.GotBlob, v.Ref, path, v.Head)
	case Vanished:
		return fmt.Sprintf("%s shipped in %s of the %s lineage (blob %s) and is missing from the tree. "+
			"A shipped step is never removed or renamed: restore it (git checkout %s -- %s).",
			path, v.Ref, v.Lineage, v.WantBlob, v.Ref, path)
	default:
		return fmt.Sprintf("%s: %s", path, v.Kind)
	}
}

// Check holds tree (every file in the lineage's directory; files that are not
// NNN_name.sql steps are ignored) to the shipped entry and returns every
// violation, sorted by step number, then file name, then kind.
func Check(entry Lineage, tree []Step) []Violation {
	shippedBlob := make(map[string]string, len(entry.Steps))
	for _, s := range entry.Steps {
		shippedBlob[s.File] = s.Blob
	}
	treeBlob := map[string]string{}
	maxN, width := entry.Head, 0
	for _, s := range tree {
		n, ok := StepNumber(s.File)
		if !ok {
			continue
		}
		treeBlob[s.File] = s.Blob
		if n > maxN {
			maxN = n
		}
	}
	base := Violation{Lineage: entry.Name, Dir: entry.Dir, Head: entry.Head, Ref: entry.Ref}
	var out []Violation
	for _, s := range entry.Steps {
		n, _ := StepNumber(s.File)
		v := base
		v.File, v.Number, v.WantBlob = s.File, n, s.Blob
		got, present := treeBlob[s.File]
		switch {
		case !present:
			v.Kind = Vanished
			out = append(out, v)
		case got != s.Blob:
			v.Kind, v.GotBlob = Changed, got
			out = append(out, v)
		}
	}
	for file, blob := range treeBlob {
		n, _ := StepNumber(file)
		if _, ok := shippedBlob[file]; ok || n > entry.Head {
			continue
		}
		width = len(strings.SplitN(file, "_", 2)[0])
		v := base
		v.Kind, v.File, v.Number, v.GotBlob = Late, file, n, blob
		v.NextFree = fmt.Sprintf("%0*d", width, maxN+1)
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Number != out[j].Number {
			return out[i].Number < out[j].Number
		}
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return out[i].Kind < out[j].Kind
	})
	return out
}

// Merge returns the lineage entry after ref (resolved to commit) shipped with
// tree as the lineage's directory. prev is the current entry, or nil when the
// lineage has none yet.
//
// Merge refuses a tree that breaks the rule against prev (a late step, or a
// shipped step changed or gone), so recording a release can never bless a
// late or edited step. A tree that passes holds every shipped step
// unchanged, so the shipped set only grows and the head never falls.
func Merge(prev *Lineage, def LineageDef, ref, commit string, tree []Step) (Lineage, error) {
	var steps []Step
	head := 0
	for _, s := range tree {
		n, ok := StepNumber(s.File)
		if !ok {
			continue
		}
		steps = append(steps, s)
		if n > head {
			head = n
		}
	}
	if len(steps) == 0 {
		return Lineage{}, fmt.Errorf("shipped.Merge: %s has no migration steps at %s", def.Dir, ref)
	}
	if prev != nil {
		if vs := Check(*prev, steps); len(vs) > 0 {
			msgs := make([]string, len(vs))
			for i, v := range vs {
				msgs[i] = v.String()
			}
			return Lineage{}, fmt.Errorf("shipped.Merge: %s at %s breaks the released-step rule:\n%s", def.Name, ref, strings.Join(msgs, "\n"))
		}
	}
	out := Lineage{Name: def.Name, Dir: def.Dir, Head: head, Ref: ref, Commit: commit, Steps: sortedSteps(steps)}
	if err := out.Validate(); err != nil {
		return Lineage{}, fmt.Errorf("shipped.Merge: %w", err)
	}
	return out, nil
}
