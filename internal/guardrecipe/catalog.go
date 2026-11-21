package guardrecipe

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// catalogFS is the built-in recipe catalog. Adding a recipe: drop
// catalog/<name>.toml here, list it in docs/guard-recipes.md, and add one
// case to catalog_test.go (every built-in compiles and lints clean against
// the built-in rule catalog in internal/guardrecipesvc's tests).
//
//go:embed catalog/*.toml
var catalogFS embed.FS

// Set is a resolved recipe catalog: the built-ins plus user recipes, by
// name. Built-in names are reserved; a user file with a built-in name is
// refused with an issue, never shadows it.
type Set struct {
	byName map[string]*Recipe
	// Issues are the user recipes that did not load, one line each.
	Issues []string
}

// Builtin returns the embedded catalog. A malformed embedded recipe is a
// build defect, reported as an error (catalog_test.go keeps it from
// shipping).
func Builtin() (*Set, error) {
	s := &Set{byName: map[string]*Recipe{}}
	entries, err := fs.ReadDir(catalogFS, "catalog")
	if err != nil {
		return nil, fmt.Errorf("guardrecipe.Builtin: %w", err)
	}
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok || e.IsDir() {
			continue
		}
		raw, err := catalogFS.ReadFile("catalog/" + e.Name())
		if err != nil {
			return nil, fmt.Errorf("guardrecipe.Builtin: read %s: %w", e.Name(), err)
		}
		r, err := Parse(name, raw, SourceBuiltin)
		if err != nil {
			return nil, err
		}
		s.byName[r.Name] = r
	}
	if err := s.checkExtends(); err != nil {
		return nil, fmt.Errorf("guardrecipe.Builtin: %w", err)
	}
	return s, nil
}

// AddUser adds one user recipe file (name = file name without .toml). A
// file that does not parse, reuses a built-in name, or extends a recipe of
// another kind or one that does not exist is skipped with an issue: one bad
// user file never hides the rest of the catalog.
func (s *Set) AddUser(name string, raw []byte) {
	// The file name is the recipe's name: one that is not a recipe name (a
	// file named exactly ".toml" has an empty one) would let the file's own
	// `name` key choose which entry it fills, a built-in's included (sweep
	// finding UI-4).
	if !NameRx.MatchString(name) {
		s.Issues = append(s.Issues, fmt.Sprintf("user recipe file %q skipped: the file name is not a recipe name (lowercase letters, digits and dashes, then .toml)", name+".toml"))
		return
	}
	if s.builtin(name) {
		s.Issues = append(s.Issues, fmt.Sprintf("user recipe %s skipped: the name belongs to a built-in recipe", name))
		return
	}
	r, err := Parse(name, raw, SourceUser)
	if err != nil {
		s.Issues = append(s.Issues, fmt.Sprintf("user recipe %s skipped: %v", name, err))
		return
	}
	if s.builtin(r.Name) {
		s.Issues = append(s.Issues, fmt.Sprintf("user recipe %s skipped: the name %s belongs to a built-in recipe", name, r.Name))
		return
	}
	s.byName[r.Name] = r
	if err := s.checkExtends(); err != nil {
		delete(s.byName, r.Name)
		s.Issues = append(s.Issues, fmt.Sprintf("user recipe %s skipped: %v", name, err))
	}
}

// builtin reports whether name is a built-in recipe of s.
func (s *Set) builtin(name string) bool {
	r, ok := s.byName[name]
	return ok && r.Source == SourceBuiltin
}

// Get returns a recipe by name.
func (s *Set) Get(name string) (*Recipe, bool) {
	if s == nil {
		return nil, false
	}
	r, ok := s.byName[name]
	return r, ok
}

// All returns every recipe: levels first by Order, then packs by name.
func (s *Set) All() []*Recipe {
	out := make([]*Recipe, 0, len(s.byName))
	for _, r := range s.byName {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Kind != b.Kind {
			return a.Kind == KindLevel
		}
		if a.Kind == KindLevel && a.Order != b.Order {
			return a.Order < b.Order
		}
		return a.Name < b.Name
	})
	return out
}

// Levels returns the level recipes in slider order.
func (s *Set) Levels() []*Recipe { return s.ofKind(KindLevel) }

// Packs returns the pack recipes by name.
func (s *Set) Packs() []*Recipe { return s.ofKind(KindPack) }

func (s *Set) ofKind(k Kind) []*Recipe {
	var out []*Recipe
	for _, r := range s.All() {
		if r.Kind == k {
			out = append(out, r)
		}
	}
	return out
}

// maxExtendsDepth bounds an extends chain.
const maxExtendsDepth = 8

// checkExtends verifies every extends target exists, has the same kind, and
// that no chain loops or runs past maxExtendsDepth.
func (s *Set) checkExtends() error {
	for _, r := range s.byName {
		if _, err := s.chain(r); err != nil {
			return err
		}
	}
	return nil
}

// chain returns r's extends chain, base first, r last.
func (s *Set) chain(r *Recipe) ([]*Recipe, error) {
	var out []*Recipe
	seen := map[string]bool{}
	for cur := r; cur != nil; {
		if seen[cur.Name] {
			return nil, fmt.Errorf("recipe %s: extends loops back to %s", r.Name, cur.Name)
		}
		seen[cur.Name] = true
		out = append([]*Recipe{cur}, out...)
		if len(out) > maxExtendsDepth {
			return nil, fmt.Errorf("recipe %s: extends chain is longer than %d", r.Name, maxExtendsDepth)
		}
		if cur.Extends == "" {
			break
		}
		base, ok := s.byName[cur.Extends]
		if !ok {
			return nil, fmt.Errorf("recipe %s: extends %s, which is not in the catalog", cur.Name, cur.Extends)
		}
		if base.Kind != cur.Kind {
			return nil, fmt.Errorf("recipe %s: extends %s, a %s, but is a %s", cur.Name, base.Name, base.Kind, cur.Kind)
		}
		cur = base
	}
	return out, nil
}
