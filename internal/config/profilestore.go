package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// ProfileStore extends the built-in profile set (the embedded
// recipes + "default") with USER profiles — TOML files under Dir
// (canonically ~/.observer/profiles/<name>.toml) carrying the same
// allow-listed shape as a recipe: [compression.*] parameter keys.
// Built-in names are reserved; user files never shadow them.
//
// The zero value (empty Dir) degrades to built-ins only, so every
// pre-P3.4 call path keeps working unchanged.
type ProfileStore struct {
	// Dir holds user profile files. Empty = built-ins only.
	Dir string
}

// DefaultProfilesDir returns the canonical user-profiles directory
// for a resolved config.toml path (a sibling "profiles" dir).
func DefaultProfilesDir(configPath string) string {
	if configPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configPath), "profiles")
}

// profileNameRx allow-lists profile names: filesystem-safe,
// lowercase, no path separators or dots (they become <name>.toml on
// disk and instance-key parts at the router).
var profileNameRx = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,63}$`)

// Names returns every resolvable profile name: "default", the
// embedded recipes, then user profiles. Sorted, deduplicated
// (built-ins win collisions).
func (ps ProfileStore) Names() []string {
	names := ProfileNames()
	seen := map[string]bool{}
	for _, n := range names {
		seen[n] = true
	}
	for _, n := range ps.userNames() {
		if !seen[n] {
			names = append(names, n)
			seen[n] = true
		}
	}
	sort.Strings(names)
	return names
}

func (ps ProfileStore) userNames() []string {
	if ps.Dir == "" {
		return nil
	}
	entries, err := os.ReadDir(ps.Dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		name, ok := strings.CutSuffix(e.Name(), ".toml")
		if !ok || e.IsDir() || !profileNameRx.MatchString(name) {
			continue
		}
		out = append(out, name)
	}
	return out
}

// IsBuiltin reports whether name is "default" or an embedded recipe.
func IsBuiltin(name string) bool {
	if name == DefaultProfileName {
		return true
	}
	for _, n := range RecipeNames() {
		if n == name {
			return true
		}
	}
	return false
}

// Validate reports whether name resolves through this store —
// built-in or existing user profile — with the available set named
// on failure (the loud-typo contract LoadProfile set).
func (ps ProfileStore) Validate(name string) error {
	if name == "" || IsBuiltin(name) {
		return nil
	}
	if ps.userPath(name) != "" {
		if _, err := os.Stat(ps.userPath(name)); err == nil {
			return nil
		}
	}
	return fmt.Errorf("config: unknown profile %q (available: %s)", name, strings.Join(ps.Names(), ", "))
}

func (ps ProfileStore) userPath(name string) string {
	if ps.Dir == "" || !profileNameRx.MatchString(name) {
		return ""
	}
	return filepath.Join(ps.Dir, name+".toml")
}

// ResolveCompression mirrors the package-level ResolveCompression
// but also resolves user profiles, returning a content stamp
// ("" for built-ins, mtime.size for user files) callers fold into
// instance keys so user-profile edits apply to new sessions without
// a restart.
func (ps ProfileStore) ResolveCompression(master CompressionConfig, name string) (CompressionConfig, string, error) {
	if name == "" || IsBuiltin(name) {
		out, err := ResolveCompression(master, name)
		return out, "", err
	}
	path := ps.userPath(name)
	if path == "" {
		return CompressionConfig{}, "", fmt.Errorf("config: unknown profile %q (available: %s)", name, strings.Join(ps.Names(), ", "))
	}
	fi, err := os.Stat(path)
	if err != nil {
		return CompressionConfig{}, "", fmt.Errorf("config: profile %q: %w", name, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return CompressionConfig{}, "", fmt.Errorf("config: profile %q: %w", name, err)
	}
	// Same partial-merge semantics as the embedded recipes: the
	// profile's keys overlay MASTER parameters; the enablement split
	// stays master-owned.
	overlay := Config{Compression: master}
	if err := toml.Unmarshal(body, &overlay); err != nil {
		return CompressionConfig{}, "", fmt.Errorf("config: profile %q: %w", name, err)
	}
	out := overlay.Compression
	out.Conversation.Enabled = master.Conversation.Enabled
	stamp := strconv.FormatInt(fi.ModTime().UnixNano(), 10) + "." + strconv.FormatInt(fi.Size(), 10)
	return out, stamp, nil
}

// Read returns the raw TOML body backing name: the embedded recipe
// for built-ins, the on-disk file for user profiles. The "default"
// pseudo-profile has no body (it is the master-config passthrough)
// and errors. Display source for the Settings profile editor.
func (ps ProfileStore) Read(name string) ([]byte, error) {
	if name == "" || name == DefaultProfileName {
		return nil, fmt.Errorf("config: profile %q has no file — it is the master-config passthrough", DefaultProfileName)
	}
	if IsBuiltin(name) {
		return readRecipe(name)
	}
	if err := ps.Validate(name); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(ps.userPath(name))
	if err != nil {
		return nil, fmt.Errorf("config: read profile %q: %w", name, err)
	}
	return body, nil
}

// Stamp returns the content stamp for a user profile ("" for
// built-ins and missing files) — folded into router instance keys so
// profile-file edits apply to new sessions without a restart.
func (ps ProfileStore) Stamp(name string) string {
	if name == "" || IsBuiltin(name) {
		return ""
	}
	path := ps.userPath(name)
	if path == "" {
		return ""
	}
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return strconv.FormatInt(fi.ModTime().UnixNano(), 10) + "." + strconv.FormatInt(fi.Size(), 10)
}

// Create writes a new user profile seeded from another profile:
// built-in bases copy the recipe's own keys verbatim (a tuned
// starting point with its comments... none survive marshaling — the
// raw embed is copied byte-for-byte so they DO); user bases copy the
// file; "default" seeds an empty parameter file (master passthrough
// until keys are added). Refuses reserved names, invalid names, and
// existing files.
func (ps ProfileStore) Create(name, from string) error {
	if ps.Dir == "" {
		return errors.New("config: profile store has no directory configured")
	}
	if !profileNameRx.MatchString(name) {
		return fmt.Errorf("config: invalid profile name %q (lowercase letters, digits, dashes; max 64)", name)
	}
	if IsBuiltin(name) {
		return fmt.Errorf("config: %q is a built-in profile name (reserved)", name)
	}
	path := ps.userPath(name)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("config: profile %q already exists at %s", name, path)
	}
	var body []byte
	switch {
	case from == "" || from == DefaultProfileName:
		body = []byte("# custom observer compression profile \"" + name + "\"\n" +
			"# Keys here overlay your master config's compression parameters.\n" +
			"# Set values with: observer profile set " + name + " <key> <value>\n")
	case IsBuiltin(from):
		raw, err := readRecipe(from)
		if err != nil {
			return err
		}
		body = raw
	default:
		if err := ps.Validate(from); err != nil {
			return err
		}
		raw, err := os.ReadFile(ps.userPath(from))
		if err != nil {
			return fmt.Errorf("config: read base profile %q: %w", from, err)
		}
		body = raw
	}
	if err := os.MkdirAll(ps.Dir, 0o755); err != nil {
		return fmt.Errorf("config: ensure profiles dir: %w", err)
	}
	return os.WriteFile(path, body, 0o644) //nolint:gosec // G306: non-secret profile TOML; mirrors config.toml's readable perms (the write.go precedent).
}

// Delete removes a user profile. Built-ins are refused; missing
// files error.
func (ps ProfileStore) Delete(name string) error {
	if IsBuiltin(name) {
		return fmt.Errorf("config: %q is built-in and cannot be deleted", name)
	}
	path := ps.userPath(name)
	if path == "" {
		return fmt.Errorf("config: invalid profile name %q", name)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("config: delete profile %q: %w", name, err)
	}
	return nil
}

// SetKey sets one dotted compression key in a USER profile file
// (e.g. "compression.conversation.target_ratio") — the editing
// front door behind `observer profile set`. Built-ins are immutable;
// the same allow-list shape as project files applies (compression.*
// only — profile files carry parameters, not assignments).
//
// PRESENCE-PRESERVING (the D16 fix): the write touches ONLY the
// dotted key. Re-marshaling the parsed CompressionConfig struct — the
// pre-fix behavior — materialized every key the file never mentioned
// as an EXPLICIT ZERO ("" / 0 / false), and per the D7 explicit-zeros
// rule those then pinned over master fallthrough, silently changing
// resolution semantics for every untouched key. The typed parse is
// kept for validation (allow-list, type checks, loud unknown
// segments); the file write goes through a raw TOML tree so absent
// keys stay absent. Comments are still lost on first edit (same as
// before — TOML re-marshal has no comment model).
func (ps ProfileStore) SetKey(name, dotted, value string) error {
	if IsBuiltin(name) {
		return fmt.Errorf("config: %q is built-in and immutable — create a copy first: observer profile create my-%s --from %s", name, name, name)
	}
	if err := ps.Validate(name); err != nil {
		return err
	}
	if strings.SplitN(dotted, ".", 2)[0] != "compression" {
		return fmt.Errorf("config: profile files accept only compression.* keys (got %q)", dotted)
	}
	path := ps.userPath(name)
	body, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config: read profile %q: %w", name, err)
	}
	var doc struct {
		Compression CompressionConfig `toml:"compression"`
	}
	if err := toml.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("config: profile %q does not parse; fix it before setting keys: %w", name, err)
	}
	// Typed validation pass: type conversion + allow-listed path or a
	// loud error, exactly as before.
	if err := setStructKey(reflect.ValueOf(&doc).Elem(), strings.Split(dotted, "."), dotted, value); err != nil {
		return err
	}
	// Extract the typed leaf the validation pass produced by
	// re-marshaling the struct and plucking the dotted path from it.
	full := map[string]any{}
	if err := remarshalInto(doc, &full); err != nil {
		return fmt.Errorf("config: profile %q: %w", name, err)
	}
	leaf, ok := mapGet(full, strings.Split(dotted, "."))
	if !ok {
		return fmt.Errorf("config: profile %q: key %q did not survive the typed pass", name, dotted)
	}
	// Apply ONLY that leaf onto the file's own tree.
	tree := map[string]any{}
	if err := toml.Unmarshal(body, &tree); err != nil {
		return fmt.Errorf("config: profile %q does not parse; fix it before setting keys: %w", name, err)
	}
	mapSet(tree, strings.Split(dotted, "."), leaf)
	return writeTOMLAtomic(path, tree)
}

// remarshalInto round-trips v through TOML into out — the cheap way
// to view a typed struct as a raw key tree.
func remarshalInto(v any, out *map[string]any) error {
	var sb strings.Builder
	if err := toml.NewEncoder(&sb).Encode(v); err != nil {
		return err
	}
	return toml.Unmarshal([]byte(sb.String()), out)
}

// mapGet walks a nested map[string]any by path.
func mapGet(m map[string]any, path []string) (any, bool) {
	cur := any(m)
	for _, seg := range path {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		cur, ok = mm[seg]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

// mapSet sets a leaf in a nested map[string]any tree, creating
// intermediate maps as needed. A non-map intermediate is replaced —
// the typed validation pass already guaranteed the path shape.
func mapSet(m map[string]any, path []string, v any) {
	cur := m
	for _, seg := range path[:len(path)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[path[len(path)-1]] = v
}
