package defaultworkspace

import (
	"fmt"
	"path/filepath"
	"strings"
)

// BuiltinName is the folder name of the built-in default workspace, created
// directly under the home folder.
const BuiltinName = "observer-workspace"

// MaxPathBytes bounds a configured path.
const MaxPathBytes = 4096

// Resolved is the default workspace as configured.
type Resolved struct {
	// Dir is the folder. Empty only when nothing is configured and no home
	// folder resolves.
	Dir string
	// Builtin reports that Dir is the built-in default (nothing configured,
	// or the configured value names the built-in folder).
	Builtin bool
	// BuiltinDir is <home>/observer-workspace ("" without a home folder).
	BuiltinDir string
}

// BuiltinDir is the built-in default workspace for home, or "" when home is
// empty.
func BuiltinDir(home string) string {
	if strings.TrimSpace(home) == "" {
		return ""
	}
	return filepath.Join(home, BuiltinName)
}

// Resolve answers what the default workspace is: the configured value
// (trimmed and cleaned) when set, else the built-in <home>/observer-workspace.
// It does not validate; Validate and Check do.
func Resolve(configured, home string) Resolved {
	builtin := BuiltinDir(home)
	c := strings.TrimSpace(configured)
	if c == "" {
		return Resolved{Dir: builtin, Builtin: builtin != "", BuiltinDir: builtin}
	}
	c = filepath.Clean(c)
	return Resolved{Dir: c, Builtin: builtin != "" && samePath(c, builtin), BuiltinDir: builtin}
}

// Refusal is a broken folder rule: Rule names the table row, Msg says what
// is wrong in plain words.
type Refusal struct {
	Rule string
	Msg  string
}

// Error implements error.
func (r *Refusal) Error() string { return r.Msg }

// Input is what Validate checks.
type Input struct {
	// Path is the candidate folder.
	Path string
	// Home is the home folder ("" skips the home rules).
	Home string
	// DataDirs are Observer's data folders (~/.observer and the database's
	// folder); empty entries are skipped.
	DataDirs []string
	// The disk facts, injected so the rules stay pure. A nil func skips the
	// rules that need it.
	//
	// RepoRoot answers the top level of the git working tree holding dir
	// (looked up from the nearest folder that exists), spelled as dir itself
	// when that top level IS dir.
	RepoRoot func(dir string) (string, bool)
	// Marked reports the workspace marker (MarkerName) at dir's root.
	Marked func(dir string) bool
	// ChildRepos names dir's immediate subfolders that hold a .git entry
	// (a bounded, shallow look).
	ChildRepos func(dir string) []string
	// HoldsFiles reports that dir exists and has at least one entry.
	HoldsFiles func(dir string) bool
}

// marked reports the marker through the injected fact.
func (in Input) marked(p string) bool { return in.Marked != nil && in.Marked(p) }

// ownRepo reports an Observer workspace that is its own repository: a git
// working tree rooted exactly at p that carries the marker.
func (in Input) ownRepo(p string) bool {
	if in.RepoRoot == nil || !in.marked(p) {
		return false
	}
	root, ok := in.RepoRoot(p)
	return ok && samePath(root, p)
}

// homeRepo reports a repository top level that is exactly the home folder.
func (in Input) homeRepo(root string) bool {
	return in.Home != "" && samePath(root, in.Home)
}

// maxNamed is how many child repositories a refusal names.
const maxNamed = 3

// namedList renders up to maxNamed names and a count of the rest.
func namedList(names []string) string {
	if len(names) <= maxNamed {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s and %d more", strings.Join(names[:maxNamed], ", "), len(names)-maxNamed)
}

// rule is one ordered validation row: a non-empty return is the refusal.
type rule struct {
	id    string
	check func(in Input, p string) string
}

// rules is walked top-down; the first refusal wins. p is the trimmed,
// cleaned path ("" when nothing was typed).
var rules = []rule{
	{"empty", func(_ Input, p string) string {
		if p == "" {
			return "Enter the full path of a folder."
		}
		return ""
	}},
	{"length", func(_ Input, p string) string {
		if len(p) > MaxPathBytes {
			return fmt.Sprintf("That path is longer than %d bytes.", MaxPathBytes)
		}
		return ""
	}},
	{"control", func(_ Input, p string) string {
		for _, r := range p {
			if r < 0x20 || r == 0x7f {
				return "That path contains a control character."
			}
		}
		return ""
	}},
	{"absolute", func(_ Input, p string) string {
		if !filepath.IsAbs(p) {
			return "The folder must be a full path (start at the drive or at /), not a relative one."
		}
		return ""
	}},
	{"root", func(_ Input, p string) string {
		if isRoot(p) {
			return "A drive or filesystem root cannot be the workspace; pick a folder inside your home folder."
		}
		return ""
	}},
	{"home", func(in Input, p string) string {
		if in.Home != "" && samePath(p, in.Home) {
			return "Your home folder cannot be the workspace; pick a folder inside it."
		}
		return ""
	}},
	{"holds_home", func(in Input, p string) string {
		if in.Home != "" && within(in.Home, p) {
			return "That folder holds your home folder; pick a folder inside your home folder instead."
		}
		return ""
	}},
	{"data_dir", func(in Input, p string) string {
		for _, d := range in.DataDirs {
			if d != "" && (samePath(p, d) || within(p, d)) {
				return "That folder is inside Observer's own data folder; pick another one."
			}
		}
		return ""
	}},
	{"holds_data_dir", func(in Input, p string) string {
		for _, d := range in.DataDirs {
			if d != "" && within(d, p) {
				return "That folder holds Observer's own data folder; pick another one."
			}
		}
		return ""
	}},
	// A git repository is refused unless it is an Observer workspace: rooted
	// exactly at this folder AND carrying the marker. Such a workspace must
	// not itself sit inside another repository. A repository rooted exactly
	// at the home folder (a dotfiles checkout with ~/.git) does not count as
	// another repository (review finding 5, 2026-11-12): the workspace gets
	// its own .git, so git treats it as a separate repository and the hosted
	// listing's `rev-parse --show-toplevel` answers the workspace, never the
	// home folder. A repository anywhere else still refuses.
	{"git", func(in Input, p string) string {
		if in.RepoRoot == nil {
			return ""
		}
		root, ok := in.RepoRoot(p)
		switch {
		case !ok, in.homeRepo(root):
			return ""
		case samePath(root, p) && in.marked(p):
			if outer, ok := in.RepoRoot(filepath.Dir(p)); ok && !in.homeRepo(outer) {
				return fmt.Sprintf("That Observer workspace is inside the git repository at %s; pick a folder outside your projects.", outer)
			}
			return ""
		case samePath(root, p):
			return "That folder is a git repository Observer did not create (it has no " + MarkerName + " file); pick a folder outside your projects."
		}
		return fmt.Sprintf("That folder is inside the git repository at %s; pick a folder outside your projects so nothing is added to one.", root)
	}},
	// A parent of projects (like a code folder) would upload them if it were
	// consented. A marked workspace is exempt: git lists its own files only,
	// never a nested repository's.
	{"holds_repos", func(in Input, p string) string {
		if in.ChildRepos == nil || in.ownRepo(p) {
			return ""
		}
		if names := in.ChildRepos(p); len(names) > 0 {
			return fmt.Sprintf("That folder holds git repositories (%s); pick a folder that is not a parent of your projects.", namedList(names))
		}
		return ""
	}},
	// Observer sets up only a new or empty folder (the marker and the
	// repository), so a folder that already holds files must be one it set
	// up before.
	{"not_empty", func(in Input, p string) string {
		if in.HoldsFiles != nil && in.HoldsFiles(p) && !in.marked(p) {
			return "That folder already holds files and is not an Observer workspace; pick a new or empty folder so Observer can set it up."
		}
		return ""
	}},
}

// Validate walks the rule table and returns the first refusal (a *Refusal),
// or nil when the folder may be the default workspace. Pure: every question
// about the disk is an injected fact on in.
func Validate(in Input) error {
	p := strings.TrimSpace(in.Path)
	if p != "" {
		p = filepath.Clean(p)
	}
	for _, r := range rules {
		if msg := r.check(in, p); msg != "" {
			return &Refusal{Rule: r.id, Msg: msg}
		}
	}
	return nil
}

// isRoot reports a filesystem or drive root ("/", `C:\`, a UNC share root).
func isRoot(p string) bool {
	c := filepath.Clean(p)
	return filepath.Dir(c) == c
}

// samePath compares two cleaned paths (case-insensitively where the host's
// filepath.Rel is, i.e. on Windows).
func samePath(a, b string) bool {
	rel, err := filepath.Rel(filepath.Clean(b), filepath.Clean(a))
	return err == nil && rel == "."
}

// within reports that child is strictly below parent.
func within(child, parent string) bool {
	rel, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil || rel == "." || filepath.IsAbs(rel) {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
