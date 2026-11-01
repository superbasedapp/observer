package secfeed

import (
	"net/url"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// scope.go is where one install's names are classified (security plan
// section 8.3, X4; lane SEC-D1FIX2 milestone 1): the project, every
// directory whose package-manager configuration applies (the working
// directory, a cd target and a --prefix, -C, --cwd, --dir or
// --manifest-path target, each up to the project root), and the variables
// from the developer's shell that name a private source. Every extra source
// only ever makes a name MORE private: a name is public only when the
// classifier of every directory, under every environment, calls it public
// (AllPublic).

// Scope is one ask's classification scope.
type Scope struct {
	// ProjectRoot is the project the event belongs to; "" means unknown,
	// and then no name is public.
	ProjectRoot string
	// Dirs lists every directory whose project files are read, absolute
	// and cleaned (the project root is always read too). Unknown reports a
	// directory the command changes to that could not be resolved (a
	// variable, `cd -`, popd): no name is public then.
	Dirs    []string
	Unknown bool
	// Env is the developer's variables that name a package source, as the
	// hook saw them (ScopeEnv): they are applied on top of the reader's
	// own environment, never in place of it.
	Env map[string]string
}

// Scope limits.
const (
	// MaxScopeDirs caps the directories one scope names; a longer list
	// makes the scope unknown.
	MaxScopeDirs = 48
	// MaxScopeEnv caps the variables one scope carries, and
	// maxScopeEnvValue one value.
	MaxScopeEnv      = 48
	maxScopeEnvValue = 1024
)

// Public reports whether a scope can call any name public: a known
// project root, every directory resolved and absolute, within the caps.
func (s Scope) Public() bool {
	if s.ProjectRoot == "" || s.Unknown || len(s.Dirs) > MaxScopeDirs || len(s.Env) > MaxScopeEnv {
		return false
	}
	for _, d := range s.Dirs {
		if d == "" || !filepath.IsAbs(d) || filepath.Clean(d) != d {
			return false
		}
	}
	return true
}

// ConfigDirs returns the directories to read for the scope: the project
// root and every named directory, each once, in a stable order.
func (s Scope) ConfigDirs() []string {
	seen := map[string]bool{}
	var out []string
	for _, d := range append([]string{s.ProjectRoot}, s.Dirs...) {
		if d == "" || seen[d] {
			continue
		}
		seen[d] = true
		out = append(out, d)
	}
	return out
}

// AllPublic combines classifiers: a name is public only when every one
// says so. No classifier, or any nil one, is nothing public (nil).
func AllPublic(cs ...Classifier) Classifier {
	if len(cs) == 0 {
		return nil
	}
	for _, c := range cs {
		if c == nil {
			return nil
		}
	}
	return func(s InstallSpec) bool {
		for _, c := range cs {
			if !c(s) {
				return false
			}
		}
		return true
	}
}

// scopeEnvKeys are the variables that name a package source, or a
// configuration file that does, matched on the upper-cased name.
var scopeEnvKeys = set(
	"GOPRIVATE", "GONOPROXY", "GONOSUMDB", "GOPROXY", "GOFLAGS", "GOENV",
	"NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG",
	"YARN_NPM_REGISTRY_SERVER", "YARN_REGISTRY",
	"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE",
	"UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_FIND_LINKS", "UV_CONFIG_FILE",
	"CARGO_HOME", "CARGO_REGISTRY_DEFAULT", "VIRTUAL_ENV", "BUN_CONFIG_REGISTRY",
)

// scopeEnvPrefixes are variable name prefixes that name a source.
var scopeEnvPrefixes = []string{"NPM_CONFIG_@", "UV_INDEX", "CARGO_REGISTRIES_", "POETRY_REPOSITORIES_", "POETRY_SOURCE_"}

// scopeEnvKey reports whether one variable name is carried, and its
// canonical (upper-cased) spelling. An npm_config_ variable is carried only
// when it names a registry or a config file, never a credential.
func scopeEnvKey(name string) (string, bool) {
	up := strings.ToUpper(name)
	if scopeEnvKeys[up] {
		return up, true
	}
	if strings.HasPrefix(up, "NPM_CONFIG_") && strings.HasSuffix(up, "REGISTRY") {
		return up, true
	}
	if strings.Contains(up, "TOKEN") || strings.Contains(up, "PASSWORD") || strings.Contains(up, "AUTH") || strings.Contains(up, "USERNAME") {
		return "", false
	}
	for _, p := range scopeEnvPrefixes {
		if strings.HasPrefix(up, p) {
			return up, true
		}
	}
	return "", false
}

// ScopeEnv picks the source-naming variables out of a NAME=value list (the
// hook's own environment): never a credential variable, and any URL's
// credentials replaced by a marker that still reads as "not the public
// default". At most MaxScopeEnv variables, each value capped.
func ScopeEnv(environ []string) map[string]string {
	out := map[string]string{}
	keys := make([]string, 0, len(environ))
	vals := map[string]string{}
	for _, kv := range environ {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		up, carried := scopeEnvKey(k)
		if !carried || strings.TrimSpace(v) == "" {
			continue
		}
		if _, dup := vals[up]; !dup {
			keys = append(keys, up)
		}
		vals[up] = v
	}
	sort.Strings(keys)
	for _, k := range keys {
		if len(out) >= MaxScopeEnv {
			break
		}
		v := redactValue(vals[k])
		if len(v) > maxScopeEnvValue {
			// A value that does not fit cannot be read back faithfully: a
			// marker that is no public address keeps the name private.
			v = "(over the cap)"
		}
		out[k] = v
	}
	return out
}

// redactValue replaces the credentials of every URL in a value (one or
// several, space or comma separated) with a fixed marker.
func redactValue(v string) string {
	if !strings.Contains(v, "@") || !strings.Contains(v, "://") {
		return v
	}
	fields := strings.FieldsFunc(v, func(r rune) bool { return r == ' ' || r == ',' })
	for i, f := range fields {
		name, addr, named := strings.Cut(f, "=")
		if !named || strings.Contains(name, "/") {
			addr, name, named = f, "", false
		}
		u, err := url.Parse(addr)
		if err != nil || u.User == nil {
			continue
		}
		u.User = url.User("redacted")
		if named {
			fields[i] = name + "=" + u.String()
		} else {
			fields[i] = u.String()
		}
	}
	return strings.Join(fields, " ")
}

// EnvReader turns a scope's variables into the two readers
// PrivConfigInput takes.
func EnvReader(env map[string]string) (func(string) string, func() []string) {
	get := func(k string) string { return env[strings.ToUpper(k)] }
	list := func() []string {
		out := make([]string, 0, len(env))
		for k, v := range env {
			out = append(out, k+"="+v)
		}
		sort.Strings(out)
		return out
	}
	return get, list
}

// dirFlags are the flags whose value is a directory (or, for
// --manifest-path, a file in one) whose configuration applies to the
// install, read the same for every ecosystem: reading one more directory
// only ever makes a name more private.
var dirFlags = set("--prefix", "-C", "--cwd", "--dir", "--directory", "--project", "--working-dir", "-d", "--manifest-path", "-modfile")

// fileFlags are the dirFlags whose value names a file.
var fileFlags = set("--manifest-path", "-modfile")

// dirChangeBases change the shell's directory for the rest of the line.
var dirChangeBases = set("cd", "chdir", "pushd", "set-location", "push-location", "sl")

// dirResetBases change it to somewhere the line does not name.
var dirResetBases = set("popd", "pop-location")

// InstallDirs returns the directories an event's installs read their
// configuration from, beyond the working directory base: every cd target
// in force at an install (cd frontend && npm i x) and every directory flag
// on an install unit, joined onto base. unknown reports a directory that
// cannot be resolved (a variable, `cd -`, no operand, popd); base "" makes
// every relative directory unknown.
func InstallDirs(ev *policy.Event, base string) (dirs []string, unknown bool) {
	if ev == nil || ev.Kind != policy.KindShellExec {
		return nil, false
	}
	var cmds []policy.Command
	if len(ev.Args) > 0 {
		cmds = policy.ParseArgv(ev.Args, ev.Dialect)
	} else {
		cmds = policy.ParseCommand(ev.Target, ev.Dialect)
	}
	w := &dirWalker{base: base, cur: base}
	for i := range cmds {
		w.unit(&cmds[i])
	}
	if len(w.dirs) > MaxScopeDirs {
		w.unknown = true
	}
	return w.dirs, w.unknown
}

// dirWalker is InstallDirs' running state: the directory in force and
// what was found.
type dirWalker struct {
	base, cur string
	dirs      []string
	unknown   bool
}

// add records one directory (one over the cap marks the list too long).
func (w *dirWalker) add(d string) {
	if d != "" && len(w.dirs) <= MaxScopeDirs {
		w.dirs = append(w.dirs, d)
	}
}

// resolve joins a directory word onto the directory in force; a variable,
// `-`, a home-relative word or a relative word with no base is unknown.
func (w *dirWalker) resolve(word string) (string, bool) {
	if word == "" || word == "-" || strings.ContainsAny(word, "$%`~") {
		return "", false
	}
	if filepath.IsAbs(word) {
		return filepath.Clean(word), true
	}
	if w.cur == "" {
		return "", false
	}
	return filepath.Join(w.cur, word), true
}

// unit reads one command unit: a directory change, or an install's
// directory flags.
func (w *dirWalker) unit(c *policy.Command) {
	switch {
	case dirResetBases[c.Base]:
		w.unknown = true
		return
	case dirChangeBases[c.Base]:
		w.change(c.Args())
		return
	}
	if _, _, _, ok := matchInstall(c); !ok {
		return
	}
	if w.cur != w.base {
		w.add(w.cur)
	}
	args := c.Args()
	for j := 0; j < len(args); j++ {
		name, value, hasValue := strings.Cut(args[j], "=")
		if !dirFlags[name] || (name == "-d" && c.Base != "composer") {
			continue
		}
		if !hasValue {
			if j+1 >= len(args) {
				w.unknown = true
				continue
			}
			j++
			value = args[j]
		}
		d, ok := w.resolve(value)
		if !ok {
			w.unknown = true
			continue
		}
		if fileFlags[name] {
			d = filepath.Dir(d)
		}
		w.add(d)
	}
}

// change applies a cd-like unit: exactly one resolvable operand moves the
// directory in force; anything else is unknown.
func (w *dirWalker) change(args []string) {
	var ops []string
	for _, a := range args {
		if (strings.HasPrefix(a, "-") && a != "-") || strings.EqualFold(a, "/d") {
			continue
		}
		ops = append(ops, a)
	}
	if len(ops) != 1 {
		w.unknown = true
		return
	}
	d, ok := w.resolve(ops[0])
	if !ok {
		w.unknown = true
		return
	}
	w.cur = d
}
