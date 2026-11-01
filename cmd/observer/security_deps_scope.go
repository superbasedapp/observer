//go:build !sbo_omit_security && !sbo_omit_security_deps

package main

import (
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/hookctx"
	"github.com/marmutapp/superbased-observer/internal/secfeed"
)

// security_deps_scope.go reads the package-manager configuration that
// decides whether a name may leave the machine (security plan section 8.3,
// X4; lane SEC-D1FIX2 milestone 1): the project files of every directory
// an install reads its configuration from (the working directory, cd and
// --prefix-like targets, each up to the project root), and the user and
// machine files under an environment. A name is public only when the
// classifier of every directory under every environment says so
// (secfeed.AllPublic): a directory or a variable can only ever make a name
// more private.

// depsScopeMaxDepth caps the directories one target walks up.
const depsScopeMaxDepth = 24

// depsEnvSource is one environment the configuration is read under: get
// and list read it; nil reads nothing (the files' defaults only).
type depsEnvSource struct {
	get  func(string) string
	list func() []string
}

// depsDaemonEnv is the daemon's own process environment.
func depsDaemonEnv() depsEnvSource { return depsEnvSource{get: os.Getenv, list: os.Environ} }

// depsScopeEnv is the environment a scope carries (the developer's
// variables the hook passed), or none.
func depsScopeEnv(s secfeed.Scope) (depsEnvSource, bool) {
	if len(s.Env) == 0 {
		return depsEnvSource{}, false
	}
	get, list := secfeed.EnvReader(s.Env)
	return depsEnvSource{get: get, list: list}, true
}

// depsClassifier is the daemon's classifier for an ask's scope: every
// directory, under the daemon's own environment and under the scope's
// variables (the developer's shell, which may only restrict). A scope with
// no project root, or a directory that could not be resolved, has nothing
// public (nil).
func depsClassifier(scope secfeed.Scope) secfeed.Classifier {
	envs := []depsEnvSource{depsDaemonEnv()}
	if e, ok := depsScopeEnv(scope); ok {
		envs = append(envs, e)
	}
	return depsScopeClassifier(scope, envs)
}

// hookDepsClassifier is the hook's classifier: the same directories, read
// with no environment and under the developer's variables the scope
// carries (the hook's own). The daemon classifies again with its own
// environment before anything is sent.
func hookDepsClassifier(scope secfeed.Scope) secfeed.Classifier {
	envs := []depsEnvSource{{}}
	if e, ok := depsScopeEnv(scope); ok {
		envs = append(envs, e)
	}
	return depsScopeClassifier(scope, envs)
}

// depsScopeClassifier builds the conjunction of every directory's
// classifier under every environment.
func depsScopeClassifier(scope secfeed.Scope, envs []depsEnvSource) secfeed.Classifier {
	if !scope.Public() {
		return nil
	}
	dirs := scope.ConfigDirs()
	projects := make([]depsFiles, len(dirs))
	for i, d := range dirs {
		projects[i] = depsProjectFiles(d)
	}
	var cs []secfeed.Classifier
	for _, env := range envs {
		user := depsUserFiles(env.get)
		for _, proj := range projects {
			in := secfeed.PrivConfigInput{Files: map[secfeed.ConfigFile][]byte{}, Unreadable: map[secfeed.ConfigFile]bool{}, Env: env.get, Environ: env.list}
			user.into(&in)
			proj.into(&in)
			cs = append(cs, secfeed.NewClassifier(secfeed.BuildPrivConfig(in)))
		}
	}
	return secfeed.AllPublic(cs...)
}

// depsFiles is what one read found: bytes per role, and the roles whose
// file exists but could not be read.
type depsFiles struct {
	files      map[secfeed.ConfigFile][]byte
	unreadable map[secfeed.ConfigFile]bool
}

func newDepsFiles() depsFiles {
	return depsFiles{files: map[secfeed.ConfigFile][]byte{}, unreadable: map[secfeed.ConfigFile]bool{}}
}

// read adds one file under role; a missing file adds nothing, one that
// exists but cannot be read marks the role unreadable.
func (f depsFiles) read(role secfeed.ConfigFile, path string) {
	if path == "" {
		return
	}
	b, err := readDepsConfigFile(path, depsConfigMaxBytes)
	switch {
	case err == nil:
		if len(f.files[role]) > 0 {
			f.files[role] = append(f.files[role], '\n')
		}
		f.files[role] = append(f.files[role], b...)
	case !errors.Is(err, os.ErrNotExist):
		f.unreadable[role] = true
	}
}

// readAll adds every existing file of paths under role (pip reads them
// all; ini files concatenate).
func (f depsFiles) readAll(role secfeed.ConfigFile, paths ...string) {
	seen := map[string]bool{}
	for _, p := range paths {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		f.read(role, p)
	}
}

func (f depsFiles) into(in *secfeed.PrivConfigInput) {
	for r, b := range f.files {
		in.Files[r] = append(in.Files[r], b...)
	}
	for r, bad := range f.unreadable {
		if bad {
			in.Unreadable[r] = true
		}
	}
}

// depsProjectFiles reads one directory's project files.
func depsProjectFiles(dir string) depsFiles {
	f := newDepsFiles()
	if dir == "" {
		return f
	}
	f.read(secfeed.ConfNpmrcProject, filepath.Join(dir, ".npmrc"))
	f.read(secfeed.ConfYarnrcProject, filepath.Join(dir, ".yarnrc.yml"))
	f.read(secfeed.ConfYarn1Project, filepath.Join(dir, ".yarnrc"))
	f.read(secfeed.ConfBunfigProject, filepath.Join(dir, "bunfig.toml"))
	f.read(secfeed.ConfPipProject, filepath.Join(dir, "pip.conf"))
	f.read(secfeed.ConfPyproject, filepath.Join(dir, "pyproject.toml"))
	f.read(secfeed.ConfUVProject, filepath.Join(dir, "uv.toml"))
	f.read(secfeed.ConfCargoProject, firstExisting(filepath.Join(dir, ".cargo", "config.toml"), filepath.Join(dir, ".cargo", "config")))
	f.read(secfeed.ConfNuGetProject, firstExisting(filepath.Join(dir, "nuget.config"), filepath.Join(dir, "NuGet.Config"), filepath.Join(dir, "NuGet.config")))
	if m, err := filepath.Glob(filepath.Join(dir, "requirements*.txt")); err == nil {
		sort.Strings(m)
		for i, p := range m {
			if i >= 8 {
				break
			}
			f.read(secfeed.ConfRequirements, p)
		}
	}
	return f
}

// depsUserFiles reads the user and machine files, at the paths env names
// (or the defaults; a nil env reads the defaults).
func depsUserFiles(env func(string) string) depsFiles {
	f := newDepsFiles()
	getenv := func(k string) string {
		if env == nil {
			return ""
		}
		return env(k)
	}
	home, _ := os.UserHomeDir()
	cfgDir, _ := os.UserConfigDir()
	xdg := ""
	if home != "" {
		xdg = filepath.Join(home, ".config")
	}
	at := func(base string, parts ...string) string {
		if base == "" {
			return ""
		}
		return filepath.Join(append([]string{base}, parts...)...)
	}
	userNpmrc := getenv("NPM_CONFIG_USERCONFIG")
	if userNpmrc == "" {
		userNpmrc = at(home, ".npmrc")
	}
	f.read(secfeed.ConfNpmrcUser, userNpmrc)
	f.read(secfeed.ConfNpmrcGlobal, firstExisting(append([]string{getenv("NPM_CONFIG_GLOBALCONFIG")}, globalNpmrcPaths()...)...))
	f.read(secfeed.ConfYarnrcUser, at(home, ".yarnrc.yml"))
	f.read(secfeed.ConfYarn1User, at(home, ".yarnrc"))
	f.read(secfeed.ConfBunfigUser, firstExisting(at(home, ".bunfig.toml"), at(xdg, ".bunfig.toml")))
	cargoHome := getenv("CARGO_HOME")
	if cargoHome == "" {
		cargoHome = at(home, ".cargo")
	}
	f.read(secfeed.ConfCargoUser, firstExisting(at(cargoHome, "config.toml"), at(cargoHome, "config")))
	f.read(secfeed.ConfNuGetUser, firstExisting(at(home, ".nuget", "NuGet", "NuGet.Config"), at(home, "AppData", "Roaming", "NuGet", "NuGet.Config")))
	// pip reads every one of these that exists; PIP_CONFIG_FILE is one
	// more (read in addition, which is only ever more private).
	f.readAll(secfeed.ConfPipUser, getenv("PIP_CONFIG_FILE"),
		at(xdg, "pip", "pip.conf"), at(home, ".pip", "pip.conf"),
		at(home, "Library", "Application Support", "pip", "pip.conf"),
		at(home, "AppData", "Roaming", "pip", "pip.ini"), at(cfgDir, "pip", "pip.conf"))
	f.readAll(secfeed.ConfPipGlobal, depsGlobalPipPaths()...)
	if venv := getenv("VIRTUAL_ENV"); venv != "" {
		f.readAll(secfeed.ConfPipVenv, at(venv, "pip.conf"), at(venv, "pip.ini"))
	}
	uvUser := getenv("UV_CONFIG_FILE")
	if uvUser == "" {
		uvUser = at(cfgDir, "uv", "uv.toml")
	}
	f.read(secfeed.ConfUVUser, uvUser)
	if x := at(xdg, "uv", "uv.toml"); x != uvUser {
		f.read(secfeed.ConfUVUserXDG, x)
	}
	// The go env file: what `go env GOENV` prints, without running go.
	goenv := getenv("GOENV")
	if goenv == "" {
		goenv = at(cfgDir, "go", "env")
	}
	if goenv != "off" {
		f.read(secfeed.ConfGoEnv, goenv)
	}
	return f
}

// depsGlobalPipPaths are pip's machine-wide files.
func depsGlobalPipPaths() []string {
	out := []string{"/etc/pip.conf", "/etc/xdg/pip/pip.conf", "/Library/Application Support/pip/pip.conf"}
	if pd := os.Getenv("PROGRAMDATA"); pd != "" {
		out = append(out, filepath.Join(pd, "pip", "pip.ini"))
	}
	return out
}

// depsPrivInput is one directory's files and the user files under one
// environment, merged (the single-directory form the tests read).
func depsPrivInput(projectRoot string, env func(string) string, environ func() []string) secfeed.PrivConfigInput {
	in := secfeed.PrivConfigInput{Files: map[secfeed.ConfigFile][]byte{}, Unreadable: map[secfeed.ConfigFile]bool{}, Env: env, Environ: environ}
	depsUserFiles(env).into(&in)
	depsProjectFiles(projectRoot).into(&in)
	return in
}

// hookDepsScope is the hook's classification scope for an install: the
// project root, every directory whose configuration applies (the working
// directory and each cd, --prefix, -C, --cwd, --dir or --manifest-path
// target, and a manifest's own directory, each walked up to the project
// root), and the hook's own source-naming variables. No project root is a
// scope with nothing public; no working directory (except for a manifest
// edit at an absolute path) is an Unknown scope, so nothing is public.
func hookDepsScope(req hookctx.InstallRequest, environ []string) secfeed.Scope {
	root := filepath.Clean(req.ProjectRoot)
	if req.ProjectRoot == "" || !filepath.IsAbs(root) {
		return secfeed.Scope{}
	}
	s := secfeed.Scope{ProjectRoot: root, Env: secfeed.ScopeEnv(environ)}
	ev := req.Event
	base := root
	_, _, manifest := secfeed.EventSpecs(ev)
	switch {
	case ev != nil && ev.Cwd != "":
		base = ev.Cwd
		if !filepath.IsAbs(base) {
			base = filepath.Join(root, base)
		}
		base = filepath.Clean(base)
	case manifest && filepath.IsAbs(ev.Target):
		// A manifest edit at an absolute path: the configuration that
		// applies is its own directory's chain, below; no working
		// directory is needed.
	default:
		// No working directory: the install may run anywhere under the
		// root, whose configuration is not known, so the names are
		// private (lane SEC-DEPS3 item 9), never classified as "the root".
		s.Unknown = true
	}
	targets := []string{base}
	if extra, unknown := secfeed.InstallDirs(ev, base); unknown {
		s.Unknown = true
	} else {
		targets = append(targets, extra...)
	}
	if manifest {
		t := ev.Target
		if !filepath.IsAbs(t) {
			t = filepath.Join(base, t)
		}
		targets = append(targets, filepath.Dir(filepath.Clean(t)))
	}
	seen := map[string]bool{root: true}
	for _, t := range targets {
		chain, ok := depsDirChain(t, root)
		if !ok {
			s.Unknown = true
		}
		for _, d := range chain {
			if !seen[d] {
				seen[d] = true
				s.Dirs = append(s.Dirs, d)
			}
		}
	}
	if len(s.Dirs) > secfeed.MaxScopeDirs {
		s.Unknown, s.Dirs = true, s.Dirs[:secfeed.MaxScopeDirs]
	}
	return s
}

// depsDirChain returns dir and its parents up to root (inclusive), with a
// directory that exists spelled with its symlinks resolved (the way the
// root is). A directory outside the root walks up to the filesystem root;
// a chain over depsScopeMaxDepth is cut and reported not ok.
func depsDirChain(dir, root string) ([]string, bool) {
	dir = filepath.Clean(dir)
	if r, err := filepath.EvalSymlinks(dir); err == nil {
		dir = r
	}
	var out []string
	for range depsScopeMaxDepth {
		out = append(out, dir)
		if dir == root {
			return out, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return out, true
		}
		dir = parent
	}
	return out, false
}

// depsConfirmed records, per project, the names an ask classified public
// (the hook's classifier and the daemon's both): the only names a prefetch
// sends (X4: never the raw dependency list of a manifest). It lives in
// memory; a restart starts empty, so a prefetch then sends nothing until
// the hook has asked.
type depsConfirmed struct {
	mu    sync.Mutex
	roots map[string]*depsConfirmedRoot
	tick  uint64
}

// depsConfirmedRoot is one project's record.
type depsConfirmedRoot struct {
	scope secfeed.Scope
	names map[string]bool
	seen  uint64
}

// Caps on the record.
const (
	depsConfirmedRoots = 64
	depsConfirmedNames = 1024
)

// confirmedKey keys a name by ecosystem and normalized name (any version).
func confirmedKey(eco secfeed.Ecosystem, name string) string {
	return string(eco) + "\x00" + secfeed.Normalize(eco, name)
}

// add records public names for a scope's project.
func (c *depsConfirmed) add(scope secfeed.Scope, specs []secfeed.InstallSpec) {
	if c == nil || scope.ProjectRoot == "" || len(specs) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.roots == nil {
		c.roots = map[string]*depsConfirmedRoot{}
	}
	c.tick++
	r, ok := c.roots[scope.ProjectRoot]
	if !ok {
		if len(c.roots) >= depsConfirmedRoots {
			oldest, at := "", ^uint64(0)
			for k, v := range c.roots {
				if v.seen < at {
					oldest, at = k, v.seen
				}
			}
			delete(c.roots, oldest)
		}
		r = &depsConfirmedRoot{names: map[string]bool{}}
		c.roots[scope.ProjectRoot] = r
	}
	r.scope, r.seen = scope, c.tick
	for _, s := range specs {
		if len(r.names) >= depsConfirmedNames {
			break
		}
		r.names[confirmedKey(s.Eco, s.Name)] = true
	}
}

// filter returns the scope last seen for root and the specs among in whose
// names were confirmed public there; ok is false for a root with none.
func (c *depsConfirmed) filter(root string, in []secfeed.InstallSpec) (secfeed.Scope, []secfeed.InstallSpec, bool) {
	if c == nil {
		return secfeed.Scope{}, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	r, ok := c.roots[root]
	if !ok {
		return secfeed.Scope{}, nil, false
	}
	var out []secfeed.InstallSpec
	for _, s := range in {
		if !s.Invalid && !s.Private && r.names[confirmedKey(s.Eco, s.Name)] {
			out = append(out, s)
		}
	}
	return r.scope, out, len(out) > 0
}
