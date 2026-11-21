package secfeed

import (
	"regexp"
	"slices"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// install.go reads agent-issued package installs from the guard shell
// parser's command units (security plan section 5.4): npm, pnpm, yarn and
// bun add and install, npx and the dlx forms, pip (and python -m pip), uv
// pip, uv add, uvx, pipx, poetry add, cargo add and install, go get and go
// install, gem install, composer require and dotnet add package. The
// parser has already unwrapped sudo, env, sh -c and the like, so a nested
// install is one more unit.

// InstallSpec is one package an install command names.
type InstallSpec struct {
	Eco Ecosystem
	// Spec is the word as the command gave it; Name and Version are what
	// it parses to (Version "" when unpinned). Invalid specs (a URL, a
	// path, a git spec) are kept with Invalid set: they are never sent
	// anywhere and never looked up.
	Spec    string
	Name    string
	Version string
	Invalid bool
	// Private reports that the command itself points this install at a
	// registry or index other than the default (a registry or index flag,
	// or an environment variable that sets one, on the command line): the
	// name may resolve on a private registry, so it is never sent to a
	// public registry or to the OSV API (X4). The gate, the ask channel
	// and Service.Answer all honour it.
	Private bool
}

// Installs is one event's parsed installs.
type Installs struct {
	Specs []InstallSpec
	// CustomRegistry reports a registry or index flag (or environment
	// variable) that points the install somewhere other than the default
	// (S-745, dependency confusion).
	CustomRegistry bool
	// IgnoreScripts reports that an npm-family install already passes
	// --ignore-scripts.
	IgnoreScripts bool
}

// MaxInstallSpecs caps the packages one online ask may name.
const MaxInstallSpecs = 64

// MaxParsedInstallSpecs caps the packages read from one event. It is well
// above policy.InstallChecksMax on purpose: Gate checks every parsed
// package against the offline index, so a known-malicious name cannot hide
// behind 64 others, and names the rest with one too_many_packages check
// (RB1 sweep finding P1). The event body itself is capped, so this bounds
// work, not what a reader sees.
const MaxParsedInstallSpecs = 1024

// installRow is one row of the install command table.
type installRow struct {
	// base is the canonical command name; subs the subcommand path that
	// must follow ("*" matches any one word: yarn workspace <name> add).
	base string
	subs []string
	eco  Ecosystem
	// first takes only the first positional after the subcommand (npx
	// runs one package; its other words are the package's arguments).
	first bool
	// create maps the first positional to the package a create or init
	// form runs (npm create vite runs create-vite); no positional is no
	// package.
	create bool
	// skip drops this many leading positionals (pipx inject <venv> pkg).
	skip int
	// withOnly reads packages from the --with flags only; positionals are
	// a script or a command (uv run --with x script.py).
	withOnly bool
	// needVersion keeps a positional only when it names a version (go run
	// mod@version downloads the module; go run ./cmd is local).
	needVersion bool
}

// installTable is THE install command table, one test case per row.
var installTable = []installRow{
	{base: "npm", subs: []string{"install"}, eco: EcoNpm},
	{base: "npm", subs: []string{"i"}, eco: EcoNpm},
	{base: "npm", subs: []string{"add"}, eco: EcoNpm},
	// npm's other spellings of install (npm install --help lists them) and
	// install-test, which installs the named packages before npm test.
	{base: "npm", subs: []string{"in"}, eco: EcoNpm},
	{base: "npm", subs: []string{"ins"}, eco: EcoNpm},
	{base: "npm", subs: []string{"inst"}, eco: EcoNpm},
	{base: "npm", subs: []string{"insta"}, eco: EcoNpm},
	{base: "npm", subs: []string{"instal"}, eco: EcoNpm},
	{base: "npm", subs: []string{"isnt"}, eco: EcoNpm},
	{base: "npm", subs: []string{"isnta"}, eco: EcoNpm},
	{base: "npm", subs: []string{"isntal"}, eco: EcoNpm},
	{base: "npm", subs: []string{"isntall"}, eco: EcoNpm},
	{base: "npm", subs: []string{"install-test"}, eco: EcoNpm},
	{base: "npm", subs: []string{"it"}, eco: EcoNpm},
	{base: "npm", subs: []string{"exec"}, eco: EcoNpm, first: true},
	{base: "npm", subs: []string{"x"}, eco: EcoNpm, first: true},
	{base: "npm", subs: []string{"create"}, eco: EcoNpm, create: true},
	{base: "npm", subs: []string{"init"}, eco: EcoNpm, create: true},
	{base: "npm", subs: []string{"innit"}, eco: EcoNpm, create: true},
	{base: "pnpm", subs: []string{"add"}, eco: EcoNpm},
	{base: "pnpm", subs: []string{"install"}, eco: EcoNpm},
	{base: "pnpm", subs: []string{"i"}, eco: EcoNpm},
	{base: "pnpm", subs: []string{"dlx"}, eco: EcoNpm, first: true},
	{base: "pnpm", subs: []string{"create"}, eco: EcoNpm, create: true},
	{base: "yarn", subs: []string{"add"}, eco: EcoNpm},
	{base: "yarn", subs: []string{"global", "add"}, eco: EcoNpm},
	{base: "yarn", subs: []string{"workspace", "*", "add"}, eco: EcoNpm},
	{base: "yarn", subs: []string{"dlx"}, eco: EcoNpm, first: true},
	{base: "yarn", subs: []string{"create"}, eco: EcoNpm, create: true},
	{base: "bun", subs: []string{"add"}, eco: EcoNpm},
	{base: "bun", subs: []string{"a"}, eco: EcoNpm},
	{base: "bun", subs: []string{"install"}, eco: EcoNpm},
	{base: "bun", subs: []string{"i"}, eco: EcoNpm},
	{base: "bun", subs: []string{"x"}, eco: EcoNpm, first: true},
	{base: "bun", subs: []string{"create"}, eco: EcoNpm, create: true},
	{base: "npx", eco: EcoNpm, first: true},
	{base: "pnpx", eco: EcoNpm, first: true},
	{base: "bunx", eco: EcoNpm, first: true},
	{base: "pip", subs: []string{"install"}, eco: EcoPyPI},
	{base: "uv", subs: []string{"pip", "install"}, eco: EcoPyPI},
	{base: "uv", subs: []string{"add"}, eco: EcoPyPI},
	{base: "uv", subs: []string{"tool", "install"}, eco: EcoPyPI, first: true},
	{base: "uv", subs: []string{"tool", "run"}, eco: EcoPyPI, first: true},
	{base: "uv", subs: []string{"run"}, eco: EcoPyPI, withOnly: true},
	{base: "uvx", eco: EcoPyPI, first: true},
	{base: "pipx", subs: []string{"install"}, eco: EcoPyPI},
	{base: "pipx", subs: []string{"run"}, eco: EcoPyPI, first: true},
	{base: "pipx", subs: []string{"inject"}, eco: EcoPyPI, skip: 1},
	{base: "poetry", subs: []string{"add"}, eco: EcoPyPI},
	{base: "cargo", subs: []string{"add"}, eco: EcoCargo},
	{base: "cargo", subs: []string{"install"}, eco: EcoCargo},
	{base: "go", subs: []string{"get"}, eco: EcoGo},
	{base: "go", subs: []string{"install"}, eco: EcoGo},
	{base: "go", subs: []string{"run"}, eco: EcoGo, first: true, needVersion: true},
	{base: "gem", subs: []string{"install"}, eco: EcoRubyGems},
	{base: "composer", subs: []string{"require"}, eco: EcoPackagist},
	{base: "composer", subs: []string{"global", "require"}, eco: EcoPackagist},
	{base: "dotnet", subs: []string{"add", "package"}, eco: EcoNuGet, first: true},
}

// valueFlagsByEco are flags whose next word is their value, so it is never
// read as a package.
var valueFlagsByEco = map[Ecosystem]map[string]bool{
	EcoNpm: set("--registry", "--tag", "-w", "--workspace", "--prefix", "-C", "--dir", "--cwd", "--filter", "-F", "--save-prefix", "-p", "--package",
		"--userconfig", "--globalconfig", "--cache", "--loglevel", "-c", "--call", "--workspace-dir"),
	EcoPyPI: set("-r", "--requirement", "-c", "--constraint", "-e", "--editable", "-i", "--index-url", "--extra-index-url",
		"--index", "--default-index", "-t", "--target", "--prefix", "-f", "--find-links", "--python", "-p", "--source",
		"--group", "-G", "--with", "--with-requirements", "--from", "--root", "--platform", "--trusted-host", "--cache-dir", "--src",
		"--proxy", "--log", "--retries", "--timeout", "--cert", "--client-cert", "--exists-action", "--directory", "--project",
		"--config-file", "--color", "--find-links-url", "--extra", "--suffix", "--spec"),
	EcoCargo: set("--registry", "--index", "--git", "--branch", "--tag", "--rev", "--path", "--features", "-F", "--root", "--version", "--vers",
		"--package", "-p", "--target", "--manifest-path", "--rename", "--config", "-Z", "--color", "-C"),
	EcoGo:        set("-C", "-modfile", "-o", "-tags", "-ldflags", "-gcflags", "-mod", "-p", "-pkgdir", "-exec", "-overlay", "-asmflags"),
	EcoRubyGems:  set("-s", "--source", "-v", "--version", "-i", "--install-dir", "--platform"),
	EcoPackagist: set("--repository", "-d", "--working-dir"),
	EcoNuGet:     set("-s", "--source", "-v", "--version", "-f", "--framework", "--package-directory"),
}

// registryFlags raise S-745 and make the unit's packages Private, by
// ecosystem: a registry or index, or a configuration file the daemon does
// not read.
var registryFlags = map[Ecosystem]map[string]bool{
	EcoNpm:       set("--registry", "--userconfig", "--globalconfig"),
	EcoPyPI:      set("-i", "--index-url", "--extra-index-url", "--index", "--default-index", "-f", "--find-links", "--source", "--config-file"),
	EcoCargo:     set("--registry", "--index", "--config"),
	EcoRubyGems:  set("-s", "--source"),
	EcoPackagist: set("--repository"),
	EcoNuGet:     set("-s", "--source"),
}

// registryEnvKeys are environment variables that redirect an install, or
// point it at a configuration file the daemon does not read (matched on
// the upper-cased name, so npm_config_registry counts too): S-745 and
// private.
var registryEnvKeys = set(
	"NPM_CONFIG_REGISTRY", "NPM_CONFIG_USERCONFIG", "NPM_CONFIG_GLOBALCONFIG",
	"YARN_NPM_REGISTRY_SERVER", "YARN_REGISTRY", "YARN_RC_FILENAME",
	"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "PIP_CONFIG_FILE",
	"UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_FIND_LINKS", "UV_CONFIG_FILE",
	"GOPROXY", "GOPRIVATE", "GONOPROXY", "GONOSUMDB",
	"CARGO_REGISTRY_DEFAULT", "BUN_CONFIG_REGISTRY",
	"GEM_SOURCE", "BUNDLE_MIRROR__ALL", "COMPOSER_HOME", "NUGET_PACKAGES",
)

// privateOnlyEnvKeys move where a package manager reads its configuration
// (GOENV, CARGO_HOME): the line's packages are private, because that
// configuration is not the one the daemon read, but the variable names no
// registry, so it is not S-745 (lane SEC-D1FIX2 milestone 2d). GOFLAGS
// names no source at all and is neither.
var privateOnlyEnvKeys = set("GOENV", "CARGO_HOME")

// registryEnvPrefixes are variable name prefixes that redirect an install
// (a scoped npm registry, a named Cargo registry, a Poetry or uv source).
var registryEnvPrefixes = []string{"NPM_CONFIG_@", "CARGO_REGISTRIES_", "POETRY_REPOSITORIES_", "POETRY_SOURCE_", "UV_INDEX_", "YARN_NPM_SCOPES"}

// envEffect reads one NAME=value word: private reports that it makes the
// line's packages private, custom that it also names another registry
// (S-745). A PowerShell "$env:NAME=value" word counts the same.
func envEffect(word string) (private, custom bool) {
	if len(word) > 5 && strings.EqualFold(word[:5], "$env:") {
		word = word[5:]
	}
	name, _, ok := strings.Cut(word, "=")
	if !ok || name == "" {
		return false, false
	}
	name = strings.ToUpper(name)
	switch {
	case registryEnvKeys[name]:
		return true, true
	case privateOnlyEnvKeys[name]:
		return true, false
	case strings.HasPrefix(name, "NPM_CONFIG_") && strings.Contains(name, "REGISTRY"):
		return true, true
	}
	for _, p := range registryEnvPrefixes {
		if strings.HasPrefix(name, p) {
			return true, true
		}
	}
	return false, false
}

// exportBases are the shell words that set a variable for the commands
// after them (export X=1 && npm i x; set X=1 & pip install x).
var exportBases = set("export", "set", "declare", "typeset")

// exportedEffect reads what a unit sets for the units after it: export,
// set and declare words, and every shape policy.ExportedEnv reads
// (PowerShell's `$env:NAME = "v"` with or without spaces, `Set-Item
// env:NAME v`, setx, [Environment]::SetEnvironmentVariable).
func exportedEffect(c *policy.Command) (private, custom bool) {
	if len(c.Argv) == 0 {
		return false, false
	}
	words := policy.ExportedEnv(c)
	if exportBases[c.Base] {
		words = append(words, c.Argv[1:]...)
	}
	for _, w := range words {
		p, cu := envEffect(w)
		private, custom = private || p, custom || cu
	}
	return private, custom
}

// configRedirect is one row of the config-then-install table: a unit that
// writes a package manager's configuration so that a later install on the
// same line resolves elsewhere (`npm config set registry x && npm i y`).
// match reads the unit's words after the command name.
type configRedirect struct {
	base  string
	match func(args []string) bool
}

// configRedirectTable is THE config-then-install table, one test case per
// row (lane SEC-D1FIX2 milestone 2b).
var configRedirectTable = []configRedirect{
	{"npm", npmConfigSet},
	{"pnpm", npmConfigSet},
	{"yarn", npmConfigSet},
	{"bun", npmConfigSet},
	{"pip", func(a []string) bool {
		pos := positional(a, pipConfigValueFlags)
		if len(pos) >= 2 && pos[0] == "config" && pos[1] == "edit" {
			return true
		}
		return len(pos) >= 2 && pos[0] == "config" && pos[1] == "set" &&
			anyWord(wordsAfter(a, "set"), "index-url", "index_url", "find-links", "find_links")
	}},
	{"uv", func(a []string) bool { return wordsAt(a, "pip", "config") }},
	{"go", func(a []string) bool {
		if len(a) == 0 || a[0] != "env" || !slices.Contains(a, "-w") {
			return false
		}
		for _, w := range a[1:] {
			if _, custom := envEffect(w); custom {
				return true
			}
		}
		return false
	}},
	{"poetry", func(a []string) bool {
		return wordsAt(a, "source", "add") || (wordsAt(a, "config") && len(a) > 1 && anyWord(a[1:], "repositories.", "source"))
	}},
	{"cargo", func(a []string) bool { return wordsAt(a, "config", "set") }},
}

// npmConfigSet matches `npm config set <key>` (also `npm c set`, and with
// a value flag before the verb: `npm config --location project set`),
// `npm set <key>` and the pnpm, yarn and bun spellings, for a key that
// names a registry or a config file (registry, @scope:registry,
// npmRegistryServer, npmScopes, userconfig), and `npm config edit`, which
// may write any key (lane SEC-DEPS3 item 10).
//
// A flag before the verb that the table does not know may or may not take
// a value (pnpm's -w is boolean, npm's -w names a workspace), so the words
// are read three ways: known value flags, every flag boolean, and every
// flag taking the next word. Any reading that finds a redirect counts, so
// an unknown flag fails private, never public.
func npmConfigSet(a []string) bool {
	every := map[string]bool{}
	for _, w := range a {
		if strings.HasPrefix(w, "-") {
			every[w] = true
		}
	}
	for _, flags := range []map[string]bool{npmConfigValueFlags, nil, every} {
		if npmConfigSetWith(a, positional(a, flags)) {
			return true
		}
	}
	return false
}

// npmConfigSetWith is npmConfigSet over one reading of the positional
// words.
func npmConfigSetWith(a, pos []string) bool {
	switch {
	case len(pos) >= 2 && (pos[0] == "config" || pos[0] == "c") && pos[1] == "edit":
		return true
	case len(pos) >= 2 && (pos[0] == "config" || pos[0] == "c") && pos[1] == "set",
		len(pos) >= 1 && pos[0] == "set":
		return anyWord(wordsAfter(a, "set"), "registry", "npmscopes", "userconfig", "globalconfig")
	}
	return false
}

// npmConfigValueFlags and pipConfigValueFlags are the flags of the config
// verbs that take the next word as their value, so that value is not read
// as the verb.
var (
	npmConfigValueFlags = set("--location", "-L", "--userconfig", "--globalconfig", "--prefix", "--cwd", "--dir", "-C", "-w", "--workspace")
	pipConfigValueFlags = set("--editor")
)

// positional returns the words that are neither flags nor a value flag's
// value (a "--flag=value" word carries its own value).
func positional(args []string, valueFlags map[string]bool) []string {
	var pos []string
	for i := 0; i < len(args); i++ {
		w := args[i]
		if strings.HasPrefix(w, "-") {
			if valueFlags[w] {
				i++
			}
			continue
		}
		pos = append(pos, w)
	}
	return pos
}

// wordsAfter returns the words after the first word equal to verb.
func wordsAfter(args []string, verb string) []string {
	for i, w := range args {
		if w == verb {
			return args[i+1:]
		}
	}
	return nil
}

// wordsAt reports whether the positional words (flags skipped) start with
// want.
func wordsAt(args []string, want ...string) bool {
	var pos []string
	for _, w := range args {
		if !strings.HasPrefix(w, "-") {
			pos = append(pos, w)
		}
		if len(pos) == len(want) {
			break
		}
	}
	return slices.Equal(pos, want)
}

// anyWord reports whether a word contains one of the (lower-case) parts.
func anyWord(words []string, parts ...string) bool {
	for _, w := range words {
		lw := strings.ToLower(w)
		for _, p := range parts {
			if strings.Contains(lw, p) {
				return true
			}
		}
	}
	return false
}

// redirectsConfig reports whether a unit is a config-then-install row.
func redirectsConfig(c *policy.Command) bool {
	base, argv := normalizeBase(c)
	if len(argv) == 0 {
		return false
	}
	for _, r := range configRedirectTable {
		if r.base == base && r.match(argv[1:]) {
			return true
		}
	}
	return false
}

func set(items ...string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

// ParseInstalls reads the installs out of an event (a shell command); any
// other event kind has none.
func ParseInstalls(ev *policy.Event) Installs {
	if ev == nil || ev.Kind != policy.KindShellExec {
		return Installs{}
	}
	var cmds []policy.Command
	if len(ev.Args) > 0 {
		cmds = policy.ParseArgv(ev.Args, ev.Dialect)
	} else {
		cmds = policy.ParseCommand(ev.Target, ev.Dialect)
	}
	return InstallsFromCommands(cmds)
}

// UnpinnedInstallEcosystem reports the ecosystem of the first install in
// cmds that names a package with no version (or "latest"): the detector
// cmd/observer registers as internal/secshellrisk's LangInstalls.
func UnpinnedInstallEcosystem(cmds []policy.Command) (string, bool) {
	for _, s := range InstallsFromCommands(cmds).Specs {
		if !s.Invalid && (s.Version == "" || strings.EqualFold(s.Version, "latest")) {
			return string(s.Eco), true
		}
	}
	return "", false
}

// InstallsFromCommands reads the installs out of parsed command units. A
// registry or index flag, or a variable that sets one (on the unit itself,
// through env, or exported by an earlier unit of the same command), makes
// every package of that unit Private (X4).
func InstallsFromCommands(cmds []policy.Command) Installs {
	var out Installs
	exported, exportedCustom := false, false
	for i := range cmds {
		c := &cmds[i]
		if p, cu := exportedEffect(c); p {
			exported, exportedCustom = true, exportedCustom || cu
			continue
		}
		if redirectsConfig(c) {
			exported, exportedCustom = true, true
			continue
		}
		row, rest, pre, ok := matchInstall(c)
		if !ok {
			continue
		}
		redirect, custom := exported, exportedCustom
		for _, e := range c.Env {
			p, cu := envEffect(e)
			redirect, custom = redirect || p, custom || cu
		}
		specs, argCustom, ignore := readInstallArgs(row, rest)
		_, preCustom, preIgnore := readInstallArgs(installRow{eco: row.eco}, pre)
		redirect = redirect || argCustom || preCustom
		out.CustomRegistry = out.CustomRegistry || custom || argCustom || preCustom
		out.IgnoreScripts = out.IgnoreScripts || ignore || preIgnore
		for _, s := range specs {
			if len(out.Specs) >= MaxParsedInstallSpecs {
				break
			}
			if redirect && !s.Invalid {
				s.Private = true
			}
			out.Specs = append(out.Specs, s)
		}
	}
	return out
}

// pythonBase matches a Python interpreter name (python, python3, py,
// python3.12); pipBase a pip name (pip, pip3, pip3.12).
var (
	pythonBase = regexp.MustCompile(`^(python|py)[0-9.]*$`)
	pipBase    = regexp.MustCompile(`^pip[0-9.]*$`)
)

// normalizeBase maps the interpreter forms to their row base: python -m
// pip (with interpreter flags before -m), pip3.12 and python3.12 -m pip
// all read as pip.
func normalizeBase(c *policy.Command) (string, []string) {
	base, argv := c.Base, c.Argv
	if pipBase.MatchString(base) {
		return "pip", argv
	}
	if !pythonBase.MatchString(base) {
		return base, argv
	}
	for j := 1; j+1 < len(argv) && j < 6; j++ {
		w := argv[j]
		if w == "-m" {
			if pipBase.MatchString(argv[j+1]) {
				return "pip", append([]string{argv[j+1]}, argv[j+2:]...)
			}
			return base, argv
		}
		if !strings.HasPrefix(w, "-") {
			break
		}
	}
	return base, argv
}

// matchInstall finds the row for a unit and returns the words after its
// subcommand path, and the flags before it (pre). Global flags before the
// subcommand are skipped, value-taking ones with their value (pnpm
// --filter web add x, npm --prefix app install x, cargo +nightly install
// x). When a value flag's value is itself the subcommand word, the word is
// read as the subcommand: an ambiguous unit is checked, never skipped.
func matchInstall(c *policy.Command) (installRow, []string, []string, bool) {
	base, argv := normalizeBase(c)
	if len(argv) == 0 {
		return installRow{}, nil, nil, false
	}
	for _, row := range installTable {
		if row.base != base {
			continue
		}
		vf := valueFlagsByEco[row.eco]
		rest := argv[1:]
		var pre []string
		matched := true
		for _, sub := range row.subs {
			j := 0
			for j < len(rest) {
				w := rest[j]
				if row.eco == EcoCargo && strings.HasPrefix(w, "+") {
					j++
					continue
				}
				if !strings.HasPrefix(w, "-") || w == "-" {
					break
				}
				if !strings.Contains(w, "=") && vf[w] && j+1 < len(rest) && rest[j+1] != sub {
					j += 2
					continue
				}
				j++
			}
			if j >= len(rest) || (sub != "*" && rest[j] != sub) {
				matched = false
				break
			}
			pre = append(pre, rest[:j]...)
			rest = rest[j+1:]
		}
		if !matched && row.base == "dotnet" {
			// dotnet add <project> package NAME
			if len(argv) >= 4 && argv[1] == "add" && argv[3] == "package" {
				return row, argv[4:], nil, true
			}
		}
		if matched {
			return row, rest, pre, true
		}
	}
	return installRow{}, nil, nil, false
}

// argState is readInstallArgs' running state.
type argState struct {
	specs          []InstallSpec
	custom, ignore bool
	pkgFlag        bool
}

// flag reads one flag word (and its value word, when it takes one) and
// reports whether the next word was consumed.
func (st *argState) flag(row installRow, w, next string, hasNext bool) bool {
	name, value, hasValue := strings.Cut(w, "=")
	if registryFlags[row.eco][name] || attachedRegistryFlag(row.eco, name) {
		st.custom = true
	}
	if name == "--ignore-scripts" {
		st.ignore = true
	}
	v := value
	if !hasValue && hasNext {
		v = next
	}
	switch {
	case row.eco == EcoNpm && (name == "--package" || name == "-p"),
		row.eco == EcoPyPI && (name == "--from" || name == "--spec"):
		// npx --package=x cmd, npm exec -p x, uvx --from x cmd: the package
		// is the value.
		if v != "" {
			st.specs = append(st.specs, ParseSpec(row.eco, v))
			st.pkgFlag = true
		}
	case row.eco == EcoPyPI && name == "--with":
		// uvx --with x cmd, uv run --with x,y script: extra packages.
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				st.specs = append(st.specs, ParseSpec(row.eco, p))
			}
		}
	}
	return !hasValue && valueFlagsByEco[row.eco][name] && hasNext
}

// attachedRegistryFlag reports the registry flag spellings a table lookup
// cannot see: an npm `--@scope:registry`, pnpm's `--config.registry=` (and
// `--config.@scope:registry`, `--config.userconfig`), and pip's short `-i`
// and `-f` with the value attached (`-ihttps://...`).
func attachedRegistryFlag(eco Ecosystem, name string) bool {
	switch eco {
	case EcoNpm:
		if strings.HasPrefix(name, "--@") && strings.HasSuffix(name, ":registry") {
			return true
		}
		if rest, ok := strings.CutPrefix(name, "--config."); ok {
			return anyWord([]string{rest}, "registry", "userconfig", "globalconfig")
		}
	case EcoPyPI:
		return len(name) > 2 && (strings.HasPrefix(name, "-i") || strings.HasPrefix(name, "-f")) && name[1] != '-'
	}
	return false
}

// readInstallArgs reads a row's package words.
func readInstallArgs(row installRow, words []string) (specs []InstallSpec, custom, ignore bool) {
	var st argState
	positional := 0
	for i := 0; i < len(words); i++ {
		w := words[i]
		if w == "--" {
			continue
		}
		if strings.HasPrefix(w, "-") && len(w) > 1 {
			next, hasNext := "", i+1 < len(words)
			if hasNext {
				next = words[i+1]
			}
			if st.flag(row, w, next, hasNext) {
				i++
			}
			continue
		}
		if row.withOnly {
			// uv run: the positionals are a script or a command.
			break
		}
		positional++
		if positional <= row.skip {
			continue
		}
		if row.first && st.pkgFlag {
			// npx --package=x cmd: cmd is a binary of x, not a package.
			break
		}
		switch {
		case row.create:
			st.specs = append(st.specs, ParseSpec(row.eco, createPackage(w)))
		case row.needVersion && !strings.Contains(w, "@"):
		default:
			st.specs = append(st.specs, ParseSpec(row.eco, w))
		}
		if row.first || row.create {
			break
		}
	}
	return st.specs, st.custom, st.ignore
}

// createPackage maps a create or init initializer to the package it runs
// (npm's rule): vite -> create-vite, @scope -> @scope/create,
// @scope/app -> @scope/create-app; a version stays attached.
func createPackage(w string) string {
	if looksLikeLocation(w) {
		return w
	}
	name, ver := w, ""
	if i := strings.LastIndex(w, "@"); i > 0 {
		name, ver = w[:i], w[i:]
	}
	switch {
	case strings.HasPrefix(name, "@") && !strings.Contains(name, "/"):
		name += "/create"
	case strings.HasPrefix(name, "@"):
		scope, rest, _ := strings.Cut(name, "/")
		name = scope + "/create-" + rest
	default:
		name = "create-" + name
	}
	return name + ver
}

// ParseSpec splits one package word into name and version, marking a URL,
// path or git spec invalid.
func ParseSpec(eco Ecosystem, spec string) InstallSpec {
	s := InstallSpec{Eco: eco, Spec: spec}
	t := strings.TrimSpace(spec)
	if t == "" || strings.ContainsAny(t, " \t\r\n\x00") || looksLikeLocation(t) {
		s.Invalid = true
		return s
	}
	switch eco {
	case EcoNpm:
		t = strings.TrimPrefix(t, "npm:")
		name, ver := t, ""
		if i := strings.LastIndex(t, "@"); i > 0 {
			name, ver = t[:i], t[i+1:]
		}
		if strings.Count(name, "/") > 1 || (strings.Contains(name, "/") && !strings.HasPrefix(name, "@")) {
			s.Invalid = true // user/repo is a GitHub shorthand
			return s
		}
		s.Name, s.Version = name, exactVersion(ver)
	case EcoPyPI:
		if strings.Contains(t, "@") || strings.Contains(t, "://") {
			s.Invalid = true // a direct reference
			return s
		}
		name := t
		if i := strings.IndexAny(name, "[;"); i >= 0 {
			name = name[:i]
		}
		ver := ""
		if i := strings.Index(name, "=="); i > 0 {
			name, ver = name[:i], name[i+2:]
		}
		if i := strings.IndexAny(name, "<>=!~"); i > 0 {
			name = name[:i]
		}
		s.Name, s.Version = strings.TrimSpace(name), strings.TrimSpace(ver)
	case EcoGo:
		name, ver, _ := strings.Cut(t, "@")
		if strings.HasPrefix(name, ".") || !strings.Contains(name, ".") || !strings.Contains(name, "/") {
			// a local package pattern ("./...") or a std package
			s.Invalid = true
			return s
		}
		if ver == "latest" || ver == "upgrade" || ver == "patch" {
			ver = ""
		}
		s.Name, s.Version = name, ver
	case EcoCargo, EcoRubyGems:
		name, ver, _ := strings.Cut(t, "@")
		if eco == EcoRubyGems {
			name, ver, _ = strings.Cut(t, ":")
		}
		s.Name, s.Version = name, exactVersion(ver)
	case EcoPackagist:
		name, ver, _ := strings.Cut(t, ":")
		if !strings.Contains(name, "/") {
			s.Invalid = true
			return s
		}
		s.Name, s.Version = name, exactVersion(ver)
	case EcoNuGet:
		s.Name = t
	}
	if s.Name == "" || len(s.Name) > 214 {
		s.Invalid = true
	}
	return s
}

// exactVersion keeps a version only when it is exact (no range operator,
// no tag): a range resolves to whatever the registry picks.
func exactVersion(v string) string {
	if v == "" || strings.ContainsAny(v, "^~<>=*| xX") || v == "latest" || v == "next" {
		return ""
	}
	return v
}

// looksLikeLocation reports a URL, path, git spec or archive (the JSP-11
// classifier's "invalid" rows): never a registry name.
func looksLikeLocation(spec string) bool {
	l := strings.ToLower(spec)
	for _, p := range []string{"http://", "https://", "git+", "git:", "git@", "github:", "gitlab:", "bitbucket:", "gist:", "file:", "link:", "./", "../", "/", "~/", "workspace:", "portal:", "patch:"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	return strings.HasSuffix(l, ".tgz") || strings.HasSuffix(l, ".tar.gz") || strings.HasSuffix(l, ".whl") ||
		strings.HasSuffix(l, ".zip") || strings.HasSuffix(l, ".gem") || strings.HasSuffix(l, ".nupkg") ||
		strings.Contains(l, "\\") || (len(l) > 1 && l[1] == ':')
}
