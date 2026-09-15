package toolresolve

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// Verdict is the classified outcome of a resolution. The five values are a
// closed vocabulary shared verbatim by the launcher, doctor, and dashboard so
// one honest string is rendered everywhere.
type Verdict string

const (
	// VerdictOK: a native binary is first on PATH — launch it, no note.
	VerdictOK Verdict = "ok"
	// VerdictOKOffPath: a native binary was found, but via a probe dir or a
	// login-only PATH entry rather than the process PATH — launchable, with a
	// PATH-hygiene note (and, if a foreign shim also sits earlier on PATH, a
	// note naming it).
	VerdictOKOffPath Verdict = "ok_off_path"
	// VerdictShadowed: a native binary exists on the process PATH but a /mnt
	// interop shim precedes it — still launchable (Bin is the native hit), the
	// shims are recorded in Shadowing.
	VerdictShadowed Verdict = "shadowed"
	// VerdictForeignOnly: only a Windows install exists (on PATH or under a
	// Windows home over /mnt) — NOT launchable by a Linux daemon. Bin is empty;
	// the guided fix is a native install.
	VerdictForeignOnly Verdict = "foreign_only"
	// VerdictNotFound: nothing anywhere.
	VerdictNotFound Verdict = "not_found"
)

// Origin records where a Candidate was found, for the evidence trail and the
// verdict rules. It is a closed vocabulary.
type Origin string

const (
	// OriginProcessPath: a dir from the daemon's own process PATH.
	OriginProcessPath Origin = "process_path"
	// OriginLoginPath: a dir present only on the login-shell PATH (merged in
	// from a $SHELL -lc capture), not on the process PATH.
	OriginLoginPath Origin = "login_path"
	// OriginProbeDir: a native HOME-relative probe dir (common table or a
	// per-tool extra).
	OriginProbeDir Origin = "probe_dir"
	// OriginForeignPath: reserved for a foreign-classified PATH hit; the
	// resolver leaves such hits under their PATH origin (process/login) and
	// counts them as foreign evidence, so this value is part of the vocabulary
	// downstream may key on but is not produced by Resolve today.
	OriginForeignPath Origin = "foreign_path"
	// OriginForeignProbe: a hit under a Windows user home reached over /mnt.
	OriginForeignProbe Origin = "foreign_probe"
)

// NoGroundedInstallMsg is the ONE sentence every surface renders when a tool
// carries no grounded install command for the daemon's OS. The registry's
// honesty rule is that a missing install hint is a zero value, never a
// fabricated command — so the launcher stderr (FormatVerdict), `observer
// doctor <tool>` (internal/diag) and the dashboard install dialog must all say
// exactly this, from here, rather than each spelling their own near-copy.
const NoGroundedInstallMsg = "no grounded install command — see the vendor's docs"

// shebangHeadBytes bounds the interpreter sniff: a "#!" line is the first line
// of the file and is far shorter than this, so reading more would only cost I/O
// on a real binary.
const shebangHeadBytes = 256

// Candidate is one binary the resolver found (or a foreign shim it saw). Real
// is the EvalSymlinks target ("" when it could not be resolved). Foreign marks
// a hit that lives under, or symlinks into, /mnt on a WSL daemon.
type Candidate struct {
	Path    string
	Real    string
	Origin  Origin
	Foreign bool
}

// Resolution is the full classified result. Bin is the launchable path (empty
// for foreign_only / not_found). Chosen points at the selected Candidate (nil
// when none). Shadowing lists the foreign PATH shims that precede the chosen
// binary. Considered is the complete ordered evidence trail. Installs are the
// grounded install hints filtered to the daemon OS. Notes are honest one-line
// advisories (login-merge failures, PATH hygiene, shim warnings).
// LoginOnlyDirs are the merged-PATH dirs contributed by the login shell that
// are NOT on the daemon's own process PATH — the launcher prepends them to a
// child's PATH so a `#!/usr/bin/env node` shim can find its interpreter
// (DI-04b). Interpreter is the `#!/usr/bin/env <name>` interpreter of Bin ("" for
// an absolute shebang, a non-script, or a nil Env.ReadHead).
type Resolution struct {
	Verdict       Verdict
	Bin           string
	Chosen        *Candidate
	Shadowing     []Candidate
	Considered    []Candidate
	Installs      []integration.InstallHint
	Notes         []string
	LoginOnlyDirs []string
	Interpreter   string
}

// Env is the injected I/O surface. Every field is data or a func so the
// resolver stays pure (imports_test.go pins it free of os/exec/sql/http). GOOS
// and WSL describe the daemon; Home is the native home; ForeignHomes are the
// Windows user homes reached over /mnt (empty off WSL). ProcessPath is the
// daemon's PATH split into dirs; LoginPath (nil when unavailable, e.g. on a
// Windows daemon) returns the login-shell PATH. PathExt is the Windows PATHEXT
// precedence list (uppercase extensions WITH dots, e.g. [".COM",".EXE",".BAT",
// ".CMD"]) used to order the Windows candidate spellings so resolution follows
// the operator's real PATHEXT rather than a hardcoded order; empty (the normal
// case off Windows) keeps the spec's candidate order. Stat/EvalSymlinks/Glob
// are the filesystem probes — each is nil-safe (a nil Stat resolves NO
// candidates, the honest "cannot tell", never an assumed hit; the same
// contract statDir documents). Getenv reads one environment variable (nil-safe;
// used ONLY to expand a ProbeDir.EnvRoot such as %ProgramFiles%, never to read
// PATH — that arrives as data in ProcessPath). NpmPrefix returns `npm prefix
// -g` (nil disables the probe; an error becomes an honest Note, never a
// failure). ReadHead reads the first n bytes of a file (nil disables the
// `#!/usr/bin/env` interpreter sniff).
type Env struct {
	GOOS         string
	WSL          bool
	Home         string
	ForeignHomes []string
	ProcessPath  []string
	PathExt      []string
	LoginPath    func() ([]string, error)
	Stat         func(string) (fs.FileInfo, error)
	EvalSymlinks func(string) (string, error)
	Glob         func(string) ([]string, error)
	Getenv       func(string) string
	NpmPrefix    func() (string, error)
	ReadHead     func(path string, n int) ([]byte, error)
}

// pathEntry is one merged-PATH dir plus which list it came from.
type pathEntry struct {
	dir   string
	login bool
}

// Resolve walks the resolution ladder for one tool and returns a classified
// Resolution. It is pure: all I/O comes through env. The ladder is merged PATH
// (process then login-only), then native probe dirs, then — on WSL — foreign
// Windows homes; the verdict table is then walked top-down over the ordered
// evidence trail.
func Resolve(spec integration.BinaryResolveSpec, env Env) Resolution {
	var notes []string

	names := candidateNames(spec, env.GOOS)
	if env.GOOS == "windows" {
		names = orderNamesByPathExt(names, env.PathExt)
	}
	merged := mergePath(env, &notes)

	var considered []Candidate

	// 1. PATH candidates (process then login-only), dir-outer × name-inner.
	for _, e := range merged {
		origin := OriginProcessPath
		if e.login {
			origin = OriginLoginPath
		}
		for _, name := range names {
			if c, ok := statCandidate(env, filepath.Join(e.dir, name), origin); ok {
				considered = append(considered, c)
			}
		}
	}

	// 2. Native probe dirs (OS-selected common table + per-tool extras + the
	// absolute table + the injected npm -g prefix).
	probeDirs := nativeProbeDirs(spec, env, &notes)
	for _, dir := range probeDirs {
		for _, name := range names {
			if c, ok := statCandidate(env, filepath.Join(dir, name), OriginProbeDir); ok {
				considered = append(considered, c)
			}
		}
	}

	// 3. Foreign probes: Windows homes over /mnt (WSL only, Windows names only).
	if env.WSL && len(spec.Names.Windows) > 0 {
		for _, home := range env.ForeignHomes {
			rels := append([]string{}, commonForeignWindowsDirs...)
			for _, pd := range spec.ProbeDirs {
				if pd.OS == integration.ProbeWindows {
					rels = append(rels, pd.Rel)
				}
			}
			for _, dir := range expandProbeDirs(env, home, rels) {
				for _, name := range spec.Names.Windows {
					if c, ok := statForeignCandidate(env, filepath.Join(dir, name)); ok {
						considered = append(considered, c)
					}
				}
			}
		}
	}

	res := classify(considered)
	res.Considered = considered
	res.Installs = filterInstalls(spec.Installs, env.GOOS)
	res.LoginOnlyDirs = loginOnlyDirs(merged)
	applyInterpreterNote(&res, env, merged, probeDirs)
	res.Notes = append(notes, res.Notes...)
	return res
}

// MergedPathDirs returns the ordered, deduped merged PATH the resolver walks —
// all is the process PATH followed by the login-only entries, login is just the
// login-only subset a launcher prepends to a child's PATH (DI-04b). It reuses
// the resolver's own mergePath so the launcher's PATH and the resolver's
// evidence trail can never drift apart (never a copy). A login-capture error is
// swallowed here (Resolve surfaces it as a Note); an empty/relative entry is
// dropped, as it is for resolution — a child must never resolve a binary from
// the daemon's cwd.
func MergedPathDirs(env Env) (all, login []string) {
	var discard []string
	merged := mergePath(env, &discard)
	for _, e := range merged {
		all = append(all, e.dir)
		if e.login {
			login = append(login, e.dir)
		}
	}
	return all, login
}

// loginOnlyDirs projects the login-contributed entries out of a merged PATH.
func loginOnlyDirs(merged []pathEntry) []string {
	var out []string
	for _, e := range merged {
		if e.login {
			out = append(out, e.dir)
		}
	}
	return out
}

// nativeProbeDirs builds the ordered ABSOLUTE probe dirs for the daemon's own
// OS: the OS-selected common HOME-relative table plus the per-tool extras for
// that OS (both joined to Home, skipped entirely when Home is unknown), then
// the per-tool ABSOLUTE and EnvRoot dirs (walked verbatim / rooted at an
// environment variable instead of HOME, the latter skipped when the variable is
// unset), then — off Windows — the absolute table, then the injected
// `npm prefix -g` dir. Glob segments are expanded newest-first. A failing npm
// probe appends an honest Note and is otherwise ignored.
func nativeProbeDirs(spec integration.BinaryResolveSpec, env Env, notes *[]string) []string {
	var dirs []string
	if env.Home != "" {
		rels := append([]string{}, nativeProbeTable(env.GOOS)...)
		for _, pd := range spec.ProbeDirs {
			if probeOSMatchesDaemon(pd.OS, env.GOOS) && !pd.Abs && pd.EnvRoot == "" {
				rels = append(rels, pd.Rel)
			}
		}
		for _, rel := range rels {
			dirs = append(dirs, filepath.Join(env.Home, rel))
		}
	}

	// Per-tool ABSOLUTE and EnvRoot dirs, resolved by SHAPE through the one
	// helper the GUI ladder also uses, so the two can never disagree about
	// what a ProbeDir means. The HOME-relative rows are already folded in
	// above (unchanged order); this pass contributes only the rows that have
	// a root other than HOME.
	for _, pd := range spec.ProbeDirs {
		if !probeOSMatchesDaemon(pd.OS, env.GOOS) || (!pd.Abs && pd.EnvRoot == "") {
			continue
		}
		dirs = append(dirs, resolveProbeDirRoot(pd, env)...)
	}

	// The absolute table is Unix-only (Homebrew/snap/go prefixes).
	if env.GOOS != "windows" {
		dirs = append(dirs, commonNativeAbsProbeDirs...)
	}

	// The npm -g prefix is a capability, not a tool fact: a binary found under
	// the operator's own npm prefix is evidence for EVERY tool, so the probe
	// runs unconditionally when the Env supplies it. On Windows npm lays the
	// shim trio directly in the prefix dir; elsewhere it uses <prefix>/bin.
	if env.NpmPrefix != nil {
		prefix, err := env.NpmPrefix()
		switch {
		case err != nil:
			*notes = append(*notes, fmt.Sprintf("npm prefix not probed: %v", err))
		case strings.TrimSpace(prefix) == "":
			// Nothing to probe; stay silent rather than invent a note.
		case env.GOOS == "windows":
			dirs = append(dirs, filepath.Clean(prefix))
		default:
			dirs = append(dirs, filepath.Join(prefix, "bin"))
		}
	}

	return expandGlobDirs(env, dirs)
}

// applyInterpreterNote records the chosen binary's `#!/usr/bin/env <name>`
// interpreter and, when that interpreter is NOT reachable from the daemon's own
// process PATH, appends the honest Note that explains the DI-04b failure class:
// the shim launches fine from an interactive shell and exits 127 under the
// daemon. It runs only for the launchable verdicts (ok / ok_off_path) — a tool
// that is not launchable has a bigger problem to report first.
func applyInterpreterNote(res *Resolution, env Env, merged []pathEntry, probeDirs []string) {
	if res.Bin == "" || (res.Verdict != VerdictOK && res.Verdict != VerdictOKOffPath) {
		return
	}
	interp := interpreterOf(env, res.Bin)
	if interp == "" {
		return
	}
	res.Interpreter = interp

	// On the daemon's own PATH ⇒ the child inherits a working interpreter.
	for _, e := range merged {
		if e.login {
			continue
		}
		if _, ok := statCandidate(env, filepath.Join(e.dir, interp), OriginProcessPath); ok {
			return
		}
	}
	// Off-PATH but reachable: name the dir the launcher will prepend.
	var search []string
	for _, e := range merged {
		if e.login {
			search = append(search, e.dir)
		}
	}
	search = append(search, probeDirs...)
	for _, dir := range search {
		if _, ok := statCandidate(env, filepath.Join(dir, interp), OriginProbeDir); ok {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"%s is a #!/usr/bin/env %s shim; %s is not on the daemon's PATH (found at %s) — "+
					"the launcher prepends that directory to the child's PATH; add it to the daemon's PATH to silence this",
				filepath.Base(res.Bin), interp, interp, dir,
			))
			return
		}
	}
	res.Notes = append(res.Notes, fmt.Sprintf(
		"%s is a #!/usr/bin/env %s shim; %s is not found anywhere on the merged PATH — "+
			"the child will fail at startup until %s is installed or added to PATH",
		filepath.Base(res.Bin), interp, interp, interp,
	))
}

// interpreterOf reads the head of bin and returns its `#!/usr/bin/env <name>`
// interpreter, or "" when no reader is injected, the read fails, or the file is
// not an env-shebang script.
func interpreterOf(env Env, bin string) string {
	if env.ReadHead == nil || bin == "" {
		return ""
	}
	head, err := env.ReadHead(bin, shebangHeadBytes)
	if err != nil {
		return ""
	}
	return parseEnvShebang(head)
}

// parseEnvShebang returns the interpreter NAME of a `#!/usr/bin/env <name>`
// shebang and "" for everything else. Only the first line is considered. An
// ABSOLUTE interpreter (`#!/home/u/.local/share/uv/tools/x/bin/python`, what uv
// writes) returns "" on purpose: such a script carries its own interpreter path
// and needs no PATH help. `env` flags (-S, -i, -u NAME, --) and leading
// NAME=VALUE assignments are skipped, so `#!/usr/bin/env -S node --enable-x`
// yields "node".
func parseEnvShebang(head []byte) string {
	s := string(head)
	if !strings.HasPrefix(s, "#!") {
		return ""
	}
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = s[:i]
	}
	fields := strings.Fields(strings.TrimSpace(s[2:]))
	if len(fields) == 0 {
		return ""
	}
	if filepath.Base(fields[0]) != "env" {
		return ""
	}
	for i := 1; i < len(fields); i++ {
		f := fields[i]
		switch {
		case f == "--":
			continue
		case f == "-u" || f == "--unset":
			i++ // -u takes a variable NAME operand
			continue
		case strings.HasPrefix(f, "-"):
			continue
		case strings.Contains(f, "="):
			continue // NAME=VALUE assignment, not the interpreter
		default:
			return filepath.Base(f)
		}
	}
	return ""
}

// classify walks the verdict table top-down over the ordered evidence trail.
func classify(considered []Candidate) Resolution {
	idxNativePath := -1
	idxNativeOffPath := -1
	var foreignPathIdx []int
	anyForeign := false

	for i, c := range considered {
		if c.Foreign {
			anyForeign = true
			if c.Origin == OriginProcessPath || c.Origin == OriginLoginPath {
				foreignPathIdx = append(foreignPathIdx, i)
			}
			continue
		}
		if c.Origin == OriginProcessPath && idxNativePath < 0 {
			idxNativePath = i
		}
		if (c.Origin == OriginLoginPath || c.Origin == OriginProbeDir) && idxNativeOffPath < 0 {
			idxNativeOffPath = i
		}
	}

	shadowBefore := func(idx int) []Candidate {
		var out []Candidate
		for _, fi := range foreignPathIdx {
			if fi < idx {
				out = append(out, considered[fi])
			}
		}
		return out
	}

	switch {
	case idxNativePath >= 0:
		chosen := considered[idxNativePath]
		shadow := shadowBefore(idxNativePath)
		res := Resolution{Bin: chosen.Path, Chosen: &considered[idxNativePath], Shadowing: shadow}
		if len(shadow) > 0 {
			res.Verdict = VerdictShadowed
			// Always record a Note (not just Shadowing) so surfaces that render
			// ONLY Notes (the dashboard dialog) still explain what happened —
			// mirror the ok_off_path shim-note wording.
			res.Notes = append(res.Notes, fmt.Sprintf(
				"a Windows interop shim is earlier on PATH (%s); using the native install %s instead",
				shadow[0].Path, chosen.Path,
			))
		} else {
			res.Verdict = VerdictOK
		}
		return res

	case idxNativeOffPath >= 0:
		chosen := considered[idxNativeOffPath]
		shadow := shadowBefore(idxNativeOffPath)
		res := Resolution{
			Verdict:   VerdictOKOffPath,
			Bin:       chosen.Path,
			Chosen:    &considered[idxNativeOffPath],
			Shadowing: shadow,
		}
		res.Notes = append(res.Notes, fmt.Sprintf(
			"%s resolved from %s, which is not on PATH — add it to PATH to silence this note",
			filepath.Base(chosen.Path), filepath.Dir(chosen.Path),
		))
		if len(shadow) > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf(
				"a Windows interop shim is earlier on PATH (%s); using the native install %s instead",
				shadow[0].Path, chosen.Path,
			))
		}
		return res

	case anyForeign:
		return Resolution{Verdict: VerdictForeignOnly}

	default:
		return Resolution{Verdict: VerdictNotFound}
	}
}

// candidateNames picks the binary spellings for the daemon OS, falling back to
// Unix names when a Windows daemon has no grounded Windows spelling.
func candidateNames(spec integration.BinaryResolveSpec, goos string) []string {
	if goos == "windows" && len(spec.Names.Windows) > 0 {
		return spec.Names.Windows
	}
	return spec.Names.Unix
}

// orderNamesByPathExt reorders Windows candidate spellings to follow the
// operator's PATHEXT precedence, since real Windows resolution consults PATHEXT
// (e.g. PATHEXT=.CMD;.EXE picks x.cmd over x.exe) rather than a fixed
// .exe/.cmd/bare order. Names whose extension is listed in pathExt sort first
// by that list's index (case-insensitive); names with an extension NOT in
// pathExt keep their relative order after those; a bare name (no extension)
// sorts last. An empty pathExt returns names unchanged, preserving the spec's
// default order. The input slice is not mutated.
func orderNamesByPathExt(names, pathExt []string) []string {
	if len(pathExt) == 0 || len(names) < 2 {
		return names
	}
	idx := make(map[string]int, len(pathExt))
	for i, e := range pathExt {
		up := strings.ToUpper(e)
		if _, ok := idx[up]; !ok {
			idx[up] = i
		}
	}
	rank := func(name string) int {
		ext := filepath.Ext(name)
		if ext == "" {
			return len(pathExt) + 1 // bare name: sorts last
		}
		if i, ok := idx[strings.ToUpper(ext)]; ok {
			return i
		}
		return len(pathExt) // extension not in PATHEXT: after the listed ones
	}
	out := append([]string{}, names...)
	sort.SliceStable(out, func(i, j int) bool {
		return rank(out[i]) < rank(out[j])
	})
	return out
}

// mergePath builds the ordered, deduped merged PATH: process entries first,
// then login-only entries. Empty and relative entries are dropped (never
// resolve a binary from cwd). A login-capture error appends a Note and the
// merge proceeds with the process PATH alone.
func mergePath(env Env, notes *[]string) []pathEntry {
	seen := map[string]bool{}
	var out []pathEntry
	add := func(raw string, login bool) {
		if raw == "" {
			return
		}
		c := filepath.Clean(raw)
		if !filepath.IsAbs(c) {
			return
		}
		if seen[c] {
			return
		}
		seen[c] = true
		out = append(out, pathEntry{dir: c, login: login})
	}
	for _, d := range env.ProcessPath {
		add(d, false)
	}
	if env.LoginPath != nil {
		login, err := env.LoginPath()
		if err != nil {
			*notes = append(*notes, fmt.Sprintf("login-shell PATH not merged (%v)", err))
		} else {
			for _, d := range login {
				add(d, true)
			}
		}
	}
	return out
}

// statCandidate stats path as a native (non-foreign) candidate: it must be a
// regular file and, on non-Windows, carry an execute bit. Real is the
// best-effort symlink target; Foreign is set when the path or its target lives
// under /mnt on a WSL daemon.
func statCandidate(env Env, path string, origin Origin) (Candidate, bool) {
	if env.Stat == nil {
		return Candidate{}, false
	}
	fi, err := env.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return Candidate{}, false
	}
	if env.GOOS != "windows" && fi.Mode().Perm()&0o111 == 0 {
		return Candidate{}, false
	}
	real := evalReal(env, path)
	// Classify by the RESOLVED location, not the entry dir: a candidate is
	// foreign iff where it ACTUALLY lives is under /mnt. Use Real when the
	// symlink resolved; fall back to Path otherwise. This keeps a /mnt PATH
	// entry that symlinks to a NATIVE binary (/mnt/c/bin/tool → /usr/local/
	// bin/tool) classified NATIVE, while a native-dir entry whose target lands
	// under /mnt (~/.local/bin/tool → /mnt/c/...) stays foreign.
	loc := real
	if loc == "" {
		loc = path
	}
	return Candidate{
		Path:    path,
		Real:    real,
		Origin:  origin,
		Foreign: env.WSL && underMnt(loc),
	}, true
}

// statForeignCandidate stats a hit under a Windows home over /mnt. It requires
// a regular file (no execute-bit gate — Windows binaries need none) and is
// always classified Foreign.
func statForeignCandidate(env Env, path string) (Candidate, bool) {
	if env.Stat == nil {
		return Candidate{}, false
	}
	fi, err := env.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return Candidate{}, false
	}
	return Candidate{
		Path:    path,
		Real:    evalReal(env, path),
		Origin:  OriginForeignProbe,
		Foreign: true,
	}, true
}

// evalReal resolves symlinks best-effort, returning "" on error or when no
// resolver is injected.
func evalReal(env Env, path string) string {
	if env.EvalSymlinks == nil {
		return ""
	}
	if r, err := env.EvalSymlinks(path); err == nil {
		return r
	}
	return ""
}

// expandProbeDirs joins each HOME-relative dir to home and glob-expands it.
func expandProbeDirs(env Env, home string, rels []string) []string {
	full := make([]string, 0, len(rels))
	for _, rel := range rels {
		full = append(full, filepath.Join(home, rel))
	}
	return expandGlobDirs(env, full)
}

// expandGlobDirs expands a single glob segment in each ABSOLUTE dir via
// env.Glob. Non-glob dirs pass through verbatim.
func expandGlobDirs(env Env, dirs []string) []string {
	var out []string
	for _, full := range dirs {
		if strings.Contains(full, "*") {
			if env.Glob != nil {
				if matches, err := env.Glob(full); err == nil {
					// Probe newest-first: sort DESCENDING so a higher version
					// dir wins over a lower one (filepath.Glob returns
					// nvm-style version dirs in lexical ASCENDING order, so
					// v18 would otherwise shadow v22). The comparison is
					// numeric-aware — each base is split into digit and
					// non-digit runs and compared run-by-run (digit runs as
					// integers) — so v20.11.0 correctly beats v20.9.0 and v10
					// beats v9, which a plain lexical sort gets wrong. It is
					// still NOT a full semver sort: prerelease tags compare
					// lexically.
					sort.SliceStable(matches, func(i, j int) bool {
						return compareVersionDirs(matches[i], matches[j]) > 0
					})
					out = append(out, matches...)
				}
			}
			continue
		}
		out = append(out, full)
	}
	return out
}

// compareVersionDirs orders two glob-matched paths with numeric-aware
// comparison, returning -1, 0, or 1 for a<b, a==b, a>b. The version component
// may be an interior path segment (e.g. .nvm/versions/node/v20.11.0/bin), so
// the WHOLE string is compared: each side is split into maximal digit and
// non-digit runs, and the runs are compared pairwise — digit runs as integers
// (leading zeros ignored), non-digit runs lexically — so v20.11.0 sorts AFTER
// v20.9.0 and v10 AFTER v9, which a plain lexical sort gets wrong. Two paths
// with no digit run on either side compare equal, so a stable sort leaves
// non-version dirs in their input order. It is numeric-aware, NOT a full semver
// sort: prerelease tags compare lexically.
func compareVersionDirs(a, b string) int {
	ra := splitDigitRuns(a)
	rb := splitDigitRuns(b)
	if !hasDigitRun(ra) && !hasDigitRun(rb) {
		return 0
	}
	n := len(ra)
	if len(rb) < n {
		n = len(rb)
	}
	for i := 0; i < n; i++ {
		x, y := ra[i], rb[i]
		if isDigits(x) && isDigits(y) {
			if c := compareNumeric(x, y); c != 0 {
				return c
			}
			continue
		}
		if c := strings.Compare(x, y); c != 0 {
			return c
		}
	}
	switch {
	case len(ra) < len(rb):
		return -1
	case len(ra) > len(rb):
		return 1
	default:
		return 0
	}
}

// splitDigitRuns splits s into maximal runs of digits and non-digits, in order.
func splitDigitRuns(s string) []string {
	var runs []string
	var cur strings.Builder
	var curDigit bool
	for i, r := range s {
		d := r >= '0' && r <= '9'
		if i > 0 && d != curDigit {
			runs = append(runs, cur.String())
			cur.Reset()
		}
		cur.WriteRune(r)
		curDigit = d
	}
	if cur.Len() > 0 {
		runs = append(runs, cur.String())
	}
	return runs
}

// compareNumeric compares two all-digit strings as unsigned integers without
// overflow: leading zeros are trimmed, then the longer value wins, else the
// two are compared lexically (equal length ⇒ same digit-magnitude ordering).
func compareNumeric(x, y string) int {
	x = strings.TrimLeft(x, "0")
	y = strings.TrimLeft(y, "0")
	if len(x) != len(y) {
		if len(x) < len(y) {
			return -1
		}
		return 1
	}
	return strings.Compare(x, y)
}

// isDigits reports whether s is non-empty and all ASCII digits.
func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// hasDigitRun reports whether any run in the split is all digits.
func hasDigitRun(runs []string) bool {
	for _, r := range runs {
		if isDigits(r) {
			return true
		}
	}
	return false
}

// underMnt reports whether an absolute path lives under the /mnt bind (a
// Windows drive reached from a WSL daemon). "" is never under /mnt.
func underMnt(p string) bool {
	if p == "" {
		return false
	}
	c := filepath.Clean(p)
	return c == "/mnt" || strings.HasPrefix(c, "/mnt/")
}

// filterInstalls keeps hints matching the daemon OS (or OS-agnostic hints).
func filterInstalls(hints []integration.InstallHint, goos string) []integration.InstallHint {
	want := goosToInstallOS(goos)
	var out []integration.InstallHint
	for _, h := range hints {
		if h.OS == "" || h.OS == want {
			out = append(out, h)
		}
	}
	return out
}

// goosToInstallOS maps a GOOS to an InstallHint.OS token.
func goosToInstallOS(goos string) string {
	switch goos {
	case "windows":
		return "windows"
	case "darwin":
		return "darwin"
	default:
		return "linux"
	}
}
