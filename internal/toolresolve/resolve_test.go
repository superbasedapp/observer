package toolresolve

import (
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

const (
	exeMode = fs.FileMode(0o755)
	regMode = fs.FileMode(0o644)
)

// fakeInfo is a minimal fs.FileInfo for staged files.
type fakeInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeInfo) Name() string       { return f.name }
func (f fakeInfo) Size() int64        { return 0 }
func (f fakeInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return nil }

// fakeFS is a map-backed filesystem for the injected Env funcs.
type fakeFS struct {
	files    map[string]fs.FileMode // regular files present (with perm bits)
	symlinks map[string]string      // path -> EvalSymlinks target
	globs    map[string][]string    // glob pattern -> matched dirs
}

func (f fakeFS) stat(p string) (fs.FileInfo, error) {
	m, ok := f.files[p]
	if !ok {
		return nil, fs.ErrNotExist
	}
	return fakeInfo{name: filepath.Base(p), mode: m}, nil
}

func (f fakeFS) eval(p string) (string, error) {
	if r, ok := f.symlinks[p]; ok {
		return r, nil
	}
	if _, ok := f.files[p]; ok {
		return p, nil
	}
	return "", fs.ErrNotExist
}

func (f fakeFS) glob(pattern string) ([]string, error) { return f.globs[pattern], nil }

func (f fakeFS) env(base Env) Env {
	base.Stat = f.stat
	base.EvalSymlinks = f.eval
	base.Glob = f.glob
	return base
}

// p converts a POSIX-spelled fixture path into an absolute path for the test
// host. The resolver drops PATH entries that fail filepath.IsAbs and joins
// probe dirs with filepath.Join, so on Windows a fixture like "/usr/bin" must
// become C:\usr\bin for the fake FS keys, the Env dirs and the expected Bin
// to agree. On unix hosts it is the identity (DI-20, 2026-09-02).
func p(posix string) string {
	if runtime.GOOS != "windows" {
		return posix
	}
	return filepath.Join("C:"+string(filepath.Separator), filepath.FromSlash(posix))
}

func specOpencode() integration.BinaryResolveSpec {
	return integration.BinaryResolveSpec{
		Names: integration.BinaryNames{
			Unix:    []string{"opencode"},
			Windows: []string{"opencode.cmd", "opencode"},
		},
	}
}

func containsNote(notes []string, sub string) bool {
	for _, n := range notes {
		if strings.Contains(n, sub) {
			return true
		}
	}
	return false
}

func consideredHas(cs []Candidate, path string) bool {
	for _, c := range cs {
		if c.Path == path {
			return true
		}
	}
	return false
}

func TestResolve(t *testing.T) {
	t.Parallel()

	shim := p("/mnt/c/Users/u/AppData/Roaming/npm/opencode")
	shimCmd := p("/mnt/c/Users/u/AppData/Roaming/npm/opencode.cmd")

	tests := []struct {
		name  string
		spec  integration.BinaryResolveSpec
		fs    fakeFS
		env   Env
		check func(t *testing.T, r Resolution)
		// posixOnly marks a case whose expectations depend on the /mnt bind
		// semantics of a WSL host (underMnt is POSIX by design); the case is
		// skipped on a Windows test host rather than rewritten.
		posixOnly bool
	}{
		{
			name:      "a1 native on PATH after shim -> shadowed",
			posixOnly: true,
			spec:      specOpencode(),
			fs: fakeFS{files: map[string]fs.FileMode{
				shim:                         exeMode,
				p("/usr/local/bin/opencode"): exeMode,
			}},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ProcessPath: []string{p("/mnt/c/Users/u/AppData/Roaming/npm"), p("/usr/local/bin")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictShadowed {
					t.Fatalf("verdict = %q, want shadowed", r.Verdict)
				}
				if r.Bin != p("/usr/local/bin/opencode") {
					t.Errorf("bin = %q", r.Bin)
				}
				if len(r.Shadowing) != 1 || r.Shadowing[0].Path != shim {
					t.Errorf("shadowing = %+v", r.Shadowing)
				}
				// F11: a shadowed verdict must ALSO populate Notes (surfaces
				// that render only Notes, e.g. the dashboard dialog, need it),
				// naming the shim and the native binary being used.
				if !containsNote(r.Notes, "interop shim") || !containsNote(r.Notes, shim) {
					t.Errorf("shadowed notes missing shim line: %v", r.Notes)
				}
				if !containsNote(r.Notes, p("/usr/local/bin/opencode")) {
					t.Errorf("shadowed notes missing native-bin line: %v", r.Notes)
				}
			},
		},
		{
			name:      "a2 native only via probe -> ok_off_path with shadowing",
			posixOnly: true,
			spec:      specOpencode(),
			fs: fakeFS{files: map[string]fs.FileMode{
				shim:                                   exeMode,
				p("/home/u/.hermes/node/bin/opencode"): exeMode,
			}},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ProcessPath: []string{p("/mnt/c/Users/u/AppData/Roaming/npm"), p("/usr/local/bin")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != p("/home/u/.hermes/node/bin/opencode") {
					t.Errorf("bin = %q", r.Bin)
				}
				if len(r.Shadowing) != 1 {
					t.Errorf("shadowing = %+v (want the /mnt shim)", r.Shadowing)
				}
				if !containsNote(r.Notes, "interop shim") {
					t.Errorf("notes missing shim warning: %v", r.Notes)
				}
				if !containsNote(r.Notes, "not on PATH") {
					t.Errorf("notes missing hygiene line: %v", r.Notes)
				}
				if !consideredHas(r.Considered, shim) {
					t.Errorf("considered trail lost the shim: %+v", r.Considered)
				}
			},
		},
		{
			name:      "b foreign shim on PATH only -> foreign_only",
			posixOnly: true,
			spec:      specOpencode(),
			fs:        fakeFS{files: map[string]fs.FileMode{shim: exeMode}},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ProcessPath: []string{p("/mnt/c/Users/u/AppData/Roaming/npm")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictForeignOnly {
					t.Fatalf("verdict = %q, want foreign_only", r.Verdict)
				}
				if r.Bin != "" {
					t.Errorf("bin = %q, want empty", r.Bin)
				}
			},
		},
		{
			name:      "b2 foreign-home probe hit -> foreign_only",
			posixOnly: true,
			spec:      specOpencode(),
			fs:        fakeFS{files: map[string]fs.FileMode{shimCmd: regMode}},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ForeignHomes: []string{p("/mnt/c/Users/u")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictForeignOnly {
					t.Fatalf("verdict = %q, want foreign_only", r.Verdict)
				}
				if !consideredHas(r.Considered, shimCmd) {
					t.Errorf("foreign probe hit missing from trail: %+v", r.Considered)
				}
			},
		},
		{
			name: "c1 not_found filters installs to linux",
			spec: integration.BinaryResolveSpec{
				Names: integration.BinaryNames{Unix: []string{"opencode"}},
				Installs: []integration.InstallHint{
					{OS: "linux", Channel: "npm", Display: "npm i -g opencode-ai"},
					{OS: "windows", Channel: "npm", Display: "npm i -g opencode-ai (win)"},
					{OS: "", Channel: "script", Display: "curl … | bash"},
				},
			},
			fs:  fakeFS{},
			env: Env{GOOS: "linux", ProcessPath: []string{p("/usr/local/bin")}},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictNotFound {
					t.Fatalf("verdict = %q, want not_found", r.Verdict)
				}
				if len(r.Installs) != 2 { // linux + any-OS
					t.Errorf("installs = %+v (want linux + any)", r.Installs)
				}
			},
		},
		{
			name: "c2 not_found filters all installs out on darwin",
			spec: integration.BinaryResolveSpec{
				Names: integration.BinaryNames{Unix: []string{"opencode"}},
				Installs: []integration.InstallHint{
					{OS: "linux", Display: "npm i -g x"},
					{OS: "windows", Display: "win"},
				},
			},
			fs:  fakeFS{},
			env: Env{GOOS: "darwin", ProcessPath: []string{p("/usr/local/bin")}},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictNotFound {
					t.Fatalf("verdict = %q", r.Verdict)
				}
				if len(r.Installs) != 0 {
					t.Errorf("installs = %+v (want none on darwin)", r.Installs)
				}
			},
		},
		{
			name: "d login-only dir finds fresh install -> ok_off_path",
			spec: specOpencode(),
			fs:   fakeFS{files: map[string]fs.FileMode{p("/home/u/.volta/bin/opencode"): exeMode}},
			env: Env{
				GOOS: "linux", Home: p("/home/u"),
				ProcessPath: []string{p("/usr/bin")},
				LoginPath:   func() ([]string, error) { return []string{p("/usr/bin"), p("/home/u/.volta/bin")}, nil },
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != p("/home/u/.volta/bin/opencode") {
					t.Errorf("bin = %q", r.Bin)
				}
				if r.Chosen == nil || r.Chosen.Origin != OriginLoginPath {
					t.Errorf("chosen origin = %+v, want login_path", r.Chosen)
				}
			},
		},
		{
			name: "e login capture error -> note, resolution proceeds",
			spec: specOpencode(),
			fs:   fakeFS{files: map[string]fs.FileMode{p("/usr/local/bin/opencode"): exeMode}},
			env: Env{
				GOOS: "linux", Home: p("/home/u"),
				ProcessPath: []string{p("/usr/local/bin")},
				LoginPath:   func() ([]string, error) { return nil, errBoom },
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOK {
					t.Fatalf("verdict = %q, want ok", r.Verdict)
				}
				if !containsNote(r.Notes, "login-shell PATH not merged") {
					t.Errorf("notes missing login-merge failure: %v", r.Notes)
				}
			},
		},
		{
			name:      "f native symlink into /mnt -> foreign_only",
			posixOnly: true,
			spec:      specOpencode(),
			fs: fakeFS{
				files:    map[string]fs.FileMode{p("/home/u/.local/bin/opencode"): exeMode},
				symlinks: map[string]string{p("/home/u/.local/bin/opencode"): shim},
			},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ProcessPath: []string{p("/home/u/.local/bin")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictForeignOnly {
					t.Fatalf("verdict = %q, want foreign_only", r.Verdict)
				}
			},
		},
		{
			name: "g macOS: /mnt-looking path is NOT foreign",
			spec: specOpencode(),
			fs:   fakeFS{files: map[string]fs.FileMode{p("/mnt/weird/bin/opencode"): exeMode}},
			env: Env{
				GOOS: "darwin", WSL: false,
				ProcessPath: []string{p("/mnt/weird/bin")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOK {
					t.Fatalf("verdict = %q, want ok (no WSL classification)", r.Verdict)
				}
				if r.Bin != p("/mnt/weird/bin/opencode") {
					t.Errorf("bin = %q", r.Bin)
				}
			},
		},
		{
			name: "h GOOS=windows uses Names.Windows (no exec bit needed)",
			spec: specOpencode(),
			fs:   fakeFS{files: map[string]fs.FileMode{p("/opt/tools/opencode.cmd"): regMode}},
			env: Env{
				GOOS: "windows", WSL: false, Home: "",
				ProcessPath: []string{p("/opt/tools")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOK {
					t.Fatalf("verdict = %q, want ok", r.Verdict)
				}
				if !strings.HasSuffix(r.Bin, "opencode.cmd") {
					t.Errorf("bin = %q, want the .cmd Windows spelling", r.Bin)
				}
			},
		},
		{
			name: "i empty and relative PATH entries dropped",
			spec: specOpencode(),
			fs:   fakeFS{files: map[string]fs.FileMode{"relative/bin/opencode": exeMode}},
			env: Env{
				GOOS: "linux", Home: "",
				ProcessPath: []string{"", ".", "relative/bin"},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictNotFound {
					t.Fatalf("verdict = %q, want not_found (relative/empty dropped)", r.Verdict)
				}
			},
		},
		{
			name: "j glob probe dir match -> ok_off_path",
			spec: specOpencode(),
			fs: fakeFS{
				files: map[string]fs.FileMode{p("/home/u/.nvm/versions/node/v20/bin/opencode"): exeMode},
				globs: map[string][]string{
					p("/home/u/.nvm/versions/node/*/bin"): {p("/home/u/.nvm/versions/node/v20/bin")},
				},
			},
			env: Env{GOOS: "linux", Home: p("/home/u"), ProcessPath: nil},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != p("/home/u/.nvm/versions/node/v20/bin/opencode") {
					t.Errorf("bin = %q", r.Bin)
				}
			},
		},
		{
			name: "k ok happy path",
			spec: specOpencode(),
			fs:   fakeFS{files: map[string]fs.FileMode{p("/usr/local/bin/opencode"): exeMode}},
			env:  Env{GOOS: "linux", WSL: false, Home: p("/home/u"), ProcessPath: []string{p("/usr/local/bin")}},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOK {
					t.Fatalf("verdict = %q, want ok", r.Verdict)
				}
				if r.Bin != p("/usr/local/bin/opencode") || r.Chosen == nil {
					t.Errorf("bin = %q chosen = %+v", r.Bin, r.Chosen)
				}
				if len(r.Shadowing) != 0 {
					t.Errorf("shadowing = %+v, want empty", r.Shadowing)
				}
			},
		},
		{
			// F8 direction 1: a /mnt PATH entry whose EvalSymlinks target is a
			// NATIVE path is NOT foreign — classify by the resolved location,
			// not the entry dir. (/mnt/c/bin/opencode → /usr/local/bin/opencode.)
			name:      "l /mnt PATH entry symlinked to a native target -> ok (not foreign)",
			posixOnly: true,
			spec:      specOpencode(),
			fs: fakeFS{
				files:    map[string]fs.FileMode{p("/mnt/c/bin/opencode"): exeMode},
				symlinks: map[string]string{p("/mnt/c/bin/opencode"): p("/usr/local/bin/opencode")},
			},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ProcessPath: []string{p("/mnt/c/bin")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOK {
					t.Fatalf("verdict = %q, want ok (real target is native)", r.Verdict)
				}
				if r.Bin != p("/mnt/c/bin/opencode") {
					t.Errorf("bin = %q, want the on-PATH entry path", r.Bin)
				}
			},
		},
		{
			// F8 direction 2: a native-dir entry whose EvalSymlinks target
			// lands under /mnt stays foreign (the resolved location is foreign).
			// (~/.local/bin/opencode → /mnt/c/...) — verdict foreign_only.
			name:      "m native-dir entry symlinked into /mnt -> foreign_only",
			posixOnly: true,
			spec:      specOpencode(),
			fs: fakeFS{
				files:    map[string]fs.FileMode{p("/home/u/.local/bin/opencode"): exeMode},
				symlinks: map[string]string{p("/home/u/.local/bin/opencode"): p("/mnt/c/Users/u/AppData/Roaming/npm/opencode")},
			},
			env: Env{
				GOOS: "linux", WSL: true, Home: p("/home/u"),
				ProcessPath: []string{p("/home/u/.local/bin")},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictForeignOnly {
					t.Fatalf("verdict = %q, want foreign_only (real target under /mnt)", r.Verdict)
				}
			},
		},
		{
			// F9: filepath.Glob returns nvm vNN dirs in lexical ASCENDING order
			// (v18 before v22); the resolver sorts DESCENDING so the newer
			// version wins.
			name: "n glob yields v18 + v22 -> picks v22's binary",
			spec: specOpencode(),
			fs: fakeFS{
				files: map[string]fs.FileMode{
					p("/home/u/.nvm/versions/node/v18/bin/opencode"): exeMode,
					p("/home/u/.nvm/versions/node/v22/bin/opencode"): exeMode,
				},
				globs: map[string][]string{
					p("/home/u/.nvm/versions/node/*/bin"): {
						p("/home/u/.nvm/versions/node/v18/bin"),
						p("/home/u/.nvm/versions/node/v22/bin"),
					},
				},
			},
			env: Env{GOOS: "linux", Home: p("/home/u"), ProcessPath: nil},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != p("/home/u/.nvm/versions/node/v22/bin/opencode") {
					t.Errorf("bin = %q, want v22 (newest-first glob order)", r.Bin)
				}
			},
		},
		{
			// R3: numeric-aware sort — a plain reverse-lexical sort mispicks
			// v20.9.0 ahead of v20.11.0 ("9" > "1"); the comparator treats the
			// digit runs as integers so v20.11.0 wins.
			name: "o glob yields v20.9.0 + v20.11.0 -> picks v20.11.0",
			spec: specOpencode(),
			fs: fakeFS{
				files: map[string]fs.FileMode{
					p("/home/u/.nvm/versions/node/v20.9.0/bin/opencode"):  exeMode,
					p("/home/u/.nvm/versions/node/v20.11.0/bin/opencode"): exeMode,
				},
				globs: map[string][]string{
					p("/home/u/.nvm/versions/node/*/bin"): {
						p("/home/u/.nvm/versions/node/v20.11.0/bin"),
						p("/home/u/.nvm/versions/node/v20.9.0/bin"),
					},
				},
			},
			env: Env{GOOS: "linux", Home: p("/home/u"), ProcessPath: nil},
			check: func(t *testing.T, r Resolution) {
				if r.Bin != p("/home/u/.nvm/versions/node/v20.11.0/bin/opencode") {
					t.Errorf("bin = %q, want v20.11.0 (numeric-aware newest-first)", r.Bin)
				}
			},
		},
		{
			// R2: PATHEXT precedence — with PATHEXT=.CMD;.EXE the .cmd spelling
			// resolves ahead of the .exe spelling in the SAME dir.
			name: "p windows PATHEXT=.CMD;.EXE picks x.cmd over x.exe",
			spec: integration.BinaryResolveSpec{
				Names: integration.BinaryNames{Windows: []string{"opencode.exe", "opencode.cmd"}},
			},
			fs: fakeFS{files: map[string]fs.FileMode{
				p("/opt/tools/opencode.exe"): regMode,
				p("/opt/tools/opencode.cmd"): regMode,
			}},
			env: Env{
				GOOS: "windows", Home: "",
				ProcessPath: []string{p("/opt/tools")},
				PathExt:     []string{".CMD", ".EXE"},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOK {
					t.Fatalf("verdict = %q, want ok", r.Verdict)
				}
				if !strings.HasSuffix(r.Bin, "opencode.cmd") {
					t.Errorf("bin = %q, want the .cmd spelling (PATHEXT order)", r.Bin)
				}
			},
		},
		{
			// DI-22: a native-Windows daemon walks the WINDOWS probe table —
			// before the split it walked the Unix table, where nothing exists.
			name: "q windows daemon walks the windows probe table",
			spec: specOpencode(),
			fs: fakeFS{files: map[string]fs.FileMode{
				p("/home/u/AppData/Roaming/npm/opencode.cmd"): regMode,
			}},
			env: Env{
				GOOS: "windows", Home: p("/home/u"),
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != p("/home/u/AppData/Roaming/npm/opencode.cmd") {
					t.Errorf("bin = %q", r.Bin)
				}
			},
		},
		{
			// A per-tool ProbeDir rooted at an environment variable rather than
			// HOME (kiro-cli's %ProgramFiles%\Kiro-Cli).
			name: "r windows EnvRoot probe dir is expanded from the environment",
			spec: integration.BinaryResolveSpec{
				Names: integration.BinaryNames{Windows: []string{"kiro-cli.exe"}},
				ProbeDirs: []integration.ProbeDir{
					{OS: integration.ProbeWindows, Rel: "Kiro-Cli", EnvRoot: "ProgramFiles"},
				},
			},
			fs: fakeFS{files: map[string]fs.FileMode{
				p("/pf/Kiro-Cli/kiro-cli.exe"): regMode,
			}},
			env: Env{
				GOOS: "windows", Home: p("/home/u"),
				Getenv: func(k string) string {
					if k == "ProgramFiles" {
						return p("/pf")
					}
					return ""
				},
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != p("/pf/Kiro-Cli/kiro-cli.exe") {
					t.Errorf("bin = %q", r.Bin)
				}
			},
		},
		{
			// An unset EnvRoot variable means the root does not exist on this
			// host: skip the dir rather than probing a bare Rel off the cwd.
			name: "s EnvRoot unset -> the probe dir is skipped",
			spec: integration.BinaryResolveSpec{
				Names: integration.BinaryNames{Windows: []string{"kiro-cli.exe"}},
				ProbeDirs: []integration.ProbeDir{
					{OS: integration.ProbeWindows, Rel: "Kiro-Cli", EnvRoot: "ProgramFiles"},
				},
			},
			fs: fakeFS{files: map[string]fs.FileMode{
				p("/pf/Kiro-Cli/kiro-cli.exe"): regMode,
			}},
			env: Env{
				GOOS: "windows", Home: p("/home/u"),
				Getenv: func(string) string { return "" },
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictNotFound {
					t.Fatalf("verdict = %q, want not_found", r.Verdict)
				}
				if consideredHas(r.Considered, p("/pf/Kiro-Cli/kiro-cli.exe")) {
					t.Error("an unset EnvRoot must not be probed")
				}
			},
		},
		{
			// The ABSOLUTE table (homebrew/snap/go), walked without a home join.
			name: "t abs probe dir (linuxbrew) -> ok_off_path",
			spec: specOpencode(),
			fs: fakeFS{files: map[string]fs.FileMode{
				absDir("/home/linuxbrew/.linuxbrew/bin", "opencode"): exeMode,
			}},
			env: Env{
				GOOS: "linux", Home: p("/home/u"),
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictOKOffPath {
					t.Fatalf("verdict = %q, want ok_off_path", r.Verdict)
				}
				if r.Bin != absDir("/home/linuxbrew/.linuxbrew/bin", "opencode") {
					t.Errorf("bin = %q", r.Bin)
				}
			},
		},
		{
			// …and the abs table is Unix-only: a Windows daemon must not walk
			// POSIX prefixes.
			name: "u abs probe list is skipped on a windows daemon",
			spec: specOpencode(),
			fs: fakeFS{files: map[string]fs.FileMode{
				absDir("/home/linuxbrew/.linuxbrew/bin", "opencode.cmd"): regMode,
			}},
			env: Env{
				GOOS: "windows", Home: p("/home/u"),
			},
			check: func(t *testing.T, r Resolution) {
				if r.Verdict != VerdictNotFound {
					t.Fatalf("verdict = %q, want not_found", r.Verdict)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.posixOnly && runtime.GOOS == "windows" {
				t.Skip("depends on WSL /mnt bind semantics; POSIX-only by design")
			}
			env := tc.fs.env(tc.env)
			r := Resolve(tc.spec, env)
			tc.check(t, r)
		})
	}
}

func TestFormatVerdict(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		pathFlag string
		r        Resolution
		wantSub  []string
		notSub   []string
	}{
		{
			name:     "ok",
			pathFlag: "--opencode-path",
			r:        Resolution{Verdict: VerdictOK, Bin: "/usr/local/bin/opencode"},
			wantSub:  []string{"found at", "/usr/local/bin/opencode"},
		},
		{
			name:     "shadowed names shim and native",
			pathFlag: "--opencode-path",
			r: Resolution{
				Verdict:   VerdictShadowed,
				Bin:       "/usr/local/bin/opencode",
				Shadowing: []Candidate{{Path: "/mnt/c/Users/u/AppData/Roaming/npm/opencode"}},
			},
			wantSub: []string{"shim", "/mnt/c/Users/u/AppData/Roaming/npm/opencode", "native", "/usr/local/bin/opencode"},
		},
		{
			name:     "foreign_only with install names the exact flag escape hatch",
			pathFlag: "--opencode-path",
			r: Resolution{
				Verdict:  VerdictForeignOnly,
				Installs: []integration.InstallHint{{Display: "npm i -g opencode-ai"}},
			},
			wantSub: []string{
				"installed on Windows", "not in WSL", "npm i -g opencode-ai", "planned follow-up",
				// F10 escape hatch: the exact caller-owned flag + config key.
				"force it", "--opencode-path", "[launch.tools.opencode].path",
			},
		},
		{
			name:     "foreign_only no grounded command",
			pathFlag: "--opencode-path",
			r:        Resolution{Verdict: VerdictForeignOnly},
			wantSub:  []string{"no grounded install command"},
		},
		{
			name:     "not_found lists install + overrides with the exact flag",
			pathFlag: "--opencode-path",
			r: Resolution{
				Verdict:  VerdictNotFound,
				Installs: []integration.InstallHint{{Display: "npm i -g opencode-ai"}},
			},
			wantSub: []string{"not installed", "npm i -g opencode-ai", "--opencode-path", "[launch.tools.opencode].path"},
		},
		{
			// F10: an empty pathFlag (a caller that owns no flag, e.g. the
			// doctor) omits the flag suggestion and names only the config key —
			// never a fabricated "--opencode-path".
			name:     "not_found empty pathFlag omits flag, keeps config key",
			pathFlag: "",
			r: Resolution{
				Verdict:  VerdictNotFound,
				Installs: []integration.InstallHint{{Display: "npm i -g opencode-ai"}},
			},
			wantSub: []string{"not installed", "[launch.tools.opencode].path"},
			notSub:  []string{"--opencode-path", "pass "},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := FormatVerdict("opencode", tc.pathFlag, tc.r)
			for _, sub := range tc.wantSub {
				if !strings.Contains(out, sub) {
					t.Errorf("output missing %q:\n%s", sub, out)
				}
			}
			for _, sub := range tc.notSub {
				if strings.Contains(out, sub) {
					t.Errorf("output unexpectedly contains %q:\n%s", sub, out)
				}
			}
		})
	}
}

func TestOrderNamesByPathExt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		names   []string
		pathExt []string
		want    []string
	}{
		{
			name:    "cmd before exe by PATHEXT index",
			names:   []string{"x.exe", "x.cmd"},
			pathExt: []string{".CMD", ".EXE"},
			want:    []string{"x.cmd", "x.exe"},
		},
		{
			name:    "nil PATHEXT keeps spec order (exe first)",
			names:   []string{"x.exe", "x.cmd"},
			pathExt: nil,
			want:    []string{"x.exe", "x.cmd"},
		},
		{
			name:    "bare name sorts last",
			names:   []string{"x", "x.exe"},
			pathExt: []string{".EXE"},
			want:    []string{"x.exe", "x"},
		},
		{
			name:    "unrecognized extensions keep relative order after listed",
			names:   []string{"x.bat", "x.exe", "x.cmd"},
			pathExt: []string{".EXE"},
			want:    []string{"x.exe", "x.bat", "x.cmd"},
		},
		{
			name:    "case-insensitive extension match",
			names:   []string{"X.EXE", "x.cmd"},
			pathExt: []string{".CMD", ".EXE"},
			want:    []string{"x.cmd", "X.EXE"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := orderNamesByPathExt(tc.names, tc.pathExt)
			if len(got) != len(tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestCompareVersionDirs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"minor 9 before 11", "v20.9.0", "v20.11.0", -1},
		{"minor 11 after 9", "v20.11.0", "v20.9.0", 1},
		{"major 9 before 10", "v9", "v10", -1},
		{"major 10 after 9", "v10", "v9", 1},
		{"equal", "v20.9.0", "v20.9.0", 0},
		{"leading zeros ignored", "v20.09.0", "v20.9.0", 0},
		{"non-version dirs compare equal (stable)", "current", "lts", 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := compareVersionDirs(tc.a, tc.b); got != tc.want {
				t.Errorf("compareVersionDirs(%q, %q) = %d, want %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

// errBoom is a stable sentinel for the login-capture-failure case.
var errBoom = fsErr("boom")

type fsErr string

func (e fsErr) Error() string { return string(e) }
