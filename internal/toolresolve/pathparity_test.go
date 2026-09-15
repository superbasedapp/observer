package toolresolve

import (
	"errors"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// TestMergedPathDirsOrdersProcessThenLogin pins the export the LAUNCHER
// consumes (DI-04b): the merged PATH is process entries first, login-only
// entries after, deduped, with empty/relative entries dropped — and the second
// return is exactly the login-only subset a child's PATH is widened with.
func TestMergedPathDirsOrdersProcessThenLogin(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		env       Env
		wantAll   []string
		wantLogin []string
	}{
		{
			name: "process first, login-only after, deduped",
			env: Env{
				ProcessPath: []string{p("/usr/bin"), p("/bin")},
				LoginPath: func() ([]string, error) {
					return []string{p("/usr/bin"), p("/home/u/.hermes/node/bin")}, nil
				},
			},
			wantAll:   []string{p("/usr/bin"), p("/bin"), p("/home/u/.hermes/node/bin")},
			wantLogin: []string{p("/home/u/.hermes/node/bin")},
		},
		{
			name: "empty and relative entries dropped from both lists",
			env: Env{
				ProcessPath: []string{"", p("/usr/bin"), "relative/dir"},
				LoginPath:   func() ([]string, error) { return []string{"", "also/relative", p("/opt/x")}, nil },
			},
			wantAll:   []string{p("/usr/bin"), p("/opt/x")},
			wantLogin: []string{p("/opt/x")},
		},
		{
			name:      "no login capture leaves the login subset empty",
			env:       Env{ProcessPath: []string{p("/usr/bin")}},
			wantAll:   []string{p("/usr/bin")},
			wantLogin: nil,
		},
		{
			name: "a failing login capture is swallowed here (Resolve notes it)",
			env: Env{
				ProcessPath: []string{p("/usr/bin")},
				LoginPath:   func() ([]string, error) { return nil, errors.New("boom") },
			},
			wantAll:   []string{p("/usr/bin")},
			wantLogin: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			all, login := MergedPathDirs(tc.env)
			if !equalStrings(all, tc.wantAll) {
				t.Errorf("all = %v, want %v", all, tc.wantAll)
			}
			if !equalStrings(login, tc.wantLogin) {
				t.Errorf("login = %v, want %v", login, tc.wantLogin)
			}
		})
	}
}

func equalStrings(a, b []string) bool {
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

// TestParseEnvShebang pins the interpreter sniff: only a `#!/usr/bin/env <name>`
// shebang yields a name; an ABSOLUTE interpreter (what uv writes) is
// self-contained and yields "".
func TestParseEnvShebang(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		head string
		want string
	}{
		{name: "env node", head: "#!/usr/bin/env node\nconsole.log(1)\n", want: "node"},
		{name: "env node no trailing newline", head: "#!/usr/bin/env node", want: "node"},
		{name: "env -S with interpreter flags", head: "#!/usr/bin/env -S node --enable-source-maps\n", want: "node"},
		{name: "env -u NAME skips the operand", head: "#!/usr/bin/env -u NODE_OPTIONS node\n", want: "node"},
		{name: "env -- ends options", head: "#!/usr/bin/env -- python3\n", want: "python3"},
		{name: "env NAME=VALUE assignment skipped", head: "#!/usr/bin/env FOO=bar node\n", want: "node"},
		{name: "absolute interpreter is self-contained", head: "#!/usr/bin/python3\n", want: ""},
		{name: "uv tool absolute shebang", head: "#!/home/u/.local/share/uv/tools/aider/bin/python\n", want: ""},
		{name: "env with an absolute interpreter arg is basenamed", head: "#!/usr/bin/env /usr/local/bin/node\n", want: "node"},
		{name: "non-script (ELF header)", head: "\x7fELF\x02\x01\x01\x00", want: ""},
		{name: "empty", head: "", want: ""},
		{name: "bare shebang with no interpreter", head: "#!\n", want: ""},
		{name: "env with no operand", head: "#!/usr/bin/env\n", want: ""},
		{name: "CRLF first line", head: "#!/usr/bin/env node\r\n", want: "node"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseEnvShebang([]byte(tc.head)); got != tc.want {
				t.Errorf("parseEnvShebang(%q) = %q, want %q", tc.head, got, tc.want)
			}
		})
	}
}

// TestParsePathMarkers pins the marker parser that makes the login capture
// banner-proof (the pre-marker code absorbed banner text into the PATH list).
func TestParsePathMarkers(t *testing.T) {
	t.Parallel()

	wrap := func(path string) string { return PathMarkBegin + path + PathMarkEnd }

	tests := []struct {
		name    string
		out     string
		want    []string
		wantErr bool
	}{
		{
			name: "banner before and after is discarded",
			out:  "Welcome to Ubuntu 24.04\n" + wrap("/usr/bin:/bin") + "\nnvm: done\n",
			want: []string{"/usr/bin", "/bin"},
		},
		{
			name: "empty entries dropped",
			out:  wrap("/usr/bin::/bin:"),
			want: []string{"/usr/bin", "/bin"},
		},
		{
			name: "empty PATH between markers is not an error",
			out:  wrap(""),
			want: nil,
		},
		{name: "missing begin marker", out: "/usr/bin" + PathMarkEnd, wantErr: true},
		{name: "missing end marker", out: PathMarkBegin + "/usr/bin", wantErr: true},
		{name: "no markers at all (a banner-only capture)", out: "some banner\n", wantErr: true},
		{
			name:    "duplicated marker pair (two attempts interleaved)",
			out:     wrap("/usr/bin") + wrap("/bin"),
			wantErr: true,
		},
		{
			name:    "end marker precedes begin marker",
			out:     PathMarkEnd + "/usr/bin" + PathMarkBegin,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParsePathMarkers(tc.out)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got %v", got)
				}
				if !errors.Is(err, ErrNoPathMarkers) {
					t.Errorf("err = %v, want ErrNoPathMarkers", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParsePathMarkers: %v", err)
			}
			if !equalStrings(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestProbeTablesAreSelectedByGOOS pins DI-22: the common probe table is chosen
// by the DAEMON's OS shape, and the two tables are genuinely different (a
// Windows daemon used to walk the Unix table, where nothing exists).
func TestProbeTablesAreSelectedByGOOS(t *testing.T) {
	t.Parallel()

	for _, goos := range []string{"linux", "darwin", "freebsd", ""} {
		if got := nativeProbeTable(goos); !sameTable(got, commonNativeProbeDirs) {
			t.Errorf("nativeProbeTable(%q) did not return the unix table", goos)
		}
	}
	if got := nativeProbeTable("windows"); !sameTable(got, commonWindowsNativeProbeDirs) {
		t.Error("nativeProbeTable(\"windows\") did not return the windows table")
	}

	if !hasEntry(commonWindowsNativeProbeDirs, "AppData/Roaming/npm") {
		t.Error("windows table lost the npm -g shim dir")
	}
	if hasEntry(commonNativeProbeDirs, "AppData/Roaming/npm") {
		t.Error("unix table must not carry a Windows AppData dir")
	}
	if !hasEntry(commonNativeProbeDirs, ".nvm/versions/node/*/bin") {
		t.Error("unix table lost the nvm glob dir")
	}
	if hasEntry(commonWindowsNativeProbeDirs, ".nvm/versions/node/*/bin") {
		t.Error("windows table must not carry the POSIX nvm dir")
	}
	// The WinGet Links dir must be visible BOTH natively and through a /mnt
	// Windows home (a WSL daemon's foreign probe).
	if !hasEntry(commonForeignWindowsDirs, "AppData/Local/Microsoft/WinGet/Links") {
		t.Error("foreign windows table lost the WinGet Links dir")
	}
}

func sameTable(a, b []string) bool { return equalStrings(a, b) }

func hasEntry(table []string, want string) bool {
	for _, e := range table {
		if e == want {
			return true
		}
	}
	return false
}

// TestShimInterpreterNote pins the DI-04b explanation: an npm shim whose
// `#!/usr/bin/env node` interpreter is missing from the DAEMON's process PATH
// launches fine and dies at exit 127, so the resolver says so up front. The
// negative case (interpreter on the process PATH) must stay silent.
func TestShimInterpreterNote(t *testing.T) {
	t.Parallel()

	bin := p("/home/u/.hermes/node/bin/opencode")
	loginDir := p("/home/u/.hermes/node/bin")
	shebang := []byte("#!/usr/bin/env node\n")

	tests := []struct {
		name        string
		files       map[string]fs.FileMode
		readHead    func(string, int) ([]byte, error)
		processPath []string
		loginPath   []string
		wantInterp  string
		wantNoteSub string
		wantNoNote  bool
	}{
		{
			name: "interpreter only on a login-only dir names that dir",
			files: map[string]fs.FileMode{
				bin:                                exeMode,
				p("/home/u/.hermes/node/bin/node"): exeMode,
			},
			readHead:    func(string, int) ([]byte, error) { return shebang, nil },
			processPath: []string{p("/usr/bin")},
			loginPath:   []string{loginDir},
			wantInterp:  "node",
			wantNoteSub: "node is not on the daemon's PATH (found at " + loginDir + ")",
		},
		{
			name: "interpreter on the process PATH -> no note",
			files: map[string]fs.FileMode{
				bin:                 exeMode,
				p("/usr/bin/node"):  exeMode,
				p("/usr/bin/other"): exeMode,
			},
			readHead:    func(string, int) ([]byte, error) { return shebang, nil },
			processPath: []string{p("/usr/bin"), loginDir},
			wantInterp:  "node",
			wantNoNote:  true,
		},
		{
			name:        "interpreter nowhere on the merged PATH",
			files:       map[string]fs.FileMode{bin: exeMode},
			readHead:    func(string, int) ([]byte, error) { return shebang, nil },
			processPath: []string{loginDir},
			wantInterp:  "node",
			wantNoteSub: "not found anywhere on the merged PATH",
		},
		{
			name:        "no ReadHead injected -> no interpreter, no note",
			files:       map[string]fs.FileMode{bin: exeMode},
			processPath: []string{loginDir},
			wantInterp:  "",
			wantNoNote:  true,
		},
		{
			name:        "a non-script binary yields no interpreter",
			files:       map[string]fs.FileMode{bin: exeMode},
			readHead:    func(string, int) ([]byte, error) { return []byte("\x7fELF"), nil },
			processPath: []string{loginDir},
			wantInterp:  "",
			wantNoNote:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ff := fakeFS{files: tc.files}
			env := ff.env(Env{
				GOOS:        "linux",
				Home:        p("/home/u"),
				ProcessPath: tc.processPath,
				ReadHead:    tc.readHead,
			})
			if tc.loginPath != nil {
				dirs := tc.loginPath
				env.LoginPath = func() ([]string, error) { return dirs, nil }
			}

			r := Resolve(specOpencode(), env)
			if r.Bin != bin {
				t.Fatalf("bin = %q, want %q", r.Bin, bin)
			}
			if r.Interpreter != tc.wantInterp {
				t.Errorf("interpreter = %q, want %q", r.Interpreter, tc.wantInterp)
			}
			hasShimNote := containsNote(r.Notes, "#!/usr/bin/env")
			if tc.wantNoNote {
				if hasShimNote {
					t.Errorf("unexpected shim note: %v", r.Notes)
				}
				return
			}
			if !hasShimNote {
				t.Fatalf("expected a shim note, got %v", r.Notes)
			}
			if !containsNote(r.Notes, tc.wantNoteSub) {
				t.Errorf("notes = %v, want one containing %q", r.Notes, tc.wantNoteSub)
			}
		})
	}
}

// TestResolveLoginOnlyDirs pins that the launcher-facing login-only subset is
// reported on EVERY resolution, not only the launchable ones — the boundary
// needs it to widen a child's PATH regardless of verdict.
func TestResolveLoginOnlyDirs(t *testing.T) {
	t.Parallel()

	ff := fakeFS{files: map[string]fs.FileMode{}}
	env := ff.env(Env{
		GOOS:        "linux",
		Home:        p("/home/u"),
		ProcessPath: []string{p("/usr/bin")},
		LoginPath:   func() ([]string, error) { return []string{p("/usr/bin"), p("/opt/login/bin")}, nil },
	})
	r := Resolve(specOpencode(), env)
	if r.Verdict != VerdictNotFound {
		t.Fatalf("verdict = %q, want not_found", r.Verdict)
	}
	if !equalStrings(r.LoginOnlyDirs, []string{p("/opt/login/bin")}) {
		t.Errorf("LoginOnlyDirs = %v", r.LoginOnlyDirs)
	}
}

// TestResolveNpmPrefixProbe pins the injected `npm prefix -g` probe: it is a
// CAPABILITY (a binary under the operator's own npm prefix is evidence for
// every tool), the prefix dir is used directly on Windows and <prefix>/bin
// elsewhere, and a failing probe is an honest Note, never a failure.
func TestResolveNpmPrefixProbe(t *testing.T) {
	t.Parallel()

	t.Run("unix probes <prefix>/bin", func(t *testing.T) {
		hit := p("/opt/npmpfx/bin/opencode")
		ff := fakeFS{files: map[string]fs.FileMode{hit: exeMode}}
		env := ff.env(Env{
			GOOS: "linux", Home: p("/home/u"),
			NpmPrefix: func() (string, error) { return p("/opt/npmpfx"), nil },
		})
		r := Resolve(specOpencode(), env)
		if r.Verdict != VerdictOKOffPath || r.Bin != hit {
			t.Fatalf("verdict = %q bin = %q, want ok_off_path at %q", r.Verdict, r.Bin, hit)
		}
	})

	t.Run("windows probes the prefix dir itself", func(t *testing.T) {
		hit := p("/npmpfx/opencode.cmd")
		ff := fakeFS{files: map[string]fs.FileMode{
			hit:                       regMode,
			p("/npmpfx/bin/opencode"): regMode, // must NOT be preferred on windows
		}}
		env := ff.env(Env{
			GOOS: "windows", Home: p("/home/u"),
			NpmPrefix: func() (string, error) { return p("/npmpfx"), nil },
		})
		r := Resolve(specOpencode(), env)
		if r.Verdict != VerdictOKOffPath || r.Bin != hit {
			t.Fatalf("verdict = %q bin = %q, want ok_off_path at %q", r.Verdict, r.Bin, hit)
		}
	})

	t.Run("a failing probe is a note, not a failure", func(t *testing.T) {
		ff := fakeFS{files: map[string]fs.FileMode{}}
		env := ff.env(Env{
			GOOS: "linux", Home: p("/home/u"),
			NpmPrefix: func() (string, error) { return "", errors.New("npm not found on the merged PATH") },
		})
		r := Resolve(specOpencode(), env)
		if r.Verdict != VerdictNotFound {
			t.Fatalf("verdict = %q, want not_found", r.Verdict)
		}
		if !containsNote(r.Notes, "npm prefix not probed: npm not found on the merged PATH") {
			t.Errorf("notes = %v, want the honest npm-probe note", r.Notes)
		}
	})

	t.Run("an empty prefix invents no note", func(t *testing.T) {
		ff := fakeFS{files: map[string]fs.FileMode{}}
		env := ff.env(Env{
			GOOS: "linux", Home: p("/home/u"),
			NpmPrefix: func() (string, error) { return "  ", nil },
		})
		r := Resolve(specOpencode(), env)
		if containsNote(r.Notes, "npm prefix") {
			t.Errorf("notes = %v, want no npm note for an empty prefix", r.Notes)
		}
	})
}

// TestNoGroundedInstallMsgIsTheOneSentence pins §5.1: the sentence every
// surface renders lives in ONE place. FormatVerdict must consume the constant
// rather than spelling its own copy.
func TestNoGroundedInstallMsgIsTheOneSentence(t *testing.T) {
	t.Parallel()

	if NoGroundedInstallMsg != "no grounded install command — see the vendor's docs" {
		t.Fatalf("NoGroundedInstallMsg changed: %q — update internal/diag and the dashboard together", NoGroundedInstallMsg)
	}
	for _, v := range []Verdict{VerdictForeignOnly, VerdictNotFound} {
		out := FormatVerdict("opencode", "--opencode-path", Resolution{Verdict: v})
		if !strings.Contains(out, NoGroundedInstallMsg) {
			t.Errorf("FormatVerdict(%s) = %q, want the shared sentence", v, out)
		}
	}
}

// absDir joins a POSIX-spelled ABSOLUTE probe-table dir the way the resolver
// does. Unlike p(), it must NOT gain a drive letter on a Windows test host:
// commonNativeAbsProbeDirs entries are used verbatim by Resolve.
func absDir(dir, name string) string { return filepath.Join(dir, name) }
