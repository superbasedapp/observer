package setup

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/update"
)

func TestPathEntryEdits(t *testing.T) {
	const dir = `C:\Users\dev\AppData\Local\SuperBased\Observer\bin`
	cases := []struct {
		name       string
		value      string
		wantAdd    string
		wantAddOK  bool
		wantRm     string
		wantRmOK   bool
		wantHasDir bool
	}{
		{
			name: "empty Path", value: "",
			wantAdd: dir, wantAddOK: true,
			wantRm: "", wantRmOK: false,
		},
		{
			name: "appended at the end, after an existing copy", value: `C:\a;C:\Users\dev\AppData\Roaming\npm`,
			wantAdd: `C:\a;C:\Users\dev\AppData\Roaming\npm;` + dir, wantAddOK: true,
			wantRm: `C:\a;C:\Users\dev\AppData\Roaming\npm`, wantRmOK: false,
		},
		{
			name: "a trailing separator is not doubled", value: `C:\a;`,
			wantAdd: `C:\a;` + dir, wantAddOK: true,
			wantRm: `C:\a;`, wantRmOK: false,
		},
		{
			name: "already present in another case with a trailing backslash", value: `C:\a;c:\users\dev\appdata\local\superbased\observer\bin\;C:\b`,
			wantAdd: `C:\a;c:\users\dev\appdata\local\superbased\observer\bin\;C:\b`, wantAddOK: false,
			wantRm: `C:\a;C:\b`, wantRmOK: true, wantHasDir: true,
		},
		{
			name: "remove drops every copy and keeps the rest byte-identical, empty entries too", value: dir + `;C:\a;;` + dir + `;C:\b`,
			wantAdd: dir + `;C:\a;;` + dir + `;C:\b`, wantAddOK: false,
			wantRm: `C:\a;;C:\b`, wantRmOK: true, wantHasDir: true,
		},
	}
	// An install followed by an uninstall gives the user's Path back exactly.
	for _, before := range []string{"", `C:\a`, `C:\a;;C:\b`, `%USERPROFILE%\bin;C:\x`} {
		added, _ := AddPathEntry(before, dir)
		if back, _ := RemovePathEntry(added, dir); back != before {
			t.Errorf("round trip of %q gave %q", before, back)
		}
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := HasPathEntry(tc.value, dir); got != tc.wantHasDir {
				t.Errorf("HasPathEntry = %v, want %v", got, tc.wantHasDir)
			}
			got, ok := AddPathEntry(tc.value, dir)
			if got != tc.wantAdd || ok != tc.wantAddOK {
				t.Errorf("AddPathEntry = (%q, %v), want (%q, %v)", got, ok, tc.wantAdd, tc.wantAddOK)
			}
			got, ok = RemovePathEntry(tc.value, dir)
			if got != tc.wantRm || ok != tc.wantRmOK {
				t.Errorf("RemovePathEntry = (%q, %v), want (%q, %v)", got, ok, tc.wantRm, tc.wantRmOK)
			}
		})
	}
	if _, ok := AddPathEntry(`C:\a`, "  "); ok {
		t.Error("a blank directory must never be added")
	}
}

func TestRunValue(t *testing.T) {
	got := RunValue(`C:\Program Files\x\observerw.exe`)
	want := `"C:\Program Files\x\observerw.exe" setup launch`
	if got != want {
		t.Fatalf("RunValue = %q, want %q", got, want)
	}
}

type fakeFS map[string]bool

func (f fakeFS) sibling(dir, name string) bool { return f[strings.ToLower(dir+"/"+name)] }

func TestPreflight(t *testing.T) {
	const installDir = `C:\Users\dev\AppData\Local\SuperBased\Observer\bin`
	npmShim := `C:\Users\dev\AppData\Roaming\npm\observer.cmd`
	pipExe := `C:\Users\dev\AppData\Local\Programs\Python\Python312\Lib\site-packages\observer\bin\observer.exe`
	own := installDir + `\observer.exe`
	fs := fakeFS{strings.ToLower(`C:/Users/dev/AppData/Roaming/npm/` + npmShimMarker): true}

	cases := []struct {
		name        string
		in          PreflightInput
		wantOthers  []string // kinds
		wantForeign bool
		wantOwn     bool
		wantBlocked bool
	}{
		{
			name:        "a clean computer",
			in:          PreflightInput{InstallDir: installDir, GOOS: "windows"},
			wantBlocked: false,
		},
		{
			name:        "only this install on the Path (an upgrade)",
			in:          PreflightInput{InstallDir: installDir, GOOS: "windows", OnPath: []string{strings.ToUpper(own)}},
			wantBlocked: false,
		},
		{
			name: "npm shim and a pip copy on the Path",
			in: PreflightInput{
				InstallDir: installDir, GOOS: "windows", OnPath: []string{npmShim, pipExe, npmShim},
				SiblingExists: fs.sibling,
			},
			wantOthers: []string{"npm install", "pip install"}, wantBlocked: true,
		},
		{
			name: "our own daemon is running (upgrade, renamed aside later)",
			in: PreflightInput{
				InstallDir: installDir, GOOS: "windows",
				Daemon: &DaemonInfo{PID: 42, BinaryPath: own},
			},
			wantOwn: true, wantBlocked: false,
		},
		{
			name: "a daemon from another install is running",
			in: PreflightInput{
				InstallDir: installDir, GOOS: "windows",
				Daemon: &DaemonInfo{PID: 7, BinaryPath: `C:\tools\observer.exe`},
			},
			wantForeign: true, wantBlocked: true,
		},
		{
			name: "linux paths compare case-sensitively",
			in: PreflightInput{
				InstallDir: "/home/dev/.local/bin", GOOS: "linux",
				OnPath: []string{"/home/dev/.LOCAL/bin/observer"},
			},
			wantOthers: []string{"downloaded copy"}, wantBlocked: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := Preflight(tc.in)
			var kinds []string
			for _, o := range r.Others {
				kinds = append(kinds, o.Kind)
			}
			if strings.Join(kinds, ",") != strings.Join(tc.wantOthers, ",") {
				t.Errorf("others = %v, want %v", kinds, tc.wantOthers)
			}
			if (r.ForeignDaemon != nil) != tc.wantForeign {
				t.Errorf("foreign daemon = %v, want %v", r.ForeignDaemon, tc.wantForeign)
			}
			if (r.OwnDaemon != nil) != tc.wantOwn {
				t.Errorf("own daemon = %v, want %v", r.OwnDaemon, tc.wantOwn)
			}
			if r.Blocked() != tc.wantBlocked {
				t.Errorf("Blocked = %v, want %v", r.Blocked(), tc.wantBlocked)
			}
			report := PreflightReport(r, "force hint")
			if tc.wantBlocked != (report != "") {
				t.Errorf("report presence = %v, want %v", report != "", tc.wantBlocked)
			}
		})
	}
}

func TestClassifyNamesTheUpgradeCommand(t *testing.T) {
	cases := []struct {
		exe         string
		sibling     func(dir, name string) bool
		wantKind    string
		wantUpgrade string
	}{
		{
			`C:\Users\dev\AppData\Roaming\npm\observer.cmd`,
			fakeFS{strings.ToLower(`C:/Users/dev/AppData/Roaming/npm/` + npmShimMarker): true}.sibling,
			"npm install", "npm i -g @superbased/observer@latest",
		},
		{
			"/usr/lib/node_modules/@superbased/observer-linux-x64/bin/observer", nil,
			"npm install", "npm i -g @superbased/observer@latest",
		},
		{
			"/home/dev/.local/lib/python3.12/site-packages/observer/bin/observer", nil,
			"pip install", "pip install -U superbased-observer",
		},
		{
			"/home/dev/.vscode/extensions/superbased.superbased-observer-1.36.0/bin/observer", nil,
			"VS Code extension copy", "update the SuperBased Observer extension in VS Code",
		},
		{"/home/dev/bin/observer", nil, "downloaded copy", ""},
	}
	for _, tc := range cases {
		got := Classify(tc.exe, tc.sibling)
		if got.Kind != tc.wantKind || got.Upgrade != tc.wantUpgrade {
			t.Errorf("Classify(%q) = %+v, want kind %q upgrade %q", tc.exe, got, tc.wantKind, tc.wantUpgrade)
		}
	}
}

// TestInstallerMarkerMatchesTheInstallMethodTable pins the one constant this
// core package repeats from internal/update (an omittable component it must
// not import): both name the setup program's uninstaller.
func TestInstallerMarkerMatchesTheInstallMethodTable(t *testing.T) {
	if InstallerMarker != update.InstallerUninstallerName {
		t.Fatalf("InstallerMarker %q != update.InstallerUninstallerName %q", InstallerMarker, update.InstallerUninstallerName)
	}
	got := Classify(`C:\Users\dev\AppData\Local\SuperBased\Observer\bin\observer.exe`,
		fakeFS{"c:/users/dev/appdata/local/superbased/observer/" + InstallerMarker: true}.sibling)
	if got.Kind != "installed copy" || !strings.Contains(got.Upgrade, DownloadURL) {
		t.Errorf("Classify of a setup-program copy = %+v", got)
	}
	got = Classify(`C:\Users\dev\pipx\venvs\superbased-observer\Scripts\observer.exe`, nil)
	if got.Kind != "pipx install" || got.Upgrade != "pipx upgrade superbased-observer" {
		t.Errorf("Classify of a pipx copy = %+v", got)
	}
}

func TestPreflightReportWording(t *testing.T) {
	r := PreflightResult{
		Others:        []Other{{Path: "/x/observer", Kind: "npm install", Upgrade: "npm i -g @superbased/observer@latest"}},
		ForeignDaemon: &DaemonInfo{PID: 9, BinaryPath: "/x/observer"},
	}
	got := PreflightReport(r, "Run it with --force to install a second copy anyway.")
	for _, want := range []string{
		"already installed", "npm install: /x/observer", "upgrade it with: npm i -g @superbased/observer@latest",
		"running daemon: pid 9", "one install per computer", "--force",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report lacks %q:\n%s", want, got)
		}
	}
	if strings.ContainsAny(got, "\u2014\u2013") {
		t.Error("report carries an em or en dash")
	}
}

func TestStaleAsideAndAsideName(t *testing.T) {
	got := StaleAsideNames([]string{"observer.exe", "observer.exe.old-20261020", "superbased.exe.old-1", "observerw.exe"})
	if strings.Join(got, ",") != "observer.exe.old-20261020,superbased.exe.old-1" {
		t.Fatalf("StaleAsideNames = %v", got)
	}
	if AsideName("observer.exe", "123") != "observer.exe.old-123" {
		t.Fatal("AsideName shape changed; install.ps1's Remove-StaleAside matches *.exe.old-*")
	}
}
