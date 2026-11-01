package crossmount

import (
	"errors"
	"path/filepath"
	"testing"
	"unicode/utf16"
)

// utf16le encodes s as wsl.exe writes it to a pipe.
func utf16le(s string, bom bool) []byte {
	var out []byte
	if bom {
		out = append(out, 0xFF, 0xFE)
	}
	for _, u := range utf16.Encode([]rune(s)) {
		out = append(out, byte(u), byte(u>>8))
	}
	return out
}

func TestParseWSLDistroList(t *testing.T) {
	for _, tc := range []struct {
		name string
		out  []byte
		want []string
	}{
		{"utf-16le", utf16le("Ubuntu\r\nDebian\r\n", false), []string{"Ubuntu", "Debian"}},
		{"utf-16le with bom", utf16le("Ubuntu-24.04\r\n", true), []string{"Ubuntu-24.04"}},
		{"utf-8 (WSL_UTF8)", []byte("WinRig\nkali-linux\n"), []string{"WinRig", "kali-linux"}},
		{"empty", nil, nil},
		{"a message is not a distro", utf16le("There are no running distributions.\r\n", false), nil},
		{"duplicate", []byte("Ubuntu\nubuntu\n"), []string{"Ubuntu"}},
		{"path-like line", []byte(`..\x` + "\n" + "a/b\n"), nil},
	} {
		got := parseWSLDistroList(tc.out)
		if len(got) != len(tc.want) {
			t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%s: got %q, want %q", tc.name, got, tc.want)
			}
		}
	}
}

// TestWindowsWSLHomesUseTheDistroList (FU-189): Windows refuses to list
// \\wsl.localhost\ itself, so the distros come from the injected list of
// running distros, and only those are opened.
func TestWindowsWSLHomesUseTheDistroList(t *testing.T) {
	t.Parallel()
	root := `\\wsl.localhost\`
	ub := filepath.Join(root, "Ubuntu")
	stopped := filepath.Join(root, "Stopped")
	fs := &fakeFS{
		dirs: map[string]bool{
			filepath.Join(ub, "home"):              true,
			filepath.Join(ub, "home", "me"):        true,
			filepath.Join(stopped, "home"):         true,
			filepath.Join(stopped, "home", "them"): true,
		},
		listings: map[string][]string{
			filepath.Join(ub, "home"):      {"me"},
			filepath.Join(stopped, "home"): {"them"},
		},
	}
	var opened []string
	d := &detector{
		runtimeOS:  OSWindows,
		nativeHome: func() (string, error) { return `C:\Users\me`, nil },
		statDir: func(p string) bool {
			opened = append(opened, p)
			return fs.statDir(p)
		},
		readDir: func(p string) ([]string, error) {
			if p == root {
				return nil, errors.New("Windows cannot list the \\\\wsl.localhost root")
			}
			return fs.readDir(p)
		},
		wslDistros: func() ([]string, error) { return []string{"Ubuntu"}, nil },
	}
	got := d.extraHomes()
	if len(got) != 1 || got[0].Path != filepath.Join(ub, "home", "me") || got[0].Origin != "wslhost:Ubuntu/me" {
		t.Fatalf("extraHomes() = %+v, want the one home of the running Ubuntu", got)
	}
	for _, p := range opened {
		if p == root || filepath.Dir(filepath.Dir(p)) == stopped || filepath.Dir(p) == stopped || p == stopped {
			t.Errorf("detection opened %q (the root or a distro that is not running)", p)
		}
	}

	d.wslDistros = func() ([]string, error) { return nil, errors.New("wsl.exe failed") }
	if got := d.extraHomes(); len(got) != 0 {
		t.Errorf("a failed distro list gave homes: %+v", got)
	}
	d.wslDistros = func() ([]string, error) { return []string{`..\Windows`}, nil }
	if got := d.extraHomes(); len(got) != 0 {
		t.Errorf("a name that is not a distro name was opened: %+v", got)
	}
}

// TestRunningWSLDistrosNeverExecsInATestBinary: the production list is
// refused inside a test binary (the testguard rule), so no test can reach
// the real wsl.exe.
func TestRunningWSLDistrosNeverExecsInATestBinary(t *testing.T) {
	if !testBinaryGuard {
		t.Skip("the live-crossmount escape hatch is open for this run")
	}
	if names, err := runningWSLDistros(); err == nil || names != nil {
		t.Fatalf("runningWSLDistros() = %q, %v; want the test-binary refusal", names, err)
	}
}

// TestDefaultDetectorListsDistrosOnlyWhenNotStaged: production reads the
// running-distro list; a staged test layout keeps listing its own temp root.
func TestDefaultDetectorListsDistrosOnlyWhenNotStaged(t *testing.T) {
	if d := defaultDetector(); d.wslDistros == nil {
		t.Fatal("the default detector has no distro list")
	}
	StageForeignLayoutForTest(t, ForeignLayoutForTest{Root: t.TempDir()})
	if d := defaultDetector(); d.wslDistros != nil {
		t.Fatal("a staged layout must list its own temp root, not run wsl.exe")
	}
}

// TestWSLExeIn (FU-209): wsl.exe is named in the System32 directory the
// Windows API reports, with a fixed fallback; no environment variable is in
// the path.
func TestWSLExeIn(t *testing.T) {
	t.Setenv("SystemRoot", `D:\Elsewhere`)
	for _, tc := range []struct{ dir, want string }{
		{`C:\WINDOWS\system32`, `C:\WINDOWS\system32\wsl.exe`},
		{`E:\Win\System32`, `E:\Win\System32\wsl.exe`},
		{"", `C:\Windows\System32\wsl.exe`},
	} {
		if got := wslExeIn(tc.dir); got != tc.want {
			t.Errorf("wslExeIn(%q) = %q, want %q", tc.dir, got, tc.want)
		}
	}
}
