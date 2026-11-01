package crossmount

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestIsWSLHostHome(t *testing.T) {
	cases := []struct {
		name   string
		h      HomeRoot
		want   bool
		distro string
	}{
		{"wsl home seen from windows", HomeRoot{OS: OSLinux, Origin: "wslhost:Ubuntu/me"}, true, "Ubuntu"},
		{"native linux home", HomeRoot{OS: OSLinux, Origin: "native"}, false, ""},
		{"windows home from wsl", HomeRoot{OS: OSWindows, Origin: "wsl-mnt:me"}, false, ""},
		{"wrong os tag", HomeRoot{OS: OSWindows, Origin: "wslhost:Ubuntu/me"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := IsWSLHostHome(c.h); got != c.want {
				t.Errorf("IsWSLHostHome = %v, want %v", got, c.want)
			}
			if got := WSLHostDistro(c.h); got != c.distro {
				t.Errorf("WSLHostDistro = %q, want %q", got, c.distro)
			}
		})
	}
}

func TestLinuxPathFromWSLHost(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`\\wsl.localhost\Ubuntu\home\me\.claude\settings.json`, "/home/me/.claude/settings.json", true},
		{`\\WSL.LOCALHOST\Ubuntu\home\me`, "/home/me", true},
		{`\\wsl$\Debian\home\me\`, "/home/me", true},
		{`//wsl.localhost/Ubuntu/home/me`, "/home/me", true},
		{`\\wsl.localhost\Ubuntu`, "/", true},
		{`\\wsl.localhost\`, "", false},
		{`C:\Users\me`, "", false},
		{"/home/me", "", false},
		{`\\server\share\x`, "", false},
	}
	for _, c := range cases {
		got, ok := LinuxPathFromWSLHost(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("LinuxPathFromWSLHost(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

func TestMountPathFromWindows(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{`C:\Users\me\AppData\Roaming\npm\observer.exe`, "/mnt/c/Users/me/AppData/Roaming/npm/observer.exe", true},
		{`D:/tools/observer.exe`, "/mnt/d/tools/observer.exe", true},
		{`C:\`, "/mnt/c", true},
		{`C:`, "", false},
		{`C:x`, "", false},
		{`1:\x`, "", false},
		{`\\wsl.localhost\Ubuntu\home`, "", false},
		{"/usr/bin/observer", "", false},
		{"observer.exe", "", false},
	}
	for _, c := range cases {
		got, ok := MountPathFromWindows(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("MountPathFromWindows(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
		if ok {
			back, bok := WindowsPathFromMount(got)
			if !bok || filepath.ToSlash(back) == "" {
				t.Errorf("round trip of %q failed: %q, %v", got, back, bok)
			}
		}
	}
}

func TestSoleUserHome(t *testing.T) {
	root := t.TempDir()
	one := filepath.Join(root, "one", "home")
	two := filepath.Join(root, "two", "home")
	for _, d := range []string{
		filepath.Join(one, "me"),
		filepath.Join(two, "me"), filepath.Join(two, "other"),
	} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// A stray file beside the only home does not make the distro ambiguous.
	if err := os.WriteFile(filepath.Join(one, "README"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		home string
		want bool
	}{
		{"sole user", filepath.Join(one, "me"), true},
		{"two users is ambiguous", filepath.Join(two, "me"), false},
		{"missing home", filepath.Join(one, "ghost"), false},
		{"empty", "", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := WSLHomeOwnedByCurrentUser(c.home); got != c.want {
				t.Errorf("WSLHomeOwnedByCurrentUser(%q) = %v, want %v", c.home, got, c.want)
			}
		})
	}
	failing := func(string) ([]string, error) { return nil, errors.New("unreachable") }
	if soleUserHome(filepath.Join(one, "me"), failing, isExistingDir) {
		t.Error("an unreadable /home must not prove ownership")
	}
}
