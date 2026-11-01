package crossmount

import (
	"bytes"
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
	"unicode/utf16"
)

// # Which WSL distros a Windows host reads (FU-189)
//
// Windows refuses to list the root \\wsl.localhost\ (only
// \\wsl.localhost\<distro>\... lists), so windowsWSLHomes cannot find the
// distros by reading that directory: on the FU-177 rig it found no WSL home
// with a distro running, and no "-wsl" hook twin was ever written.
//
// The distro names come from `wsl.exe --list --running --quiet` instead.
// Only RUNNING distros are listed on purpose: opening any
// \\wsl.localhost\<distro> path starts a stopped distro, so detection must
// never stat a distro that is not already up. The registry key
// HKCU\Software\Microsoft\Windows\CurrentVersion\Lxss names every
// registered distro, running or not, so it cannot be used without that side
// effect. Listing the running distros does not start one.
//
// A race no stat can close (FU-209): a distro that stops between the
// running list and the stat of its home is started again by that stat,
// since opening any \\wsl.localhost\<distro> path starts it and Windows has
// no stat that does not. The window is kept small instead: windowsWSLHomes
// stats each listed distro's home right after the list, once, with no
// retry, and a home that does not answer is skipped.

// wslListTimeout bounds the wsl.exe call: detection is best-effort and runs
// on start, init and doctor paths.
const wslListTimeout = 3 * time.Second

// errWSLListUnavailable is returned where no wsl.exe may run: off Windows,
// and inside a test binary (testguard.go), which never execs it.
var errWSLListUnavailable = errors.New("crossmount: wsl.exe distro list unavailable")

// wslDistroName is the shape of a WSL distro name (wsl.exe --import and the
// store packages use letters, digits, '.', '-' and '_'). A line of any other
// shape (a localized "no running distributions" message) is not a distro.
var wslDistroName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

// runningWSLDistros is the production distro list of a Windows host: the
// names `wsl.exe --list --running --quiet` prints. A test binary never runs
// it (the testBinaryGuard rule, as WindowsUserName).
func runningWSLDistros() ([]string, error) {
	if testBinaryGuard {
		return nil, errWSLListUnavailable
	}
	ctx, cancel := context.WithTimeout(context.Background(), wslListTimeout)
	defer cancel()
	out, err := runWSLList(ctx, wslExePath())
	if err != nil {
		return nil, err
	}
	return parseWSLDistroList(out), nil
}

// defaultSystem32 is the System32 directory wslExeIn falls back to when the
// Windows API answers nothing (it does not on a working Windows).
const defaultSystem32 = `C:\Windows\System32`

// wslExeIn is wsl.exe in the System32 directory system32 (the Windows API's
// answer, wslExePath in wsldistros_windows.go), never a PATH lookup and
// never an environment variable: %SystemRoot% is the caller's to set, and a
// daemon started with a doctored one must not run another wsl.exe (FU-209).
func wslExeIn(system32 string) string {
	if system32 == "" {
		system32 = defaultSystem32
	}
	return system32 + `\wsl.exe`
}

// parseWSLDistroList reads wsl.exe's list output: UTF-16LE (with or without
// a byte-order mark) as wsl.exe writes it to a pipe, or UTF-8 when WSL_UTF8
// is set. One name per line; a line that is not a distro name is dropped.
func parseWSLDistroList(out []byte) []string {
	text := decodeWSLOutput(out)
	var names []string
	seen := map[string]bool{}
	for _, line := range strings.Split(text, "\n") {
		name := strings.TrimSpace(strings.Trim(line, "\r\x00\ufeff"))
		if !wslDistroName.MatchString(name) || seen[strings.ToLower(name)] {
			continue
		}
		seen[strings.ToLower(name)] = true
		names = append(names, name)
	}
	return names
}

// decodeWSLOutput returns out as text: UTF-16LE when it carries the
// little-endian byte-order mark or a NUL in an odd byte (ASCII text in
// UTF-16LE), else the bytes as they are.
func decodeWSLOutput(out []byte) string {
	utf16le := bytes.HasPrefix(out, []byte{0xFF, 0xFE})
	if !utf16le {
		for i := 1; i < len(out); i += 2 {
			if out[i] == 0 {
				utf16le = true
				break
			}
		}
	}
	if !utf16le {
		return string(out)
	}
	out = bytes.TrimPrefix(out, []byte{0xFF, 0xFE})
	units := make([]uint16, 0, len(out)/2)
	for i := 0; i+1 < len(out); i += 2 {
		units = append(units, uint16(out[i])|uint16(out[i+1])<<8)
	}
	return string(utf16.Decode(units))
}
