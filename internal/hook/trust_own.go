package hook

import (
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
)

// trust_own.go is what the repository trust check (cmd/observer, component
// security.trust) needs from this package to tell Observer's own entries in
// a home config file from look-alikes (docs/security.md SECP-5). The
// registrars' own recognisers (IsObserverHookCommand,
// IsObserverStatuslineCommand) go by shape on purpose: a registrar must
// refresh its stale entries, so a false negative strands a user on an old
// binary. Trust needs the opposite: a command in Observer's shape naming
// some other executable is not Observer's. So these return the executable
// token of a command in exactly the shapes the registrars write, and the
// caller compares it with the running binary and the binaries the
// registration record names (RecordedBinaryPaths).

// ObserverHookCommandBinaries returns the executable a hook command names
// when cmd is in a shape Observer's registrars write: IsObserverHookCommand
// holds and the only text before the executable is the cross-OS bridge
// prefix the `*-windows` registrars write (`[MSYS_NO_PATHCONV=1 ]wsl.exe -d
// <distro> --`), never any other environment assignment. For a bridged
// command the executable is the Linux binary inside the bridge. The command
// is read as written and with its backslashes turned to slashes (an
// unquoted or double-quoted Windows path loses its backslashes to the POSIX
// tokenizer), so up to two spellings come back; none means the shape is
// not one Observer writes.
func ObserverHookCommandBinaries(cmd string) []string {
	if !IsObserverHookCommand(cmd) {
		return nil
	}
	var out []string
	for _, c := range commandSpellings(cmd) {
		toks, ok := stripOwnedCommandPrefix(splitCommandTokens(c))
		if ok && len(toks) >= 3 && isObserverBinaryToken(toks[0]) && toks[1] == "hook" && toks[2] != "" {
			out = appendDistinct(out, toks[0])
		}
	}
	return out
}

// ObserverStatuslineCommandBinaries returns the executable the status line
// command names when cmd is the status line Observer registers
// (`<bin> statusline`, IsObserverStatuslineCommand), in the same spellings
// as ObserverHookCommandBinaries.
func ObserverStatuslineCommandBinaries(cmd string) []string {
	var out []string
	for _, c := range commandSpellings(cmd) {
		if isObserverStatuslineEntry(c) {
			out = appendDistinct(out, splitCommandTokens(c)[0])
		}
	}
	return out
}

// commandSpellings is cmd, and cmd with backslashes as slashes when it has
// any.
func commandSpellings(cmd string) []string {
	if strings.Contains(cmd, `\`) {
		return []string{cmd, strings.ReplaceAll(cmd, `\`, "/")}
	}
	return []string{cmd}
}

// appendDistinct appends s to list unless it is already there.
func appendDistinct(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}

// stripOwnedCommandPrefix strips exactly the prefixes Observer's registrars
// write before the observer binary: PowerShell's call operator `&` (the
// native Codex writer before a quoted Windows binary), or an optional
// MSYS_NO_PATHCONV=1 then an optional `wsl.exe -d <distro> --` bridge. Any
// other leading assignment or wrapper is not Observer's, so ok is false.
func stripOwnedCommandPrefix(toks []string) ([]string, bool) {
	// The native Codex writer's PowerShell call operator before a quoted
	// Windows binary (codexHookExe).
	if len(toks) > 1 && toks[0] == "&" {
		return toks[1:], true
	}
	if len(toks) > 0 && toks[0] == "MSYS_NO_PATHCONV=1" {
		toks = toks[1:]
	}
	if len(toks) == 0 {
		return nil, false
	}
	if strings.Contains(toks[0], "=") && !strings.ContainsAny(toks[0], `/\`) {
		return nil, false
	}
	base := strings.ToLower(strings.TrimSuffix(commandBaseName(toks[0]), ".exe"))
	if base != "wsl" {
		return toks, true
	}
	if len(toks) < 5 || toks[1] != "-d" || toks[2] == "" || toks[3] != "--" {
		return nil, false
	}
	return toks[4:], true
}

// ChecksumsPathFor is the registration record (hook_checksums.json) the
// registrars write for home: <home>/.observer/hook_checksums.json, the
// default of Options.ChecksumsPath.
func ChecksumsPathFor(home string) string {
	return filepath.Join(home, ".observer", "hook_checksums.json")
}

// RecordedBinaryPaths returns the distinct binary_path values the
// registration record at path holds, sorted: every binary a registrar wrote
// an entry for (recordChecksum and recordHookChecksum store it per config
// file). A missing or unreadable record gives none. The caller supplies
// readFile (os.ReadFile in production): this package reads no file on the
// trust path itself, so the hook-context inventory
// (hookctx_inventory_test.go) keeps holding without a new row.
func RecordedBinaryPaths(path string, readFile func(string) ([]byte, error)) []string {
	if readFile == nil {
		return nil
	}
	raw, err := readFile(path)
	if err != nil {
		return nil
	}
	var entries map[string]struct {
		BinaryPath string `json:"binary_path"`
	}
	if json.Unmarshal(raw, &entries) != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, e := range entries {
		if p := strings.TrimSpace(e.BinaryPath); p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	sort.Strings(out)
	return out
}
