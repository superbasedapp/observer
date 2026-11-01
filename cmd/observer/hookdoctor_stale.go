package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/tailscale/hujson"
	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
)

// hookdoctor_stale.go is the stale hook entry check of `observer doctor
// --hooks` (lane shr-hookseam2, PT-06). A hook entry whose command runs a
// binary that no longer exists, or one under a temp or go-build directory
// (a Go test's observer.test registered by a test that reached a real
// home), fails on every event it is registered for, and every host lets
// the event through when a hook cannot run. The check READS the vendor
// config files the registration writers name (their DryRun ConfigPath) and
// reports such entries; it never edits or deletes a file. It adds a line
// only when a stale entry exists, so a clean machine sees nothing new. The
// dashboard shows it where it shows the rest of this report: the Security
// page, Coverage tab, per-tool hook doctor (`POST /api/guard/hook-doctor`).

// staleHookEntry is one hook command that cannot run as registered.
type staleHookEntry struct {
	Command, Binary, Reason string
	// Owned is true when the registration writers recognise the entry as
	// Observer's own (its binary is named observer), so a re-registration
	// rewrites it; false for a Go test binary, which they treat as foreign.
	Owned bool
}

// staleEnv is what the binary rules consult: the file system and the
// temp roots of this machine.
type staleEnv struct {
	exists    func(p string) bool
	tempRoots []string
}

// staleBinaryRules decide why a hook entry's binary is stale, walked top to
// bottom; the first match names the reason.
var staleBinaryRules = []struct {
	when   func(bin string, env staleEnv) bool
	reason string
}{
	{func(bin string, _ staleEnv) bool { return underGoBuild(bin) }, "its binary is under a go-build directory (a Go test build)"},
	{func(bin string, _ staleEnv) bool { return isGoTestBinary(bin) }, "its binary is a Go test binary"},
	{underTempRoot, "its binary is under a temp directory"},
	{func(bin string, env staleEnv) bool {
		local, ok := checkablePath(bin)
		return ok && env.exists != nil && !env.exists(local)
	}, "its binary is missing"},
}

// staleRemedies are the next steps per ownership: what the existing
// re-registration does for the entry.
var staleRemedies = map[bool]string{
	true: "re-register: the next `observer start` rewrites it to this binary (auto_register), or run `observer init`; nothing to remove by hand",
	false: "the re-registration (`observer init --force`) adds Observer's current entry but leaves this one in place, because a Go test binary is not recognised as Observer's: " +
		"remove this entry from the file by hand (this check never edits or deletes a file)",
}

// staleHookChecks reads the config files of tools' hook targets (native and
// -windows) and returns one WARN check per file holding a stale entry.
func staleHookChecks(o hookDoctorOptions, tools []string) []diag.Check {
	env := staleEnv{exists: pathExists, tempRoots: defaultTempRoots()}
	var out []diag.Check
	for _, file := range staleHookConfigFiles(o.Binary, o.ConfigPath, tools) {
		body, err := os.ReadFile(file) //nolint:gosec // a vendor config path the registration writers name
		if err != nil {
			continue
		}
		if ck, ok := staleHookCheck(file, body, env); ok {
			out = append(out, ck)
		}
	}
	return out
}

// staleHookConfigFiles is the set of config files the registration writers
// name for tools (DryRun, so nothing is written), existing files only.
func staleHookConfigFiles(binary, configPath string, tools []string) []string {
	seen := map[string]bool{}
	var files []string
	reg, err := hook.NewRegistry(hookRegistrationOptions(binary, configPath))
	if err != nil {
		return nil
	}
	for _, tool := range tools {
		// Every home a writer of tool names: native, -windows, the Xcode
		// agent homes (FU-145) and the -wsl twins (FU-211; a twin names a
		// file only on a Windows host whose running distro holds the
		// tool, and a gated twin names none).
		for _, target := range append([]string{tool, tool + "-windows"}, hook.HomeTargetsFor(tool)...) {
			p := reg.Register(target).ConfigPath
			if p == "" || seen[p] || !pathExists(p) {
				continue
			}
			seen[p] = true
			files = append(files, p)
		}
	}
	sort.Strings(files)
	return files
}

// staleHookCheck is the check for one file, or false when it holds no
// stale entry.
func staleHookCheck(file string, body []byte, env staleEnv) (diag.Check, bool) {
	entries := findStaleHookEntries(file, body, env)
	if len(entries) == 0 {
		return diag.Check{}, false
	}
	ck := diag.Check{
		Name:    "hook.stale:" + file,
		Status:  diag.StatusWarn,
		Message: fmt.Sprintf("%s: %d hook entr%s cannot run as registered, so the host lets those events through", file, len(entries), plural(len(entries), "y", "ies")),
	}
	remedies := map[bool]bool{}
	for _, e := range entries {
		ck.Details = append(ck.Details, fmt.Sprintf("%s: %s", e.Reason, e.Command))
		remedies[e.Owned] = true
	}
	for _, owned := range []bool{true, false} {
		if remedies[owned] {
			ck.Details = append(ck.Details, "remedy: "+staleRemedies[owned])
		}
	}
	return ck, true
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// findStaleHookEntries decodes body by the file's extension and returns
// every Observer hook command in it whose binary a stale rule matches.
func findStaleHookEntries(file string, body []byte, env staleEnv) []staleHookEntry {
	var out []staleHookEntry
	seen := map[string]bool{}
	for _, s := range configStrings(file, body) {
		if seen[s] {
			continue
		}
		seen[s] = true
		bin, owned, ok := observerHookBinary(s)
		if !ok {
			continue
		}
		for _, r := range staleBinaryRules {
			if r.when(bin, env) {
				out = append(out, staleHookEntry{Command: s, Binary: bin, Reason: r.reason, Owned: owned})
				break
			}
		}
	}
	return out
}

// configStrings returns every string value in a JSON (JSONC tolerated),
// TOML or YAML config. Other file kinds hold no hook command entries.
func configStrings(file string, body []byte) []string {
	var doc any
	switch strings.ToLower(filepath.Ext(file)) {
	case ".json", ".jsonc":
		std, err := hujson.Standardize(body)
		if err != nil || json.Unmarshal(std, &doc) != nil {
			return nil
		}
	case ".toml":
		var m map[string]any
		if _, err := toml.Decode(string(body), &m); err != nil {
			return nil
		}
		doc = m
	case ".yaml", ".yml":
		if yaml.Unmarshal(body, &doc) != nil {
			return nil
		}
	default:
		return nil
	}
	var out []string
	var walk func(v any)
	walk = func(v any) {
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case map[string]any:
			for _, val := range x {
				walk(val)
			}
		case []any:
			for _, e := range x {
				walk(e)
			}
		case []map[string]any:
			for _, e := range x {
				walk(e)
			}
		}
	}
	walk(doc)
	return out
}

// observerHookBinary parses cmd as an Observer hook invocation, the shapes
// the registration writers write (`<bin> hook <tool> ...`, optionally after
// PowerShell's call operator, KEY=VALUE assignments and the `wsl.exe -d
// <distro> --` bridge), and
// returns its binary. owned is true when the binary is named observer (the
// writers' own recogniser); a Go test binary of cmd/observer
// (`observer.test`) is also returned, with owned false.
func observerHookBinary(cmd string) (bin string, owned, ok bool) {
	toks := splitHookCommand(strings.ReplaceAll(cmd, `\`, "/"))
	// PowerShell's call operator before a quoted Windows binary (the native
	// Codex writer on Windows, FU-162).
	if len(toks) > 1 && toks[0] == "&" {
		toks = toks[1:]
	}
	for len(toks) > 0 && strings.Contains(toks[0], "=") && !strings.Contains(toks[0], "/") {
		toks = toks[1:]
	}
	if len(toks) > 0 && strings.TrimSuffix(strings.ToLower(path.Base(toks[0])), ".exe") == "wsl" {
		for i, t := range toks {
			if t == "--" {
				toks = toks[i+1:]
				break
			}
		}
	}
	if len(toks) < 3 || toks[1] != "hook" || toks[2] == "" {
		return "", false, false
	}
	switch {
	case hook.IsObserverBinary(toks[0]):
		return toks[0], true, true
	case isGoTestBinary(toks[0]) && strings.HasPrefix(strings.ToLower(path.Base(toks[0])), "observer"):
		return toks[0], false, true
	}
	return "", false, false
}

// splitHookCommand splits a command on spaces, honouring single and double
// quotes (no escapes: separators were already turned into slashes).
func splitHookCommand(s string) []string {
	var toks []string
	var cur strings.Builder
	var quote rune
	started := false
	for _, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '"' || r == '\'':
			quote, started = r, true
		case r == ' ' || r == '\t':
			if started {
				toks = append(toks, cur.String())
				cur.Reset()
				started = false
			}
		default:
			cur.WriteRune(r)
			started = true
		}
	}
	if started {
		toks = append(toks, cur.String())
	}
	return toks
}

// underGoBuild reports a path with a go-build* directory segment (the Go
// build cache's temporary work directories).
func underGoBuild(bin string) bool {
	for _, seg := range strings.Split(bin, "/") {
		if strings.HasPrefix(seg, "go-build") {
			return true
		}
	}
	return false
}

// isGoTestBinary reports a `<pkg>.test` binary.
func isGoTestBinary(bin string) bool {
	return strings.HasSuffix(strings.TrimSuffix(strings.ToLower(path.Base(bin)), ".exe"), ".test")
}

// underTempRoot reports a binary under one of env's temp roots, or under a
// Windows user temp directory however it is spelled.
func underTempRoot(bin string, env staleEnv) bool {
	low := strings.ToLower(bin)
	if strings.Contains(low, "/appdata/local/temp/") || strings.Contains(low, "/windows/temp/") {
		return true
	}
	for _, root := range env.tempRoots {
		if root != "" && crossmount.PathUnder(filepath.ToSlash(root), bin) {
			return true
		}
	}
	return false
}

// defaultTempRoots are this machine's temp directories.
func defaultTempRoots() []string {
	roots := []string{filepath.ToSlash(os.TempDir()), "/tmp", "/var/tmp", "/private/tmp", "/var/folders", "/private/var/folders"}
	sort.Strings(roots)
	return roots
}

// checkablePath returns bin as a path this process can stat, and false
// when it names a path of another system (a WSL path read on Windows) or
// no absolute path at all (a bare `observer` resolved through PATH).
func checkablePath(bin string) (string, bool) {
	local := filepath.FromSlash(crossmount.TranslateForeignPath(bin))
	return local, filepath.IsAbs(local)
}
