package diag

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/hook"
	"github.com/marmutapp/superbased-observer/internal/hookdisable"
	"github.com/marmutapp/superbased-observer/internal/platform/crossmount"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// checkHooksDisabled reports a vendor-side switch that silences every hook
// the vendor runs, Observer's included (hook-parity T-046): Claude Code's
// disableAllHooks (which also silences the hosts that replay Claude Code's
// hook settings), the managed allowManagedHooksOnly, Gemini CLI's
// hooksConfig.enabled=false, Factory's hooksDisabled, and the rest of the
// internal/hookdisable table. Observer's own files are untouched by such a
// switch, so neither the hook checksum check nor the registrar notices.
// Since T-910 the project-scope rows are read too, for roots (the most
// recently active projects the store knows, at most
// hookdisable.MaxProjectRoots).
//
// StatusWarn when any switch is set (the developer may have meant it; the
// finding names what Observer stops seeing), StatusOK otherwise. Pure file
// inspection, report only: Observer never edits the vendor file. A
// sandboxed run (homeOverride non-empty) skips the system-wide
// managed-settings file, as checkCursorHooks skips the cross-mounted home.
//
// getenv is the doctor's one lookup (DoctorOptions.Getenv, under the
// pinned-home rule, FU-129): it reads the env-scope switches and the
// relocation variables of the user rows; a sandboxed run reads neither.
//
// Named "hooks.disabled" so `observer doctor hooks` scopes to it.
func checkHooksDisabled(homeDir, homeOverride string, roots []string, getenv func(string) string) Check {
	const name = "hooks.disabled"
	goos := runtime.GOOS
	if homeOverride != "" {
		goos = ""
	}
	o := HookSwitchInputs(hookdisable.Options{Home: homeDir, GOOS: goos, ProjectRoots: roots, Getenv: getenv, ReadFile: ReadHookSwitchFile})
	o.IncludeReplayOnly = true
	fs := hookdisable.Detect(o)
	if len(fs) == 0 {
		return Check{Name: name, Status: StatusOK, Message: "no vendor switch turns hooks off"}
	}
	details := make([]string, 0, len(fs))
	var off, replay []hookdisable.Finding
	for _, f := range fs {
		where := ""
		if f.ProjectRoot != "" {
			where = " in project " + f.ProjectRoot
		}
		silent := "Observer is silent on"
		if f.ReplayOnly {
			silent = "Observer's Claude Code hooks are not replayed on"
			replay = append(replay, f)
		} else {
			off = append(off, f)
		}
		details = append(details, fmt.Sprintf("%s: %s (%s scope): %s; %s %s%s",
			f.Path, f.Key, f.Scope, f.Effect, silent, strings.Join(f.Tools, ", "), where))
	}
	var parts []string
	if len(off) > 0 {
		parts = append(parts, "Observer's hooks do not run on "+strings.Join(hookdisable.AffectedTools(off), ", "))
	}
	if len(replay) > 0 {
		parts = append(parts, "Observer's Claude Code hooks are not replayed on "+strings.Join(hookdisable.AffectedTools(replay), ", "))
	}
	return Check{
		Name:    name,
		Status:  StatusWarn,
		Message: fmt.Sprintf("%d vendor switch(es) turn hooks off; %s", len(fs), strings.Join(parts, "; ")),
		Details: details,
	}
}

// ReadHookSwitchFile is the hook-off switch table's file read
// (hookdisable.Options.ReadFile) for every caller: the doctor, the daemon's
// hook-off watch, the managed-integrity cycle and the launch gates. It is the
// settings snapshot reader's capped regular-file read
// (agentconfigsvc.ReadRegularFile at agentconfigsvc.DefaultMaxFileBytes), so
// a FIFO or an outsized file at a switch path, in any of up to
// hookdisable.MaxProjectRoots projects, is refused at once (an unreadable
// file, never a finding) instead of hanging or bloating the cycle (R-188 F7).
func ReadHookSwitchFile(path string) ([]byte, error) {
	return agentconfigsvc.ReadRegularFile(path, agentconfigsvc.DefaultMaxFileBytes)
}

// HookSwitchInputs fills the injected inputs internal/hookdisable cannot
// own itself (it imports neither internal/hook nor internal/agentconfig,
// which imports it), leaving any the caller already set:
//
//   - ManagedFiles resolves a managed row's agentconfig FileRow id on the
//     Options' GOOS from the FileRow itself (the one owner of the path), and
//     for Claude Code adds its managed-settings.d drop-ins in name order
//     from hook.ClaudeManagedPaths (CC-5: C:\Program Files\ClaudeCode on
//     Windows, never the legacy C:\ProgramData path);
//   - OwnHookCommand is hook.IsObserverHookCommand (the DimCode deny list).
//
// Getenv is left to the caller: an env-scope row is read only by a caller
// whose own environment is the one the vendor tool starts in (the doctor in
// the developer's shell, the daemon for the tools it launches). Every caller
// of hookdisable.Detect that reads managed or deny-list rows goes through
// it, so the doctor, the daemon's watch and the gates read the same files.
func HookSwitchInputs(o hookdisable.Options) hookdisable.Options {
	if o.ReadFile == nil {
		o.ReadFile = ReadHookSwitchFile
	}
	if o.ManagedFiles == nil {
		o.ManagedFiles = hookSwitchManagedFiles
	}
	if o.OwnHookCommand == nil {
		o.OwnHookCommand = hook.IsObserverHookCommand
	}
	if o.UserFiles == nil && o.Home != "" {
		o.UserFiles = hookSwitchUserFiles(o.Home, o.GOOS, o.Getenv)
	}
	return o
}

// hookSwitchUserFiles is the production Options.UserFiles: a user row's
// agentconfig FileRow resolved under home with its relocation rules applied
// (ResolvePath with Relocate on, FU-38), read from getenv (when the caller
// passed none, the pinned-home rule for home, crossmount.HomeEnvAt, FU-129:
// the environment the tool starts in, the same one the route and hook
// writers read, unless home is pinned or isolated). goos "" (a
// sandboxed doctor run against an override home, which skips managed rows)
// resolves nothing, so every row reads its default HomeRel under the
// override home: no relocation variable or %APPDATA% may lead the run out
// of it.
func hookSwitchUserFiles(home, goos string, getenv func(string) string) func(string) (string, bool) {
	if goos == "" {
		return func(string) (string, bool) { return "", false }
	}
	if getenv == nil {
		getenv = crossmount.HomeEnvAt(home, nil)
	}
	return func(fileID string) (string, bool) {
		r, err := agentconfig.ResolveArtifact(fileID, agentconfig.PathEnv{GOOS: goos, Home: home, Getenv: getenv, Relocate: true})
		if err != nil || r.Status != agentconfig.PathResolved || r.Path == "" {
			return "", false
		}
		return r.Path, true
	}
}

// hookSwitchDropInDirs is the drop-in directory beside a managed file, per
// FileRow id: the files in it are read after the file, in name order.
var hookSwitchDropInDirs = map[string]func(goos string) string{
	"claude-code/managed-settings": func(goos string) string { return hook.ClaudeManagedPaths(goos).DropInDir },
}

// hookSwitchManagedFiles is the production Options.ManagedFiles.
func hookSwitchManagedFiles(fileID, goos string) []string {
	return managedFilesFor(fileID, goos, agentconfig.Files(), hookSwitchDropInDirs, os.ReadDir)
}

// managedFilesFor resolves one managed FileRow on goos, then lists the
// .json drop-ins beside it (hidden files skipped, name order), as Claude
// Code merges them. An id with no row, or no path on goos, resolves to
// nothing.
func managedFilesFor(fileID, goos string, rows []agentconfig.FileRow, dropIns map[string]func(string) string, readDir func(string) ([]os.DirEntry, error)) []string {
	var out []string
	for _, r := range rows {
		if r.ID != fileID {
			continue
		}
		if p := agentconfig.ResolvePath(r, agentconfig.PathEnv{GOOS: goos}); p.Status == agentconfig.PathResolved && p.Path != "" {
			out = append(out, p.Path)
		}
		break
	}
	if len(out) == 0 {
		return nil
	}
	dirFor := dropIns[fileID]
	if dirFor == nil || readDir == nil {
		return out
	}
	dir := dirFor(goos)
	if dir == "" {
		return out
	}
	entries, err := readDir(dir)
	if err != nil {
		return out
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".json") {
			continue
		}
		names = append(names, n)
	}
	sort.Strings(names)
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	for _, n := range names {
		out = append(out, strings.TrimRight(dir, `/\`)+sep+n)
	}
	return out
}

// hookSwitchProjectRoots is the bounded, most-recent-first project set the
// hooks.disabled check reads (nil when the database is unavailable: the
// check then covers home and managed scope only).
func hookSwitchProjectRoots(ctx context.Context, db *sql.DB) []string {
	if db == nil {
		return nil
	}
	roots, err := store.New(db).RecentProjectRoots(ctx, hookdisable.MaxProjectRoots)
	if err != nil {
		return nil
	}
	return roots
}
