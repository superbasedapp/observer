package shellwrapsvc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/shellwrap"
)

// Service applies and inspects the command-wrapping shell integration. The
// zero value targets the real machine; tests set Home (and GOOS/Getenv) so
// nothing outside a temp directory is ever touched.
type Service struct {
	// ConfigPath is config.toml ("" = <Home>/.observer/config.toml).
	ConfigPath string
	// Home overrides the home directory ("" = os.UserHomeDir).
	Home string
	// GOOS overrides the target OS ("" = runtime.GOOS). Only tests set it.
	GOOS string
	// Getenv reads the shell environment ($SHELL, $ZDOTDIR,
	// $XDG_CONFIG_HOME, and on Windows the %VAR% references in the User
	// Shell Folders value). nil = os.Getenv.
	Getenv func(string) string
	// ObserverPath is the observer executable baked into shims ("" =
	// Executable).
	ObserverPath string
	// Executable reports the running observer binary. nil = os.Executable.
	Executable func() (string, error)
	// EvalSymlinks resolves symlinks when the start-time refresh compares a
	// shim's baked path with the running binary. nil = filepath.EvalSymlinks.
	EvalSymlinks func(string) (string, error)
	// FileExists reports whether a shim's baked observer binary is still a
	// regular file (the start-time refresh keeps a shim whose binary exists).
	// nil = os.Stat.
	FileExists func(string) bool
	// ObserverRunnable reports whether the observer path the start-time
	// refresh would bake in is currently a regular executable file. nil =
	// os.Stat (regular, and on non-Windows at least one execute bit).
	ObserverRunnable func(string) bool
	// DocumentsKnownFolder / DocumentsShellFolder are the Windows lookups
	// behind the PowerShell profile location (shellwrap.ResolveDocumentsDir):
	// the known-folder API and the raw User Shell Folders registry value.
	// nil = the OS lookups (documents_windows.go; they fail elsewhere, which
	// leaves <home>\Documents).
	DocumentsKnownFolder func() (string, error)
	DocumentsShellFolder func() (string, error)
	// Installed reports whether an id's vendor command is installed (nil =
	// unknown). cmd wires the toolresolve ladder; with the shim exclusion
	// in place that ladder never counts a shim as an install.
	Installed func(id string) bool

	// The WSL bridge target (TargetWindows, T-419): Windows shells on the
	// machine whose WSL distro runs this process. See target.go.

	// WindowsHome is the Windows user home as this process reaches it (a
	// WSL drive-mount path such as /mnt/c/Users/<u>). "" = detect through
	// crossmount (the one Windows home that belongs to the current Windows
	// user). Tests set it to a temp dir under WindowsMountRoot.
	WindowsHome string
	// WindowsMountRoot is the WSL drive-mount root ("" = /mnt).
	WindowsMountRoot string
	// WSLDistro overrides $WSL_DISTRO_NAME (the distro a bridge shim names).
	WSLDistro string
	// IsWSL reports whether this process runs inside WSL (nil =
	// crossmount.IsWSL). Ignored when WindowsHome is set.
	IsWSL func() bool
	// WindowsShellFolder returns the Windows user's raw User Shell Folders
	// "Personal" value (the Documents folder that holds the PowerShell
	// profiles). nil = `reg.exe query` through WSL interop.
	WindowsShellFolder func() (string, error)
	// WindowsInstalled reports whether an id is installed on the side its
	// bridge shim runs (the Windows program for SideHost, the distro for
	// SideWSL). nil = unknown.
	WindowsInstalled func(id string, side shellwrap.Side) bool

	// OrgMaintained reports whether this node's organization maintains the
	// native target's wrap (surface-gap CLI-1b, D6: a managed node whose
	// admin pinned shell_wrap.org_maintain ON). While it does, a request
	// that would remove the native wrap (Disable, or an Apply of no tool)
	// is refused with ErrOrgMaintained unless the organization itself makes
	// it. nil = never (an individual node, and every test that does not set
	// it).
	OrgMaintained func() bool
}

// ErrOrgMaintained refuses a developer's removal of a wrap the organization
// maintains on this managed node (CLI-1b).
var ErrOrgMaintained = errors.New("your organization keeps command wrapping on for every installed tool on this managed machine, so it cannot be turned off or narrowed here (`observer shell-wrap enable all` keeps it); ask your administrator")

// Target names whose shells a call manages.
type Target string

// Targets.
const (
	// TargetNative: the shells of the OS this process runs on (the default).
	TargetNative Target = ""
	// TargetWindows: the Windows shells of the machine whose WSL distro runs
	// this process (the WSL bridge target).
	TargetWindows Target = "windows"
)

// ParseTarget resolves a target name. "", "native" and "local" are the
// native target.
func ParseTarget(name string) (Target, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "", "native", "local":
		return TargetNative, nil
	case "windows":
		return TargetWindows, nil
	}
	return "", fmt.Errorf("shellwrapsvc: unknown target %q (want native or windows)", name)
}

// Request is one apply / preview.
type Request struct {
	// Target selects whose shells are managed ("" = native).
	Target Target `json:"target,omitempty"`
	// Tools are ids to wrap, or shellwrap.AllTools. Empty = wrap nothing
	// (applying it is the same as Disable).
	Tools []string `json:"tools"`
	// Shells are shell names; empty = auto-detect.
	Shells []string `json:"shells"`
	// DryRun computes the changes and writes nothing.
	DryRun bool `json:"dry_run"`
	// ByOrganization marks an apply the managed daemon makes for the
	// organization (CLI-1b). It is recorded as [shell_wrap].org_applied, so
	// only such a wrap is removed when the organization releases it. Never
	// decoded from a request body: a dashboard or CLI apply is the
	// developer's own.
	ByOrganization bool `json:"-"`
}

// Change is one file-level effect of an apply.
type Change struct {
	// Path is the file (for a start-up file, the path the shell reads; a
	// symlink is edited at Target).
	Path   string `json:"path"`
	Target string `json:"target,omitempty"`
	// Kind is "shim" or "rc" (a shell start-up file) or "dir".
	Kind string `json:"kind"`
	// Action is create / update / delete / unchanged.
	Action string `json:"action"`
	Shell  string `json:"shell,omitempty"`
	// Detail is what is written (the shim, or the marked block) or removed,
	// so a preview shows exactly the bytes involved.
	Detail string `json:"detail,omitempty"`

	after []byte
	mode  fs.FileMode
	// local is the path this process writes or removes (Path on a native
	// target; the drive-mount path on the WSL bridge target; the symlink
	// target of a start-up file).
	local string
}

// Change actions.
const (
	ActionCreate    = "create"
	ActionUpdate    = "update"
	ActionDelete    = "delete"
	ActionUnchanged = "unchanged"
)

// Outcome is Apply's / Disable's result.
type Outcome struct {
	DryRun  bool           `json:"dry_run"`
	Plan    shellwrap.Plan `json:"plan"`
	Changes []Change       `json:"changes"`
	// ConfigPath is the config file the choice is recorded in; ConfigNote
	// explains a skipped record (dry run) or a fallback.
	ConfigPath string   `json:"config_path"`
	Notes      []string `json:"notes"`
	// Status is the state after the apply (for a dry run: the state now).
	Status shellwrap.Status `json:"status"`
}

// applyMu serializes applies within one process (the CLI and a dashboard
// request never share a process, and the file writes are atomic, so a
// cross-process race costs at most a re-apply).
var applyMu sync.Mutex

func (s Service) goos() string {
	if s.GOOS != "" {
		return s.GOOS
	}
	return runtime.GOOS
}

func (s Service) getenv(k string) string {
	if s.Getenv != nil {
		return s.Getenv(k)
	}
	return os.Getenv(k)
}

func (s Service) home() (string, error) {
	if s.Home != "" {
		return s.Home, nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("shellwrapsvc: home: %w", err)
	}
	return h, nil
}

func (s Service) configPath(home string) string {
	if s.ConfigPath != "" {
		return s.ConfigPath
	}
	return filepath.Join(home, ".observer", "config.toml")
}

func (s Service) observerPath() (string, error) {
	p := s.ObserverPath
	if p == "" {
		executable := s.Executable
		if executable == nil {
			executable = os.Executable
		}
		exe, err := executable()
		if err != nil {
			return "", fmt.Errorf("shellwrapsvc: observer executable: %w", err)
		}
		p = exe
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", fmt.Errorf("shellwrapsvc: observer executable: %w", err)
	}
	return abs, nil
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// Host describes the target machine for the pure planner.
func (s Service) Host() (shellwrap.Host, error) {
	home, err := s.home()
	if err != nil {
		return shellwrap.Host{}, err
	}
	h := shellwrap.Host{
		GOOS:          s.goos(),
		Home:          home,
		LoginShell:    s.getenv("SHELL"),
		ZDotDir:       s.getenv("ZDOTDIR"),
		XDGConfigHome: s.getenv("XDG_CONFIG_HOME"),
		Exists:        exists,
	}
	if h.GOOS == "windows" {
		// The PowerShell profiles live in the REAL Documents folder, which
		// OneDrive folder backup or a managed redirect often moves away from
		// <home>\Documents: ask the OS the way PowerShell does.
		if docs, _, ok := shellwrap.ResolveDocumentsDir(s.documentsLookup(home)); ok {
			h.DocumentsDir = docs
		}
	}
	return h, nil
}

// documentsLookup wires the Windows Documents-folder ladder's inputs.
func (s Service) documentsLookup(home string) shellwrap.DocumentsLookup {
	l := shellwrap.DocumentsLookup{
		KnownFolder: s.DocumentsKnownFolder,
		ShellFolder: s.DocumentsShellFolder,
		Getenv:      s.getenv,
		Home:        home,
	}
	if l.KnownFolder == nil {
		l.KnownFolder = osDocumentsKnownFolder
	}
	if l.ShellFolder == nil {
		l.ShellFolder = osDocumentsShellFolder
	}
	return l
}

// shimDirFor resolves a target's shim directory in the target's own path
// notation: the recorded override (with a leading ~ meaning the target home),
// else <home>/.observer/shims.
func shimDirFor(h shellwrap.Host, view config.ShellWrapTargetConfig) string {
	d := strings.TrimSpace(view.ShimDir)
	switch {
	case d == "":
		return shellwrap.DefaultShimDir(h)
	case d == "~":
		return h.Home
	case strings.HasPrefix(d, "~/") || strings.HasPrefix(d, `~\`):
		if h.GOOS == "windows" {
			return h.Join(h.Home, strings.ReplaceAll(d[2:], "/", `\`))
		}
		return filepath.Join(h.Home, d[2:])
	}
	return d
}

func (s Service) loadConfig(path string) (config.Config, error) {
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		return config.Config{}, fmt.Errorf("shellwrapsvc: load %s: %w", path, err)
	}
	return cfg, nil
}

// configuredSelection is a target's recorded choice.
func configuredSelection(view config.ShellWrapTargetConfig) (tools []string, shells []shellwrap.Shell) {
	for id, on := range view.Tools {
		if on {
			tools = append(tools, id)
		}
	}
	sort.Strings(tools)
	for name, on := range view.Shells {
		if sh, ok := shellwrap.ParseShell(name); on && ok {
			shells = append(shells, sh)
		}
	}
	sort.Slice(shells, func(i, j int) bool { return shells[i] < shells[j] })
	return tools, shells
}

// Status reports the native target's recorded choice against what is on
// disk. Read-only.
func (s Service) Status(ctx context.Context) (shellwrap.Status, error) {
	return s.StatusFor(ctx, TargetNative)
}

// StatusFor reports target's recorded choice against what is on disk.
// Read-only.
func (s Service) StatusFor(ctx context.Context, target Target) (shellwrap.Status, error) {
	if err := ctx.Err(); err != nil {
		return shellwrap.Status{}, err
	}
	home, err := s.home()
	if err != nil {
		return shellwrap.Status{}, err
	}
	cfg, err := s.loadConfig(s.configPath(home))
	if err != nil {
		return shellwrap.Status{}, err
	}
	te, err := s.targetEnv(cfg, target)
	if err != nil {
		return shellwrap.Status{}, err
	}
	obs, err := s.observerPath()
	if err != nil {
		return shellwrap.Status{}, err
	}
	return s.status(te, obs)
}

func (s Service) status(te targetEnv, obs string) (shellwrap.Status, error) {
	h := te.host
	shimDir := te.shimDir()
	tools, shells := configuredSelection(te.view)
	plan := shellwrap.Plan{ShimDir: shimDir}
	if te.view.Enabled {
		p, err := shellwrap.BuildPlan(shellwrap.PlanInput{
			Host: h, ShimDir: shimDir, ObserverPath: obs, ConfigPath: te.shimConfig,
			Selection: shellwrap.Selection{Tools: tools, Shells: shells},
			Installed: te.installed,
		})
		if err != nil {
			return shellwrap.Status{}, err
		}
		plan = p
	}
	disk, _ := inspect(te, shimDir)
	return shellwrap.ComputeStatus(shellwrap.StatusInput{
		Host: h, Enabled: te.view.Enabled, Plan: plan, Selected: tools,
		ObserverPath: obs, Disk: disk, Installed: te.installed,
	}), nil
}

// rcState is one candidate start-up file as read.
type rcState struct {
	path    string // in the target's notation
	local   string // the same file as this process reaches it
	target  string // where writes go (the symlink target, or local)
	exists  bool
	content string
	mode    fs.FileMode
	shell   shellwrap.Shell
	err     error
}

// readRC reads one start-up file. local maps the target path to the path
// this process reaches; an unreachable path is reported, never guessed at.
func readRC(p string, local func(string) (string, error)) rcState {
	st := rcState{path: p, mode: 0o644}
	lp, err := local(p)
	if err != nil {
		st.err = err
		return st
	}
	st.local, st.target = lp, lp
	fi, err := os.Lstat(lp)
	if errors.Is(err, fs.ErrNotExist) {
		return st
	}
	if err != nil {
		st.err = err
		return st
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		t, err := filepath.EvalSymlinks(lp)
		if err != nil {
			st.err = fmt.Errorf("a symlink whose target cannot be resolved (%w) - not touched", err)
			return st
		}
		st.target = t
		if fi, err = os.Stat(t); err != nil {
			st.err = err
			return st
		}
	}
	if !fi.Mode().IsRegular() {
		st.err = errors.New("not a regular file - not touched")
		return st
	}
	b, err := os.ReadFile(st.target) /* #nosec G304 -- a shell start-up file path from the fixed per-shell table under the operator's own home */
	if err != nil {
		st.err = err
		return st
	}
	st.exists, st.content, st.mode = true, string(b), fi.Mode().Perm()
	return st
}

// readHead reads up to n bytes of p.
func readHead(p string, n int) ([]byte, error) {
	f, err := os.Open(p) /* #nosec G304 -- a file inside the observer-owned shim directory */
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, n)
	got, err := io.ReadFull(f, buf)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return buf[:got], nil
}

// inspectShims reads the marked shims in the shim directory. Symlinks and
// anything without shellwrap.ShimMarker are not the applier's files and are
// never returned. Paths are reported in the target's notation (join), read
// at the local directory.
func inspectShims(shimDir, localDir string, join func(...string) string) []shellwrap.OnDiskShim {
	out := []shellwrap.OnDiskShim{}
	entries, err := os.ReadDir(localDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		lp := filepath.Join(localDir, e.Name())
		head, err := readHead(lp, 512)
		if err != nil || !shellwrap.IsShim(head) {
			continue
		}
		tool, command, version, _ := shellwrap.ParseMarkerLine(string(head))
		full, err := os.ReadFile(lp) /* #nosec G304 -- a marked shim inside the observer-owned shim directory */
		if err != nil {
			continue
		}
		out = append(out, shellwrap.OnDiskShim{
			FileName: e.Name(), Path: join(shimDir, e.Name()), ToolID: tool, Command: command, Version: version, Content: string(full),
		})
	}
	return out
}

// inspect reads the shim directory and every candidate start-up file.
func inspect(te targetEnv, shimDir string) (shellwrap.OnDisk, map[string]rcState) {
	h := te.host
	shims := []shellwrap.OnDiskShim{}
	if localDir, err := te.local(shimDir); err == nil {
		shims = inspectShims(shimDir, localDir, h.Join)
	}
	disk := shellwrap.OnDisk{ShimDir: shimDir, Shims: shims, RC: []shellwrap.OnDiskRC{}}
	states := map[string]rcState{}
	for _, p := range shellwrap.CandidateRCPaths(h) {
		st := readRC(p, te.local)
		sh, _ := shellwrap.ShellForRCPath(p, h)
		st.shell = sh
		states[p] = st
		r := shellwrap.OnDiskRC{Path: p, Shell: sh, Exists: st.exists}
		if st.err != nil {
			r.Err = st.err.Error()
		} else if st.exists {
			body, found, err := shellwrap.BlockBody(st.content)
			if err != nil {
				r.Err = err.Error()
			}
			r.HasBlock, r.Body = found, body
		}
		disk.RC = append(disk.RC, r)
	}
	return disk, states
}

// shellsFromNames parses request shell names.
func shellsFromNames(names []string) ([]shellwrap.Shell, error) {
	var out []shellwrap.Shell
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			continue
		}
		sh, ok := shellwrap.ParseShell(n)
		if !ok {
			return nil, fmt.Errorf("shellwrapsvc: unknown shell %q (want bash, zsh, fish or powershell)", n)
		}
		out = append(out, sh)
	}
	return out, nil
}

// Apply reconciles the machine to req: shims for the selected commands, a
// PATH block in each selected shell's start-up file, and nothing else - a
// shim or block from an earlier selection is removed. Unless DryRun it then
// records the choice in [shell_wrap]. An empty Tools list is Disable.
func (s Service) Apply(ctx context.Context, req Request) (Outcome, error) {
	shells, err := shellsFromNames(req.Shells)
	if err != nil {
		return Outcome{}, err
	}
	return s.reconcile(ctx, req.Target, shellwrap.Selection{Tools: req.Tools, Shells: shells}, req.DryRun, false, req.ByOrganization)
}

// Disable removes every native-target shim and marked block, restoring each
// start-up file byte-for-byte, and records enabled = false (the per-tool
// choice is kept so a later enable restores it).
func (s Service) Disable(ctx context.Context, dryRun bool) (Outcome, error) {
	return s.DisableFor(ctx, TargetNative, dryRun)
}

// DisableFor is Disable for one target.
func (s Service) DisableFor(ctx context.Context, target Target, dryRun bool) (Outcome, error) {
	return s.reconcile(ctx, target, shellwrap.Selection{}, dryRun, true, false)
}

// ReleaseOrganization removes the native target's wrap when, and only when,
// the managed daemon applied it for the organization ([shell_wrap].
// org_applied, CLI-1b). A wrap the developer applied is theirs and is left
// alone. released reports whether a wrap was removed.
func (s Service) ReleaseOrganization(ctx context.Context) (out Outcome, released bool, err error) {
	home, err := s.home()
	if err != nil {
		return Outcome{}, false, err
	}
	cfg, err := s.loadConfig(s.configPath(home))
	if err != nil {
		return Outcome{}, false, err
	}
	if !cfg.ShellWrap.OrgApplied {
		return Outcome{}, false, nil
	}
	out, err = s.reconcile(ctx, TargetNative, shellwrap.Selection{}, false, true, true)
	return out, err == nil, err
}

// orgBlocksRemoval reports whether the organization's maintained wrap
// refuses this reconcile: the native target, not made by the organization,
// while it maintains it, and a request that would leave less than the
// organization's selection (every installed CLI tool, shellwrap.AllTools):
// a disable, an empty selection, or a selection that does not ask for
// AllTools (a narrower one would otherwise read in sync and never be put
// back).
func (s Service) orgBlocksRemoval(target Target, sel shellwrap.Selection, disable, byOrg bool) bool {
	if target != TargetNative || byOrg || s.OrgMaintained == nil {
		return false
	}
	narrows := disable || !slices.Contains(sel.Tools, shellwrap.AllTools)
	return narrows && s.OrgMaintained()
}

// OrgSelectionCovered reports whether a native status already carries the
// organization's selection (CLI-1b): every CLI row AllTools would wrap (an
// installed terminal row, or one whose install state is unknown) is
// selected, and every detected shell is planned. The managed maintenance
// and the shell_wrap_missing check read it beside the status's own sync
// state, so a narrower choice recorded before the pin is not read as the
// organization's wrap.
func OrgSelectionCovered(st shellwrap.Status) bool {
	for _, t := range st.Tools {
		if t.Kind != integration.LaunchKindTerminal {
			continue
		}
		if (t.Installed == nil || *t.Installed) && !t.Selected {
			return false
		}
	}
	for _, sh := range st.DetectedShells {
		if !slices.Contains(st.PlannedShells, sh) {
			return false
		}
	}
	return true
}

func (s Service) reconcile(ctx context.Context, target Target, sel shellwrap.Selection, dryRun, disable, byOrg bool) (Outcome, error) {
	if err := ctx.Err(); err != nil {
		return Outcome{}, err
	}
	if s.orgBlocksRemoval(target, sel, disable, byOrg) {
		return Outcome{}, ErrOrgMaintained
	}
	applyMu.Lock()
	defer applyMu.Unlock()

	home, err := s.home()
	if err != nil {
		return Outcome{}, err
	}
	cfgPath := s.configPath(home)
	cfg, err := s.loadConfig(cfgPath)
	if err != nil {
		return Outcome{}, err
	}
	te, err := s.targetEnv(cfg, target)
	if err != nil {
		return Outcome{}, err
	}
	obs, err := s.observerPath()
	if err != nil {
		return Outcome{}, err
	}
	if err := te.checkObserver(obs); err != nil {
		return Outcome{}, err
	}
	shimDir := te.shimDir()
	plan, err := shellwrap.BuildPlan(shellwrap.PlanInput{
		Host: te.host, ShimDir: shimDir, ObserverPath: obs, ConfigPath: te.shimConfig, Selection: sel, Installed: te.installed,
	})
	if err != nil {
		return Outcome{}, err
	}
	disk, states := inspect(te, shimDir)
	changes, err := computeChanges(plan, disk, states, te)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{DryRun: dryRun, Plan: plan, Changes: changes, ConfigPath: cfgPath, Notes: []string{}}
	if dryRun {
		out.Notes = append(out.Notes, "dry run - nothing was written")
		out.Status, err = s.status(te, obs)
		return out, err
	}
	localDir, err := te.local(shimDir)
	if err != nil {
		return out, err
	}
	if err := execute(changes, localDir, plan.Empty()); err != nil {
		return out, err
	}
	if err := recordChoice(cfgPath, cfg, plan, sel, disable, target, byOrg); err != nil {
		out.Notes = append(out.Notes, "the files were applied but the choice was not recorded in "+cfgPath+": "+err.Error())
	}
	if written := countWritten(changes); written > 0 {
		out.Notes = append(out.Notes, te.reopenNote())
	}
	cfg2, err := s.loadConfig(cfgPath)
	if err != nil {
		cfg2 = cfg
	}
	if te2, err := s.targetEnv(cfg2, target); err == nil {
		te = te2
	}
	out.Status, err = s.status(te, obs)
	return out, err
}

func countWritten(cs []Change) int {
	n := 0
	for _, c := range cs {
		if c.Action != ActionUnchanged {
			n++
		}
	}
	return n
}

// computeChanges diffs the plan against the disk. It refuses (before any
// write) when a start-up file it would have to touch cannot be read or
// carries malformed markers.
func computeChanges(plan shellwrap.Plan, disk shellwrap.OnDisk, states map[string]rcState, te targetEnv) ([]Change, error) {
	var changes []Change
	planned := map[string]bool{}
	onDisk := map[string]shellwrap.OnDiskShim{}
	for _, d := range disk.Shims {
		onDisk[d.FileName] = d
	}
	for _, sh := range plan.Shims {
		planned[sh.FileName] = true
		lp, err := te.local(sh.Path)
		if err != nil {
			return nil, fmt.Errorf("shellwrapsvc: %s: %w", sh.Path, err)
		}
		c := Change{Path: sh.Path, Kind: "shim", Detail: sh.Content, after: []byte(sh.Content), mode: 0o755, local: lp}
		switch cur, ok := onDisk[sh.FileName]; {
		case !ok:
			if exists(lp) {
				return nil, fmt.Errorf("shellwrapsvc: %s exists and is not an observer shim - move it away or pick another shim_dir", sh.Path)
			}
			c.Action = ActionCreate
		case cur.Content == sh.Content:
			c.Action, c.Detail = ActionUnchanged, ""
		default:
			c.Action = ActionUpdate
		}
		changes = append(changes, c)
	}
	for _, d := range disk.Shims {
		if !planned[d.FileName] {
			lp, err := te.local(d.Path)
			if err != nil {
				return nil, fmt.Errorf("shellwrapsvc: %s: %w", d.Path, err)
			}
			changes = append(changes, Change{Path: d.Path, Kind: "shim", Action: ActionDelete, local: lp})
		}
	}

	wanted := map[string]shellwrap.RCFile{}
	for _, r := range plan.RC {
		wanted[r.Path] = r
	}
	for p, r := range wanted {
		if _, ok := states[p]; !ok {
			// Defensive: every planned path is a candidate path today.
			st := readRC(p, te.local)
			st.shell = r.Shell
			states[p] = st
		}
	}
	paths := make([]string, 0, len(states))
	for p := range states {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		st := states[p]
		w, isWanted := wanted[p]
		if !isWanted && !st.exists {
			continue
		}
		if st.err != nil {
			if isWanted {
				return nil, fmt.Errorf("shellwrapsvc: %s: %w", p, st.err)
			}
			continue
		}
		c := Change{Path: p, Kind: "rc", Shell: string(st.shell), mode: st.mode, local: st.target}
		if st.target != st.local {
			c.Target = st.target
		}
		if isWanted {
			next, err := shellwrap.InsertBlock(st.content, w.Body, st.exists)
			if err != nil {
				return nil, fmt.Errorf("shellwrapsvc: %s: %w", p, err)
			}
			switch {
			case !st.exists:
				c.Action = ActionCreate
			case next == st.content:
				c.Action = ActionUnchanged
			default:
				c.Action = ActionUpdate
			}
			if c.Action != ActionUnchanged {
				c.Detail = blockText(next)
			}
			c.after = []byte(next)
			changes = append(changes, c)
			continue
		}
		res, err := shellwrap.RemoveBlock(st.content)
		if err != nil {
			return nil, fmt.Errorf("shellwrapsvc: %s: %w", p, err)
		}
		if !res.Found {
			continue
		}
		c.Detail = blockText(st.content)
		c.after = []byte(res.Content)
		c.Action = ActionUpdate
		if res.DeleteFile {
			c.Action = ActionDelete
		}
		changes = append(changes, c)
	}
	return changes, nil
}

// blockText extracts the marked block (for a preview).
func blockText(content string) string {
	begin := strings.Index(content, shellwrap.BlockBegin)
	end := strings.Index(content, shellwrap.BlockEnd)
	if begin < 0 || end < begin {
		return ""
	}
	return content[begin : end+len(shellwrap.BlockEnd)]
}

// execute performs the changes: shims first (so a PATH block never points at
// a directory missing its shims), then start-up files, then deletions. Every
// path here is the LOCAL one (Change.local, and shimDir as this process
// reaches it).
func execute(changes []Change, shimDir string, planEmpty bool) error {
	var errs []error
	for _, c := range changes {
		if c.Kind != "shim" || (c.Action != ActionCreate && c.Action != ActionUpdate) {
			continue
		}
		if err := os.MkdirAll(shimDir, 0o755); err != nil { /* #nosec G301 -- the shim dir must be traversable by the operator's shells, like ~/.local/bin */
			return fmt.Errorf("shellwrapsvc: mkdir %s: %w", shimDir, err)
		}
		if err := fsatomic.WriteFile(c.local, c.after, fsatomic.Options{FilePerm: 0o755, DirPerm: 0o755, TempPattern: ".sbo-shim-*.tmp"}); err != nil {
			return fmt.Errorf("shellwrapsvc: write %s: %w", c.Path, err)
		}
	}
	for _, c := range changes {
		if c.Kind != "rc" || c.Action == ActionUnchanged {
			continue
		}
		target := c.local
		if c.Action == ActionDelete {
			if err := os.Remove(target); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("shellwrapsvc: remove %s: %w", target, err))
			}
			continue
		}
		mode := c.mode
		if mode == 0 {
			mode = 0o644
		}
		if err := fsatomic.WriteFile(target, c.after, fsatomic.Options{FilePerm: mode, DirPerm: 0o755, TempPattern: ".sbo-rc-*.tmp"}); err != nil {
			errs = append(errs, fmt.Errorf("shellwrapsvc: write %s: %w", target, err))
		}
	}
	for _, c := range changes {
		if c.Kind == "shim" && c.Action == ActionDelete {
			if err := os.Remove(c.local); err != nil && !errors.Is(err, fs.ErrNotExist) {
				errs = append(errs, fmt.Errorf("shellwrapsvc: remove %s: %w", c.Path, err))
			}
		}
	}
	if planEmpty {
		// Only an EMPTY directory is removed (os.Remove refuses otherwise):
		// anything the operator put there themselves stays.
		_ = os.Remove(shimDir)
	}
	return errors.Join(errs...)
}

// configKeyRE is the closed spelling a tool id may take as a TOML bare key.
var configKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// targetConfigPrefix is where a target's choice lives in config.toml.
func targetConfigPrefix(t Target) string {
	if t == TargetWindows {
		return "shell_wrap.windows"
	}
	return "shell_wrap"
}

// targetView returns a target's recorded choice.
func targetView(cfg config.Config, t Target) config.ShellWrapTargetConfig {
	if t == TargetWindows {
		return cfg.ShellWrap.Windows
	}
	return cfg.ShellWrap.Native()
}

// setTargetView writes a target's choice back into cfg.
func setTargetView(cfg *config.Config, t Target, v config.ShellWrapTargetConfig) {
	if t == TargetWindows {
		cfg.ShellWrap.Windows = v
		return
	}
	cfg.ShellWrap.SetNative(v)
}

// recordChoice writes the target's [shell_wrap] keys through
// config.PatchFile (scalar line edits: comments and untouched lines survive
// byte-for-byte).
func recordChoice(path string, cfg config.Config, plan shellwrap.Plan, sel shellwrap.Selection, disable bool, target Target, byOrg bool) error {
	var patches []config.Patch
	prefix := targetConfigPrefix(target)
	set := func(dotted string, v bool) {
		rhs := "false"
		if v {
			rhs = "true"
		}
		patches = append(patches, config.Patch{Dotted: prefix + "." + dotted, RHS: rhs, Scalar: true})
	}
	view := targetView(cfg, target)
	enabled := !disable && !plan.Empty()
	view.Enabled = enabled
	set("enabled", enabled)
	// The native target's provenance (CLI-1b): set by the organization's
	// apply, cleared by any other write (the developer then owns the wrap).
	if target == TargetNative {
		if orgApplied := byOrg && enabled; orgApplied != cfg.ShellWrap.OrgApplied {
			set("org_applied", orgApplied)
			cfg.ShellWrap.OrgApplied = orgApplied
		}
	}
	if !disable {
		chosen := map[string]bool{}
		for _, t := range plan.Tools {
			chosen[t.ID] = true
		}
		tools := map[string]bool{}
		for k, v := range view.Tools {
			tools[k] = v
		}
		ids := map[string]bool{}
		for id := range chosen {
			ids[id] = true
		}
		for id := range tools {
			ids[id] = true
		}
		for _, id := range sortedKeys(ids) {
			if !configKeyRE.MatchString(id) {
				continue
			}
			if tools[id] == chosen[id] && !chosen[id] {
				continue // already false: no churn
			}
			tools[id] = chosen[id]
			set("tools."+id, chosen[id])
		}
		view.Tools = tools
		explicit := map[string]bool{}
		for _, sh := range sel.Shells {
			explicit[string(sh)] = true
		}
		shells := map[string]bool{}
		for k, v := range view.Shells {
			shells[k] = v
		}
		names := map[string]bool{}
		for n := range explicit {
			names[n] = true
		}
		for n := range shells {
			names[n] = true
		}
		for _, n := range sortedKeys(names) {
			if shells[n] == explicit[n] && !explicit[n] {
				continue
			}
			shells[n] = explicit[n]
			set("shells."+n, explicit[n])
		}
		view.Shells = shells
	}
	setTargetView(&cfg, target, view)
	if _, err := config.PatchFile(path, cfg, patches); err != nil {
		return err
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
