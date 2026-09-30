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
	"sort"
	"strings"
	"sync"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/fsatomic"
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
}

// Request is one apply / preview.
type Request struct {
	// Tools are ids to wrap, or shellwrap.AllTools. Empty = wrap nothing
	// (applying it is the same as Disable).
	Tools []string `json:"tools"`
	// Shells are shell names; empty = auto-detect.
	Shells []string `json:"shells"`
	// DryRun computes the changes and writes nothing.
	DryRun bool `json:"dry_run"`
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

func (s Service) shimDir(h shellwrap.Host, cfg config.Config) string {
	d := strings.TrimSpace(cfg.ShellWrap.ShimDir)
	switch {
	case d == "":
		return shellwrap.DefaultShimDir(h)
	case d == "~":
		return h.Home
	case strings.HasPrefix(d, "~/") || strings.HasPrefix(d, `~\`):
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

// configuredSelection is the recorded choice in [shell_wrap].
func configuredSelection(cfg config.Config) (tools []string, shells []shellwrap.Shell) {
	for id, on := range cfg.ShellWrap.Tools {
		if on {
			tools = append(tools, id)
		}
	}
	sort.Strings(tools)
	for name, on := range cfg.ShellWrap.Shells {
		if sh, ok := shellwrap.ParseShell(name); on && ok {
			shells = append(shells, sh)
		}
	}
	sort.Slice(shells, func(i, j int) bool { return shells[i] < shells[j] })
	return tools, shells
}

// Status reports the recorded choice against what is on disk. Read-only.
func (s Service) Status(ctx context.Context) (shellwrap.Status, error) {
	if err := ctx.Err(); err != nil {
		return shellwrap.Status{}, err
	}
	h, err := s.Host()
	if err != nil {
		return shellwrap.Status{}, err
	}
	cfg, err := s.loadConfig(s.configPath(h.Home))
	if err != nil {
		return shellwrap.Status{}, err
	}
	obs, err := s.observerPath()
	if err != nil {
		return shellwrap.Status{}, err
	}
	return s.status(h, cfg, obs)
}

func (s Service) status(h shellwrap.Host, cfg config.Config, obs string) (shellwrap.Status, error) {
	shimDir := s.shimDir(h, cfg)
	tools, shells := configuredSelection(cfg)
	plan := shellwrap.Plan{ShimDir: shimDir}
	if cfg.ShellWrap.Enabled {
		p, err := shellwrap.BuildPlan(shellwrap.PlanInput{
			Host: h, ShimDir: shimDir, ObserverPath: obs,
			Selection: shellwrap.Selection{Tools: tools, Shells: shells},
			Installed: s.Installed,
		})
		if err != nil {
			return shellwrap.Status{}, err
		}
		plan = p
	}
	disk, _ := inspect(h, shimDir)
	return shellwrap.ComputeStatus(shellwrap.StatusInput{
		Host: h, Enabled: cfg.ShellWrap.Enabled, Plan: plan, Selected: tools,
		ObserverPath: obs, Disk: disk, Installed: s.Installed,
	}), nil
}

// rcState is one candidate start-up file as read.
type rcState struct {
	path    string
	target  string // where writes go (the symlink target, or path)
	exists  bool
	content string
	mode    fs.FileMode
	shell   shellwrap.Shell
	err     error
}

func readRC(p string) rcState {
	st := rcState{path: p, target: p, mode: 0o644}
	fi, err := os.Lstat(p)
	if errors.Is(err, fs.ErrNotExist) {
		return st
	}
	if err != nil {
		st.err = err
		return st
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		t, err := filepath.EvalSymlinks(p)
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
// never returned.
func inspectShims(shimDir string) []shellwrap.OnDiskShim {
	out := []shellwrap.OnDiskShim{}
	entries, err := os.ReadDir(shimDir)
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		p := filepath.Join(shimDir, e.Name())
		head, err := readHead(p, 512)
		if err != nil || !shellwrap.IsShim(head) {
			continue
		}
		tool, command, version, _ := shellwrap.ParseMarkerLine(string(head))
		full, err := os.ReadFile(p) /* #nosec G304 -- a marked shim inside the observer-owned shim directory */
		if err != nil {
			continue
		}
		out = append(out, shellwrap.OnDiskShim{
			FileName: e.Name(), Path: p, ToolID: tool, Command: command, Version: version, Content: string(full),
		})
	}
	return out
}

// inspect reads the shim directory and every candidate start-up file.
func inspect(h shellwrap.Host, shimDir string) (shellwrap.OnDisk, map[string]rcState) {
	disk := shellwrap.OnDisk{ShimDir: shimDir, Shims: inspectShims(shimDir), RC: []shellwrap.OnDiskRC{}}
	states := map[string]rcState{}
	for _, p := range shellwrap.CandidateRCPaths(h) {
		st := readRC(p)
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
	return s.reconcile(ctx, shellwrap.Selection{Tools: req.Tools, Shells: shells}, req.DryRun, false)
}

// Disable removes every shim and every marked block, restoring each start-up
// file byte-for-byte, and records enabled = false (the per-tool choice is
// kept so a later enable restores it).
func (s Service) Disable(ctx context.Context, dryRun bool) (Outcome, error) {
	return s.reconcile(ctx, shellwrap.Selection{}, dryRun, true)
}

func (s Service) reconcile(ctx context.Context, sel shellwrap.Selection, dryRun, disable bool) (Outcome, error) {
	if err := ctx.Err(); err != nil {
		return Outcome{}, err
	}
	applyMu.Lock()
	defer applyMu.Unlock()

	h, err := s.Host()
	if err != nil {
		return Outcome{}, err
	}
	cfgPath := s.configPath(h.Home)
	cfg, err := s.loadConfig(cfgPath)
	if err != nil {
		return Outcome{}, err
	}
	obs, err := s.observerPath()
	if err != nil {
		return Outcome{}, err
	}
	shimDir := s.shimDir(h, cfg)
	plan, err := shellwrap.BuildPlan(shellwrap.PlanInput{
		Host: h, ShimDir: shimDir, ObserverPath: obs, Selection: sel, Installed: s.Installed,
	})
	if err != nil {
		return Outcome{}, err
	}
	disk, states := inspect(h, shimDir)
	changes, err := computeChanges(plan, disk, states)
	if err != nil {
		return Outcome{}, err
	}
	out := Outcome{DryRun: dryRun, Plan: plan, Changes: changes, ConfigPath: cfgPath, Notes: []string{}}
	if dryRun {
		out.Notes = append(out.Notes, "dry run - nothing was written")
		out.Status, err = s.status(h, cfg, obs)
		return out, err
	}
	if err := execute(changes, shimDir, plan.Empty()); err != nil {
		return out, err
	}
	if err := recordChoice(cfgPath, cfg, plan, sel, disable); err != nil {
		out.Notes = append(out.Notes, "the files were applied but the choice was not recorded in "+cfgPath+": "+err.Error())
	}
	if written := countWritten(changes); written > 0 {
		out.Notes = append(out.Notes, "open a new shell (or re-source its start-up file) for the change to take effect")
	}
	cfg2, err := s.loadConfig(cfgPath)
	if err != nil {
		cfg2 = cfg
	}
	out.Status, err = s.status(h, cfg2, obs)
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
func computeChanges(plan shellwrap.Plan, disk shellwrap.OnDisk, states map[string]rcState) ([]Change, error) {
	var changes []Change
	planned := map[string]bool{}
	onDisk := map[string]shellwrap.OnDiskShim{}
	for _, d := range disk.Shims {
		onDisk[d.FileName] = d
	}
	for _, sh := range plan.Shims {
		planned[sh.FileName] = true
		c := Change{Path: sh.Path, Kind: "shim", Detail: sh.Content, after: []byte(sh.Content), mode: 0o755}
		switch cur, ok := onDisk[sh.FileName]; {
		case !ok:
			if exists(sh.Path) {
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
			changes = append(changes, Change{Path: d.Path, Kind: "shim", Action: ActionDelete})
		}
	}

	wanted := map[string]shellwrap.RCFile{}
	for _, r := range plan.RC {
		wanted[r.Path] = r
	}
	for p, r := range wanted {
		if _, ok := states[p]; !ok {
			// Defensive: every planned path is a candidate path today.
			st := readRC(p)
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
		c := Change{Path: p, Kind: "rc", Shell: string(st.shell), mode: st.mode}
		if st.target != p {
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
// a directory missing its shims), then start-up files, then deletions.
func execute(changes []Change, shimDir string, planEmpty bool) error {
	var errs []error
	for _, c := range changes {
		if c.Kind != "shim" || (c.Action != ActionCreate && c.Action != ActionUpdate) {
			continue
		}
		if err := os.MkdirAll(shimDir, 0o755); err != nil { /* #nosec G301 -- the shim dir must be traversable by the operator's shells, like ~/.local/bin */
			return fmt.Errorf("shellwrapsvc: mkdir %s: %w", shimDir, err)
		}
		if err := fsatomic.WriteFile(c.Path, c.after, fsatomic.Options{FilePerm: 0o755, DirPerm: 0o755, TempPattern: ".sbo-shim-*.tmp"}); err != nil {
			return fmt.Errorf("shellwrapsvc: write %s: %w", c.Path, err)
		}
	}
	for _, c := range changes {
		if c.Kind != "rc" || c.Action == ActionUnchanged {
			continue
		}
		target := c.Path
		if c.Target != "" {
			target = c.Target
		}
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
			if err := os.Remove(c.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
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

// recordChoice writes [shell_wrap] through config.PatchFile (scalar line
// edits: comments and untouched lines survive byte-for-byte).
func recordChoice(path string, cfg config.Config, plan shellwrap.Plan, sel shellwrap.Selection, disable bool) error {
	var patches []config.Patch
	set := func(dotted string, v bool) {
		rhs := "false"
		if v {
			rhs = "true"
		}
		patches = append(patches, config.Patch{Dotted: dotted, RHS: rhs, Scalar: true})
	}
	enabled := !disable && !plan.Empty()
	cfg.ShellWrap.Enabled = enabled
	set("shell_wrap.enabled", enabled)
	if !disable {
		chosen := map[string]bool{}
		for _, t := range plan.Tools {
			chosen[t.ID] = true
		}
		if cfg.ShellWrap.Tools == nil {
			cfg.ShellWrap.Tools = map[string]bool{}
		}
		ids := map[string]bool{}
		for id := range chosen {
			ids[id] = true
		}
		for id := range cfg.ShellWrap.Tools {
			ids[id] = true
		}
		for _, id := range sortedKeys(ids) {
			if !configKeyRE.MatchString(id) {
				continue
			}
			if cfg.ShellWrap.Tools[id] == chosen[id] && !chosen[id] {
				continue // already false: no churn
			}
			cfg.ShellWrap.Tools[id] = chosen[id]
			set("shell_wrap.tools."+id, chosen[id])
		}
		explicit := map[string]bool{}
		for _, sh := range sel.Shells {
			explicit[string(sh)] = true
		}
		if cfg.ShellWrap.Shells == nil {
			cfg.ShellWrap.Shells = map[string]bool{}
		}
		names := map[string]bool{}
		for n := range explicit {
			names[n] = true
		}
		for n := range cfg.ShellWrap.Shells {
			names[n] = true
		}
		for _, n := range sortedKeys(names) {
			if cfg.ShellWrap.Shells[n] == explicit[n] && !explicit[n] {
				continue
			}
			cfg.ShellWrap.Shells[n] = explicit[n]
			set("shell_wrap.shells."+n, explicit[n])
		}
	}
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
