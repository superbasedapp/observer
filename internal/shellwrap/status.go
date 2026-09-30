package shellwrap

import (
	"sort"
	"strings"
)

// DefaultShimDir is the observer-owned shim directory under home.
func DefaultShimDir(h Host) string {
	return h.join(h.Home, ".observer", "shims")
}

// OnDiskShim is one file in the shim directory that carries ShimMarker.
type OnDiskShim struct {
	FileName string `json:"file_name"`
	Path     string `json:"path"`
	ToolID   string `json:"tool_id"`
	Command  string `json:"command"`
	Version  string `json:"version"`
	// Content is the full file (for staleness comparison; never rendered).
	Content string `json:"-"`
}

// OnDiskRC is one candidate start-up file as found on disk.
type OnDiskRC struct {
	Path     string `json:"path"`
	Shell    Shell  `json:"shell"`
	Exists   bool   `json:"exists"`
	HasBlock bool   `json:"has_block"`
	// Body is the installed block body (LF-normalized), "" when none.
	Body string `json:"-"`
	// Err names a file that could not be read or whose markers are
	// malformed; the applier will not touch it.
	Err string `json:"error,omitempty"`
}

// OnDisk is the installed state.
type OnDisk struct {
	ShimDir string       `json:"shim_dir"`
	Shims   []OnDiskShim `json:"shims"`
	RC      []OnDiskRC   `json:"rc"`
}

// ToolStatus is one wrappable row's state.
type ToolStatus struct {
	Candidate
	// Selected: the row is in the configured selection.
	Selected bool `json:"selected"`
	// Installed is nil when unknown.
	Installed *bool `json:"installed,omitempty"`
	// Active are the commands whose shim is on disk.
	Active []string `json:"active"`
	// Stale are active commands whose shim differs from a fresh render
	// (observer moved, template changed): re-apply refreshes them.
	Stale []string `json:"stale,omitempty"`
}

// RCStatus is one managed start-up file.
type RCStatus struct {
	OnDiskRC
	// Wanted: the configured plan puts a block here.
	Wanted bool `json:"wanted"`
	// Current: the installed block equals the planned one.
	Current bool `json:"current"`
}

// Status is the full report the CLI and the dashboard render.
type Status struct {
	GOOS         string `json:"goos"`
	Enabled      bool   `json:"enabled"`
	ShimDir      string `json:"shim_dir"`
	ObserverPath string `json:"observer_path"`
	// Shells are the shells manageable on this OS, and which the plan uses.
	Shells         []Shell `json:"shells"`
	DetectedShells []Shell `json:"detected_shells"`
	PlannedShells  []Shell `json:"planned_shells"`
	// Active: any shim or block is installed.
	Active bool `json:"active"`
	// InSync: the installed files equal the configured plan (nothing to do).
	InSync   bool         `json:"in_sync"`
	Tools    []ToolStatus `json:"tools"`
	RC       []RCStatus   `json:"rc"`
	Orphans  []OnDiskShim `json:"orphans"`
	Warnings []string     `json:"warnings"`
}

// StatusInput is ComputeStatus's input.
type StatusInput struct {
	Host Host
	// Enabled is the configured [shell_wrap].enabled.
	Enabled bool
	// Plan is BuildPlan over the CONFIGURED selection (an empty plan when
	// disabled).
	Plan Plan
	// Selected are the configured tool ids (before AllTools expansion).
	Selected     []string
	ObserverPath string
	Disk         OnDisk
	Installed    func(id string) bool
}

// ComputeStatus compares the configured plan against what is on disk.
func ComputeStatus(in StatusInput) Status {
	st := Status{
		GOOS:           in.Host.GOOS,
		Enabled:        in.Enabled,
		ShimDir:        in.Disk.ShimDir,
		ObserverPath:   in.ObserverPath,
		Shells:         ShellsFor(in.Host.GOOS),
		DetectedShells: nonNilShells(DetectShells(in.Host)),
		PlannedShells:  nonNilShells(in.Plan.Shells),
		Warnings:       append([]string{}, in.Plan.Warnings...),
	}
	planned := map[string]ShimFile{}
	for _, s := range in.Plan.Shims {
		planned[s.FileName] = s
	}
	var known map[string]bool
	st.Tools, known = toolStatuses(in, planned)
	var shimsInSync, rcInSync bool
	st.Orphans, shimsInSync = shimSync(in.Disk.Shims, planned, known)
	st.RC, rcInSync, st.Warnings = rcStatuses(in.Disk.RC, in.Plan.RC, st.Warnings)
	st.InSync = shimsInSync && rcInSync
	st.Active = len(in.Disk.Shims) > 0
	for _, r := range in.Disk.RC {
		st.Active = st.Active || r.HasBlock
	}
	return st
}

func nonNilShells(s []Shell) []Shell {
	if s == nil {
		return []Shell{}
	}
	return s
}

// toolStatuses renders one row per wrappable candidate and reports which
// on-disk shim files belong to a known row.
func toolStatuses(in StatusInput, planned map[string]ShimFile) ([]ToolStatus, map[string]bool) {
	selected := map[string]bool{}
	for _, t := range in.Plan.Tools {
		selected[t.ID] = true
	}
	for _, id := range in.Selected {
		if id != AllTools {
			selected[id] = true
		}
	}
	byTool := map[string][]OnDiskShim{}
	for _, s := range in.Disk.Shims {
		byTool[s.ToolID] = append(byTool[s.ToolID], s)
	}
	known := map[string]bool{}
	out := []ToolStatus{}
	for _, c := range Candidates(in.Host.GOOS) {
		ts := ToolStatus{Candidate: c, Selected: selected[c.ID], Active: []string{}}
		if in.Installed != nil {
			v := in.Installed(c.ID)
			ts.Installed = &v
		}
		for _, s := range byTool[c.ID] {
			known[s.FileName] = true
			ts.Active = append(ts.Active, s.Command)
			if p, ok := planned[s.FileName]; !ok || p.Content != s.Content {
				ts.Stale = append(ts.Stale, s.Command)
			}
		}
		sort.Strings(ts.Active)
		out = append(out, ts)
	}
	return out, known
}

// shimSync lists shims no wrappable row owns and reports whether the shim
// files equal the plan exactly.
func shimSync(disk []OnDiskShim, planned map[string]ShimFile, known map[string]bool) ([]OnDiskShim, bool) {
	orphans := []OnDiskShim{}
	inSync := true
	onDisk := map[string]bool{}
	for _, s := range disk {
		onDisk[s.FileName] = true
		if !known[s.FileName] {
			orphans = append(orphans, s)
		}
		if p, ok := planned[s.FileName]; !ok || p.Content != s.Content {
			inSync = false
		}
	}
	for name := range planned {
		if !onDisk[name] {
			inSync = false
		}
	}
	return orphans, inSync
}

// rcStatuses reports each start-up file that has or should have a block.
func rcStatuses(disk []OnDiskRC, plan []RCFile, warnings []string) ([]RCStatus, bool, []string) {
	wanted := map[string]RCFile{}
	for _, r := range plan {
		wanted[r.Path] = r
	}
	out := []RCStatus{}
	inSync := true
	for _, r := range disk {
		w, isWanted := wanted[r.Path]
		rs := RCStatus{OnDiskRC: r, Wanted: isWanted}
		rs.Current = isWanted && r.HasBlock && normalizeBody(r.Body) == normalizeBody(w.Body)
		if isWanted != r.HasBlock || (isWanted && !rs.Current) {
			inSync = false
		}
		if r.Err != "" {
			warnings = append(warnings, r.Path+": "+r.Err)
		}
		if r.HasBlock || isWanted {
			out = append(out, rs)
		}
	}
	return out, inSync, warnings
}

func normalizeBody(s string) string {
	return strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
