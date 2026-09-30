package shellwrap

import (
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/integration"
)

// AllTools is the selection keyword that expands to every installed CLI
// (terminal-kind) row. IDE / desktop-app rows are never part of "all": their
// vendor command doubles as a file-opening CLI, so wrapping one is an explicit
// per-row choice.
const AllTools = "all"

// Candidate is one row that CAN be wrapped on a given OS: a WrappedCommandFor
// hit with at least one command spelling to replace.
type Candidate struct {
	// ID is the registry tool key or GUI launch id.
	ID string `json:"id"`
	// Label is a display name (the GUI row's label; the id for a CLI row).
	Label string `json:"label"`
	// Kind is "terminal" (CLI launcher) or "gui" (IDE / desktop app).
	Kind integration.LaunchKind `json:"kind"`
	// Wrapped is the observer command the shim runs ("observer claude").
	Wrapped string `json:"wrapped"`
	// Commands are the command names replaced on this OS.
	Commands []string `json:"commands"`
	// Routes / TrafficProven echo integration.WrappedCommand.
	Routes        bool `json:"routes"`
	TrafficProven bool `json:"traffic_proven"`
	// Honesty + HonestyText: what wrapping buys (see HonestyFor).
	Honesty     Honesty `json:"honesty"`
	HonestyText string  `json:"honesty_text"`

	projectDirArgv  bool
	handoffSegments []string
	args            []string
}

// commandsFor returns the replaced command names on goos. Windows spellings
// lose their extension (the shim is <name>.cmd, found by PATHEXT); names a
// shim cannot carry are dropped.
func commandsFor(r integration.BinaryNames, goos string) []string {
	src := r.Unix
	if goos == "windows" {
		src = r.Windows
	}
	var out []string
	for _, n := range src {
		if goos == "windows" {
			ext := strings.ToLower(path.Ext(n))
			switch ext {
			case ".exe", ".cmd", ".bat", ".ps1", ".com":
				n = n[:len(n)-len(ext)]
			}
		}
		if ValidCommandName(n) {
			out = append(out, n)
		}
	}
	return dedupe(out)
}

// Candidates returns every wrappable row on goos, sorted by ID. The id space
// is the union of registry tool keys and GUI launch ids; which ones resolve is
// integration.WrappedCommandFor's decision, not this package's.
func Candidates(goos string) []Candidate {
	ids := append([]string{}, integration.Tools()...)
	for _, g := range integration.GUILaunchables() {
		ids = append(ids, g.Spec.ID)
	}
	var out []Candidate
	for _, id := range dedupe(ids) {
		if c, ok := CandidateFor(id, goos); ok {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// CandidateFor resolves one id. ok=false when the id is not wrappable on goos.
func CandidateFor(id, goos string) (Candidate, bool) {
	w, ok := integration.WrappedCommandFor(id)
	if !ok {
		return Candidate{}, false
	}
	cmds := commandsFor(w.Replaces, goos)
	if len(cmds) == 0 {
		return Candidate{}, false
	}
	h, text := HonestyFor(w)
	c := Candidate{
		ID:            id,
		Label:         id,
		Kind:          w.Kind,
		Wrapped:       "observer " + strings.Join(w.Args, " "),
		Commands:      cmds,
		Routes:        w.Routes,
		TrafficProven: w.TrafficProven,
		Honesty:       h,
		HonestyText:   text,
		args:          w.Args,
	}
	if g, ok := integration.GUILaunchFor(id); ok && w.Kind == integration.LaunchKindGUI {
		if g.Spec.ProbeOnly {
			// The row's spelling is not a PATH command (it collides with an
			// unrelated binary, or the app has no PATH alias): a shim of
			// that name would shadow the wrong program.
			return Candidate{}, false
		}
		c.Label = g.Spec.Label
		c.projectDirArgv = g.Spec.ProjectDirArgv
		c.handoffSegments = g.Spec.Wrap.HandoffPathSegments
	}
	return c, true
}

// Selection is what the operator asked for.
type Selection struct {
	// Tools are ids, or AllTools.
	Tools []string
	// Shells are the start-up files to manage; empty = DetectShells.
	Shells []Shell
}

// PlanInput is everything BuildPlan needs.
type PlanInput struct {
	Host Host
	// ShimDir is the absolute shim directory.
	ShimDir string
	// ObserverPath is the absolute observer executable baked into shims.
	ObserverPath string
	Selection    Selection
	// Installed reports whether an id's vendor command is installed. It
	// narrows AllTools and warns on an explicit selection that is not
	// installed. nil = unknown (AllTools takes every CLI row).
	Installed func(id string) bool
}

// ShimFile is one planned shim.
type ShimFile struct {
	// Command is the replaced command name.
	Command string `json:"command"`
	// FileName is the file written in the shim dir (Command, or Command.cmd
	// on Windows).
	FileName string `json:"file_name"`
	// Path is ShimDir joined with FileName.
	Path string `json:"path"`
	// ToolID is the wrapped row.
	ToolID string `json:"tool_id"`
	// Content is the full script.
	Content string `json:"content"`
}

// RCFile is one planned start-up-file block.
type RCFile struct {
	Shell Shell  `json:"shell"`
	Path  string `json:"path"`
	// Body is the block body (between the markers).
	Body string `json:"body"`
}

// ToolPlan is the per-selected-row outcome.
type ToolPlan struct {
	Candidate
	// Selected is true for every row in the plan (kept for the wire shape).
	Selected bool `json:"selected"`
	// Installed is nil when unknown.
	Installed *bool `json:"installed,omitempty"`
	// Shimmed are the commands this row got a shim for.
	Shimmed []string `json:"shimmed"`
	// Conflicts are commands another selected row already claimed.
	Conflicts []string `json:"conflicts,omitempty"`
}

// Plan is the complete desired state.
type Plan struct {
	ShimDir  string     `json:"shim_dir"`
	Shims    []ShimFile `json:"shims"`
	RC       []RCFile   `json:"rc"`
	Tools    []ToolPlan `json:"tools"`
	Shells   []Shell    `json:"shells"`
	Warnings []string   `json:"warnings"`
}

// Empty reports whether the plan wraps nothing (applying it == disabling).
func (p Plan) Empty() bool { return len(p.Shims) == 0 }

// ShimFileName returns the shim file name for command on goos.
func ShimFileName(command, goos string) string {
	if goos == "windows" {
		return command + ".cmd"
	}
	return command
}

// BuildPlan turns a selection into the desired files. It never fails on one
// bad row: unknown ids, uninstalled tools and name conflicts become warnings;
// only an unusable shim dir / observer path / shell is an error.
func BuildPlan(in PlanInput) (Plan, error) {
	goos := in.Host.GOOS
	if err := checkPath(in.ShimDir); err != nil {
		return Plan{}, fmt.Errorf("shellwrap: shim dir: %w", err)
	}
	if err := checkPath(in.ObserverPath); err != nil {
		return Plan{}, fmt.Errorf("shellwrap: observer path: %w", err)
	}
	p := Plan{ShimDir: in.ShimDir}

	ids, warn := expandTools(in.Selection.Tools, goos, in.Installed)
	p.Warnings = append(p.Warnings, warn...)

	claimed := map[string]string{} // command -> tool id
	for _, id := range ids {
		c, _ := CandidateFor(id, goos)
		tp := ToolPlan{Candidate: c, Selected: true, Shimmed: []string{}}
		if in.Installed != nil {
			inst := in.Installed(id)
			tp.Installed = &inst
			if !inst {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s: not installed here - its shim runs `%s`, which reports how to install it", id, c.Wrapped))
			}
		}
		for _, cmd := range c.Commands {
			if owner, taken := claimed[cmd]; taken {
				tp.Conflicts = append(tp.Conflicts, cmd)
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s: `%s` is already wrapped for %s - skipped", id, cmd, owner))
				continue
			}
			content, err := renderShim(c.shimSpec(cmd, in.ObserverPath, in.ShimDir), goos)
			if err != nil {
				p.Warnings = append(p.Warnings, fmt.Sprintf("%s: %v", id, err))
				continue
			}
			claimed[cmd] = id
			tp.Shimmed = append(tp.Shimmed, cmd)
			name := ShimFileName(cmd, goos)
			p.Shims = append(p.Shims, ShimFile{
				Command: cmd, FileName: name, Path: in.Host.join(in.ShimDir, name),
				ToolID: id, Content: content,
			})
		}
		p.Tools = append(p.Tools, tp)
	}
	sort.Slice(p.Shims, func(i, j int) bool { return p.Shims[i].FileName < p.Shims[j].FileName })

	shells := in.Selection.Shells
	if len(shells) == 0 {
		shells = DetectShells(in.Host)
		if len(shells) == 0 && len(p.Shims) > 0 {
			p.Warnings = append(p.Warnings, fmt.Sprintf(
				"no supported shell start-up file found - add %s to the front of PATH yourself, or pick a shell explicitly", in.ShimDir))
		}
	}
	allowed := map[Shell]bool{}
	for _, sh := range ShellsFor(goos) {
		allowed[sh] = true
	}
	for _, sh := range shells {
		if !allowed[sh] {
			return Plan{}, fmt.Errorf("shellwrap: shell %q is not manageable on %s", sh, goos)
		}
	}
	p.Shells = shells
	if len(p.Shims) == 0 {
		// Nothing to wrap: no PATH block either (applying == disabling).
		return p, nil
	}
	for _, sh := range shells {
		body, err := RCBody(sh, in.ShimDir)
		if err != nil {
			return Plan{}, err
		}
		for _, rc := range RCTargets(sh, in.Host) {
			p.RC = append(p.RC, RCFile{Shell: sh, Path: rc, Body: body})
		}
	}
	return p, nil
}

// shimSpec is the one place a candidate row becomes a renderable shim, shared
// by BuildPlan (enable) and PlanRefresh (the start-time path refresh), so a
// refreshed shim is byte-identical to what enable would write.
func (c Candidate) shimSpec(command, observerPath, shimDir string) ShimSpec {
	return ShimSpec{
		Name: command, ToolID: c.ID, Kind: c.Kind, Args: c.args,
		ProjectDirArgv: c.projectDirArgv, HandoffSegments: c.handoffSegments,
		ObserverPath: observerPath, ShimDir: shimDir,
	}
}

func renderShim(s ShimSpec, goos string) (string, error) {
	if goos == "windows" {
		return RenderCmdShim(s)
	}
	return RenderPOSIXShim(s)
}

// expandTools resolves the selection to sorted, de-duplicated wrappable ids.
func expandTools(sel []string, goos string, installed func(string) bool) ([]string, []string) {
	var ids, warn []string
	for _, raw := range sel {
		id := strings.TrimSpace(raw)
		if id == "" {
			continue
		}
		if id == AllTools {
			for _, c := range Candidates(goos) {
				if c.Kind != integration.LaunchKindTerminal {
					continue
				}
				if installed != nil && !installed(c.ID) {
					continue
				}
				ids = append(ids, c.ID)
			}
			continue
		}
		if _, ok := CandidateFor(id, goos); !ok {
			warn = append(warn, fmt.Sprintf("%s: not a wrappable command on %s - skipped", id, goos))
			continue
		}
		ids = append(ids, id)
	}
	ids = dedupe(ids)
	sort.Strings(ids)
	return ids, warn
}
