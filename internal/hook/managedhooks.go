package hook

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/regularfile"
)

// Managed hooks files (surface-gap IDE-5 and the IDE-6 managed row).
//
// Some tools read an administrator hooks file that MERGES with the user's:
// Cursor's enterprise hooks.json (highest layer, a deny from any layer wins;
// cursor.com/docs/agent/hooks) and Devin Desktop's Cascade system hooks.json
// (runs first, then user, then workspace; docs.devin.ai/desktop/cascade/
// hooks). An admin can deploy Observer's hooks there through device
// management, where the developer cannot remove them. Two things follow,
// both kept here so the managed generator and the per-node writer cannot
// drift (the IBM Bob EnforcedHooks precedent):
//
//   - ManagedHooksDocument builds the file from the SAME command text the
//     per-node writer registers (`observer hook <tool> <event>`).
//   - When the node's administrator file already carries Observer's entry
//     for an event, the per-node registration stands down for that event
//     (SkipCovered): the layers merge, so a second copy in the user file
//     would fire every event twice.
//
// The table below is the one owner of which files these are; the
// catalogue (internal/agentconfig) owns their paths. Nothing branches on a
// tool name: a row carries the shape. A file a non-administrator could have
// written is reported Untrusted and never stands Observer down.

// managedHooksSpec is one administrator hooks file.
type managedHooksSpec struct {
	// tool is the hook tool token (`observer hook <tool> <event>`).
	tool string
	// fileID is the catalogue row that owns the paths.
	fileID string
	// events returns the events Observer registers, in order.
	events func() []string
	// version, when non-zero, is written as the top-level "version" key.
	version int
	// powershell writes the Windows command into the entry's "powershell"
	// field too (Cascade runs that field on Windows).
	powershell bool
}

// managedHooksSpecs is the table of administrator hooks files.
var managedHooksSpecs = []managedHooksSpec{
	{tool: "cursor", fileID: "cursor/enterprise-hooks", events: CursorEvents, version: 1},
	{tool: "devin", fileID: "devin/cascade-system-hooks", events: CascadeEvents, powershell: true},
}

// CascadeEvents returns the Devin Desktop (Cascade) hook events Observer
// registers, in order (a copy of cascadeEvents, the one owner).
func CascadeEvents() []string { return append([]string(nil), cascadeEvents...) }

func managedHooksSpecFor(tool string) (managedHooksSpec, bool) {
	for _, s := range managedHooksSpecs {
		if s.tool == tool {
			return s, true
		}
	}
	return managedHooksSpec{}, false
}

// ManagedHooksTools returns the tools that have an administrator hooks file,
// in table order.
func ManagedHooksTools() []string {
	out := make([]string, 0, len(managedHooksSpecs))
	for _, s := range managedHooksSpecs {
		out = append(out, s.tool)
	}
	return out
}

// managedHooksPaths returns the catalogue paths of a spec's file.
var managedHooksPaths = sync.OnceValue(func() map[string]agentconfig.OSPaths {
	out := map[string]agentconfig.OSPaths{}
	for _, f := range agentconfig.Files() {
		for _, s := range managedHooksSpecs {
			if f.ID == s.fileID {
				out[s.tool] = f.Paths
			}
		}
	}
	return out
})

// ManagedHooksPath returns where tool's administrator hooks file lives on
// goos ("" when the catalogue names none).
func ManagedHooksPath(tool, goos string) string {
	p := managedHooksPaths()[tool]
	switch goos {
	case "linux":
		return p.Linux
	case "darwin":
		return p.Darwin
	case "windows":
		return p.Windows
	}
	return ""
}

// managedHookCommand is the command an administrator file runs for event:
// the per-node writer's command text (forward-slash path, quoted when it
// needs it) with no --config, since a managed node's hook reads its default
// config. binary "" is a bare observer on PATH.
func managedHookCommand(tool, binary, event string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "observer"
	}
	return shellQuoteIfNeeded(forwardSlashPath(binary)) + " hook " + tool + " " + event
}

// powershellHookCommand is the same command as PowerShell runs it: a quoted
// path needs the call operator.
func powershellHookCommand(tool, binary, event string) string {
	binary = strings.TrimSpace(binary)
	if binary == "" {
		binary = "observer"
	}
	if strings.ContainsAny(binary, " '\"") {
		return "& '" + strings.ReplaceAll(binary, "'", "''") + "' hook " + tool + " " + event
	}
	return binary + " hook " + tool + " " + event
}

// ManagedHooksDocument returns tool's administrator hooks file carrying
// Observer's hooks for goos, and the path it deploys to.
func ManagedHooksDocument(tool, binary, goos string) ([]byte, string, error) {
	spec, ok := managedHooksSpecFor(tool)
	if !ok {
		return nil, "", fmt.Errorf("hook.ManagedHooksDocument: %s has no administrator hooks file", tool)
	}
	path := ManagedHooksPath(tool, goos)
	if path == "" {
		return nil, "", fmt.Errorf("hook.ManagedHooksDocument: %s names no administrator hooks file on %s", tool, goos)
	}
	hooks := map[string][]map[string]string{}
	for _, ev := range spec.events() {
		entry := map[string]string{"command": managedHookCommand(tool, binary, ev)}
		if spec.powershell && goos == "windows" {
			entry["powershell"] = powershellHookCommand(tool, binary, ev)
		}
		hooks[ev] = []map[string]string{entry}
	}
	doc := map[string]any{"hooks": hooks}
	if spec.version != 0 {
		doc["version"] = spec.version
	}
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, "", fmt.Errorf("hook.ManagedHooksDocument: %w", err)
	}
	return append(b, '\n'), path, nil
}

// ManagedHooks is what one administrator hooks file says about Observer's
// hooks. The zero value is "no file".
type ManagedHooks struct {
	// Source is the file read; Found reports it exists.
	Source string
	Found  bool
	// Untrusted is non-empty when the file exists but Observer does not
	// rely on it (unreadable, not a JSON object, or writable by a
	// non-administrator). An untrusted file never stands Observer down.
	Untrusted string
	// events maps each event to the commands of its entries.
	events map[string][]string
}

// ManagedHooksCoverage is how much of Observer's wiring an administrator
// file carries.
type ManagedHooksCoverage struct {
	// Covered are the asked events the file carries Observer's entry for;
	// Missing the rest.
	Covered, Missing []string
}

// Complete reports that every asked event rides the file.
func (c ManagedHooksCoverage) Complete() bool { return len(c.Covered) > 0 && len(c.Missing) == 0 }

// Coverage decides which of events the file carries an Observer entry for:
// a command running `observer hook <tool> <event>` (any observer binary).
// An untrusted file covers nothing.
func (m ManagedHooks) Coverage(tool string, events []string) ManagedHooksCoverage {
	var c ManagedHooksCoverage
	for _, ev := range events {
		hit := false
		if m.Found && m.Untrusted == "" {
			for _, cmd := range m.events[ev] {
				if observerHookEventInvocation(cmd, tool, ev) {
					hit = true
					break
				}
			}
		}
		if hit {
			c.Covered = append(c.Covered, ev)
		} else {
			c.Missing = append(c.Missing, ev)
		}
	}
	return c
}

// ParseManagedHooksDocument reads an administrator hooks file's bytes.
func ParseManagedHooksDocument(source string, data []byte) ManagedHooks {
	m := ManagedHooks{Source: source, Found: true, events: map[string][]string{}}
	var doc struct {
		Hooks map[string][]json.RawMessage `json:"hooks"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		m.Untrusted = source + " is not a hooks JSON object - the tool ignores it"
		return m
	}
	for ev, entries := range doc.Hooks {
		for _, raw := range entries {
			var e struct {
				Command    string `json:"command"`
				PowerShell string `json:"powershell"`
			}
			if json.Unmarshal(raw, &e) != nil {
				continue
			}
			for _, c := range []string{e.Command, e.PowerShell} {
				if c != "" {
					m.events[ev] = append(m.events[ev], strings.TrimPrefix(strings.TrimSpace(c), "& "))
				}
			}
		}
	}
	return m
}

// managedHooksMaxBytes bounds an administrator hooks file read.
const managedHooksMaxBytes = 1 << 20

// readManagedHooksFile reads an administrator hooks file under the trust
// rule of this OS (managedHooksOwnerUntrusted, per OS). The values are read
// either way, so the doctor can report them, but an untrusted file never
// stands Observer down.
//
// The read is one descriptor (regularfile.ReadNoFollow, orchestrator
// follow-up H3): opened read-only without following a link at the leaf
// (O_NOFOLLOW and non-blocking on unix, FILE_FLAG_OPEN_REPARSE_POINT on
// Windows), then fstat'ed, and it must be a regular file within the cap, so
// a FIFO or a link swapped in after a path check cannot hang `observer
// init`, the daemon's hook registration or the cursor.hooks doctor row. On
// unix the owner check (root-owned, not group or other writable) reads that
// descriptor's stat, so a swapped file cannot lend its owner to the bytes
// read. On Windows it does not: managedHooksOwnerUntrusted reads the owner
// by PATH (GetNamedSecurityInfo), because ReadNoFollow closes the handle
// before it returns and a handle-based GetSecurityInfo would need the open
// file passed through; a file renamed over the path after the read is
// judged instead (the swap needs write access to the administrator
// directory, which is checked too).
func readManagedHooksFile(path string) ManagedHooks {
	data, fi, err := regularfile.ReadNoFollow(path, managedHooksMaxBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return ManagedHooks{}
	case errors.Is(err, regularfile.ErrNotRegular):
		return ManagedHooks{Source: path, Found: true, Untrusted: path + " is not a regular file"}
	case errors.Is(err, regularfile.ErrTooLarge):
		return ManagedHooks{Source: path, Found: true, Untrusted: path + " is too large"}
	case err != nil:
		return ManagedHooks{Source: path, Found: true, Untrusted: path + " could not be read"}
	}
	untrusted := managedHooksOwnerUntrusted(path, fi)
	if untrusted == "" {
		if dfi, err := os.Stat(filepath.Dir(path)); err != nil {
			untrusted = filepath.Dir(path) + " could not be inspected"
		} else {
			untrusted = managedHooksOwnerUntrusted(filepath.Dir(path), dfi)
		}
	}
	m := ParseManagedHooksDocument(path, data)
	if m.Untrusted == "" {
		m.Untrusted = untrusted
	}
	return m
}

// managedHooksReader reads this host's administrator hooks file for tool. A
// test binary never reads the host's file: tests replace the reader, and the
// default returns "no file" so a developer box with one cannot change a
// test's outcome.
var managedHooksReader = func(tool string) ManagedHooks {
	if testing.Testing() {
		return ManagedHooks{}
	}
	path := ManagedHooksPath(tool, runtime.GOOS)
	if path == "" {
		return ManagedHooks{}
	}
	return readManagedHooksFile(path)
}

// ReadManagedHooks returns this host's administrator hooks file for tool as
// the per-node registration sees it (the zero value when none is deployed).
func ReadManagedHooks(tool string) ManagedHooks { return managedHooksReader(tool) }

// managedHooksPlan is what the node's administrator hooks file means for
// one per-node registration of a tool.
type managedHooksPlan struct {
	// register are the events still to register per node.
	register []string
	// drop are the events the trusted administrator file runs Observer's
	// hook for: Observer's own per-node entry for each is removed (the
	// layers merge, so a second copy fires every event twice). A
	// non-Observer entry is never touched.
	drop []string
	// complete reports that the file covers every event.
	complete bool
	// source is the administrator file.
	source string
	// warnings are the operator notes.
	warnings []string
}

// managedHooksPlanFor applies the node's administrator hooks file to a
// per-node registration of tool over events. An absent or untrusted file,
// one that covers nothing, and --force leave every event to register.
func (r *Registry) managedHooksPlanFor(tool string, events []string) managedHooksPlan {
	all := managedHooksPlan{register: events}
	if r.foreignOSTwin {
		// A Windows to WSL twin writes a home inside a distro: this host's
		// administrator file is another OS's layer and covers nothing there.
		return all
	}
	m := managedHooksReader(tool)
	if !m.Found {
		return all
	}
	if m.Untrusted != "" {
		all.warnings = []string{fmt.Sprintf("an administrator hooks file exists (%s) but Observer does not rely on it: %s; Observer registered its hooks per node, and if the tool runs the file's Observer hooks too every event fires twice", m.Source, m.Untrusted)}
		return all
	}
	cov := m.Coverage(tool, events)
	if len(cov.Covered) == 0 {
		return all
	}
	if r.opts.Force {
		all.warnings = []string{fmt.Sprintf("the administrator hooks file %s already runs Observer's hooks for %s; --force registered them per node too, so those events fire twice", m.Source, strings.Join(cov.Covered, ", "))}
		return all
	}
	p := managedHooksPlan{register: cov.Missing, drop: cov.Covered, complete: cov.Complete(), source: m.Source}
	if !p.complete {
		p.warnings = []string{fmt.Sprintf("the administrator hooks file %s already runs Observer's hooks for %s; registered only %s per node", m.Source, strings.Join(cov.Covered, ", "), strings.Join(cov.Missing, ", "))}
	}
	return p
}

// finish turns a registration result into the stand-down result when the
// administrator file covers every event (SkipCovered), naming the per-node
// entries the pass removed. Any other plan returns res as it is.
func (p managedHooksPlan) finish(res RegistrationResult) RegistrationResult {
	if !p.complete {
		return res
	}
	res.Skipped, res.SkipKind = true, SkipCovered
	res.SkipReason = fmt.Sprintf("the administrator hooks file %s already runs Observer's hooks for every event, and the tool merges it with the user's", p.source)
	res.SkipAdvice = "nothing registered; the administrator file provides it. Re-run with --force to register anyway (both fire, doubling every event)."
	if len(res.HooksDropped) > 0 {
		verb := "removed"
		if res.DryRun {
			verb = "would remove"
		}
		res.SkipAdvice += fmt.Sprintf(" This pass %s Observer's own per-node entries for %s from %s, which would otherwise fire twice.", verb, strings.Join(res.HooksDropped, ", "), res.ConfigPath)
	}
	return res
}
