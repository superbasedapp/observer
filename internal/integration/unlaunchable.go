package integration

import "sort"

// UnlaunchableKind says WHY an advertised product cannot be started from the
// dashboard's New Terminal picker (T-494, D-160): the picker lists it with an
// honest note instead of omitting it.
type UnlaunchableKind string

// Unlaunchable kinds, one per rule in unlaunchableRules.
const (
	// UnlaunchableBrowser: a chat product captured from the browser by the
	// SuperBased browser extension. There is nothing to start.
	UnlaunchableBrowser UnlaunchableKind = "browser"
	// UnlaunchableHosted: runs inside an editor the picker can open (a VS
	// Code or JetBrains extension, an IDE-embedded agent).
	UnlaunchableHosted UnlaunchableKind = "hosted"
	// UnlaunchableDesktop: a desktop or IDE app whose launch spelling is not
	// grounded yet, so the picker has no verified way to open it.
	UnlaunchableDesktop UnlaunchableKind = "desktop"
	// UnlaunchableCLINoLauncher: a command-line tool with a grounded binary
	// row (Capability.Binary) but no `observer <verb>` launcher yet, so the
	// picker cannot start it while its sessions are still captured (the
	// 2026-10-21 capture-only wave).
	UnlaunchableCLINoLauncher UnlaunchableKind = "cli_no_launcher"
	// UnlaunchableNoCLI: no standalone command at all (a web or desktop
	// product with no launch row of any kind).
	UnlaunchableNoCLI UnlaunchableKind = "no_cli"
)

// Unlaunchable is one advertised product the picker cannot start, with the
// reason in plain words. Host is the editor's label for a hosted row.
type Unlaunchable struct {
	Tool string
	Kind UnlaunchableKind
	Host string
	Note string
}

// unlaunchableFacts is what the rules read about a row, resolved once.
type unlaunchableFacts struct {
	c Capability
	// host is the label of an advertised editor host (a GUI row with no
	// adapter of its own) that lists this tool, "" when none does.
	host string
}

// unlaunchableRules is the ordered rule table (CLAUDE.md #5): the first row
// whose match holds decides the kind and the note. Every row dispatches on
// capability shape, never on a tool name (CLAUDE.md #3).
var unlaunchableRules = []struct {
	kind  UnlaunchableKind
	match func(f unlaunchableFacts) bool
	note  func(f unlaunchableFacts) string
}{
	{
		kind:  UnlaunchableBrowser,
		match: func(f unlaunchableFacts) bool { return f.c.Hook.Mechanism == HookBrowserExtension },
		note: func(unlaunchableFacts) string {
			return "Used in your web browser and captured by the SuperBased browser extension. There is nothing to start here."
		},
	},
	{
		kind:  UnlaunchableHosted,
		match: func(f unlaunchableFacts) bool { return f.host != "" },
		note: func(f unlaunchableFacts) string {
			return "Runs inside " + f.host + ". Open " + f.host + " from the IDEs group to use it."
		},
	},
	// A grounded CLI binary wins over an ungrounded desktop row (FU-148): a
	// CLI-first tool whose vendor also ships a desktop app (IBM Bob,
	// CodeBuddy, Cortex Code) is run from a terminal today, and its GUI row
	// is listed for the record only, so the note says so.
	{
		kind:  UnlaunchableCLINoLauncher,
		match: func(f unlaunchableFacts) bool { return f.c.Binary != nil },
		note: func(unlaunchableFacts) string {
			return "A command line tool this dashboard has no launcher for yet. Run it in your own terminal and its sessions are still captured."
		},
	},
	{
		kind:  UnlaunchableDesktop,
		match: func(f unlaunchableFacts) bool { return f.c.GUI != nil },
		note: func(unlaunchableFacts) string {
			return "A desktop app this dashboard cannot open yet. Start it from your system."
		},
	},
	{
		kind:  UnlaunchableNoCLI,
		match: func(unlaunchableFacts) bool { return true },
		note: func(unlaunchableFacts) string {
			return "Has no command this dashboard can start. Use the app or site it ships as."
		},
	},
}

// Unlaunchables returns every ADVERTISED registry row that the New Terminal
// picker cannot start, sorted by tool, each with its reason. A row that is
// terminal-launchable, or whose own GUI row is advertised (it already sits in
// the picker's IDE / desktop group), is not listed; neither is a deprecated
// or dead product (the lifecycle policy stops advertising it everywhere).
func Unlaunchables() []Unlaunchable {
	hostOf := map[string]string{}
	for _, g := range GUILaunchables() {
		if g.Adapter != "" || !g.Advertised() {
			continue
		}
		for _, t := range g.Spec.Hosts {
			if _, seen := hostOf[t]; !seen {
				hostOf[t] = g.Spec.Label
			}
		}
	}
	var out []Unlaunchable
	for _, c := range registry {
		if !c.Advertised() || TerminalLaunchable(c) {
			continue
		}
		if c.GUI != nil && (GUILaunchable{Spec: *c.GUI, Adapter: c.Tool, Lifecycle: c.Lifecycle}).Advertised() {
			continue
		}
		f := unlaunchableFacts{c: c, host: hostOf[c.Tool]}
		for _, r := range unlaunchableRules {
			if r.match(f) {
				u := Unlaunchable{Tool: c.Tool, Kind: r.kind, Note: r.note(f)}
				if r.kind == UnlaunchableHosted {
					u.Host = f.host
				}
				out = append(out, u)
				break
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Tool < out[j].Tool })
	return out
}
