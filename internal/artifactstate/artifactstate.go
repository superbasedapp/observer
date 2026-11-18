package artifactstate

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// State is one artifact state. The closed vocabulary below is the union of
// every artifact row's States in the component catalog
// (internal/components.Artifacts); a test pins that every state a rule table
// here can produce is listed on its catalog row.
type State string

// The closed State vocabulary.
const (
	// StateNotDetected: Observer cannot see the artifact. Never shown as
	// "not installed": an extension that never connects, or an editor
	// install outside the folders Observer checks, is invisible to it.
	StateNotDetected State = "not_detected"
	// StateConnected: the browser extension talked to the native host
	// within the connected window and speaks a supported protocol.
	StateConnected State = "connected"
	// StateStale: the artifact is older than this Observer supports (an
	// extension protocol below the host's minimum, an editor extension
	// older than this binary).
	StateStale State = "stale"
	// StateIncompatible: the extension speaks a protocol newer than this
	// Observer supports; the host refuses it with a reason.
	StateIncompatible State = "incompatible"
	// StateHostRemoved: Observer's native host is gone but the extension
	// connected recently, so it is probably still installed and running
	// content scripts in the browser.
	StateHostRemoved State = "host_removed"
	// StatePolicyBlocked: the org's browser policy output lists the
	// extension as blocked. Never derived on the node (Observer cannot
	// confirm the browser applied a policy); kept in the vocabulary for
	// the org-side renderer.
	StatePolicyBlocked State = "policy_blocked"
	// StateInstalled: the artifact is present where Observer looks.
	StateInstalled State = "installed"
	// StateAbsent: Observer looked where the artifact is placed and found
	// none of it.
	StateAbsent State = "absent"
	// StateNotApplicable: the artifact does not ship for this platform.
	StateNotApplicable State = "not_applicable"
)

// Status is one artifact's derived state.
type Status struct {
	ID       string `json:"id"`
	State    State  `json:"state"`
	Version  string `json:"version,omitempty"`
	Detail   string `json:"detail"`
	Remedy   string `json:"remedy,omitempty"`
	Leftover bool   `json:"leftover"`
	// Rule names the table row that decided the state (tests and
	// `observer components artifacts --json` both show it).
	Rule  string `json:"rule"`
	Items []Item `json:"items,omitempty"`
}

// Item is one install, host or file behind an artifact status.
type Item struct {
	Name    string `json:"name"`
	Path    string `json:"path,omitempty"`
	State   string `json:"state"`
	Version string `json:"version,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// ---------------------------------------------------------------------------
// Versions

var coreRe = regexp.MustCompile(`^v?(\d+)\.(\d+)\.(\d+)`)

// Core parses the numeric major.minor.patch core of a version string ("v1.36.0",
// "1.36.0-rc.2", "1.36.0"). ok is false for "dev", "" and anything else
// without a numeric core.
func Core(v string) (c [3]int, ok bool) {
	m := coreRe.FindStringSubmatch(strings.TrimSpace(v))
	if m == nil {
		return c, false
	}
	for i := 0; i < 3; i++ {
		n, err := strconv.Atoi(m[i+1])
		if err != nil {
			return c, false
		}
		c[i] = n
	}
	return c, true
}

// CompareCore compares the numeric cores of a and b: -1, 0 or 1, and ok
// false when either has no numeric core (so nothing is claimed).
func CompareCore(a, b string) (int, bool) {
	ca, oka := Core(a)
	cb, okb := Core(b)
	if !oka || !okb {
		return 0, false
	}
	for i := 0; i < 3; i++ {
		switch {
		case ca[i] < cb[i]:
			return -1, true
		case ca[i] > cb[i]:
			return 1, true
		}
	}
	return 0, true
}

// ---------------------------------------------------------------------------
// Browser extension

// Seen is the last handshake the native host recorded from the extension.
type Seen struct {
	// Version is the extension's manifest version ("" for an extension that
	// predates the handshake and never reports it).
	Version string
	// Protocol is the native-host protocol the extension speaks (1 for an
	// extension that predates the handshake).
	Protocol int
	// LastSeenMs is when the host last heard from it (epoch millis).
	LastSeenMs int64
}

// BrowserInput is what the caller observed about the browser extension.
type BrowserInput struct {
	// ComponentActive is whether capture.browser is active on this node.
	ComponentActive bool
	// HostPresent is whether any native-messaging host Observer installs
	// (a host manifest, a Windows bridge, the host files) is on disk.
	HostPresent bool
	// Seen is the recorded handshake; nil when none was ever recorded.
	Seen *Seen
	// NowMs is the current time (epoch millis).
	NowMs int64
	// ConnectedWindowMs is how recent a handshake must be to count as
	// connected.
	ConnectedWindowMs int64
	// ProtocolMin and ProtocolMax are the native-host protocol range this
	// Observer supports.
	ProtocolMin, ProtocolMax int
	// BinaryVersion is the running observer's version.
	BinaryVersion string
}

// browserFacts are the derived booleans the browser rule table reads.
type browserFacts struct {
	in     BrowserInput
	recent bool
}

// browserRule is one ordered row of the browser table.
type browserRule struct {
	name  string
	state State
	when  func(f browserFacts) bool
	out   func(f browserFacts) (detail, remedy string)
}

// browserRules is walked top-down; the first matching row decides.
var browserRules = []browserRule{
	{
		name: "newer-protocol", state: StateIncompatible,
		when: func(f browserFacts) bool { return f.recent && f.in.Seen.Protocol > f.in.ProtocolMax },
		out: func(f browserFacts) (string, string) {
			return fmt.Sprintf("the extension speaks native-host protocol %d; this Observer supports %d to %d and refuses it", f.in.Seen.Protocol, f.in.ProtocolMin, f.in.ProtocolMax),
				"update Observer: the extension is newer than this binary"
		},
	},
	{
		name: "host-removed", state: StateHostRemoved,
		when: func(f browserFacts) bool { return !f.in.HostPresent && f.recent },
		out: func(f browserFacts) (string, string) {
			d := "Observer's native-messaging host is not installed, but the extension connected " + ago(f.in.NowMs, f.in.Seen.LastSeenMs) + ": it is probably still installed and running in the browser"
			if f.in.ComponentActive {
				return d, "reinstall the host with `observer init --browser`, or remove the extension in the browser (chrome://extensions or edge://extensions)"
			}
			return d, "remove the extension in the browser (chrome://extensions or edge://extensions): Observer cannot uninstall it"
		},
	},
	{
		name: "no-host", state: StateNotDetected,
		when: func(f browserFacts) bool { return !f.in.HostPresent },
		out: func(f browserFacts) (string, string) {
			if f.in.ComponentActive {
				return "no native-messaging host is installed, so no extension can connect", "install the host with `observer init --browser`, then load the extension"
			}
			return "no native-messaging host is installed and capture.browser is inactive", ""
		},
	},
	{
		name: "never-connected", state: StateNotDetected,
		when: func(f browserFacts) bool { return f.in.Seen == nil },
		out: func(f browserFacts) (string, string) {
			return "the native host is installed but no extension has connected to it yet; Observer cannot see an extension that never connects", "load the extension in the browser (see docs/browser-extension.md)"
		},
	},
	{
		name: "not-recent", state: StateNotDetected,
		when: func(f browserFacts) bool { return !f.recent },
		out: func(f browserFacts) (string, string) {
			return "the extension last connected " + ago(f.in.NowMs, f.in.Seen.LastSeenMs) + versionNote(f.in.Seen.Version) + "; it may have been removed or the browser has not run since", ""
		},
	},
	{
		name: "old-protocol", state: StateStale,
		when: func(f browserFacts) bool { return f.in.Seen.Protocol < f.in.ProtocolMin },
		out: func(f browserFacts) (string, string) {
			return fmt.Sprintf("the extension speaks native-host protocol %d; this Observer supports %d to %d", f.in.Seen.Protocol, f.in.ProtocolMin, f.in.ProtocolMax),
				"update the extension to the release that matches this Observer"
		},
	},
	{
		name: "connected", state: StateConnected,
		when: func(browserFacts) bool { return true },
		out: func(f browserFacts) (string, string) {
			d := "the extension connected " + ago(f.in.NowMs, f.in.Seen.LastSeenMs)
			if f.in.Seen.Version == "" {
				d += " (it predates the version handshake and does not report its version)"
			} else {
				d += fmt.Sprintf(" (version %s, protocol %d)", f.in.Seen.Version, f.in.Seen.Protocol)
			}
			if c, ok := CompareCore(f.in.Seen.Version, f.in.BinaryVersion); ok && c != 0 {
				d += fmt.Sprintf("; its release differs from this Observer (%s), which the protocol range allows", f.in.BinaryVersion)
			}
			return d, ""
		},
	},
}

// Browser derives the browser extension's state.
func Browser(id string, in BrowserInput) Status {
	f := browserFacts{in: in}
	if in.Seen != nil && in.NowMs-in.Seen.LastSeenMs <= in.ConnectedWindowMs {
		f.recent = true
	}
	st := Status{ID: id}
	for _, r := range browserRules {
		if r.when(f) {
			st.State, st.Rule = r.state, r.name
			st.Detail, st.Remedy = r.out(f)
			break
		}
	}
	if in.Seen != nil {
		st.Version = in.Seen.Version
	}
	if !in.ComponentActive && (in.HostPresent || f.recent) {
		st.Leftover = true
		if in.HostPresent {
			st.Remedy = joinRemedy("`observer components teardown capture.browser` removes the host Observer installed", st.Remedy)
		}
	}
	return st
}

// BrowserStates lists every state the browser table can produce.
func BrowserStates() []State {
	return statesOf(len(browserRules), func(i int) State { return browserRules[i].state })
}

// ---------------------------------------------------------------------------
// Editor extension (VS Code and its forks)

// EditorInstall is one extension directory found under an editor's
// extension folder.
type EditorInstall struct {
	Editor  string // "VS Code", "VS Code Server", "Cursor", ...
	Dir     string
	Version string
}

// EditorInput is what the caller observed about the editor extension.
type EditorInput struct {
	// Searched names the extension folders the caller looked in.
	Searched []string
	// Installs are the extension directories found.
	Installs []EditorInstall
	// BinaryVersion is the running observer's version.
	BinaryVersion string
}

// editorFacts are the derived facts the editor rule table reads.
type editorFacts struct {
	in    EditorInput
	stale []EditorInstall
}

type editorRule struct {
	name  string
	state State
	when  func(f editorFacts) bool
	out   func(f editorFacts) (detail, remedy string)
}

var editorRules = []editorRule{
	{
		name: "none-found", state: StateNotDetected,
		when: func(f editorFacts) bool { return len(f.in.Installs) == 0 },
		out: func(f editorFacts) (string, string) {
			return "no superbased extension under the extension folders Observer checks; a portable or custom-location install is not visible to it", ""
		},
	},
	{
		name: "older-than-binary", state: StateStale,
		when: func(f editorFacts) bool { return len(f.stale) > 0 },
		out: func(f editorFacts) (string, string) {
			return fmt.Sprintf("%d install(s) older than this Observer (%s); the extension prefers an installed observer that is strictly newer than its bundled one", len(f.stale), f.in.BinaryVersion),
				"update the extension in the editor (Extensions view); Observer never installs or updates it"
		},
	},
	{
		name: "installed", state: StateInstalled,
		when: func(editorFacts) bool { return true },
		out: func(f editorFacts) (string, string) {
			return fmt.Sprintf("%d install(s) found", len(f.in.Installs)), ""
		},
	},
}

// Editor derives the editor extension's state.
func Editor(id string, in EditorInput) Status {
	f := editorFacts{in: in}
	st := Status{ID: id}
	for _, ins := range in.Installs {
		item := Item{Name: ins.Editor, Path: ins.Dir, Version: ins.Version, State: string(StateInstalled)}
		if c, ok := CompareCore(ins.Version, in.BinaryVersion); ok && c < 0 {
			f.stale = append(f.stale, ins)
			item.State = string(StateStale)
		}
		st.Items = append(st.Items, item)
		if st.Version == "" {
			st.Version = ins.Version
		}
	}
	for _, r := range editorRules {
		if r.when(f) {
			st.State, st.Rule = r.state, r.name
			st.Detail, st.Remedy = r.out(f)
			break
		}
	}
	return st
}

// EditorStates lists every state the editor table can produce.
func EditorStates() []State {
	return statesOf(len(editorRules), func(i int) State { return editorRules[i].state })
}

// editorDirRe matches "<version>" or "<version>-<platform>-<arch>" after the
// extension id prefix. A pre-release identifier never contains '-' in this
// project's tags (strict SemVer, scripts/sync-npm-version.sh).
var editorDirRe = regexp.MustCompile(`^(\d+\.\d+\.\d+(?:-[0-9A-Za-z.]+)?)(?:-(?:linux|darwin|win32|alpine)-(?:x64|arm64|armhf|ia32))?$`)

// EditorExtensionVersion parses an editor extension directory name
// ("superbased.superbased-observer-1.36.0-linux-x64") for the extension id
// extID ("superbased.superbased-observer"). ok is false for any other
// directory. The id comparison is case-insensitive, as editors lowercase it.
func EditorExtensionVersion(dirName, extID string) (string, bool) {
	prefix := strings.ToLower(extID) + "-"
	if !strings.HasPrefix(strings.ToLower(dirName), prefix) {
		return "", false
	}
	m := editorDirRe.FindStringSubmatch(dirName[len(prefix):])
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ---------------------------------------------------------------------------
// Plugin shims

// ShimHost is one in-process plugin host's shim file as the caller found it.
type ShimHost struct {
	Tool string
	Path string
	// Present is whether a file is at Path.
	Present bool
	// Ours is whether that file is an Observer-written shim.
	Ours bool
	// AdapterActive is whether adapter.<Tool> is active.
	AdapterActive bool
	// HooksActive is whether integration.hooks is active.
	HooksActive bool
	// Component is the catalog id whose teardown removes the shim.
	Component string
}

type shimRule struct {
	name  string
	state State
	when  func(ours, leftover int) bool
	out   func(ours, leftover int, ids []string) (detail, remedy string)
}

var shimRules = []shimRule{
	{
		name: "none", state: StateAbsent,
		when: func(ours, _ int) bool { return ours == 0 },
		out: func(int, int, []string) (string, string) {
			return "no Observer plugin shim is installed in any plugin host", ""
		},
	},
	{
		name: "leftover", state: StateInstalled,
		when: func(_, leftover int) bool { return leftover > 0 },
		out: func(ours, leftover int, ids []string) (string, string) {
			return fmt.Sprintf("%d shim(s) installed; %d belong to an inactive component and no longer report", ours, leftover),
				"`observer components teardown " + strings.Join(ids, " ") + "` removes them"
		},
	},
	{
		name: "installed", state: StateInstalled,
		when: func(int, int) bool { return true },
		out: func(ours, _ int, _ []string) (string, string) {
			return fmt.Sprintf("%d shim(s) installed; `observer start` refreshes a shim whose bytes differ from what this binary renders", ours), ""
		},
	},
}

// Shims derives the plugin shims' state.
func Shims(id string, hosts []ShimHost) Status {
	st := Status{ID: id}
	ours, leftover := 0, 0
	idset := map[string]bool{}
	for _, h := range hosts {
		if !h.Present {
			continue
		}
		item := Item{Name: h.Tool, Path: h.Path}
		switch {
		case !h.Ours:
			item.State, item.Detail = "foreign", "a file Observer did not write; left alone"
		case h.AdapterActive && h.HooksActive:
			ours++
			item.State = string(StateInstalled)
		default:
			ours++
			leftover++
			item.State, item.Detail = "leftover", "its component is inactive: "+h.Component
			idset[h.Component] = true
		}
		st.Items = append(st.Items, item)
	}
	ids := make([]string, 0, len(idset))
	for k := range idset {
		ids = append(ids, k)
	}
	sort.Strings(ids)
	for _, r := range shimRules {
		if r.when(ours, leftover) {
			st.State, st.Rule = r.state, r.name
			st.Detail, st.Remedy = r.out(ours, leftover, ids)
			break
		}
	}
	st.Leftover = leftover > 0
	return st
}

// ShimStates lists every state the shim table can produce.
func ShimStates() []State {
	return statesOf(len(shimRules), func(i int) State { return shimRules[i].state })
}

// ---------------------------------------------------------------------------
// Helper binaries

// HelperInput is what the caller observed about one helper binary.
type HelperInput struct {
	// Applicable is false when the helper does not ship for this platform.
	Applicable bool
	// Present is whether the caller found the helper where it is placed.
	Present bool
	// Path is where it was found (or the first place looked).
	Path string
	// ComponentActive is whether the component that uses it is active.
	ComponentActive bool
	// Component is that component's id.
	Component string
	// NotApplicableDetail, when set, replaces the generic not-applicable
	// detail: a helper that DOES ship beside this binary but serves another
	// host shape (U13: the Antigravity bridge ships in the Linux packages
	// for a daemon running under WSL) must not read as "does not ship".
	NotApplicableDetail string
}

type helperRule struct {
	name  string
	state State
	when  func(in HelperInput) bool
	out   func(in HelperInput) (detail, remedy string)
}

var helperRules = []helperRule{
	{
		name: "not-applicable", state: StateNotApplicable,
		when: func(in HelperInput) bool { return !in.Applicable },
		out: func(in HelperInput) (string, string) {
			if in.NotApplicableDetail != "" {
				return in.NotApplicableDetail, ""
			}
			return "this helper does not ship for this platform", ""
		},
	},
	{
		name: "absent", state: StateAbsent,
		when: func(in HelperInput) bool { return !in.Present },
		out: func(in HelperInput) (string, string) {
			if in.ComponentActive {
				return "not found where Observer looks; " + in.Component + " runs without it", "install it from the release archive (see docs/components.md)"
			}
			return "not found where Observer looks", ""
		},
	},
	{
		name: "unused", state: StateInstalled,
		when: func(in HelperInput) bool { return !in.ComponentActive },
		out: func(in HelperInput) (string, string) {
			return "present but unused: " + in.Component + " is inactive", "remove it with the tool that installed it if you do not want it on disk; Observer does not delete helpers"
		},
	},
	{
		name: "installed", state: StateInstalled,
		when: func(HelperInput) bool { return true },
		out: func(HelperInput) (string, string) {
			return "present", ""
		},
	},
}

// Helper derives one helper binary's state. A helper's version is not read
// (that would mean running it), so stale is never derived here.
func Helper(id string, in HelperInput) Status {
	st := Status{ID: id}
	for _, r := range helperRules {
		if r.when(in) {
			st.State, st.Rule = r.state, r.name
			st.Detail, st.Remedy = r.out(in)
			break
		}
	}
	if in.Present {
		st.Items = []Item{{Name: id, Path: in.Path, State: string(st.State)}}
	}
	st.Leftover = in.Applicable && in.Present && !in.ComponentActive
	return st
}

// HelperStates lists every state the helper table can produce.
func HelperStates() []State {
	return statesOf(len(helperRules), func(i int) State { return helperRules[i].state })
}

// ---------------------------------------------------------------------------
// helpers

func statesOf(n int, at func(int) State) []State {
	seen := map[State]bool{}
	var out []State
	for i := 0; i < n; i++ {
		if s := at(i); !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func versionNote(v string) string {
	if v == "" {
		return ""
	}
	return " (version " + v + ")"
}

func joinRemedy(a, b string) string {
	switch {
	case a == "":
		return b
	case b == "":
		return a
	}
	return a + "; " + b
}

// ago renders a coarse "N minutes/hours/days ago" between two epoch-millis
// instants.
func ago(nowMs, thenMs int64) string {
	d := nowMs - thenMs
	if d < 0 {
		d = 0
	}
	switch m := d / 60000; {
	case m < 1:
		return "just now"
	case m == 1:
		return "1 minute ago"
	case m < 120:
		return fmt.Sprintf("%d minutes ago", m)
	case m < 48*60:
		return fmt.Sprintf("%d hours ago", m/60)
	default:
		return fmt.Sprintf("%d days ago", m/(60*24))
	}
}
