package sandboxsetup

import (
	"time"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/toolinstall"
)

// Kind is a prerequisite's closed kind.
type Kind string

// The closed Kind vocabulary.
const (
	// KindComponent: the backend's module is selected in [components].
	KindComponent Kind = "component"
	// KindProgram: a host program (bwrap, cloud-hypervisor, docker,
	// openshell, container).
	KindProgram Kind = "program"
	// KindKernel: a kernel feature (user namespaces, the Landlock ABI,
	// /dev/kvm).
	KindKernel Kind = "kernel_feature"
	// KindOSFeature: a Windows optional feature.
	KindOSFeature Kind = "os_feature"
	// KindOSVersion: an OS edition, build, version or architecture.
	KindOSVersion Kind = "os_version"
	// KindGroup: membership of a group (kvm, docker).
	KindGroup Kind = "group"
	// KindService: a running service (an engine, `container system start`,
	// the systemd user manager).
	KindService Kind = "service"
	// KindContent: signed content (a guest image set, native files).
	KindContent Kind = "content"
	// KindImage: an engine image by digest.
	KindImage Kind = "image"
	// KindAccount: a vendor account or the org-shell sign-in.
	KindAccount Kind = "account"
	// KindCredential: an API key in the OS keychain.
	KindCredential Kind = "credential"
	// KindConsent: the per-provider consent.
	KindConsent Kind = "consent"
	// KindConfig: a disclosed config key (allow_rootful, cloud_hypervisor_path).
	KindConfig Kind = "config"
	// KindEnable: [terminal.sandbox].enabled and the backend in backends.
	KindEnable Kind = "enable"
)

// Class is what Observer may do about a missing prerequisite.
type Class string

// The closed Class vocabulary.
const (
	// ClassAuto: in-process on the person's click (a config key, a
	// component, content, a pinned download into a user-owned dir).
	ClassAuto Class = "auto"
	// ClassTerminal: a server-derived argv in a visible setup terminal, as
	// the user, no elevation.
	ClassTerminal Class = "terminal"
	// ClassElevated: a server-derived argv needing sudo or UAC in a visible
	// setup terminal; the person types the password (decision O1).
	ClassElevated Class = "elevated"
	// ClassGuide: a copyable command or steps; Observer never runs it.
	ClassGuide Class = "guide"
	// ClassNever: Observer must not touch it; words and a docs link only.
	ClassNever Class = "never"
)

// Channel is how a step is carried out. The runner dispatches on it, never
// on a backend id. The pm channel reuses internal/toolinstall's host
// package-manager table.
type Channel string

// The closed Channel vocabulary.
const (
	// ChComponent: componentsvc Preview then Apply.
	ChComponent Channel = "component_select"
	// ChEnable: the [terminal.sandbox] writer.
	ChEnable Channel = "sandbox_enable"
	// ChConfig: the [terminal.sandbox.*] writer, one named key.
	ChConfig Channel = "config_key"
	// ChPM: the host's package manager (apt, dnf, pacman, zypper, apk, brew)
	// through toolinstall.InstallArgvFor.
	ChPM Channel = "pm"
	// ChPinned: a compiled pin (sha256, size cap) downloaded into a
	// user-owned dir.
	ChPinned Channel = "pinned_download"
	// ChContent: sandbox_content.go's fetch or import.
	ChContent Channel = "content"
	// ChOCIPull: the existing engine image pull seam.
	ChOCIPull Channel = "oci_pull"
	// ChCommand: a fixed argv (container system start, runsc install,
	// Enable-WindowsOptionalFeature).
	ChCommand Channel = "terminal_cmd"
	// ChHostedKey: a keychain write of a typed key.
	ChHostedKey Channel = "hosted_connect"
	// ChConsent: the existing hosted consent route.
	ChConsent Channel = "hosted_consent"
	// ChOrgShell: the existing org-shell sign-in.
	ChOrgShell Channel = "orgshell_login"
	// ChNone: guide or never; nothing runs.
	ChNone Channel = "none"
)

// The closed After vocabulary: what the person must do once a step ran,
// before it takes effect.
const (
	AfterNone          = ""
	AfterRelogin       = "relogin"
	AfterReboot        = "reboot"
	AfterEngineRestart = "engine_restart"
	AfterDaemonRestart = "daemon_restart"
)

// Remedy is one way of providing a missing prerequisite on some hosts. The
// first remedy of a prerequisite whose Hosts and Family match wins.
type Remedy struct {
	// Hosts are where this remedy applies; empty means every host.
	Hosts []sandboxbackend.HostKind
	// Family is the host family key (FamilyFor: "debian", "fedora",
	// "arch", "suse", "alpine", "macos", "windows"); "" means any family.
	Family  string
	Class   Class
	Channel Channel
	// Package is the pm package, the pin id, the content kinds (a comma
	// list), the component id, the config key or the engine whose pull
	// seam runs, per Channel.
	Package string
	// Argv is the compile-time constant argv of a ChCommand remedy; nil for
	// every channel that derives its own.
	Argv []string
	// ArgKey, on a ChCommand remedy, is the dotted config key whose value is
	// the argv's last argument (an image reference the person configured,
	// pinned by digest). The planner appends it from PlanInput.ArgValues,
	// never from a request; without a usable value the step is a guide that
	// names the key.
	ArgKey string
	// Display is the step's one sentence (a pm or command step shows its
	// command instead once the planner derives it).
	Display string
	// Docs is the docs anchor ("sandboxed-terminals.md#...").
	Docs string
	// After is one of the After constants.
	After string
	// Disclosure is shown before the step runs.
	Disclosure string
	// Value is what a ChConfig remedy writes to its key ("" writes "true",
	// the value of the boolean keys).
	Value string
	// Action is the step's button label when its class's own label would
	// not say what the step does ("" keeps the class's label).
	Action string
}

// Detect is how a prerequisite is detected.
type Detect struct {
	// Programs are resolved passively (shims excluded). An entry may list
	// alternatives with toolinstall.AltSep ("podman|docker"); every entry
	// must resolve.
	Programs []string
	// MinVersion is the version a found program must reach. "" with
	// DriverBinary set means the row's DriverPins.RequiredMin.
	MinVersion string
	// DriverBinary: this prerequisite is its row's own driver binary, so
	// its version is judged against the row's DriverPins (required minimum
	// and tested range). Set only on a prerequisite exactly one row uses.
	DriverBinary bool
	// Verdicts are the driver probe verdicts that mean this prerequisite is
	// missing, filled from the verdict map (verdicts.go), across rows.
	Verdicts []string
	// Component is the component id of a KindComponent prerequisite.
	Component string
	// Content are the content kinds of a KindContent prerequisite.
	Content []string
	// ConfigKey is the dotted config key of a KindConfig or KindEnable
	// prerequisite.
	ConfigKey string
	// PathKey is the dotted config key that may name the program's path
	// (a placed download, a program off PATH); a set key is read before
	// Programs are resolved.
	PathKey string
	// EngineSocket: the prerequisite is a container engine's socket, present
	// when one of the engine's known socket paths exists.
	EngineSocket bool
	// DockerSocketAccess: the prerequisite is this user's access to Docker's
	// rootful socket, judged from that socket and the user's groups whichever
	// engine the row would pick (DockerAccessFact).
	DockerSocketAccess bool
}

// Prereq is one row of the prerequisite table.
type Prereq struct {
	// ID is the stable prerequisite id a registry row's Setup names.
	ID    string
	Kind  Kind
	Label string
	// Detect says how the prerequisite is detected.
	Detect Detect
	// Remedies are walked top-down; the first matching the host and family
	// wins.
	Remedies []Remedy
	// Shared: more than one backend row lists it (one record per
	// prerequisite id; never undone while another set-up row uses it, unless
	// NodeWide).
	Shared bool
	// NodeWide: the step sets ONE value every row that lists it reads (a
	// single config key, such as the hosted key custody), so its undo can
	// only change it back for all of them at once. Another set-up row's use
	// therefore does not keep it; Undo is offered and says which other rows
	// it changes (Step.UndoAlso) before it runs (audit
	// sandbox-terminal-gaps-2026-11-18, H12).
	NodeWide bool
}

// Pin is one compiled download pin (pins.go, lane download).
type Pin struct {
	ID, Version, GOOS, GOARCH, URL, SHA256 string
	Size                                   int64
	// Signer names who signs the asset upstream ("" when unsigned).
	Signer string
	// Status is PinGrounded or PinOwed.
	Status string
}

// The closed Pin.Status vocabulary. An owed pin never downloads.
const (
	PinGrounded = "grounded"
	PinOwed     = "owed"
)

// The closed DownloadSource vocabulary (decisions O2, O3).
const (
	SourceVendorRelease = "vendor_release"
	SourceOrgMirror     = "org_mirror"
	// SourceFromFile is a Consent source only (never a DownloadSource): the
	// pinned file is placed from a copy the person names, the one source of
	// a managed node with no org mirror.
	SourceFromFile = "from_file"
)

// Fact is what the caller found about one prerequisite.
type Fact struct {
	// Checked: an active check ran (false: passive facts only).
	Checked bool
	Present bool
	Version string
	Path    string
	// Verdict is the driver verdict that judged it, when one did.
	Verdict string
	Reason  string
	// NotApplicable: the prerequisite does not apply on this machine (the
	// docker group while the row uses a rootless engine this user owns).
	NotApplicable bool
}

// Record is a plain mirror of the tool_installs row fields the planner
// reads (subject_kind sandbox, tool = the prerequisite id).
type Record struct {
	ID         int64
	Status     toolinstall.Status
	Channel    string
	Digest     string
	PlacedPath string
	Elevated   bool
	StartedAt  time.Time
	FinishedAt *time.Time
}

// Consent is what a pinned download shows before the click and what the run
// request echoes.
type Consent struct {
	Pin     string
	Version string
	SHA256  string
	Bytes   int64
	// Source is SourceVendorRelease or SourceOrgMirror.
	Source string
	URL    string
}

// PlanInput is everything Build reads. The caller gathers it; Build does no
// I/O.
type PlanInput struct {
	Row  sandboxbackend.Capability
	Host sandboxbackend.HostKind
	// Family is the host family key (FamilyFor).
	Family string
	// Arch is the host's GOARCH, for pin selection; "" means the build's
	// own (runtime.GOARCH).
	Arch    string
	Managed bool
	// OrgAllowed: the AllowedBackends floor admits the row.
	OrgAllowed bool
	// ComponentID is the component the row's driver registers ("" when no
	// driver registration names one: the component step is not_applicable).
	ComponentID       string
	ComponentSelected bool
	// ComponentGoverned: [components] is set by the organization.
	ComponentGoverned bool
	SandboxOn         bool
	// Listed: the row is in [terminal.sandbox].backends.
	Listed bool
	// Probe is the latest driver probe; nil means not probed.
	Probe *sandboxselect.Probe
	// Facts are per prerequisite id.
	Facts map[string]Fact
	// Records are the latest tool_installs record per prerequisite id.
	Records map[string]Record
	// AllowInstall is [terminal.launch].allow_install.
	AllowInstall bool
	// AllowElevated is [terminal.sandbox.setup].allow_elevated (decision
	// O1, default false).
	AllowElevated bool
	// DownloadSource is SourceVendorRelease, SourceOrgMirror or "" (none
	// allowed: a pinned download reads as a guide).
	DownloadSource string
	// LiveRuns counts live runs on this backend (undo is refused while any).
	LiveRuns int
	// LiveRunsUnknown: the caller could not tell whether a run is live (a
	// CLI whose daemon did not answer); undo and update are then refused.
	LiveRunsUnknown bool
	// UnlistRelists: removing the row from [terminal.sandbox].backends would
	// leave a list that still names it (the empty list falls back to the
	// default backend), so the enable step's undo would change nothing.
	UnlistRelists bool
	// InUseBy is, per prerequisite id, the OTHER registry row ids listed in
	// [terminal.sandbox].backends whose Setup names the same id. Filled by
	// the caller (lane daemon). A prerequisite with any entry here is never
	// offered for undo (plan section 4.9), and its step names those rows.
	InUseBy map[string][]string
	// ArgValues are the local config values of the keys a remedy's ArgKey
	// names, read by the caller (the planner reads no config itself).
	ArgValues map[string]string
}

// StepState is a step's closed state.
type StepState string

// The closed StepState vocabulary.
const (
	StateDone          StepState = "done"
	StateMissing       StepState = "missing"
	StateUnknown       StepState = "unknown"
	StateBlocked       StepState = "blocked"
	StateNotApplicable StepState = "not_applicable"
	StateInFlight      StepState = "in_flight"
	StateNotAllowed    StepState = "not_allowed"
)

// Step is one planned step.
type Step struct {
	Prereq string
	Kind   Kind
	Label  string
	State  StepState
	// Class is after the input's switches: elevated becomes guide when
	// AllowElevated is false, a pinned download becomes guide with an owed
	// pin or no source, everything becomes guide when AllowInstall is false.
	Class   Class
	Channel Channel
	Display string
	// DisplayIsCommand: Display is a command line a person can paste into a
	// terminal (a derived package-manager argv, a remedy's constant argv),
	// not a sentence. A surface offers "Copy command" only for such a
	// display. Not part of the Fingerprint.
	DisplayIsCommand bool
	Reason           string
	Disclosure       string
	After            string
	Docs             string
	// Package and Argv are what the runner executes (the derived pm argv,
	// the remedy's constant argv), server-side only; never from a request.
	Package string
	Argv    []string
	// Value is the value a config_key step writes (Remedy.Value; "" is
	// "true"), server-side only.
	Value string
	// Action is the remedy's button label ("" keeps the class's label).
	Action string
	// CanRun: a Run button (class auto, terminal or elevated, state
	// missing, switches on, nothing blocked before it).
	CanRun bool
	// CanUndo: an Undo button (plan section 4.8 and 4.9).
	CanUndo bool
	// UndoNote is why Undo is not offered, when a rule has a sentence for
	// it ("" otherwise).
	UndoNote string
	// UndoAlso is what an offered undo of a NodeWide step changes beyond
	// this row, as a sentence naming the other set-up rows ("" otherwise);
	// a surface shows it before the undo runs.
	UndoAlso string
	// UndoRefused names the refusal (UndoRefusedLiveRuns and the rest) that
	// keeps an undo Observer would otherwise offer ("" when Undo is offered
	// or there is nothing to undo).
	UndoRefused string
	Record      *Record
	// Consent is set for a runnable pinned download.
	Consent *Consent
}

// Plan is a backend's ordered setup.
type Plan struct {
	Backend string
	Label   string
	Steps   []Step
	// Next is the index of the first step that is not done or not
	// applicable (-1: none).
	Next int
	// Ready: every step done and the probe passes.
	Ready bool
	// Unconfirmed: a plan from passive facts with nothing left that Observer
	// can see to do; only the active check can say it is ready.
	Unconfirmed bool
	// Blocked is why the row can never run here ("" when it can).
	Blocked string
	// Beta is the row's SetupBeta sentence, copied by Build ("" when the
	// row's setup is not beta). A label only: it gates no step and is not
	// part of the Fingerprint.
	Beta string
	// Fingerprint is the sha256 over the steps' prereq, state, class,
	// display and consent: a run request names it.
	Fingerprint string
}
