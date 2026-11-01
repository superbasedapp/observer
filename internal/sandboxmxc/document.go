package sandboxmxc

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// document.go builds the one MXC config document a run is started with:
// a one-shot ProcessContainer request of the published "1.0.0" contract
// (MXCConfiguration's OneShotRequest), the request MXC's own Node SDK hands
// to wxc-exec under a ConPTY. This driver hands it over as a file
// (`wxc-exec --config <path>`, owner-only and removed once read), never on
// a command line, because it carries the box's environment (ledger
// SBX-BE-15, audit finding F2). Only the fields this driver sets are
// modelled; every field is a closed choice the planner makes, never a
// value read from a repository. Validate refuses, before anything reaches
// MXC, every combination MXC 1.0.1 rejects or that would open the box
// beyond its plan.

// ContainmentProcessContainer is the one containment this row runs.
const ContainmentProcessContainer = "processcontainer"

// NetworkActionAllow and NetworkActionDeny are the contract's actions.
const (
	NetworkActionAllow = "allow"
	NetworkActionDeny  = "deny"
)

// Document is the MXC config document (contract 1.0.0).
type Document struct {
	Version     string     `json:"version"`
	Containment string     `json:"containment"`
	ContainerID string     `json:"containerId,omitempty"`
	Fallback    Fallback   `json:"fallback"`
	Filesystem  Filesystem `json:"filesystem"`
	// ProcessContainer carries the enumerate-only ancestors of the grants
	// (ancestors.go); nil when the host cannot serve them.
	ProcessContainer *ProcessContainer `json:"processContainer,omitempty"`
	Network          Network           `json:"network"`
	RuntimeConfig    *RuntimeConfig    `json:"runtimeConfig,omitempty"`
	Process          Process           `json:"process"`
	// UI is the box's user-interface policy (ui.go): always set by
	// BuildDocument, so MXC keeps Win32k system calls on and the box can
	// load user32.dll (D1), with the clipboard and input injection closed.
	UI        *UI       `json:"ui,omitempty"`
	Lifecycle Lifecycle `json:"lifecycle"`
	Telemetry Telemetry `json:"telemetry"`
}

// Fallback is the operator consent for containment fallback. The field is
// a plain bool WITHOUT omitempty, so the document always says
// "allowDaclMutation": false in so many words: MXC's DACL tier, which
// rewrites host ACLs, is refused rather than defaulted (sandbox plan v2
// section 4.2, HostMutation rule; ledger SBX-BE-15).
type Fallback struct {
	AllowDaclMutation bool `json:"allowDaclMutation"`
}

// Filesystem is the path policy.
type Filesystem struct {
	ReadwritePaths []string `json:"readwritePaths,omitempty"`
	ReadonlyPaths  []string `json:"readonlyPaths,omitempty"`
	DeniedPaths    []string `json:"deniedPaths,omitempty"`
}

// ProcessContainer is the contract's ProcessContainer section: the
// enumerate-only paths and the job's user-interface limits (ui.go).
type ProcessContainer struct {
	Filesystem *ProcessContainerFilesystem `json:"filesystem,omitempty"`
	UI         *ProcessContainerUI         `json:"ui,omitempty"`
}

// ProcessContainerFilesystem lists paths the box may query and enumerate
// without reading file contents (MXC 1.0.1 dist/generated/v1_0_0/wire.d.ts,
// ProcessContainerFilesystem.enumeratePaths).
type ProcessContainerFilesystem struct {
	EnumeratePaths []string `json:"enumeratePaths,omitempty"`
}

// Network is the egress and ingress policy.
type Network struct {
	Egress  NetworkEgress  `json:"egress"`
	Ingress NetworkIngress `json:"ingress"`
}

// NetworkEgress is the outbound policy.
type NetworkEgress struct {
	Default string `json:"default"`
}

// NetworkIngress is the inbound and host-loopback policy.
type NetworkIngress struct {
	Default      string `json:"default"`
	HostLoopback string `json:"hostLoopback"`
}

// RuntimeConfig names a runtime proxy endpoint. BuildDocument never sets
// it and Validate refuses it (ErrNetworkProxy); the type is kept so a
// hand-built document carrying one is refused by name.
type RuntimeConfig struct {
	NetworkProxy string `json:"networkProxy"`
}

// Process is what runs inside the container.
type Process struct {
	CommandLine       string   `json:"commandLine"`
	Cwd               string   `json:"cwd,omitempty"`
	Env               []string `json:"env"`
	InheritDefaultEnv bool     `json:"inheritDefaultEnv"`
}

// Lifecycle ends the container with the process.
type Lifecycle struct {
	DestroyOnExit bool `json:"destroyOnExit"`
}

// Telemetry switches MXC's own telemetry off for every run.
type Telemetry struct {
	Enabled bool `json:"enabled"`
}

// RunPlan is what the driver decided for one run.
type RunPlan struct {
	// RunID names the container (containerId "observer-<run id>").
	RunID string
	// Argv is the inner launch (the observer launcher and its arguments).
	Argv []string
	// Cwd is the workspace.
	Cwd string
	// Env is the inner launch's whole environment (KEY=VALUE); MXC's
	// default environment is not inherited. Any SYSTEMROOT or LOCALAPPDATA
	// entry in it is replaced by the two fields below.
	Env []string
	// SystemRoot is the host's real %SYSTEMROOT% (not sensitive) and
	// LocalAppData the run's own private box directory, never the host
	// user's LocalAppData. MXC 1.0.1 refuses a ProcessContainer whose
	// process.env lacks either when inheritDefaultEnv is false
	// (policy_validation, status 11, the laptop re-run of 2026-10-22:
	// "missing the required variable(s): SYSTEMROOT, LOCALAPPDATA ... any
	// value will do because the Windows requirement is presence-only"), so
	// every document carries both. Both are required.
	SystemRoot   string
	LocalAppData string
	// ReadWrite are the workspace and the tool's writable state.
	ReadWrite []string
	// ReadOnly are the observer binary's directory, the tool's binaries,
	// runtimes and read-only state, and the run's launch-record directory.
	ReadOnly []string
	// Denied are paths refused inside even when a broader grant covers them
	// (the observer directory and its secrets).
	Denied []string
	// ProxyPort is the run's one shared loopback port (port.go), which the
	// box reaches through host loopback. Zero allows no host loopback at
	// all (no relay either).
	ProxyPort int
	// EnumerateAncestors lists every directory above the cwd and the grants
	// enumerate-only (EnumerateAncestors), so a runtime that resolves a
	// granted path component by component can (Windows 11 Pro run 4). Set
	// only when the host's BaseContainer reports
	// baseContainerSupportsEnumeratePaths: MXC refuses the field otherwise.
	EnumerateAncestors bool
	// NeedsWin32k is the tool row's capability (BoxUI): Win32k system calls
	// stay on only for a tool that needs user32.dll.
	NeedsWin32k bool
}

// ContainerName is the containerId of a run's container, which MXC also
// uses as its AppContainer profile name (@microsoft/mxc-sdk 1.0.1
// dist/v1/types.d.ts: the profile name option is deprecated in favour of
// containerId). A process inside the box recognises its own container by
// this name (cmd/observer's box detection, audit finding F1).
func ContainerName(runID string) string { return "observer-" + runID }

// Plan errors.
var (
	ErrEmptyCommand = errors.New("sandboxmxc: the inner launch is empty")
	ErrBadPath      = errors.New("sandboxmxc: a policy path is not an absolute local Windows path")
	ErrBadEnv       = errors.New("sandboxmxc: an environment entry is not KEY=VALUE")
	ErrBadRunID     = errors.New("sandboxmxc: the run id is not a short id")
	ErrBadPort      = errors.New("sandboxmxc: the proxy port is out of range")
	ErrNoWindowsEnv = errors.New("sandboxmxc: the plan names no SYSTEMROOT or no LOCALAPPDATA (an absolute local Windows path each)")
)

// The two variables Windows needs in a process container's environment
// (presence only, MXC 1.0.1).
const (
	EnvSystemRoot   = "SYSTEMROOT"
	EnvLocalAppData = "LOCALAPPDATA"
)

// HiddenEnvEntry reports whether kv is one of the hidden entries Windows
// keeps in a process's environment block, whose name starts with "="
// ("=C:=C:\work", "=ExitCode=00000001", "=::=::\"): the per-drive current
// directories and shell state cmd.exe and PowerShell leave there, which
// every process they start inherits (Windows 11 Pro live run 2026-10-22,
// where every launch from a shell was refused with ErrBadEnv). They mean
// nothing inside a box and are not KEY=VALUE, so the box's environment
// skips them. Every reader of a host environment on the Windows launch
// path asks this one function.
func HiddenEnvEntry(kv string) bool { return strings.HasPrefix(kv, "=") }

// BuildDocument turns a run plan into the config document. It refuses a
// plan with a relative, device, UNC or parent-walking path, an environment
// entry that is not KEY=VALUE, or a NUL anywhere. Windows' hidden "="
// entries (HiddenEnvEntry) are skipped, not refused.
func BuildDocument(p RunPlan) (Document, error) {
	if len(p.Argv) == 0 || p.Argv[0] == "" {
		return Document{}, ErrEmptyCommand
	}
	if !validRunID(p.RunID) {
		return Document{}, ErrBadRunID
	}
	if p.ProxyPort < 0 || p.ProxyPort > 65535 {
		return Document{}, ErrBadPort
	}
	for _, a := range p.Argv {
		if strings.ContainsRune(a, 0) {
			return Document{}, ErrEmptyCommand
		}
	}
	if p.Cwd != "" && !LocalWindowsPath(p.Cwd) {
		return Document{}, fmt.Errorf("%w: cwd %q", ErrBadPath, p.Cwd)
	}
	for _, set := range [][]string{p.ReadWrite, p.ReadOnly, p.Denied} {
		for _, path := range set {
			if !LocalWindowsPath(path) {
				return Document{}, fmt.Errorf("%w: %q", ErrBadPath, path)
			}
		}
	}
	if !LocalWindowsPath(p.SystemRoot) || !LocalWindowsPath(p.LocalAppData) {
		return Document{}, ErrNoWindowsEnv
	}
	env := make([]string, 0, len(p.Env)+2)
	for _, kv := range p.Env {
		if HiddenEnvEntry(kv) {
			continue
		}
		k, _, ok := strings.Cut(kv, "=")
		if !ok || k == "" || strings.ContainsRune(kv, 0) {
			return Document{}, ErrBadEnv
		}
		if strings.EqualFold(k, EnvSystemRoot) || strings.EqualFold(k, EnvLocalAppData) {
			continue
		}
		env = append(env, kv)
	}
	env = append(env, EnvSystemRoot+"="+p.SystemRoot, EnvLocalAppData+"="+p.LocalAppData)
	d := Document{
		Version:     ContractVersion,
		Containment: ContainmentProcessContainer,
		ContainerID: ContainerName(p.RunID),
		Fallback:    Fallback{AllowDaclMutation: false},
		Filesystem: Filesystem{
			ReadwritePaths: dedup(p.ReadWrite),
			ReadonlyPaths:  dedup(p.ReadOnly),
			DeniedPaths:    dedup(p.Denied),
		},
		// Egress and private-network ingress are denied. The box reaches
		// the run's one loopback port (port.go) through host loopback, with
		// no runtimeConfig.networkProxy: MXC 1.0.1 refuses a ProcessContainer
		// networkProxy unless network.ingress.default is "allow" (its own
		// malformed_request message, live check 2026-10-22, finding L1), and
		// that default governs private-network inbound traffic (the SDK's
		// NetworkIngressConfig.default in dist/v1/types.d.ts and
		// NetworkIngress.default in generated/v1_0_0/wire.d.ts). Allowing it
		// would let a host on the LAN connect into the box, which no tier of
		// the plan allows, so the proxy route is not used (Validate refuses
		// it). Host loopback "allow" is what reaching the run's port needs;
		// MXC's own messages describe it as unrestricted host loopback, so
		// the port authenticates every caller with the run's token and the
		// residual (other loopback listeners are reachable) is ledger row
		// SBX-BE-15.
		Network: Network{
			Egress:  NetworkEgress{Default: NetworkActionDeny},
			Ingress: NetworkIngress{Default: NetworkActionDeny, HostLoopback: NetworkActionDeny},
		},
		Process: Process{
			CommandLine: CommandLine(p.Argv), Cwd: p.Cwd, Env: env, InheritDefaultEnv: false,
		},
		Lifecycle: Lifecycle{DestroyOnExit: true},
		Telemetry: Telemetry{Enabled: false},
		UI:        BoxUI(p.NeedsWin32k),
		// The job's user-interface limits at their strictest (WINFIX2 audit
		// finding 3): its own desktop resources, handles and atom table, no
		// desktop or system-settings control, no input method.
		ProcessContainer: &ProcessContainer{UI: BoxProcessUI()},
	}
	if p.ProxyPort > 0 {
		d.Network.Ingress.HostLoopback = NetworkActionAllow
	}
	if p.EnumerateAncestors {
		grants := append(append([]string(nil), d.Filesystem.ReadwritePaths...), d.Filesystem.ReadonlyPaths...)
		probeAt := grants
		if p.Cwd != "" {
			probeAt = append([]string{p.Cwd}, grants...)
		}
		// The cwd is walked for its parents but is not itself a grant: a cwd
		// outside every grant stays unreadable.
		anc := enumerateAncestorsOf(probeAt, grants, d.Filesystem.DeniedPaths)
		if len(anc) > 0 {
			d.ProcessContainer.Filesystem = &ProcessContainerFilesystem{EnumeratePaths: anc}
		}
	}
	return d, d.Validate()
}

// ProbeDocument is the document the create-and-close check and the request
// probe use: the same policy shape as a run, with a command that exits at
// once and no proxy. localAppData is the probe's own box directory (never
// the host user's LocalAppData).
func ProbeDocument(cmdExe, systemRoot, localAppData string) (Document, error) {
	return BuildDocument(RunPlan{RunID: "probe", Argv: []string{cmdExe, "/d", "/c", "exit 0"}, Cwd: systemRoot, SystemRoot: systemRoot, LocalAppData: localAppData})
}

// Document errors (Validate).
var (
	ErrDaclMutation = errors.New("sandboxmxc: a document allowing DACL mutation is refused")
	ErrEgressOpen   = errors.New("sandboxmxc: network.egress.default must be \"deny\"; the box reaches the network only through the run's port")
	ErrNetworkProxy = errors.New("sandboxmxc: runtimeConfig.networkProxy is refused: MXC 1.0.1 takes a ProcessContainer proxy only with network.ingress.default \"allow\" (malformed_request otherwise), and this driver never allows private-network inbound traffic")
	ErrIngressOpen  = errors.New("sandboxmxc: network.ingress.default must be \"deny\": it admits private-network inbound traffic, which no tier of the sandbox plan allows")
	ErrInheritEnv   = errors.New("sandboxmxc: process.inheritDefaultEnv must be false: the box never inherits the host's environment")
	ErrEnvMissing   = errors.New("sandboxmxc: process.env must carry SYSTEMROOT and LOCALAPPDATA: MXC 1.0.1 refuses a ProcessContainer without them when inheritDefaultEnv is false (policy_validation)")
	ErrUIOpen       = errors.New("sandboxmxc: ui.clipboard must be \"none\" and ui.injection false: the box never reads or writes the host clipboard or injects input")
	ErrJobUIOpen    = errors.New("sandboxmxc: processContainer.ui must be the strictest job limits (isolation \"container\", no desktop system control, systemSettings \"none\", no IME): the box never shares the user's desktop resources, handles or atoms")
	ErrEnumerate    = errors.New("sandboxmxc: an enumerate-only path is not an absolute local Windows path, or is a grant, lies inside one or inside a denied path (MXC would apply the narrower intent and take the grant away)")
)

// documentRules is Validate's ordered table: the first rule a document
// breaks is the refusal. The proxy rule comes before the ingress rule, so
// the combination MXC 1.0.1 rejects (a proxy with ingress denied) is
// refused by its own name.
var documentRules = []func(Document) error{
	func(d Document) error {
		if d.Fallback.AllowDaclMutation {
			return ErrDaclMutation
		}
		return nil
	},
	func(d Document) error {
		if d.Network.Egress.Default != NetworkActionDeny {
			return ErrEgressOpen
		}
		return nil
	},
	func(d Document) error {
		if d.RuntimeConfig != nil {
			return ErrNetworkProxy
		}
		return nil
	},
	func(d Document) error {
		if d.Network.Ingress.Default != NetworkActionDeny {
			return ErrIngressOpen
		}
		return nil
	},
	func(d Document) error {
		if d.Process.InheritDefaultEnv {
			return ErrInheritEnv
		}
		return nil
	},
	func(d Document) error {
		var missing []string
		for _, want := range []string{EnvSystemRoot, EnvLocalAppData} {
			found := false
			for _, kv := range d.Process.Env {
				if k, _, _ := strings.Cut(kv, "="); strings.EqualFold(k, want) {
					found = true
					break
				}
			}
			if !found {
				missing = append(missing, want)
			}
		}
		if len(missing) > 0 {
			return fmt.Errorf("%w (missing %s)", ErrEnvMissing, strings.Join(missing, ", "))
		}
		return nil
	},
	func(d Document) error {
		if d.UI != nil && (d.UI.Clipboard != UIClipboardNone || d.UI.Injection) {
			return ErrUIOpen
		}
		return nil
	},
	func(d Document) error {
		if d.ProcessContainer == nil || d.ProcessContainer.UI == nil || *d.ProcessContainer.UI != *BoxProcessUI() {
			return ErrJobUIOpen
		}
		return nil
	},
	func(d Document) error {
		if d.ProcessContainer == nil || d.ProcessContainer.Filesystem == nil {
			return nil
		}
		fs := d.Filesystem
		for _, p := range d.ProcessContainer.Filesystem.EnumeratePaths {
			if !LocalWindowsPath(p) || withinAnyPath(p, fs.ReadwritePaths) || withinAnyPath(p, fs.ReadonlyPaths) || withinAnyPath(p, fs.DeniedPaths) {
				return fmt.Errorf("%w: %q", ErrEnumerate, p)
			}
		}
		return nil
	},
}

// Validate refuses a document before it reaches MXC: DACL mutation, open
// egress, a runtime proxy, open private-network ingress, an inherited host
// environment, a process.env without SYSTEMROOT and LOCALAPPDATA, a ui
// block that opens the clipboard or input injection, or an enumerate-only
// path that would narrow a grant or a denial.
func (d Document) Validate() error {
	for _, rule := range documentRules {
		if err := rule(d); err != nil {
			return err
		}
	}
	return nil
}

// Encode is the document's JSON; a document Validate refuses is never
// encoded (a hand-built one included).
func (d Document) Encode() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(d)
}

// LocalWindowsPath reports whether p is an absolute drive-letter path with
// no parent walk ("C:\Users\a\proj"). UNC, device ("\\.\", "\\?\") and
// relative paths are refused: a share or device path could name another
// machine or a raw volume.
func LocalWindowsPath(p string) bool {
	if len(p) < 3 || strings.ContainsRune(p, 0) {
		return false
	}
	c := p[0] | 0x20
	if c < 'a' || c > 'z' || p[1] != ':' || (p[2] != '\\' && p[2] != '/') {
		return false
	}
	for _, part := range strings.FieldsFunc(p[3:], func(r rune) bool { return r == '\\' || r == '/' }) {
		if part == ".." || part == "." {
			return false
		}
	}
	return !strings.ContainsAny(p[2:], ":*?\"<>|")
}

// CommandLine joins argv the way CreateProcess and the C runtime split it
// back (the rules syscall.EscapeArg follows): an argument with a space,
// tab, quote or nothing at all is quoted, and the backslashes before a
// quote are doubled.
func CommandLine(argv []string) string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = escapeArg(a)
	}
	return strings.Join(out, " ")
}

func escapeArg(s string) string {
	if s == "" {
		return `""`
	}
	if !strings.ContainsAny(s, " \t\"\n\v") {
		return s
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			slashes++
			b.WriteByte(c)
			continue
		case '"':
			for ; slashes > 0; slashes-- {
				b.WriteByte('\\')
			}
			b.WriteByte('\\')
		}
		slashes = 0
		b.WriteByte(c)
	}
	for ; slashes > 0; slashes-- {
		b.WriteByte('\\')
	}
	b.WriteByte('"')
	return b.String()
}

// validRunID accepts the short ids the sandbox runtime mints.
func validRunID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return false
		}
	}
	return true
}

// dedup keeps the first spelling of each path, comparing case-insensitively
// (Windows paths are).
func dedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, p := range in {
		k := strings.ToLower(strings.ReplaceAll(p, "/", `\`))
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, p)
	}
	return out
}
