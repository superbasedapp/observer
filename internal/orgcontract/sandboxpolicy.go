package orgcontract

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// sandboxpolicy.go is the body of the sandbox module's managed pull, GET
// /api/agent/sandbox (sandbox plan v2 section 8.2, phase P1c; the "Managed
// pull" column of section 10.1). It rides the shared managed-pull kit
// (managedpull.go): the kit signs, versions, expires and verifies the
// document; this file only defines what the body may say.
//
// The body is CLOSED (DisallowUnknownFields) and every field is optional: an
// absent field leaves the node's own value in force, a present one sets it on
// a managed node whose honoured grant holds enforce.sandbox (and nowhere
// else). It carries only keys that exist in [terminal.sandbox] today; the
// capture, OCI, VM, hosted and credential-reference keys of section 10.1 are
// not built (P2 to P7) and so are not here.
//
// Three things it can never carry, each refused by name before decoding so
// the admin sees why, not an "unknown field": a capture-losing mode
// (allow_reduced_capture, provider key injection), a credential VALUE, and
// the egress tier "none" (it forwards not even the model proxy, so capture
// is lost; section 8.1 keeps it out of the org's reach for the same reason).
// workspaces_dir is refused by name too: the managed-workspace root is
// node-local (SBX-P1C merge finding 3). A per-node write bind may not name a
// sensitive host location (sandboxbinds.go).

// SandboxManagedSchema is the body's schema tag (the same string as the
// rail's signing domain).
const SandboxManagedSchema = "sbo-sandbox-managed-v1"

// SandboxManagedPolicyV1 is the sandbox managed-pull body.
type SandboxManagedPolicyV1 struct {
	// Schema must be SandboxManagedSchema.
	Schema string `json:"schema"`
	// Enabled is [terminal.sandbox].enabled.
	Enabled *bool `json:"enabled,omitempty"`
	// Backends is the backend preference order (registry ids). An empty
	// list enables no backend. It may only filter an ExplicitOnly registry
	// row (openshell and the other opt-in rows), never add one: a node
	// leaves such a row off unless its own list names it, with refusal
	// reason explicit_only_not_listed (lane FU8, ledger OSH-45).
	Backends *[]string `json:"backends,omitempty"`
	// DefaultOn pre-checks the "Run in sandbox" toggle.
	DefaultOn *bool `json:"default_on,omitempty"`
	// Egress is the exact network tier: host, internet or proxy_only.
	Egress *string `json:"egress,omitempty"`
	// EgressAllowCIDRs is the internet tier's private-range allow-list.
	EgressAllowCIDRs *[]string `json:"egress_allow_cidrs,omitempty"`
	// AllowToolConfigWrites lets a sandboxed tool write its own config.
	AllowToolConfigWrites *bool `json:"allow_tool_config_writes,omitempty"`
	// AllowRemoteClone allows the clone-remote workspace source.
	AllowRemoteClone *bool `json:"allow_remote_clone,omitempty"`
	// RemoteAllowedHosts restricts remote clones to these hosts.
	RemoteAllowedHosts *[]string `json:"remote_allowed_hosts,omitempty"`
	// WorkspaceRetentionDays is the workspace sweep horizon, 0 = forever.
	// It is the only path that may shorten a node's retention. No sweep
	// runs in this build (the value is carried, nothing is deleted); a
	// sweep that consumes it must never delete an unreturned workspace.
	WorkspaceRetentionDays *int `json:"workspace_retention_days,omitempty"`
	// MaskPaths are extra paths masked inside the sandbox.
	MaskPaths *[]string `json:"mask_paths,omitempty"`
	// PrepTimeoutSeconds bounds workspace preparation, 30 to 3600.
	PrepTimeoutSeconds *int `json:"prep_timeout_seconds,omitempty"`
	// Node carries this node's own path overrides (the per-node panel on
	// the node's detail page). The server fills it per caller.
	Node *SandboxManagedNodeV1 `json:"node,omitempty"`
	// HostedE2B is an org-published E2B endpoint (lane SBX-UPD, ledger
	// SBX-GOV-2, sandbox plan v2 section 5.7): DATA only. It never enables
	// the E2B row (the node's own backends list and per-provider consent
	// still decide), never carries a credential (SBX-GOV-4: a credential is
	// sent there only when the developer connected one for this origin),
	// and is shown on the consent screen. The server serves it only to a
	// node that advertised SandboxCapabilityE2BEndpoint (the body is closed,
	// so an older node would refuse the whole body for it).
	HostedE2B *SandboxManagedE2BV1 `json:"hosted_e2b,omitempty"`
	// InstallScripts is the org's floor on the container sandboxes'
	// first-start install scripts (lane LEFT-SBX, operator ruling P-136):
	// its mode can only lower the node's ("none" forbids every package
	// script), a non-empty tool list narrows the node's to the tools in
	// both, and its signed pins are extra reviewed scripts a managed node
	// accepts. It never turns install_cache on. Served only to a node that
	// advertised SandboxCapabilityInstallScripts (the body is closed, so an
	// older node would refuse the whole body for it); an older server never
	// sends it and a newer node then keeps its own policy.
	InstallScripts *SandboxManagedInstallScriptsV1 `json:"install_scripts,omitempty"`
	// SignInSeedForbidden, when true, forbids copying a tool's sign-in into
	// a sandboxed run's box on a managed node (lane BOXSIGNIN, ruling P-180
	// (6) 6): lowering only. It beats the developer's own remembered or
	// per-launch consent and the refusal names it; false or absent leaves
	// the node's own choice. It can never turn seeding on, and carries no
	// file name or value. Served only to a node that advertised
	// SandboxCapabilitySignInSeedForbid (the body is closed, so an older
	// node would refuse the whole body for it).
	SignInSeedForbidden *bool `json:"sign_in_seed_forbidden,omitempty"`
	// OrgOpenShell is the org-hosted OpenShell gateway (tracker F-019,
	// openshellorg.go): DATA only, built by the server per caller, served
	// only to a node that advertised SandboxCapabilityOrgOpenShell.
	OrgOpenShell *SandboxManagedOrgOpenShellV1 `json:"org_openshell,omitempty"`
}

// SandboxCapabilitySignInSeedForbid is the token a node sends when it
// applies sign_in_seed_forbidden on the sandbox rail.
const SandboxCapabilitySignInSeedForbid = "sandbox.sign_in_seed_forbid"

// SandboxSignInSeedForCaller is a sandbox body as served to one caller:
// unchanged when the caller advertised SandboxCapabilitySignInSeedForbid,
// else without sign_in_seed_forbidden. Pure.
func SandboxSignInSeedForCaller(p SandboxManagedPolicyV1, caps []string) SandboxManagedPolicyV1 {
	if p.SignInSeedForbidden == nil || slices.Contains(caps, SandboxCapabilitySignInSeedForbid) {
		return p
	}
	p.SignInSeedForbidden = nil
	return p
}

// SandboxManagedInstallScriptsV1 is the org's install-script floor.
type SandboxManagedInstallScriptsV1 struct {
	// Mode is "none" or "pinned" ("" leaves the node's mode).
	Mode string `json:"mode,omitempty"`
	// Tools are install-source tool ids; empty leaves the node's list.
	Tools []string `json:"tools,omitempty"`
	// Pins are the org's reviewed scripts: a tool, a package version and
	// the script file's sha256, with an optional note shown with the pin.
	Pins []SandboxManagedScriptPinV1 `json:"pins,omitempty"`
}

// SandboxManagedScriptPinV1 is one org-published install script pin.
type SandboxManagedScriptPinV1 struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Note    string `json:"note,omitempty"`
	// Packages pin what the install fetches by the registry's sha512
	// integrity (R-014, ruling P-142): for a tool whose install script
	// fetches more packages, the main package and every platform package.
	// A node runs such a tool's script under this pin only when they are
	// set.
	Packages []SandboxManagedPackagePinV1 `json:"packages,omitempty"`
}

// SandboxManagedPackagePinV1 is one fetched npm artifact pinned by its
// registry integrity value.
type SandboxManagedPackagePinV1 struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Integrity string `json:"integrity"`
}

// SandboxCapabilityInstallScripts is the token a node sends when it applies
// install_scripts on the sandbox rail.
const SandboxCapabilityInstallScripts = "sandbox.install_scripts"

// The install_scripts bounds.
const (
	sandboxInstallScriptsMaxTools = 64
	sandboxInstallScriptsMaxPins  = 256
	sandboxInstallScriptNoteMax   = 200
	sandboxInstallPinMaxPackages  = 64
)

// The install_scripts shapes (the node's sandboxoci rules, restated: this
// package does not import the sandbox module).
var (
	sandboxScriptToolRE    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	sandboxScriptVersionRE = regexp.MustCompile(`^[0-9]{1,9}\.[0-9]{1,9}\.[0-9]{1,9}([-+][0-9A-Za-z][0-9A-Za-z.-]{0,40})?$`)
	sandboxScriptSHA256RE  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	sandboxScriptPackageRE = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._-]{0,100}/)?[a-z0-9][a-z0-9._-]{0,100}$`)
	sandboxScriptIntegrity = regexp.MustCompile(`^sha512-[A-Za-z0-9+/]{86}==$`)
)

// SandboxInstallScriptsForCaller is a sandbox body as served to one caller:
// unchanged when the caller advertised SandboxCapabilityInstallScripts,
// else without install_scripts. Pure.
func SandboxInstallScriptsForCaller(p SandboxManagedPolicyV1, caps []string) SandboxManagedPolicyV1 {
	if p.InstallScripts == nil || slices.Contains(caps, SandboxCapabilityInstallScripts) {
		return p
	}
	p.InstallScripts = nil
	return p
}

// validate checks the install_scripts floor.
func (s SandboxManagedInstallScriptsV1) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrSandboxManagedBody}, a...)...)
	}
	switch s.Mode {
	case "", "none", "pinned":
	default:
		return bad("install_scripts.mode %q not in {none, pinned}", s.Mode)
	}
	if len(s.Tools) > sandboxInstallScriptsMaxTools {
		return bad("install_scripts.tools holds more than %d tools", sandboxInstallScriptsMaxTools)
	}
	for _, t := range s.Tools {
		if !sandboxScriptToolRE.MatchString(t) {
			return bad("install_scripts.tools entry %q is not a tool id", t)
		}
	}
	if len(s.Pins) > sandboxInstallScriptsMaxPins {
		return bad("install_scripts.pins holds more than %d pins", sandboxInstallScriptsMaxPins)
	}
	for i, pin := range s.Pins {
		switch {
		case !sandboxScriptToolRE.MatchString(pin.Tool):
			return bad("install_scripts.pins[%d].tool %q is not a tool id", i, pin.Tool)
		case !sandboxScriptVersionRE.MatchString(pin.Version):
			return bad("install_scripts.pins[%d].version %q is not a plain package version", i, pin.Version)
		case !sandboxScriptSHA256RE.MatchString(pin.SHA256):
			return bad("install_scripts.pins[%d].sha256 is not 64 lowercase hex characters", i)
		case len(pin.Note) > sandboxInstallScriptNoteMax || strings.ContainsFunc(pin.Note, unicode.IsControl):
			return bad("install_scripts.pins[%d].note is over %d characters or holds a control character", i, sandboxInstallScriptNoteMax)
		case len(pin.Packages) > sandboxInstallPinMaxPackages:
			return bad("install_scripts.pins[%d].packages holds more than %d packages", i, sandboxInstallPinMaxPackages)
		}
		for j, pk := range pin.Packages {
			switch {
			case !sandboxScriptPackageRE.MatchString(pk.Name):
				return bad("install_scripts.pins[%d].packages[%d].name %q is not a package name", i, j, pk.Name)
			case !sandboxScriptVersionRE.MatchString(pk.Version):
				return bad("install_scripts.pins[%d].packages[%d].version %q is not a plain package version", i, j, pk.Version)
			case !sandboxScriptIntegrity.MatchString(pk.Integrity):
				return bad("install_scripts.pins[%d].packages[%d].integrity is not a registry sha512 value", i, j)
			}
		}
	}
	return nil
}

// SandboxManagedE2BV1 is an org-published E2B endpoint: an https origin
// (scheme and host, an optional port, nothing else), an optional pin of the
// server's public key (the SHA-256 of its SubjectPublicKeyInfo, lowercase
// hex) for a self-hosted endpoint, and an optional template name.
type SandboxManagedE2BV1 struct {
	Origin     string `json:"origin"`
	SPKISHA256 string `json:"spki_sha256,omitempty"`
	Template   string `json:"template,omitempty"`
}

// SandboxCapabilityE2BEndpoint is the token a node sends when it applies
// hosted_e2b on the sandbox rail.
const SandboxCapabilityE2BEndpoint = "sandbox.hosted_e2b_endpoint"

// SandboxE2BForCaller is a sandbox body as served to one caller: unchanged
// when the caller advertised SandboxCapabilityE2BEndpoint, else without
// hosted_e2b. Pure.
func SandboxE2BForCaller(p SandboxManagedPolicyV1, caps []string) SandboxManagedPolicyV1 {
	if p.HostedE2B == nil {
		return p
	}
	for _, c := range caps {
		if c == SandboxCapabilityE2BEndpoint {
			return p
		}
	}
	p.HostedE2B = nil
	return p
}

// ValidE2BOrigin reports whether s is an https origin: scheme https, a host,
// an optional port, and no user, path, query or fragment.
func ValidE2BOrigin(s string) bool {
	if s == "" || len(s) > 256 || strings.ContainsAny(s, " \t\r\n") {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	if u.Path != "" && u.Path != "/" {
		return false
	}
	return validManagedHost(strings.ToLower(u.Hostname()))
}

// validSPKIPin is 64 lowercase hex characters.
func validSPKIPin(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

// validTemplateName is a vendor template name: letters, digits, dashes,
// underscores, dots, slashes and colons, at most 128.
func validTemplateName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for _, r := range s {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && !strings.ContainsRune("-_./:", r) {
			return false
		}
	}
	return true
}

// SandboxManagedNodeV1 is one node's path overrides. The node validates each
// exactly like a local value (the bind-plan rules) and refuses one it cannot
// use, with a reason the admin sees on the node's detail page. It carries no
// workspaces_dir: the managed-workspace root is the one termsvc, the capture
// relay and the runtime must agree on for the daemon's life, built before the
// managed body is primed, so it stays the developer's own (SBX-P1C merge
// finding 3).
type SandboxManagedNodeV1 struct {
	ExtraROBinds *[]string `json:"extra_ro_binds,omitempty"`
	ExtraRWBinds *[]string `json:"extra_rw_binds,omitempty"`
	// SkipRepoScan lists write binds the org asserts hold no repositories
	// (ruling P-060, ledger SBX-GOV-3): the node skips its walk for
	// repositories below each one (the bind itself is still checked), so
	// a very large cache bind does not hit the walk's budget. Each entry
	// must equal an extra_rw_binds entry. A parallel list rather than an
	// object per bind, so extra_rw_binds stays a string list. The server
	// serves it only to a node that advertised
	// SandboxCapabilitySkipRepoScan on its pull: the body is closed, so an
	// older node would refuse the whole body for this one field.
	SkipRepoScan *[]string `json:"skip_repo_scan,omitempty"`
}

// ManagedPullCapabilitiesHeader is the request header a node's managed pull
// names the optional body fields it can apply with: a comma-separated list
// of capability tokens, each rail reading its own. A body field a node did
// not advertise is never served to it (every body is closed, so an older
// node refuses a body carrying a field it does not know), and an older
// server ignores the header, so neither side needs the other's version.
const ManagedPullCapabilitiesHeader = "X-Observer-Pull-Capabilities"

// SandboxCapabilitySkipRepoScan is the token a node sends when it applies
// node.skip_repo_scan on the sandbox rail.
const SandboxCapabilitySkipRepoScan = "sandbox.skip_repo_scan"

// ParseManagedPullCapabilities reads the header's value: tokens are trimmed,
// empty and over-long ones dropped, at most 32 kept, duplicates once.
func ParseManagedPullCapabilities(v string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range strings.Split(v, ",") {
		t = strings.TrimSpace(t)
		if t == "" || len(t) > 64 || seen[t] || len(out) >= 32 {
			continue
		}
		seen[t] = true
		out = append(out, t)
	}
	return out
}

// SandboxSkipRepoScanForCaller is the node part of a sandbox body as served
// to one caller: unchanged when the caller advertised
// SandboxCapabilitySkipRepoScan, else without skip_repo_scan (and nil when
// nothing else is left). Pure.
func SandboxSkipRepoScanForCaller(n *SandboxManagedNodeV1, caps []string) *SandboxManagedNodeV1 {
	if n == nil || n.SkipRepoScan == nil {
		return n
	}
	for _, c := range caps {
		if c == SandboxCapabilitySkipRepoScan {
			return n
		}
	}
	out := *n
	out.SkipRepoScan = nil
	if out.ExtraROBinds == nil && out.ExtraRWBinds == nil {
		return nil
	}
	return &out
}

// Sandbox managed-body bounds.
const (
	sandboxManagedMaxList   = 64
	sandboxManagedMaxString = 1024
	// SandboxManagedPrepTimeoutMin / Max bound prep_timeout_seconds.
	SandboxManagedPrepTimeoutMin = 30
	SandboxManagedPrepTimeoutMax = 3600
	// SandboxManagedRetentionMax bounds workspace_retention_days (ten years).
	SandboxManagedRetentionMax = 3650
)

// SandboxManagedEgressTiers is the closed set of tiers the body may set.
func SandboxManagedEgressTiers() []string { return []string{"host", "internet", "proxy_only"} }

// ErrSandboxManagedBody is a body that does not decode or validate.
var ErrSandboxManagedBody = errors.New("orgcontract: sandbox managed body refused")

// SandboxManagedRefusal is why a key is refused by name.
type SandboxManagedRefusal string

// The refusal reasons a forbidden key carries.
const (
	SandboxRefusedCaptureLosing   SandboxManagedRefusal = "capture_losing_mode"
	SandboxRefusedCredentialValue SandboxManagedRefusal = "credential_value" //nolint:gosec // a refusal reason name, not a credential
	// SandboxRefusedNotOnPull is a [terminal.sandbox] key that stays the
	// developer's own (workspaces_dir).
	SandboxRefusedNotOnPull SandboxManagedRefusal = "not_on_the_pull"
	// SandboxRefusedSkipScanNotABind is a skip_repo_scan entry that names
	// no extra_rw_binds entry.
	SandboxRefusedSkipScanNotABind SandboxManagedRefusal = "skip_repo_scan_not_a_write_bind"
)

// sandboxManagedForbidden is the closed table of keys refused by name at any
// level of the body, with the reason. They are not fields of the body, so
// DisallowUnknownFields would refuse them anyway; naming them makes the
// reason the admin reads exact and pins the rule with a test.
var sandboxManagedForbidden = map[string]SandboxManagedRefusal{
	"allow_reduced_capture":  SandboxRefusedCaptureLosing,
	"capture":                SandboxRefusedCaptureLosing,
	"provider_injected":      SandboxRefusedCaptureLosing,
	"provider_key_injection": SandboxRefusedCaptureLosing,
	"key_custody":            SandboxRefusedCaptureLosing,
	"credential":             SandboxRefusedCredentialValue,
	"credentials":            SandboxRefusedCredentialValue,
	"password":               SandboxRefusedCredentialValue,
	"secret":                 SandboxRefusedCredentialValue,
	"token":                  SandboxRefusedCredentialValue,
	"api_key":                SandboxRefusedCredentialValue,
	"private_key":            SandboxRefusedCredentialValue,
	"kubeconfig":             SandboxRefusedCredentialValue,
	"workspaces_dir":         SandboxRefusedNotOnPull,
}

// DecodeSandboxManagedPolicy decodes and validates a body strictly. A signed
// empty body never reaches it (the kit clears on it before any module sees
// it).
func DecodeSandboxManagedPolicy(raw []byte) (SandboxManagedPolicyV1, error) {
	var p SandboxManagedPolicyV1
	if len(raw) > maxManagedPullBodyBytes {
		return p, fmt.Errorf("%w: body is larger than %d bytes", ErrSandboxManagedBody, maxManagedPullBodyBytes)
	}
	if err := refuseForbiddenSandboxKeys(raw); err != nil {
		return p, err
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return SandboxManagedPolicyV1{}, fmt.Errorf("%w: %w", ErrSandboxManagedBody, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return SandboxManagedPolicyV1{}, fmt.Errorf("%w: trailing data after the body", ErrSandboxManagedBody)
	}
	if err := p.Validate(); err != nil {
		return SandboxManagedPolicyV1{}, err
	}
	return p, nil
}

// maxManagedPullBodyBytes bounds a body (the document bound is 1 MiB).
const maxManagedPullBodyBytes = 256 << 10

// refuseForbiddenSandboxKeys walks every object of the body and refuses a
// forbidden key by name, whatever its case.
func refuseForbiddenSandboxKeys(raw []byte) error {
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return fmt.Errorf("%w: %w", ErrSandboxManagedBody, err)
	}
	var walk func(any) error
	walk = func(n any) error {
		switch t := n.(type) {
		case map[string]any:
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				if why, bad := sandboxManagedForbidden[strings.ToLower(k)]; bad {
					return fmt.Errorf("%w: %q is never settable remotely (%s)", ErrSandboxManagedBody, k, why)
				}
				if err := walk(t[k]); err != nil {
					return err
				}
			}
		case []any:
			for _, e := range t {
				if err := walk(e); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return walk(v)
}

// Validate checks the body's closed vocabulary and bounds. It is structural:
// the node re-checks every value the way it checks a local one (CIDR ranges,
// path symlinks) when it composes the body onto its config.
func (p SandboxManagedPolicyV1) Validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrSandboxManagedBody}, a...)...)
	}
	if p.Schema != SandboxManagedSchema {
		return bad("schema %q is not %q", p.Schema, SandboxManagedSchema)
	}
	if p.Backends != nil {
		if err := checkList("backends", *p.Backends, validManagedBackendID); err != nil {
			return err
		}
	}
	if p.Egress != nil {
		ok := false
		for _, t := range SandboxManagedEgressTiers() {
			ok = ok || *p.Egress == t
		}
		if !ok {
			return bad("egress %q not in {%s} (\"none\" loses capture and is never set remotely)", *p.Egress, strings.Join(SandboxManagedEgressTiers(), ", "))
		}
	}
	if p.EgressAllowCIDRs != nil {
		if err := checkList("egress_allow_cidrs", *p.EgressAllowCIDRs, func(s string) bool {
			pre, err := netip.ParsePrefix(s)
			return err == nil && pre.Masked() == pre && pre.String() == s
		}); err != nil {
			return err
		}
	}
	if p.RemoteAllowedHosts != nil {
		if err := checkList("remote_allowed_hosts", *p.RemoteAllowedHosts, validManagedHost); err != nil {
			return err
		}
	}
	if p.WorkspaceRetentionDays != nil && (*p.WorkspaceRetentionDays < 0 || *p.WorkspaceRetentionDays > SandboxManagedRetentionMax) {
		return bad("workspace_retention_days %d not in 0 to %d", *p.WorkspaceRetentionDays, SandboxManagedRetentionMax)
	}
	if p.PrepTimeoutSeconds != nil && (*p.PrepTimeoutSeconds < SandboxManagedPrepTimeoutMin || *p.PrepTimeoutSeconds > SandboxManagedPrepTimeoutMax) {
		return bad("prep_timeout_seconds %d not in %d to %d", *p.PrepTimeoutSeconds, SandboxManagedPrepTimeoutMin, SandboxManagedPrepTimeoutMax)
	}
	if p.MaskPaths != nil {
		if err := checkList("mask_paths", *p.MaskPaths, validManagedPath); err != nil {
			return err
		}
	}
	if p.Node != nil {
		if err := p.Node.validate(); err != nil {
			return err
		}
	}
	if e := p.HostedE2B; e != nil {
		if err := e.validate(); err != nil {
			return err
		}
	}
	if s := p.InstallScripts; s != nil {
		if err := s.validate(); err != nil {
			return err
		}
	}
	if o := p.OrgOpenShell; o != nil {
		if err := o.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validate checks an org-published E2B endpoint: an https origin, and a
// well-formed SPKI pin and template name when set.
func (e *SandboxManagedE2BV1) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrSandboxManagedBody}, a...)...)
	}
	if !ValidE2BOrigin(e.Origin) {
		return bad("hosted_e2b.origin %q is not an https origin (scheme, host and port only)", e.Origin)
	}
	if e.SPKISHA256 != "" && !validSPKIPin(e.SPKISHA256) {
		return bad("hosted_e2b.spki_sha256 is not 64 lowercase hex characters")
	}
	if e.Template != "" && !validTemplateName(e.Template) {
		return bad("hosted_e2b.template %q is not a template name", e.Template)
	}
	return nil
}

// validate checks one node's per-node values (Validate's node part).
func (n SandboxManagedNodeV1) validate() error {
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%w: "+format, append([]any{ErrSandboxManagedBody}, a...)...)
	}
	if n.ExtraROBinds != nil {
		if err := checkList("node.extra_ro_binds", *n.ExtraROBinds, validManagedPath); err != nil {
			return err
		}
	}
	if n.ExtraRWBinds != nil {
		// The publish lint of the bind decision (sandboxbinds.go): the
		// server has no real home, so the home-shaped spellings stand
		// for one; the node checks again with its own.
		for _, e := range *n.ExtraRWBinds {
			if SandboxSensitiveWriteBind(e, SandboxBindHost{}) {
				return bad("node.extra_rw_binds entry %q is a sensitive host location and is never bound read-write remotely (%s)", e, SandboxRefusedSensitivePath)
			}
		}
		if err := checkList("node.extra_rw_binds", *n.ExtraRWBinds, validManagedPath); err != nil {
			return err
		}
	}
	if n.SkipRepoScan != nil {
		if err := checkList("node.skip_repo_scan", *n.SkipRepoScan, validManagedPath); err != nil {
			return err
		}
		rw := map[string]bool{}
		if n.ExtraRWBinds != nil {
			for _, e := range *n.ExtraRWBinds {
				rw[e] = true
			}
		}
		for _, e := range *n.SkipRepoScan {
			if !rw[e] {
				return bad("node.skip_repo_scan entry %q is not one of node.extra_rw_binds (%s)", e, SandboxRefusedSkipScanNotABind)
			}
		}
	}
	return nil
}

func checkList(name string, list []string, ok func(string) bool) error {
	if len(list) > sandboxManagedMaxList {
		return fieldErr(name, FieldClassTooMany, "%s has more than %d entries", name, sandboxManagedMaxList)
	}
	seen := map[string]bool{}
	for _, e := range list {
		if len(e) > sandboxManagedMaxString || !ok(e) {
			return fieldErr(name, FieldClassInvalid, "%s entry %q is not valid", name, e)
		}
		if seen[e] {
			return fieldErr(name, FieldClassDuplicate, "%s lists %q twice", name, e)
		}
		seen[e] = true
	}
	return nil
}

// validManagedBackendID is the registry id shape, the one rule
// [terminal.sandbox].backends obeys too (sandboxvocab.ValidBackendID: lower-
// case letters, digits, dashes and underscores, so process_lite passes).
func validManagedBackendID(id string) bool { return sandboxvocab.ValidBackendID(id) }

// validManagedHost is a bare host name: lower-case letters, digits, dots and
// dashes. No scheme, port, user or path, so nothing that could carry a
// credential rides in it.
func validManagedHost(h string) bool {
	if h == "" || len(h) > 253 || strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") || strings.Contains(h, "..") {
		return false
	}
	for _, r := range h {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

// validManagedPath is an absolute, clean, slash-separated path with no NUL.
// Whether it exists, is a symlink or is allowed on this host is the node's
// check, the same one a local value gets.
func validManagedPath(p string) bool {
	if p == "" || strings.ContainsRune(p, 0) || !strings.HasPrefix(p, "/") || strings.Contains(p, "\\") {
		return false
	}
	return path.Clean(p) == p
}

// MarshalSandboxManagedPolicy is the one canonical encoding of a body (the
// server's sign-at-serve input), validated first.
func MarshalSandboxManagedPolicy(p SandboxManagedPolicyV1) ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(p)
}
