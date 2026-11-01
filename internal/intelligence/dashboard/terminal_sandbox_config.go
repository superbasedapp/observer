package dashboard

import (
	"fmt"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/integration"
)

// terminalSandboxConfigPayload is the dashboard read/write shape of
// [terminal.sandbox]. It deliberately mirrors the complete v1 config block so
// the UI never has to hide an authority-expanding escape hatch in a raw TOML
// file. The route carrying it is owner-local and confirm-token-gated.
type terminalSandboxConfigPayload struct {
	Enabled                bool     `json:"enabled"`
	Backend                string   `json:"backend"`
	HomeMode               string   `json:"home_mode"`
	DefaultOn              bool     `json:"default_on"`
	AllowRemoteClone       bool     `json:"allow_remote_clone"`
	RemoteAllowedHosts     []string `json:"remote_allowed_hosts"`
	AllowWorktreeSource    bool     `json:"allow_worktree_source"`
	WorkspacesDir          string   `json:"workspaces_dir"`
	WorkspaceRetentionDays int      `json:"workspace_retention_days"`
	MaskPaths              []string `json:"mask_paths"`
	ExtraROBinds           []string `json:"extra_ro_binds"`
	ExtraRWBinds           []string `json:"extra_rw_binds"`
	PrepTimeoutSeconds     int      `json:"prep_timeout_seconds"`
	// Egress and AllowToolConfigWrites are pointers so a client that
	// predates them (and so omits them) KEEPS the saved values instead of
	// resetting them on every save.
	Egress                *string `json:"egress,omitempty"`
	AllowToolConfigWrites *bool   `json:"allow_tool_config_writes,omitempty"`
	// EgressAllowCIDRs is a pointer for the same reason: a client that
	// predates the private-destination allow-list keeps the saved list.
	EgressAllowCIDRs *[]string `json:"egress_allow_cidrs,omitempty"`
	// EgressAllowHosts is the agent-run host allow-list (lane LEFT-SBX), a
	// pointer for the same reason.
	EgressAllowHosts *[]string `json:"egress_allow_hosts,omitempty"`
	// PassEnv names the extra variables a sandboxed agent may receive
	// (WINFIX2 R-167), a pointer for the same reason.
	PassEnv *[]string `json:"pass_env,omitempty"`
	// SignInSeedTools are the tools whose sign-in a sandboxed run copies
	// without asking (lane BOXSIGNIN, local-only), a pointer for the same
	// reason. SignInSeedCatalog (read-only, ignored on a save) lists the
	// tools with a grounded sign-in file, for the picker; SignInSeedForbidden
	// (read-only) says the organization forbids seeding, read from the
	// composed managed view (Options.SandboxSignInForbidden).
	SignInSeedTools     *[]string `json:"sign_in_seed_tools,omitempty"`
	SignInSeedCatalog   []string  `json:"sign_in_seed_catalog,omitempty"`
	SignInSeedForbidden bool      `json:"sign_in_seed_forbidden,omitempty"`
	// AllowOSC52Clipboard lets a sandboxed tool's OSC 52 clipboard
	// sequences reach the terminal (ruling P-175; default off), a pointer
	// for the same reason.
	AllowOSC52Clipboard *bool `json:"allow_osc52_clipboard,omitempty"`
	// Backends (the preference order) and MinIsolation (the local floor),
	// sandbox plan v2 section 10, are pointers for the same reason.
	Backends *[]string `json:"backends,omitempty"`
	// LiveRunUpdatePolicy (lane SBX-UPD) is a pointer for the same reason:
	// how soon a deferred update asks about live sandboxed runs.
	LiveRunUpdatePolicy *string `json:"live_run_update_policy,omitempty"`
	MinIsolation        *string `json:"min_isolation,omitempty"`
	// OCI is [terminal.sandbox.oci], the container driver (lane SBX-P3A);
	// a pointer for the same reason: an older client keeps the saved block.
	OCI *terminalSandboxOCIPayload `json:"oci,omitempty"`
	// MXC is [terminal.sandbox.mxc], the Windows driver (lane SBX-P6); a
	// pointer for the same reason.
	MXC *terminalSandboxMXCPayload `json:"mxc,omitempty"`
	// Seatbelt and AppleContainer are the macOS drivers' blocks (lane
	// SBX-P5, beta); pointers for the same reason.
	Seatbelt       *terminalSandboxSeatbeltPayload       `json:"seatbelt,omitempty"`
	AppleContainer *terminalSandboxAppleContainerPayload `json:"apple_container,omitempty"`
	// Landlock is the Landlock-only row's block (lane SBX-P3B, beta); a
	// pointer for the same reason.
	Landlock *terminalSandboxLandlockPayload `json:"landlock,omitempty"`
	// Hosted is [terminal.sandbox.hosted], the hosted rows' shared block
	// (lane SBX-P7, beta); a pointer for the same reason.
	Hosted *terminalSandboxHostedPayload `json:"hosted,omitempty"`
	// VendorForcedNative is [terminal.sandbox].vendor_forced_native (lane
	// SBX-P3D, the native panel); a pointer for the same reason.
	VendorForcedNative *string `json:"vendor_forced_native,omitempty"`
}

// terminalSandboxLandlockPayload is the dashboard shape of
// [terminal.sandbox.landlock].
type terminalSandboxLandlockPayload struct {
	MinABI int `json:"min_abi"`
}

// terminalSandboxHostedPayload is the dashboard shape of
// [terminal.sandbox.hosted]. No credential is ever part of it.
type terminalSandboxHostedPayload struct {
	MinSessionMinutes int    `json:"min_session_minutes"`
	KeyCustody        string `json:"key_custody"`
	MemoryImages      string `json:"memory_images"`
	CheckpointMinutes int    `json:"checkpoint_minutes"`
	MaxRunMinutes     int    `json:"max_run_minutes"`
	DailyBoxMinutes   int    `json:"daily_box_minutes"`
	// DBExport (the opt-in in-box database export, ruling P-141) is a
	// pointer so a client that predates it keeps the saved value.
	DBExport *bool                 `json:"db_export,omitempty"`
	E2B      hostedProviderPayload `json:"e2b"`
	Modal    hostedProviderPayload `json:"modal"`
	Vercel   hostedProviderPayload `json:"vercel"`
}

// hostedProviderPayload is one provider's table.
type hostedProviderPayload struct {
	Region    string `json:"region"`
	Template  string `json:"template"`
	BoxBinary string `json:"box_binary"`
	// Endpoint and EndpointSPKISHA256 (E2B only, lane SBX-UPD) are
	// pointers so a client that predates them keeps the saved values.
	Endpoint           *string `json:"endpoint,omitempty"`
	EndpointSPKISHA256 *string `json:"endpoint_spki_sha256,omitempty"`
}

func hostedProviderToPayload(c config.TerminalSandboxHostedProviderConfig) hostedProviderPayload {
	ep, spki := c.Endpoint, c.EndpointSPKISHA256
	return hostedProviderPayload{Region: c.Region, Template: c.Template, BoxBinary: c.BoxBinary, Endpoint: &ep, EndpointSPKISHA256: &spki}
}

// keepHostedEndpoints puts the saved endpoint keys back on a provider table
// whose payload omitted them (a client that predates them).
func keepHostedEndpoints(next *config.TerminalSandboxHostedProviderConfig, sent hostedProviderPayload, saved config.TerminalSandboxHostedProviderConfig) {
	if sent.Endpoint == nil {
		next.Endpoint = saved.Endpoint
	}
	if sent.EndpointSPKISHA256 == nil {
		next.EndpointSPKISHA256 = saved.EndpointSPKISHA256
	}
}

// terminalSandboxSeatbeltPayload is the dashboard shape of
// [terminal.sandbox.seatbelt].
type terminalSandboxSeatbeltPayload struct {
	AllowKeychain bool `json:"allow_keychain"`
	// Driver (lane SBX-UPD): "" means sandbox-exec.
	Driver string `json:"driver,omitempty"`
}

// terminalSandboxAppleContainerPayload is the dashboard shape of
// [terminal.sandbox.apple_container].
type terminalSandboxAppleContainerPayload struct {
	Image     string `json:"image"`
	MemoryMiB int    `json:"memory_mib"`
	CPUs      int    `json:"cpus"`
}

// terminalSandboxMXCPayload is the dashboard shape of [terminal.sandbox.mxc].
type terminalSandboxMXCPayload struct {
	StopGraceSeconds    int `json:"stop_grace_seconds"`
	ProbeTimeoutSeconds int `json:"probe_timeout_seconds"`
}

// terminalSandboxOCIPayload is the dashboard shape of [terminal.sandbox.oci].
type terminalSandboxOCIPayload struct {
	AllowRootful           bool   `json:"allow_rootful"`
	Socket                 string `json:"socket"`
	Image                  string `json:"image"`
	PodmanUserns           string `json:"podman_userns"`
	StopGraceSeconds       int    `json:"stop_grace_seconds"`
	AllowDevcontainerImage bool   `json:"allow_devcontainer_image"`
	InstallCache           bool   `json:"install_cache"`
	// The first-start install-script allowance and version picker (lane
	// LEFT-SBX, ruling P-136). Optional so an older dashboard's PUT (no
	// key) keeps the file's values.
	InstallScripts      *string                               `json:"install_scripts,omitempty"`
	InstallScriptsTools *[]string                             `json:"install_scripts_tools,omitempty"`
	InstallScriptPins   *[]config.TerminalSandboxOCIScriptPin `json:"install_script_pins,omitempty"`
	InstallVersions     *map[string]string                    `json:"install_versions,omitempty"`
	// InstallCatalog is read-only (GET): the install-source tools the
	// pickers offer, each with its built-in script pins.
	InstallCatalog []terminalSandboxInstallCatalogRow `json:"install_catalog,omitempty"`
}

// terminalSandboxInstallCatalogRow is one install-source tool as the Card's
// pickers show it.
type terminalSandboxInstallCatalogRow struct {
	Tool         string                             `json:"tool"`
	Package      string                             `json:"package"`
	Kind         string                             `json:"kind"`
	NeedsScripts bool                               `json:"needs_scripts"`
	DocURL       string                             `json:"doc_url"`
	BuiltinPins  []terminalSandboxInstallBuiltinPin `json:"builtin_pins"`
	// FetchesPackages says the tool's install script installs more
	// packages, so a pin counts only with their registry integrity values
	// (R-014, ruling P-142); the Card then asks for them.
	FetchesPackages bool `json:"script_fetches_packages"`
}

// terminalSandboxInstallBuiltinPin is one script pin Observer ships.
type terminalSandboxInstallBuiltinPin struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	File      string `json:"file"`
	Grounding string `json:"grounding"`
	// Packages counts the fetched artifacts the pin names by integrity.
	Packages int `json:"packages"`
}

// terminalSandboxInstallCatalog is the install-source catalog for the
// Card's pickers (never free text).
func terminalSandboxInstallCatalog() []terminalSandboxInstallCatalogRow {
	var out []terminalSandboxInstallCatalogRow
	for _, src := range integration.InstallSources() {
		row := terminalSandboxInstallCatalogRow{Tool: src.Tool, Package: src.Package, Kind: string(src.Kind), NeedsScripts: src.NeedsInstallScripts, DocURL: src.DocURL, BuiltinPins: []terminalSandboxInstallBuiltinPin{}, FetchesPackages: src.ScriptFetchesPackages}
		for _, p := range src.ScriptPins {
			row.BuiltinPins = append(row.BuiltinPins, terminalSandboxInstallBuiltinPin{Version: p.Version, SHA256: p.SHA256, File: p.File, Grounding: p.Grounding, Packages: len(p.Packages)})
		}
		out = append(out, row)
	}
	return out
}

// handleTerminalSandboxConfig serves GET/PUT
// /api/terminal/sandbox/config. The probe endpoint at /api/terminal/sandbox
// remains a read-only report of the RUNNING daemon; this route edits the
// on-disk config that binds on the next restart.
func (s *Server) handleTerminalSandboxConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleTerminalSandboxConfigGet(w, r)
	case http.MethodPut:
		s.handleTerminalSandboxConfigPut(w, r)
	default:
		http.Error(w, "GET or PUT only", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTerminalSandboxConfigGet(w http.ResponseWriter, r *http.Request) {
	confirmTok := setConfirmCookie(w, r)
	// The base a save sends back as ?base_etag= (T-639).
	etag, _ := configEtag(s.opts.ConfigPath)
	cfg, err := loadConfigForDashboard(s.opts.ConfigPath)
	if err != nil {
		writeErr(w, fmt.Errorf("load sandbox config: %w", err))
		return
	}
	p := sandboxConfigPayload(cfg.Terminal.Sandbox)
	// The org's forbid lives in the composed managed view, never in the
	// file (lane BOXSIGNIN, audit finding 3).
	if s.opts.SandboxSignInForbidden != nil && s.opts.SandboxSignInForbidden() {
		p.SignInSeedForbidden = true
	}
	writeJSON(w, map[string]any{
		"config_etag":              etag,
		"confirm_token":            confirmTok,
		"config_writable":          s.opts.ConfigPath != "",
		"restart_required_on_save": true,
		"sandbox":                  p,
	})
}

func (s *Server) handleTerminalSandboxConfigPut(w http.ResponseWriter, r *http.Request) {
	if !requireJSONConfirm(w, r) {
		return
	}
	if s.opts.ConfigPath == "" {
		http.Error(w, "config path not configured - server has no file to save to", http.StatusConflict)
		return
	}
	var body terminalSandboxConfigPayload
	if err := decodeJSONBody(r, &body); err != nil {
		http.Error(w, "decode terminal sandbox config: "+err.Error(), http.StatusBadRequest)
		return
	}

	next, err := normalizedSandboxConfig(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The ONE save pipeline (T-572): the established remoteManageMu ->
	// configWriteMu lock domain, `?dry_run=1` previews the masked diff and
	// writes nothing, `?base_etag=` refuses a file changed since that
	// preview, and the write is validated, read back and audited like every
	// section save.
	s.commitConfigEdit(w, r, configEdit{
		section: "terminal.sandbox",
		apply: func(cfg *config.Config) {
			// Omitted optional fields keep their saved value (see the payload).
			if body.Egress == nil {
				next.Egress = cfg.Terminal.Sandbox.Egress
			}
			if body.AllowToolConfigWrites == nil {
				next.AllowToolConfigWrites = cfg.Terminal.Sandbox.AllowToolConfigWrites
			}
			if body.EgressAllowCIDRs == nil {
				next.EgressAllowCIDRs = cfg.Terminal.Sandbox.EgressAllowCIDRs
			}
			if body.EgressAllowHosts == nil {
				next.EgressAllowHosts = cfg.Terminal.Sandbox.EgressAllowHosts
			}
			if body.PassEnv == nil {
				next.PassEnv = cfg.Terminal.Sandbox.PassEnv
			}
			if body.SignInSeedTools == nil {
				next.SignInSeedTools = cfg.Terminal.Sandbox.SignInSeedTools
			}
			if body.AllowOSC52Clipboard == nil {
				next.AllowOSC52Clipboard = cfg.Terminal.Sandbox.AllowOSC52Clipboard
			}
			if body.Backends == nil {
				next.Backends = cfg.Terminal.Sandbox.Backends
			}
			if body.MinIsolation == nil {
				next.MinIsolation = cfg.Terminal.Sandbox.MinIsolation
			}
			if body.LiveRunUpdatePolicy == nil {
				next.LiveRunUpdatePolicy = cfg.Terminal.Sandbox.LiveRunUpdatePolicy
			}
			if body.OCI == nil {
				next.OCI = cfg.Terminal.Sandbox.OCI
			} else {
				cur := cfg.Terminal.Sandbox.OCI
				if body.OCI.InstallScripts == nil {
					next.OCI.InstallScripts = cur.InstallScripts
				}
				if body.OCI.InstallScriptsTools == nil {
					next.OCI.InstallScriptsTools = cur.InstallScriptsTools
				}
				if body.OCI.InstallScriptPins == nil {
					next.OCI.InstallScriptPins = cur.InstallScriptPins
				}
				if body.OCI.InstallVersions == nil {
					next.OCI.InstallVersions = cur.InstallVersions
				}
			}
			if body.MXC == nil {
				next.MXC = cfg.Terminal.Sandbox.MXC
			}
			if body.Seatbelt == nil {
				next.Seatbelt = cfg.Terminal.Sandbox.Seatbelt
			}
			if body.AppleContainer == nil {
				next.AppleContainer = cfg.Terminal.Sandbox.AppleContainer
			}
			if body.Landlock == nil {
				next.Landlock = cfg.Terminal.Sandbox.Landlock
			}
			if body.Hosted == nil {
				next.Hosted = cfg.Terminal.Sandbox.Hosted
			} else {
				saved := cfg.Terminal.Sandbox.Hosted
				keepHostedEndpoints(&next.Hosted.E2B, body.Hosted.E2B, saved.E2B)
				keepHostedEndpoints(&next.Hosted.Modal, body.Hosted.Modal, saved.Modal)
				keepHostedEndpoints(&next.Hosted.Vercel, body.Hosted.Vercel, saved.Vercel)
				if body.Hosted.DBExport == nil {
					next.Hosted.DBExport = saved.DBExport
				}
			}
			if body.VendorForcedNative == nil {
				next.VendorForcedNative = cfg.Terminal.Sandbox.VendorForcedNative
			}
			cfg.Terminal.Sandbox = next
		},
		auditAction: "terminal_sandbox_config",
		auditDetailFor: func(cfg config.Config) string {
			n := cfg.Terminal.Sandbox
			return fmt.Sprintf(
				"enabled=%v default_on=%v egress=%s egress_allow_cidrs=%d tool_config_writes=%v remote_clone=%v worktree=%v mask_paths=%d ro_binds=%d rw_binds=%d backends=%d min_isolation=%s oci_rootful=%v oci_devcontainer=%v seatbelt_keychain=%v",
				n.Enabled, n.DefaultOn, n.Egress, len(n.EgressAllowCIDRs), n.AllowToolConfigWrites, n.AllowRemoteClone, n.AllowWorktreeSource,
				len(n.MaskPaths), len(n.ExtraROBinds), len(n.ExtraRWBinds), len(n.Backends), n.MinIsolation, n.OCI.AllowRootful, n.OCI.AllowDevcontainerImage, n.Seatbelt.AllowKeychain,
			)
		},
		extra: func(cfg config.Config) map[string]any {
			return map[string]any{
				"sandbox":          sandboxConfigPayload(cfg.Terminal.Sandbox),
				"restart_required": true,
			}
		},
	})
}

func sandboxConfigPayload(c config.TerminalSandboxConfig) terminalSandboxConfigPayload {
	dbExport := c.Hosted.DBExport
	egress := c.Egress
	if egress == "" {
		egress = "internet" // the empty value's meaning ([terminal.sandbox].egress)
	}
	writes := c.AllowToolConfigWrites
	cidrs := nonNilStrings(c.EgressAllowCIDRs)
	hosts := nonNilStrings(c.EgressAllowHosts)
	passEnv := nonNilStrings(c.PassEnv)
	signInTools := nonNilStrings(c.SignInSeedTools)
	osc52 := c.AllowOSC52Clipboard
	backends := nonNilStrings(c.Backends)
	floor := c.MinIsolation
	vendorForced := c.VendorForcedNative
	if vendorForced == "" {
		vendorForced = config.Default().Terminal.Sandbox.VendorForcedNative
	}
	liveRunPolicy := c.LiveRunUpdatePolicy
	installScripts := c.OCI.InstallScripts
	if installScripts == "" {
		installScripts = "pinned"
	}
	installTools := nonNilStrings(c.OCI.InstallScriptsTools)
	installPins := append([]config.TerminalSandboxOCIScriptPin{}, c.OCI.InstallScriptPins...)
	installVersions := map[string]string{}
	for k, v := range c.OCI.InstallVersions {
		installVersions[k] = v
	}
	if liveRunPolicy == "" {
		liveRunPolicy = "defer" // the empty value's meaning (live_run_update_policy)
	}
	return terminalSandboxConfigPayload{
		Enabled:                c.Enabled,
		Backend:                c.Backend,
		HomeMode:               c.HomeMode,
		DefaultOn:              c.DefaultOn,
		AllowRemoteClone:       c.AllowRemoteClone,
		RemoteAllowedHosts:     nonNilStrings(c.RemoteAllowedHosts),
		AllowWorktreeSource:    c.AllowWorktreeSource,
		WorkspacesDir:          c.WorkspacesDir,
		WorkspaceRetentionDays: c.WorkspaceRetentionDays,
		MaskPaths:              nonNilStrings(c.MaskPaths),
		ExtraROBinds:           nonNilStrings(c.ExtraROBinds),
		ExtraRWBinds:           nonNilStrings(c.ExtraRWBinds),
		PrepTimeoutSeconds:     c.PrepTimeoutSeconds,
		Egress:                 &egress,
		AllowToolConfigWrites:  &writes,
		EgressAllowCIDRs:       &cidrs,
		EgressAllowHosts:       &hosts,
		PassEnv:                &passEnv,
		SignInSeedTools:        &signInTools,
		SignInSeedCatalog:      integration.SandboxSignInTools(),
		SignInSeedForbidden:    c.SignInSeedForbidden,
		AllowOSC52Clipboard:    &osc52,
		Backends:               &backends,
		MinIsolation:           &floor,
		LiveRunUpdatePolicy:    &liveRunPolicy,
		OCI: &terminalSandboxOCIPayload{
			AllowRootful: c.OCI.AllowRootful, Socket: c.OCI.Socket, Image: c.OCI.Image,
			PodmanUserns: c.OCI.PodmanUserns, StopGraceSeconds: c.OCI.StopGraceSeconds,
			AllowDevcontainerImage: c.OCI.AllowDevcontainerImage, InstallCache: c.OCI.InstallCache,
			InstallScripts: &installScripts, InstallScriptsTools: &installTools, InstallScriptPins: &installPins, InstallVersions: &installVersions,
			InstallCatalog: terminalSandboxInstallCatalog(),
		},
		MXC: &terminalSandboxMXCPayload{
			StopGraceSeconds: c.MXC.StopGraceSeconds, ProbeTimeoutSeconds: c.MXC.ProbeTimeoutSeconds,
		},
		Seatbelt: &terminalSandboxSeatbeltPayload{AllowKeychain: c.Seatbelt.AllowKeychain, Driver: c.Seatbelt.Driver},
		AppleContainer: &terminalSandboxAppleContainerPayload{
			Image: c.AppleContainer.Image, MemoryMiB: c.AppleContainer.MemoryMiB, CPUs: c.AppleContainer.CPUs,
		},
		Landlock:           &terminalSandboxLandlockPayload{MinABI: c.Landlock.MinABI},
		VendorForcedNative: &vendorForced,
		Hosted: &terminalSandboxHostedPayload{
			MinSessionMinutes: c.Hosted.MinSessionMinutes, KeyCustody: c.Hosted.KeyCustody, MemoryImages: c.Hosted.MemoryImages,
			CheckpointMinutes: c.Hosted.CheckpointMinutes, MaxRunMinutes: c.Hosted.MaxRunMinutes, DailyBoxMinutes: c.Hosted.DailyBoxMinutes,
			DBExport: &dbExport,
			E2B:      hostedProviderToPayload(c.Hosted.E2B), Modal: hostedProviderToPayload(c.Hosted.Modal), Vercel: hostedProviderToPayload(c.Hosted.Vercel),
		},
	}
}

func normalizedSandboxConfig(p terminalSandboxConfigPayload) (config.TerminalSandboxConfig, error) {
	p.Backend = strings.TrimSpace(p.Backend)
	if p.Backend == "" {
		p.Backend = "bwrap"
	}
	p.HomeMode = strings.TrimSpace(p.HomeMode)
	if p.HomeMode == "" {
		p.HomeMode = "tmpfs"
	}
	p.WorkspacesDir = strings.TrimSpace(p.WorkspacesDir)
	p.RemoteAllowedHosts = cleanStringList(p.RemoteAllowedHosts)
	p.MaskPaths = cleanStringList(p.MaskPaths)
	p.ExtraROBinds = cleanStringList(p.ExtraROBinds)
	p.ExtraRWBinds = cleanStringList(p.ExtraRWBinds)

	if p.WorkspacesDir != "" && !filepath.IsAbs(p.WorkspacesDir) {
		return config.TerminalSandboxConfig{}, fmt.Errorf("terminal.sandbox.workspaces_dir %q must be absolute", p.WorkspacesDir)
	}
	for name, paths := range map[string][]string{
		"mask_paths":     p.MaskPaths,
		"extra_ro_binds": p.ExtraROBinds,
		"extra_rw_binds": p.ExtraRWBinds,
	} {
		for _, path := range paths {
			if !filepath.IsAbs(path) {
				return config.TerminalSandboxConfig{}, fmt.Errorf("terminal.sandbox.%s entry %q must be absolute", name, path)
			}
		}
	}

	next := config.TerminalSandboxConfig{
		Enabled:                p.Enabled,
		Backend:                p.Backend,
		HomeMode:               p.HomeMode,
		DefaultOn:              p.DefaultOn,
		AllowRemoteClone:       p.AllowRemoteClone,
		RemoteAllowedHosts:     p.RemoteAllowedHosts,
		AllowWorktreeSource:    p.AllowWorktreeSource,
		WorkspacesDir:          p.WorkspacesDir,
		WorkspaceRetentionDays: p.WorkspaceRetentionDays,
		MaskPaths:              p.MaskPaths,
		ExtraROBinds:           p.ExtraROBinds,
		ExtraRWBinds:           p.ExtraRWBinds,
		PrepTimeoutSeconds:     p.PrepTimeoutSeconds,
	}
	if p.Egress != nil {
		next.Egress = strings.TrimSpace(*p.Egress)
	}
	if p.AllowToolConfigWrites != nil {
		next.AllowToolConfigWrites = *p.AllowToolConfigWrites
	}
	if p.EgressAllowCIDRs != nil {
		next.EgressAllowCIDRs = cleanStringList(*p.EgressAllowCIDRs)
	}
	if p.EgressAllowHosts != nil {
		next.EgressAllowHosts = cleanStringList(*p.EgressAllowHosts)
	}
	if p.PassEnv != nil {
		next.PassEnv = cleanStringList(*p.PassEnv)
	}
	if p.SignInSeedTools != nil {
		next.SignInSeedTools = cleanStringList(*p.SignInSeedTools)
	}
	if p.AllowOSC52Clipboard != nil {
		next.AllowOSC52Clipboard = *p.AllowOSC52Clipboard
	}
	if p.Backends != nil {
		next.Backends = cleanStringList(*p.Backends)
	}
	if p.MinIsolation != nil {
		next.MinIsolation = strings.TrimSpace(*p.MinIsolation)
	}
	if p.LiveRunUpdatePolicy != nil {
		next.LiveRunUpdatePolicy = strings.TrimSpace(*p.LiveRunUpdatePolicy)
	}
	if p.MXC != nil {
		next.MXC = config.TerminalSandboxMXCConfig{StopGraceSeconds: p.MXC.StopGraceSeconds, ProbeTimeoutSeconds: p.MXC.ProbeTimeoutSeconds}
	}
	if p.OCI != nil {
		oci, err := normalizedSandboxOCIConfig(p.OCI)
		if err != nil {
			return config.TerminalSandboxConfig{}, err
		}
		next.OCI = oci
	}
	if p.Seatbelt != nil {
		next.Seatbelt = config.TerminalSandboxSeatbeltConfig{AllowKeychain: p.Seatbelt.AllowKeychain, Driver: strings.TrimSpace(p.Seatbelt.Driver)}
	}
	if p.AppleContainer != nil {
		next.AppleContainer = config.TerminalSandboxAppleContainerConfig{
			Image: strings.TrimSpace(p.AppleContainer.Image), MemoryMiB: p.AppleContainer.MemoryMiB, CPUs: p.AppleContainer.CPUs,
		}
	}
	if p.Landlock != nil {
		next.Landlock = config.TerminalSandboxLandlockConfig{MinABI: p.Landlock.MinABI}
	}
	// A client that predates the hosted block validates with its defaults
	// here; the save keeps the file's own block (apply).
	next.Hosted = config.Default().Terminal.Sandbox.Hosted
	if p.Hosted != nil {
		next.Hosted = normalizedSandboxHostedConfig(p.Hosted)
	}
	next.VendorForcedNative = config.Default().Terminal.Sandbox.VendorForcedNative
	if p.VendorForcedNative != nil {
		next.VendorForcedNative = strings.TrimSpace(*p.VendorForcedNative)
	}
	// Validate against an otherwise-default config before taking the write
	// locks so request mistakes are a 400, not an internal-error-shaped 500.
	probe := config.Default()
	probe.Terminal.Sandbox = next
	if err := config.Validate(probe); err != nil {
		return config.TerminalSandboxConfig{}, err
	}
	return next, nil
}

// normalizedSandboxOCIConfig is normalizedSandboxConfig's OCI block: the
// strings trimmed, and every install-script tool, pin and version checked
// against the install-source catalog the pickers offer.
func normalizedSandboxOCIConfig(o *terminalSandboxOCIPayload) (config.TerminalSandboxOCIConfig, error) {
	oci := config.TerminalSandboxOCIConfig{
		AllowRootful: o.AllowRootful, Socket: strings.TrimSpace(o.Socket), Image: strings.TrimSpace(o.Image),
		PodmanUserns: strings.TrimSpace(o.PodmanUserns), StopGraceSeconds: o.StopGraceSeconds,
		AllowDevcontainerImage: o.AllowDevcontainerImage, InstallCache: o.InstallCache,
	}
	if o.InstallScripts != nil {
		oci.InstallScripts = strings.TrimSpace(*o.InstallScripts)
	}
	// The pickers offer only the install-source catalog; anything else
	// is refused, never written (lane LEFT-SBX).
	inCatalog := func(tool string) bool { _, ok := integration.InstallSourceFor(tool); return ok }
	if o.InstallScriptsTools != nil {
		for _, t := range *o.InstallScriptsTools {
			if !inCatalog(t) {
				return config.TerminalSandboxOCIConfig{}, fmt.Errorf("terminal.sandbox.oci.install_scripts_tools entry %q is not an install-source tool", t)
			}
		}
		oci.InstallScriptsTools = *o.InstallScriptsTools
	}
	if o.InstallScriptPins != nil {
		for _, pin := range *o.InstallScriptPins {
			if !inCatalog(pin.Tool) {
				return config.TerminalSandboxOCIConfig{}, fmt.Errorf("terminal.sandbox.oci.install_script_pins tool %q is not an install-source tool", pin.Tool)
			}
		}
		oci.InstallScriptPins = *o.InstallScriptPins
	}
	if o.InstallVersions != nil {
		for t := range *o.InstallVersions {
			if !inCatalog(t) {
				return config.TerminalSandboxOCIConfig{}, fmt.Errorf("terminal.sandbox.oci.install_versions tool %q is not an install-source tool", t)
			}
		}
		oci.InstallVersions = *o.InstallVersions
	}
	return oci, nil
}

// normalizedSandboxHostedConfig is normalizedSandboxConfig's hosted block,
// every string trimmed.
func normalizedSandboxHostedConfig(h *terminalSandboxHostedPayload) config.TerminalSandboxHostedConfig {
	trim := func(c hostedProviderPayload) config.TerminalSandboxHostedProviderConfig {
		out := config.TerminalSandboxHostedProviderConfig{Region: strings.TrimSpace(c.Region), Template: strings.TrimSpace(c.Template), BoxBinary: strings.TrimSpace(c.BoxBinary)}
		if c.Endpoint != nil {
			out.Endpoint = strings.TrimSpace(*c.Endpoint)
		}
		if c.EndpointSPKISHA256 != nil {
			out.EndpointSPKISHA256 = strings.TrimSpace(*c.EndpointSPKISHA256)
		}
		return out
	}
	return config.TerminalSandboxHostedConfig{
		MinSessionMinutes: h.MinSessionMinutes, KeyCustody: strings.TrimSpace(h.KeyCustody),
		MemoryImages: strings.TrimSpace(h.MemoryImages), CheckpointMinutes: h.CheckpointMinutes,
		MaxRunMinutes: h.MaxRunMinutes, DailyBoxMinutes: h.DailyBoxMinutes,
		DBExport: h.DBExport != nil && *h.DBExport,
		E2B:      trim(h.E2B), Modal: trim(h.Modal), Vercel: trim(h.Vercel),
	}
}

func cleanStringList(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

// handleTerminalSandboxInstallVersions serves GET
// /api/terminal/sandbox/install-versions?tool=<id> (lane LEFT-SBX): the
// published versions the Container sandboxes card's version picker offers
// for one install-source tool. 501 without the seam (a build without the
// container driver), 400 for a tool outside the install-source catalog, 502
// when the registry cannot be read.
func (s *Server) handleTerminalSandboxInstallVersions(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if s.opts.SandboxInstallVersions == nil {
		http.Error(w, "the container sandbox driver is not in this build", http.StatusNotImplemented)
		return
	}
	tool := strings.TrimSpace(r.URL.Query().Get("tool"))
	if _, ok := integration.InstallSourceFor(tool); !ok {
		http.Error(w, "not an install-source tool", http.StatusBadRequest)
		return
	}
	vs, err := s.opts.SandboxInstallVersions(r.Context(), tool)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	writeJSON(w, map[string]any{"tool": tool, "versions": vs})
}
