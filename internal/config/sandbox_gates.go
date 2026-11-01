package config

// sandbox_gates.go holds the config blocks of the sandbox pieces lane
// GATES-SBX built (sandbox plan v2 sections 5.5, 7.2, 7.3 and 13 P6;
// operator ruling P-129). Each is read only while its own component is
// selected; zero values are the defaults, so no Default() entry is needed
// and an existing config is unchanged.

// TerminalSandboxReadoptConfig is [terminal.sandbox.readopt]: re-adopting
// a local container run whose host helper went away, and the Podman
// checkpoint and restore (component terminals.sandbox.oci.readopt).
type TerminalSandboxReadoptConfig struct {
	// BoundMinutes is how long a run nobody re-adopts is kept before it is
	// reaped as before. 0 (the default) is 10 minutes; 1 to 1440. An
	// organization may pin it lower (lowering-only, R-034).
	BoundMinutes int `toml:"bound_minutes"`
	// CheckpointCapMiB caps a checkpoint export written to the run's state
	// dir. 0 (the default) is 2048 MiB. Exports never leave this machine. An
	// organization may pin it lower (lowering-only, R-034).
	CheckpointCapMiB int `toml:"checkpoint_cap_mib"`
}

// TerminalSandboxWSLCConfig is [terminal.sandbox.wslc], the wslc row
// (WSL containers on Windows 11; beta, component terminals.sandbox.wslc).
type TerminalSandboxWSLCConfig struct {
	// Path is wslc.exe; empty resolves it from PATH.
	Path string `toml:"path"`
	// Image is the run's image, pinned by digest (name@sha256:<64 hex>).
	// Empty leaves the row unavailable (image_missing).
	Image string `toml:"image"`
}

// TerminalSandboxHCSConfig is [terminal.sandbox.hcs], the hcs row
// (Hyper-V isolated containers through the HCS compute system API; beta,
// probe only in this release, component terminals.sandbox.hcs).
type TerminalSandboxHCSConfig struct {
	// UtilityVMImage is the folder of the utility VM's base image layer.
	// Empty leaves the row unavailable (image_missing); until Observer
	// publishes a signed image there is no source it can verify.
	UtilityVMImage string `toml:"utility_vm_image"`
}

// TerminalSandboxWindowsConfig is [terminal.sandbox.windows] (R-034): the
// weakest MXC tier this machine may use. Its governance pin row
// (terminal.sandbox.windows.mxc_tier) is restrictive-only, so an
// organization can keep a node on ProcessContainer and never move one onto
// the weaker AppContainer tier.
type TerminalSandboxWindowsConfig struct {
	// MXCTier is "process_container" (the mxc-appcontainer row is refused),
	// "appcontainer" (it may be used) or "" (no floor: the default, as
	// before).
	MXCTier string `toml:"mxc_tier"`
}

// SandboxReadoptDefaultBoundMinutes is what a terminal.sandbox.readopt
// bound_minutes of 0 means (sandboxadopt.DefaultBound).
const SandboxReadoptDefaultBoundMinutes = 10

// SandboxReadoptDefaultCheckpointCapMiB is what a checkpoint_cap_mib of 0
// means (sandboxadopt.DefaultExportCapBytes).
const SandboxReadoptDefaultCheckpointCapMiB = 2048
