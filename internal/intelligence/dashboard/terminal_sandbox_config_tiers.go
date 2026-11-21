package dashboard

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/config"
)

// terminal_sandbox_config_tiers.go carries the [terminal.sandbox] blocks the
// Sandbox isolation card's sub-panels edit and the main payload had no
// field for (dashboard CLI parity plan, lane L3, items B-G6 and B-G7): the
// microVM row's [terminal.sandbox.vm], re-adoption's
// [terminal.sandbox.readopt], and the probe-only Windows rows'
// [terminal.sandbox.wslc], [terminal.sandbox.hcs] and
// [terminal.sandbox.windows]. Before, the GET never served them and a save
// put the file's blocks back (keepUnsentSandboxBlocks), so the panels showed
// defaults and dropped every edit, and their text sent the user to the
// config file. The payload is embedded in terminalSandboxConfigPayload, so
// each block's key sits at the top of the JSON body beside the other
// sandbox keys. Each block is a pointer: a client that omits it keeps the
// saved block. The org's pins still apply on every load (config.Load), so
// a local value a pin overrides is kept in the file and has no effect while
// the pin is in force; the card shows such a key read-only.

// terminalSandboxTiersPayload carries the five blocks.
type terminalSandboxTiersPayload struct {
	VM      *terminalSandboxVMPayload      `json:"vm,omitempty"`
	Readopt *terminalSandboxReadoptPayload `json:"readopt,omitempty"`
	WSLC    *terminalSandboxWSLCPayload    `json:"wslc,omitempty"`
	HCS     *terminalSandboxHCSPayload     `json:"hcs,omitempty"`
	Windows *terminalSandboxWindowsPayload `json:"windows,omitempty"`
}

// terminalSandboxVMPayload is the dashboard shape of [terminal.sandbox.vm].
type terminalSandboxVMPayload struct {
	VMM                 string `json:"vmm"`
	ImageSet            string `json:"image_set"`
	VCPUs               int    `json:"vcpus"`
	MemoryMB            int    `json:"memory_mb"`
	InstallCache        bool   `json:"install_cache"`
	WorkspaceDelivery   string `json:"workspace_delivery"`
	CloudHypervisorPath string `json:"cloud_hypervisor_path"`
	VirtiofsdPath       string `json:"virtiofsd_path"`
}

// terminalSandboxReadoptPayload is the dashboard shape of
// [terminal.sandbox.readopt].
type terminalSandboxReadoptPayload struct {
	BoundMinutes     int `json:"bound_minutes"`
	CheckpointCapMiB int `json:"checkpoint_cap_mib"`
}

// terminalSandboxWSLCPayload is the dashboard shape of
// [terminal.sandbox.wslc].
type terminalSandboxWSLCPayload struct {
	Path  string `json:"path"`
	Image string `json:"image"`
}

// terminalSandboxHCSPayload is the dashboard shape of [terminal.sandbox.hcs].
type terminalSandboxHCSPayload struct {
	UtilityVMImage string `json:"utility_vm_image"`
}

// terminalSandboxWindowsPayload is the dashboard shape of
// [terminal.sandbox.windows]: the MXC tier floor (R-034).
type terminalSandboxWindowsPayload struct {
	MXCTier string `json:"mxc_tier"`
}

// tiersPayloadFor is the GET shape of the five blocks.
func tiersPayloadFor(c config.TerminalSandboxConfig) terminalSandboxTiersPayload {
	vm := c.VM
	return terminalSandboxTiersPayload{
		VM: &terminalSandboxVMPayload{
			VMM: vm.VMM, ImageSet: vm.ImageSet, VCPUs: vm.VCPUs, MemoryMB: vm.MemoryMB, InstallCache: vm.InstallCache,
			WorkspaceDelivery: vm.WorkspaceDelivery, CloudHypervisorPath: vm.CloudHypervisorPath, VirtiofsdPath: vm.VirtiofsdPath,
		},
		Readopt: &terminalSandboxReadoptPayload{BoundMinutes: c.Readopt.BoundMinutes, CheckpointCapMiB: c.Readopt.CheckpointCapMiB},
		WSLC:    &terminalSandboxWSLCPayload{Path: c.WSLC.Path, Image: c.WSLC.Image},
		HCS:     &terminalSandboxHCSPayload{UtilityVMImage: c.HCS.UtilityVMImage},
		Windows: &terminalSandboxWindowsPayload{MXCTier: c.Windows.MXCTier},
	}
}

// tierPathRule is one path-valued key the tiers payload checks before the
// config validation runs (the config has no rule for the Windows rows'
// paths): empty, or an absolute, clean path.
type tierPathRule struct {
	key   string
	value string
}

// applyTo writes the sent blocks into next, trimmed, after checking the
// keys the config validation does not cover (the Windows rows' paths and
// image). The VM and re-adoption blocks are checked by config.Validate,
// which normalizedSandboxConfig runs on the result.
func (p terminalSandboxTiersPayload) applyTo(next *config.TerminalSandboxConfig) error {
	if p.VM != nil {
		next.VM = config.TerminalSandboxVMConfig{
			VMM: strings.TrimSpace(p.VM.VMM), ImageSet: strings.TrimSpace(p.VM.ImageSet), VCPUs: p.VM.VCPUs, MemoryMB: p.VM.MemoryMB,
			InstallCache: p.VM.InstallCache, WorkspaceDelivery: strings.TrimSpace(p.VM.WorkspaceDelivery),
			CloudHypervisorPath: strings.TrimSpace(p.VM.CloudHypervisorPath), VirtiofsdPath: strings.TrimSpace(p.VM.VirtiofsdPath),
		}
	}
	if p.Readopt != nil {
		next.Readopt = config.TerminalSandboxReadoptConfig{BoundMinutes: p.Readopt.BoundMinutes, CheckpointCapMiB: p.Readopt.CheckpointCapMiB}
	}
	var paths []tierPathRule
	if p.WSLC != nil {
		next.WSLC = config.TerminalSandboxWSLCConfig{Path: strings.TrimSpace(p.WSLC.Path), Image: strings.TrimSpace(p.WSLC.Image)}
		if img := next.WSLC.Image; img != "" && !wslcImagePinned.MatchString(img) {
			return fmt.Errorf("terminal.sandbox.wslc.image %q must be pinned by its digest (name@sha256:<64 lowercase hex>)", img)
		}
		paths = append(paths, tierPathRule{"wslc.path", next.WSLC.Path})
	}
	if p.HCS != nil {
		next.HCS = config.TerminalSandboxHCSConfig{UtilityVMImage: strings.TrimSpace(p.HCS.UtilityVMImage)}
		paths = append(paths, tierPathRule{"hcs.utility_vm_image", next.HCS.UtilityVMImage})
	}
	for _, r := range paths {
		if r.value != "" && (!filepath.IsAbs(r.value) || filepath.Clean(r.value) != r.value) {
			return fmt.Errorf("terminal.sandbox.%s %q must be an absolute, clean path", r.key, r.value)
		}
	}
	if p.Windows != nil {
		// The closed value set is the config validation's (sandboxChoices).
		next.Windows = config.TerminalSandboxWindowsConfig{MXCTier: strings.TrimSpace(p.Windows.MXCTier)}
	}
	return nil
}

// keepUnsent puts each saved block back when the save did not send it.
func (p terminalSandboxTiersPayload) keepUnsent(next *config.TerminalSandboxConfig, saved config.TerminalSandboxConfig) {
	if p.VM == nil {
		next.VM = saved.VM
	}
	if p.Readopt == nil {
		next.Readopt = saved.Readopt
	}
	if p.WSLC == nil {
		next.WSLC = saved.WSLC
	}
	if p.HCS == nil {
		next.HCS = saved.HCS
	}
	if p.Windows == nil {
		next.Windows = saved.Windows
	}
}

// mxcTierRank orders the MXC tier floor by strictness, higher is stricter
// ("" is no floor, the same as allowing the AppContainer tier).
var mxcTierRank = map[string]int{"": 0, "appcontainer": 0, "process_container": 1}

// mxcTierLoosens reports whether moving the floor from saved to next lets
// this machine use MXC's weaker AppContainer tier where it could not before.
// The card asks for a confirm on such a save; the guard's agent pin reads
// the request body for the same key.
func mxcTierLoosens(saved, next string) bool {
	return mxcTierRank[strings.TrimSpace(next)] < mxcTierRank[strings.TrimSpace(saved)]
}

// wslcImagePinned is the WSL container image shape the wslc row accepts: a
// name pinned by its digest. It repeats internal/sandboxwslc's imageRE
// instead of importing that package, which the dashboard must not link (the
// terminals.sandbox.wslc component's packages stay separable,
// tests/invariant TestComponentsPackageFence); keep the two in step.
var wslcImagePinned = regexp.MustCompile(`^[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}$`)
