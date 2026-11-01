//go:build !sbo_omit_terminals_sandbox_vm && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	"github.com/marmutapp/superbased-observer/internal/sandboxvm"
)

// terminal_sandbox_vm_test.go covers the microVM driver's registration,
// opt-in rule and probe wiring (lane SBX-P4, milestone 1).

func vmTestConfig(t *testing.T, selectDriver bool, backends ...string) config.Config {
	t.Helper()
	cfg := config.Default()
	cfg.Observer.DBPath = filepath.Join(t.TempDir(), "observer.db")
	cfg.Terminal.Sandbox.Enabled = true
	cfg.Terminal.Sandbox.Backends = backends
	if selectDriver {
		cfg.Components.Add = []string{vmComponent}
	}
	return cfg
}

// countVMProbe stands in a healthy KVM host and counts the probe env's
// construction and every fact it reads.
func countVMProbe(t *testing.T) (*atomic.Int64, *atomic.Int64) {
	t.Helper()
	var builds, reads atomic.Int64
	prev := vmProbeEnvFn
	vmProbeEnvFn = func(*sandboxRuntime, config.TerminalSandboxVMConfig) sandboxvm.ProbeEnv {
		builds.Add(1)
		read := func() { reads.Add(1) }
		return sandboxvm.ProbeEnv{
			GOOS:          "linux",
			KVM:           func() sandboxvm.KVMFacts { read(); return sandboxvm.KVMFacts{Exists: true, CharDevice: true} },
			InVM:          func() bool { read(); return false },
			LookVMM:       func() (string, error) { read(); return "/usr/local/bin/cloud-hypervisor", nil },
			LookVirtiofsd: func() (string, error) { read(); return "/usr/libexec/virtiofsd", nil },
			StatProgram: func(string) (sandboxvm.ProgramFacts, error) {
				read()
				return sandboxvm.ProgramFacts{Regular: true, OwnerOK: true, Perm: 0o755}, nil
			},
			VMMVersion: func(string) (string, error) { read(); return "cloud-hypervisor v54.0", nil },
			ImageSet: func() sandboxvm.ImageSetFacts {
				read()
				return sandboxvm.ImageSetFacts{Present: true, Verdict: sandboxvm.Verdict{Code: sandboxvm.VerdictAvailable}, Version: "1.0.0"}
			},
		}
	}
	t.Cleanup(func() { vmProbeEnvFn = prev })
	return &builds, &reads
}

// TestVMDriverIsOptIn: with no [components] block the driver is inactive
// (module_inactive, never probed); selected but unlisted it probes as
// disabled_by_config without reading a fact; selected and listed it walks
// the ladder.
func TestVMDriverIsOptIn(t *testing.T) {
	builds, reads := countVMProbe(t)
	reg, ok := sandboxDriverRegs[sandboxbackend.BackendCloudHypervisor]
	if !ok || reg.component != vmComponent {
		t.Fatalf("registration %+v", reg)
	}
	legacy := macTestRuntime(t, vmTestConfig(t, false, "cloud-hypervisor"))
	if _, active := legacy.drivers[sandboxbackend.BackendCloudHypervisor]; active {
		t.Fatal("an install with no [components] block got the driver")
	}
	if p := legacy.driverProbes(context.Background())[sandboxbackend.BackendCloudHypervisor]; p.Verdict != verdictModuleInactive {
		t.Fatalf("an unselected driver probes as %+v", p)
	}
	unlisted := macTestRuntime(t, vmTestConfig(t, true, "bwrap"))
	if p := unlisted.drivers[sandboxbackend.BackendCloudHypervisor].probe(context.Background()); p.Verdict != sandboxselect.VerdictDisabledByConfig {
		t.Fatalf("an unlisted driver probes as %+v", p)
	}
	if builds.Load() != 0 || reads.Load() != 0 {
		t.Fatalf("the probe ran (%d builds, %d reads) while inactive", builds.Load(), reads.Load())
	}
	listed := macTestRuntime(t, vmTestConfig(t, true, "cloud-hypervisor"))
	d := listed.drivers[sandboxbackend.BackendCloudHypervisor].(*vmDriver)
	if p := d.probe(context.Background()); p.Verdict != sandboxvm.VerdictAvailable || p.Version != "54" {
		t.Fatalf("a listed driver probes as %+v", p)
	}
	if reads.Load() == 0 {
		t.Fatal("a listed driver read no facts")
	}
}

// TestVMComponentOptInRule: the status surfaces agree (sandboxDriverOptIn
// governs the row; a config with no block leaves it off, a block that adds
// it turns it on).
func TestVMComponentOptInRule(t *testing.T) {
	governs, active := sandboxDriverOptIn(componentSnapshotForConfig(vmTestConfig(t, false)), vmComponent)
	if !governs || active {
		t.Fatalf("no block: governs %v active %v", governs, active)
	}
	governs, active = sandboxDriverOptIn(componentSnapshotForConfig(vmTestConfig(t, true)), vmComponent)
	if !governs || !active {
		t.Fatalf("selected: governs %v active %v", governs, active)
	}
	row, ok := components.Get(vmComponent)
	if !ok || row.Stability != components.StabilityPreview || len(row.Requires) != 1 || row.Requires[0] != "terminals.sandbox" {
		t.Fatalf("catalog row %+v", row)
	}
}

// TestVMProbeOffLinuxReadsNothing: off Linux the probe stops at the
// platform row.
func TestVMProbeOffLinuxReadsNothing(t *testing.T) {
	env := vmProbeEnv(nil, config.TerminalSandboxVMConfig{})
	env.GOOS = "darwin"
	if r := sandboxvm.Probe(env); r.Verdict.Code != sandboxvm.VerdictUnsupportedPlatform {
		t.Fatalf("%+v", r.Verdict)
	}
}

// sandboxVMSettingsInventory is the [terminal.sandbox.vm] inventory: its
// node home is the microVM sandboxes panel (SandboxVMPanel.tsx); every
// admin home is owed (vm.* governance pins come later, lane SBX-P4
// decision 9).
var sandboxVMSettingsInventory = map[string]adminHome{
	"vmm":                   {Owed: "vm.* governance pins (later)"},
	"image_set":             {Owed: "vm.* governance pins (later)"},
	"vcpus":                 {Owed: "vm.* governance pins (later)"},
	"memory_mb":             {Owed: "vm.* governance pins (later)"},
	"install_cache":         {Owed: "vm.* governance pins (later)"},
	"workspace_delivery":    {Owed: "vm.* governance pins (later)"},
	"cloud_hypervisor_path": {Owed: "a machine path: a per-node override on the managed pull, never a fleet pin"},
	"virtiofsd_path":        {Owed: "a machine path: a per-node override on the managed pull, never a fleet pin"},
}

// TestSandboxVMSettingsInventory walks [terminal.sandbox.vm].
func TestSandboxVMSettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxVMPanel.tsx"))
	if err != nil {
		t.Fatalf("read the panel: %v", err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxVMConfig{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		seen[key] = true
		home, ok := sandboxVMSettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox.vm].%s has no inventory row", key)
			continue
		}
		if !strings.Contains(string(panel), key) {
			t.Errorf("[terminal.sandbox.vm].%s has no node home in the microVM sandboxes panel", key)
		}
		if home.Owed == "" {
			t.Errorf("[terminal.sandbox.vm].%s has no admin home", key)
		}
	}
	for key := range sandboxVMSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no [terminal.sandbox.vm] key", key)
		}
	}
}

// TestVMPickSocketDir (audit finding 8): the state dir when its sockets fit
// the 107-byte limit, the short per-user dir when it is too deep, and a
// refusal by name when neither can hold them.
func TestVMPickSocketDir(t *testing.T) {
	root := filepath.Join(t.TempDir(), "obvm")
	prev := vmShortSocketRoot
	vmShortSocketRoot = func() string { return root }
	t.Cleanup(func() { vmShortSocketRoot = prev })
	tags := []string{sandboxvm.BootTag, sandboxvm.WorkspaceTag}
	usual := "/home/u/.observer/sandbox-vm/runs/r1"
	if got, err := vmPickSocketDir(usual, "r1", tags); err != nil || got != usual {
		t.Fatalf("usual: %s %v", got, err)
	}
	deep := "/home/" + strings.Repeat("u", 70) + "/.observer/sandbox-vm/runs/r1"
	if got, err := vmPickSocketDir(deep, "r1", tags); err != nil || got != filepath.Join(root, "r1") {
		t.Fatalf("deep: %s %v", got, err)
	}
	long := strings.Repeat("r", 100)
	if _, err := vmPickSocketDir(deep, long, tags); err == nil || !strings.Contains(err.Error(), sandboxvm.VerdictSocketPathTooLong) {
		t.Fatalf("too long everywhere: %v", err)
	}
}
