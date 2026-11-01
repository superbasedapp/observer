//go:build windows && !sbo_omit_terminals_sandbox_hcs && !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"strings"

	"golang.org/x/sys/windows/registry"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxhcs"
)

// hcsGather reads the edition and whether the Hyper-V and Containers
// feature services are installed, from the registry only (no library is
// loaded in the daemon).
func hcsGather(cfg config.TerminalSandboxHCSConfig) sandboxhcs.Facts {
	f := sandboxhcs.Facts{Windows: true, UVMImage: strings.TrimSpace(cfg.UtilityVMImage)}
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE); err == nil {
		f.Edition, _, _ = k.GetStringValue("EditionID")
		_ = k.Close()
	}
	exists := func(service string) bool {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+service, registry.QUERY_VALUE)
		if err != nil {
			return false
		}
		_ = k.Close()
		return true
	}
	f.HyperV, f.Containers = exists("hvservice"), exists("vmcompute")
	return f
}
