//go:build windows

package supervisor

import "golang.org/x/sys/windows/registry"

// serviceExists reports whether a Windows service of this name is installed:
// every installed service has a key under
// HKLM\SYSTEM\CurrentControlSet\Services, and reading it needs no privilege.
func serviceExists(name string) bool {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services\`+name, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	_ = k.Close()
	return true
}
