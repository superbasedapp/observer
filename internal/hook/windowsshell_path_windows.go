//go:build windows

package hook

import (
	"strings"

	"golang.org/x/sys/windows/registry"
)

// readPersistentWindowsPATH joins the machine and user Path values from the
// registry, expanding REG_EXPAND_SZ references.
func readPersistentWindowsPATH() (string, bool) {
	var parts []string
	for _, src := range []struct {
		root registry.Key
		path string
	}{
		{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Session Manager\Environment`},
		{registry.CURRENT_USER, `Environment`},
	} {
		k, err := registry.OpenKey(src.root, src.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		v, _, err := k.GetStringValue("Path")
		_ = k.Close()
		if err != nil || v == "" {
			continue
		}
		if x, err := registry.ExpandString(v); err == nil {
			v = x
		}
		parts = append(parts, v)
	}
	if len(parts) == 0 {
		return "", false
	}
	return strings.Join(parts, ";"), true
}
