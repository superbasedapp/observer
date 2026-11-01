//go:build windows

package hook

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// ibmBobPolicyKey is Bob's Windows policy key (bundle: the native policy
// watcher's registryPath), under HKEY_LOCAL_MACHINE for the administrator's
// policy and under HKEY_CURRENT_USER for the per-user one Bob 2.2.3 also
// applies (FU-115). Observer only READS either; the HKCU twin is read by key
// name for reporting only (readIBMBobPolicyDomainsOS), never for stand-down.
const ibmBobPolicyKey = `SOFTWARE\Policies\IBM\Bob`

// readIBMBobPolicyOS reads the values Observer reasons about: the strings
// (EnforcedHooks, OtelConfiguration, GatewayUrl) as REG_SZ and
// EnableTelemetry as a REG_DWORD (the boolean shape
// the policy watcher reads). HKLM\SOFTWARE\Policies is writable by
// administrators only, so the key is trusted as-is.
func readIBMBobPolicyOS() IBMBobPolicy {
	source := `HKLM\` + ibmBobPolicyKey
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, ibmBobPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return IBMBobPolicy{}
		}
		return IBMBobPolicy{Source: source, Found: true, Untrusted: source + " could not be opened"}
	}
	defer func() { _ = k.Close() }()
	p := IBMBobPolicy{Source: source, Found: true}
	if s, _, err := k.GetStringValue(IBMBobPolicyEnforcedHooks); err == nil {
		p.EnforcedHooks = &s
	} else if errors.Is(err, registry.ErrUnexpectedType) {
		p.EnforcedHooksWrongType = true
	}
	if s, _, err := k.GetStringValue(IBMBobPolicyOtelConfiguration); err == nil {
		p.OtelExport = ibmBobOtelNamesEndpoint(s)
	}
	if s, _, err := k.GetStringValue(IBMBobPolicyGatewayURL); err == nil {
		p.GatewayURL = strings.TrimSpace(s)
	}
	if n, typ, err := k.GetIntegerValue(IBMBobPolicyEnableTelemetry); err == nil && typ == registry.DWORD {
		b := n != 0
		p.EnableTelemetry = &b
	}
	return p
}

// readIBMBobPolicyDomainsOS reads Bob's Windows policy keys by value name
// (FU-115): HKLM as the managed side, HKCU as the user-writable side Bob
// 2.2.3 applies too (proved live 2026-10-29). system=false (a sandboxed
// doctor or layer run) reads neither: no registry hive belongs to a
// sandboxed home. HKCU is the hive of the account this Observer runs as, so
// a daemon running as another account (a service as LocalSystem) does not
// see the developer's key.
func readIBMBobPolicyDomainsOS(_ string, system bool) IBMBobPolicyDomains {
	if !system {
		return IBMBobPolicyDomains{}
	}
	return ibmBobPolicyDomainsFromRegistry(ibmBobRegistryNames(registry.LOCAL_MACHINE), ibmBobRegistryNames(registry.CURRENT_USER))
}

// ibmBobRegistryNames is the production ibmBobRegistryKey for Bob's policy
// key under root: its value names, read with QUERY_VALUE only.
func ibmBobRegistryNames(root registry.Key) ibmBobRegistryKey {
	return func() ([]string, bool, string) {
		k, err := registry.OpenKey(root, ibmBobPolicyKey, registry.QUERY_VALUE)
		if err != nil {
			if errors.Is(err, registry.ErrNotExist) {
				return nil, false, ""
			}
			return nil, true, "could not be opened"
		}
		defer func() { _ = k.Close() }()
		names, err := k.ReadValueNames(0)
		if err != nil {
			return nil, true, "could not be listed"
		}
		return names, true, ""
	}
}
