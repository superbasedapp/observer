//go:build windows

package managedconfig

import (
	"errors"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// windowsPolicyKey is the one Windows source, under HKEY_LOCAL_MACHINE.
const windowsPolicyKey = `SOFTWARE\Policies\SuperBased\Observer`

func probeOS() Probe {
	p := Probe{Source: `HKLM\` + windowsPolicyKey, Format: "registry"}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, windowsPolicyKey, registry.QUERY_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return p
		}
		p.Found, p.FailedCheck = true, "registry_open"
		return p
	}
	defer func() { _ = k.Close() }()
	p.Found = true
	if fc := keySecurity(); fc != "" {
		p.FailedCheck = fc
		return p
	}
	names, err := k.ReadValueNames(0)
	if err != nil {
		p.FailedCheck = "registry_read"
		return p
	}
	v := &RegistryValues{}
	for _, n := range names {
		switch n {
		case "Components":
			s, _, err := k.GetStringsValue(n)
			if err != nil {
				p.FailedCheck = "registry_components_not_multi_sz"
				return p
			}
			v.HaveComponents, v.Components = true, s
		case "CatalogVersion":
			n64, typ, err := k.GetIntegerValue(n)
			if err != nil || typ != registry.DWORD {
				p.FailedCheck = "registry_catalog_version_not_dword"
				return p
			}
			v.HaveVersion, v.CatalogVersion = true, n64
		case "OrgURL", "AttachMethod":
			s, typ, err := k.GetStringValue(n)
			if err != nil || typ != registry.SZ {
				p.FailedCheck = "registry_" + strings.ToLower(n) + "_not_sz"
				return p
			}
			if n == "OrgURL" {
				v.HaveOrgURL, v.OrgURL = true, s
			} else {
				v.HaveAttachMethod, v.AttachMethod = true, s
			}
		case "Locked":
			n64, typ, err := k.GetIntegerValue(n)
			if err != nil || typ != registry.DWORD {
				p.FailedCheck = "registry_locked_not_dword"
				return p
			}
			v.HaveLocked, v.Locked = true, n64
		default:
			v.Unknown = append(v.Unknown, n)
		}
	}
	p.Registry = v
	return p
}

// keySecurity reads the key's owner and DACL and applies CheckKeySecurity.
func keySecurity() string {
	sd, err := windows.GetNamedSecurityInfo(`MACHINE\`+windowsPolicyKey, windows.SE_REGISTRY_KEY,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "registry_security_read"
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "registry_owner_read"
	}
	dacl, _, err := sd.DACL()
	if err != nil && !errors.Is(err, windows.ERROR_OBJECT_NOT_FOUND) {
		return "registry_dacl_read"
	}
	var aces []ACE
	if dacl != nil {
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return "registry_dacl_read"
			}
			a := ACE{Type: ace.Header.AceType, Flags: ace.Header.AceFlags, Mask: uint32(ace.Mask)}
			if a.Type == aceTypeAccessAllowed {
				// Only the plain allowed-ACE layout puts the SID at SidStart;
				// other types are not read by the rule.
				a.SID = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			}
			aces = append(aces, a)
		}
	}
	return CheckKeySecurity(owner.String(), dacl != nil, aces)
}
