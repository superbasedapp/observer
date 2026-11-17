package config

import (
	"fmt"
	"regexp"
	"slices"
)

// security_licenses.go is [security.licenses] (security coverage gaps plan
// section 5, "Item 4: licence compliance, local first"): the project's
// licence policy, read by internal/seclicense over the dependency files a
// project carries. Deny and Allow hold SPDX ids ("GPL-3.0-only") or class
// names ("strong_copyleft"); an empty Allow allows everything not denied.
// Unknown is "ignore" (the default) or "flag". With the defaults nothing
// is recorded. Owned by component security.deps; an agent can never change
// it (guard rule R-165 denies the [security] section in every config-write
// form).

// SecurityLicensesUnknown is the picker of [security.licenses].unknown.
var SecurityLicensesUnknown = []string{"ignore", "flag"}

// MaxSecurityLicensesEntries is the most entries Deny or Allow holds.
const MaxSecurityLicensesEntries = 64

// securityLicenseEntry is the shape of one Deny or Allow entry: an SPDX id
// (with a LicenseRef- prefix allowed) or a class name.
var securityLicenseEntry = regexp.MustCompile(`^[A-Za-z0-9.+:_-]{1,64}$`)

// SecurityLicensesConfig is [security.licenses].
type SecurityLicensesConfig struct {
	// Deny lists the SPDX ids or licence classes a dependency may not use
	// (a finding, medium at most). Empty by default.
	Deny []string `toml:"deny"`
	// Allow, when not empty, lists the only SPDX ids or licence classes a
	// dependency may use. Empty by default: everything not denied.
	Allow []string `toml:"allow"`
	// Unknown is "ignore" (the default) or "flag": whether a dependency
	// whose licence Observer does not recognize is a low finding.
	Unknown string `toml:"unknown"`
}

// DefaultSecurityLicensesConfig is the [security.licenses] default: no
// policy, nothing recorded.
func DefaultSecurityLicensesConfig() SecurityLicensesConfig {
	return SecurityLicensesConfig{Deny: []string{}, Allow: []string{}, Unknown: "ignore"}
}

// validateSecurityLicenses checks [security.licenses]: Unknown on its
// picker (an empty value reads as the default), and each list at most
// MaxSecurityLicensesEntries entries of the id shape.
func validateSecurityLicenses(c SecurityLicensesConfig) error {
	if c.Unknown != "" && !slices.Contains(SecurityLicensesUnknown, c.Unknown) {
		return fmt.Errorf("config: security.licenses.unknown %q not in %v", c.Unknown, SecurityLicensesUnknown)
	}
	for _, l := range []struct {
		key  string
		list []string
	}{{"security.licenses.deny", c.Deny}, {"security.licenses.allow", c.Allow}} {
		if len(l.list) > MaxSecurityLicensesEntries {
			return fmt.Errorf("config: %s has %d entries, at most %d", l.key, len(l.list), MaxSecurityLicensesEntries)
		}
		for _, e := range l.list {
			if !securityLicenseEntry.MatchString(e) {
				return fmt.Errorf("config: %s entry %q is not an SPDX id or licence class", l.key, e)
			}
		}
	}
	return nil
}

// licenseSecuritySettings is the settings-contract rows of the section
// (their home is the Code security card).
func licenseSecuritySettings() []SecuritySetting {
	return []SecuritySetting{
		{Key: "security.licenses.deny", Class: SettingPolicy, Values: "SPDX ids or licence classes (up to 64)", Default: "none", NodeHome: "Code security"},
		{Key: "security.licenses.allow", Class: SettingPolicy, Values: "SPDX ids or licence classes (up to 64; empty allows everything not denied)", Default: "none (everything not denied)", NodeHome: "Code security"},
		{Key: "security.licenses.unknown", Class: SettingPolicy, Values: "ignore / flag", Default: "ignore", NodeHome: "Code security"},
	}
}
