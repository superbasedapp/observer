package config

import (
	"fmt"
	"slices"
)

// security_image.go is [security.scan.image] (OS and CI vulnerability
// scanning plan section 6.7, operator ruling Q6, lane OS-2 T): which driver
// scans a container image's OS packages, the native route A
// (security.scan.os, OSV-SCALIBR) or Trivy (security.scan.image.trivy). The
// zero value ("") is the default: SCALIBR where it is compiled in, else
// Trivy (the cmd layer resolves it). A local experience setting; an agent
// can never change it (guard rule R-165 denies the [security] section in
// every config-write form and the `observer security scan image driver`
// verb).

// SecurityImageScanDrivers is the picker of [security.scan.image].driver
// ("" is the default and reads as SCALIBR where it is compiled, else
// Trivy).
var SecurityImageScanDrivers = []string{"scalibr", "trivy"}

// SecurityImageScanConfig is [security.scan.image].
type SecurityImageScanConfig struct {
	// Driver is "scalibr", "trivy" or "" (the default).
	Driver string `toml:"driver"`
}

// validateSecurityImage checks the driver against the picker.
func validateSecurityImage(c SecurityImageScanConfig) error {
	if c.Driver != "" && !slices.Contains(SecurityImageScanDrivers, c.Driver) {
		return fmt.Errorf("config: security.scan.image.driver %q not in %v", c.Driver, SecurityImageScanDrivers)
	}
	return nil
}

// imageSecuritySettings is the settings-contract row of the section (its
// home is the Code security page's Scanners card).
func imageSecuritySettings() []SecuritySetting {
	return []SecuritySetting{{
		Key: "security.scan.image.driver", Class: SettingLocal, Values: "scalibr / trivy",
		Default: "scalibr where it is compiled in, else trivy", NodeHome: "Code security > Scanners",
	}}
}
