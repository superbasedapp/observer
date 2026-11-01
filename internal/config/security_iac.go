package config

import (
	"fmt"
	"slices"
)

// security_iac.go holds the two IaC driver sections (lane GATES-SEC,
// operator ruling P-129): [security.scan.trivy] and [security.scan.kics].
// Every key's default is its zero value, so a config that names neither
// section reads exactly as before (DefaultSecurityConfig is LEFT-SEC's and
// is not touched). Every key acts only while its component is selected
// under a [components] block (both are in securityOptIn) and the engine is
// installed. All are local experience settings; an agent can never change
// one (guard rule R-165).

// SecurityIaCScheduleHours are the schedule picker's steps: off, daily,
// weekly.
var SecurityIaCScheduleHours = []int{0, 24, 168}

// SecurityTrivyConfig is [security.scan.trivy] (component
// security.scan.trivy).
type SecurityTrivyConfig struct {
	// PostWrite scans the project a short while after an agent writes a
	// file in an IaC path class (Dockerfile, Terraform, Kubernetes, Helm,
	// CloudFormation). Default false (off).
	PostWrite bool `toml:"post_write"`
	// ScheduleHours runs a scan of each project active in the last week
	// once per this many hours; one of SecurityIaCScheduleHours, 0 (the
	// default) is off.
	ScheduleHours int `toml:"schedule_hours"`
	// RunOnBattery lets scheduled runs go ahead on battery. Default false:
	// scheduled runs hold while the machine runs on battery or its power
	// state cannot be read.
	RunOnBattery bool `toml:"run_on_battery"`
	// AllowRepoConfig lets Trivy read the project's own .trivyignore and
	// trivy.yaml. Default false: the repository is untrusted input (plan
	// 4.4 ConfigInputs), and the offline flags stay on either way.
	AllowRepoConfig bool `toml:"allow_repo_config"`
	// AllowUnpinned lets a Trivy binary that no pin vouches for (one found
	// on PATH, for example) run on this individual node, every result
	// labelled unverified. Default false: such a binary is refused. A
	// managed node refuses it whatever this says (ruling P-143).
	AllowUnpinned bool `toml:"allow_unpinned"`
}

// SecurityKICSConfig is [security.scan.kics] (component
// security.scan.kics). Its keys mean what [security.scan.trivy]'s do;
// AllowRepoConfig covers the project's kics.config files.
type SecurityKICSConfig struct {
	PostWrite       bool `toml:"post_write"`
	ScheduleHours   int  `toml:"schedule_hours"`
	RunOnBattery    bool `toml:"run_on_battery"`
	AllowRepoConfig bool `toml:"allow_repo_config"`
	AllowUnpinned   bool `toml:"allow_unpinned"`
}

// validateSecurityIaC checks one IaC section's schedule.
func validateSecurityIaC(section string, scheduleHours int) error {
	if !slices.Contains(SecurityIaCScheduleHours, scheduleHours) {
		return fmt.Errorf("config: %s.schedule_hours %d not in %v", section, scheduleHours, SecurityIaCScheduleHours)
	}
	return nil
}

// iacSecuritySettings are the settings-contract rows of the two sections
// (their home is the Code security page's IaC driver card).
func iacSecuritySettings() []SecuritySetting {
	var out []SecuritySetting
	for _, engine := range []string{"trivy", "kics"} {
		k := "security.scan." + engine + "."
		home := "Code security > IaC drivers"
		gate := " (acts only while security.scan." + engine + " is selected and installed)"
		out = append(out,
			SecuritySetting{Key: k + "post_write", Class: SettingLocal, Values: "Off / On", Default: "Off" + gate, NodeHome: home},
			SecuritySetting{Key: k + "schedule_hours", Class: SettingLocal, Values: "0 (off) / 24 / 168", Default: "0 (off)", NodeHome: home},
			SecuritySetting{Key: k + "run_on_battery", Class: SettingLocal, Values: "Off / On", Default: "Off (scheduled runs hold on battery)", NodeHome: home},
			SecuritySetting{Key: k + "allow_repo_config", Class: SettingLocal, Values: "Off / On", Default: "Off (the project's own scanner config is ignored)", NodeHome: home},
			SecuritySetting{Key: k + "allow_unpinned", Class: SettingLocal, Values: "Off / On", Default: "Off (a binary no pin vouches for is refused; never runs on a managed node)", NodeHome: home},
		)
	}
	return out
}
