package config

import (
	"fmt"
	"sync/atomic"
)

// component_sections.go makes config validation component-aware (the shared
// optional-module contract, lane OPTMOD; sandbox plan v2 section 10 "No
// section is required", security plan section 4.3 "No required config").
//
// A config section that belongs to an OPTIONAL component (terminals.sandbox
// today, the security module's [security] tomorrow) is checked from the table
// below, not from the core Validate body. The two entry points differ on
// purpose:
//
//   - Validate is strict. It checks every row, whatever the component state,
//     so a save path (the dashboard, `observer config set`) never writes a bad
//     value, and a component turned on later finds a file that validates.
//   - Load is component-aware. Before Validate runs, a row whose section does
//     not validate AND whose component is not active (inactive, blocked or
//     compiled out) is set aside: the loaded copy gets that section's
//     defaults, Config.Inert gets one line, and the file keeps the operator's
//     value. A config written while a module was on therefore never stops a
//     node that later turns the module off. While the component is active the
//     row fails Load exactly as before.
//
// A valid section of an inactive component is left as it is: its keys are
// inert because nothing of the component runs (the daemon also applies its
// start-time inert overlay, cmd/observer/components_gate.go).
//
// "The file keeps the operator's value" holds for the key-level save path
// (config.PatchFile, which writes only the changed leaves). A save that
// rewrites the whole file from a loaded Config (config.WriteToml) writes the
// set-aside section's defaults back, exactly as it already does for a
// Deferred setting; the bad value was unusable either way.
//
// The package cannot resolve component state itself (internal/componentstate
// imports this package), so the one resolver is injected: componentstate
// registers it with SetComponentGate when it is linked, which every observer
// binary does. With no gate registered (a binary or a test that never links
// componentstate) every row counts as active, which is today's strict
// behaviour.
//
// The gate resolves the loaded [components] block WITHOUT managed governance,
// which is read later at the cmd boundary. Both possible disagreements are
// safe: an organization that requires a module the local block leaves off
// gets a module that runs on the section's valid defaults (the bad value is
// set aside with its line), and an organization that blocks a module the
// local block selects gets today's strict load error.

// componentSection is one config section an optional component owns.
type componentSection struct {
	// component is the node catalog id (internal/components) that owns the
	// section. internal/componentstate's
	// TestComponentSectionsNameOptionalNodeComponents pins it to an optional
	// node catalog row.
	component string
	// section is the dotted TOML table, for the Inert line and the docs.
	section string
	// validate checks the section on c. Nil error means it is valid.
	validate func(c *Config) error
	// reset puts the section back to its Default() value on c.
	reset func(c *Config)
}

// componentSections is the table, walked top-down (CLAUDE.md module rule 5).
// A new optional module adds one row per section it owns and nothing else:
//
//	{
//		component: "security",
//		section:   "security",
//		validate:  func(c *Config) error { return validateSecurity(c.Security) },
//		reset:     func(c *Config) { c.Security = Default().Security },
//	},
var componentSections = []componentSection{
	{
		component: "terminals.sandbox",
		section:   "terminal.sandbox",
		validate:  func(c *Config) error { return validateTerminalSandbox(c.Terminal.Sandbox) },
		reset:     func(c *Config) { c.Terminal.Sandbox = Default().Terminal.Sandbox },
	},
	{
		// The hosted rows' shared block (lane SBX-P7): owned by the module,
		// read by the three hosted drivers.
		component: "terminals.sandbox",
		section:   "terminal.sandbox.hosted",
		validate:  func(c *Config) error { return validateTerminalSandboxHosted(c.Terminal.Sandbox.Hosted) },
		reset:     func(c *Config) { c.Terminal.Sandbox.Hosted = Default().Terminal.Sandbox.Hosted },
	},
	{
		component: "terminals.sandbox.oci",
		section:   "terminal.sandbox.oci",
		validate:  func(c *Config) error { return validateTerminalSandboxOCI(c.Terminal.Sandbox.OCI) },
		reset:     func(c *Config) { c.Terminal.Sandbox.OCI = Default().Terminal.Sandbox.OCI },
	},
	{
		component: "terminals.sandbox.mxc",
		section:   "terminal.sandbox.mxc",
		validate:  func(c *Config) error { return validateTerminalSandboxMXC(c.Terminal.Sandbox.MXC) },
		reset:     func(c *Config) { c.Terminal.Sandbox.MXC = Default().Terminal.Sandbox.MXC },
	},
	{
		component: "terminals.sandbox.apple-container",
		section:   "terminal.sandbox.apple_container",
		validate:  func(c *Config) error { return validateTerminalSandboxAppleContainer(c.Terminal.Sandbox.AppleContainer) },
		reset:     func(c *Config) { c.Terminal.Sandbox.AppleContainer = Default().Terminal.Sandbox.AppleContainer },
	},
	{
		component: "terminals.sandbox.landlock",
		section:   "terminal.sandbox.landlock",
		validate:  func(c *Config) error { return validateTerminalSandboxLandlock(c.Terminal.Sandbox.Landlock) },
		reset:     func(c *Config) { c.Terminal.Sandbox.Landlock = Default().Terminal.Sandbox.Landlock },
	},
	{
		component: "terminals.sandbox.vm",
		section:   "terminal.sandbox.vm",
		validate:  func(c *Config) error { return validateTerminalSandboxVM(c.Terminal.Sandbox.VM) },
		reset:     func(c *Config) { c.Terminal.Sandbox.VM = Default().Terminal.Sandbox.VM },
	},
	{
		component: "security",
		section:   "security",
		validate:  func(c *Config) error { return validateSecurity(c.Security) },
		reset:     func(c *Config) { c.Security.Retention = Default().Security.Retention },
	},
	{
		// [security.scanning] (lane LEFT-SEC): the module root's own keys.
		component: "security",
		section:   "security.scanning",
		validate:  func(c *Config) error { return validateSecurityScanning(c.Security.Scanning) },
		reset:     func(c *Config) { c.Security.Scanning = Default().Security.Scanning },
	},
	{
		component: "security.trust",
		section:   "security.trust",
		validate:  func(c *Config) error { return validateSecurityTrust(c.Security.Trust) },
		reset:     func(c *Config) { c.Security.Trust = Default().Security.Trust },
	},
	{
		component: "security.deps",
		section:   "security.deps",
		validate:  func(c *Config) error { return validateSecurityDeps(c.Security.Deps) },
		reset:     func(c *Config) { c.Security.Deps = Default().Security.Deps },
	},
	{
		component: "security.scan.custom",
		section:   "security.custom",
		validate:  func(c *Config) error { return validateSecurityCustom(c.Security.Custom) },
		reset:     func(c *Config) { c.Security.Custom = Default().Security.Custom },
	},
	{
		component: "security.scan.opengrep",
		section:   "security.scan.opengrep",
		validate:  func(c *Config) error { return validateSecurityOpengrep(c.Security.Scan.Opengrep) },
		reset:     func(c *Config) { c.Security.Scan.Opengrep = Default().Security.Scan.Opengrep },
	},
	{
		component: "security.scan.trivy",
		section:   "security.scan.trivy",
		validate: func(c *Config) error {
			return validateSecurityIaC("security.scan.trivy", c.Security.Scan.Trivy.ScheduleHours)
		},
		reset: func(c *Config) { c.Security.Scan.Trivy = SecurityTrivyConfig{} },
	},
	{
		component: "security.scan.kics",
		section:   "security.scan.kics",
		validate: func(c *Config) error {
			return validateSecurityIaC("security.scan.kics", c.Security.Scan.Kics.ScheduleHours)
		},
		reset: func(c *Config) { c.Security.Scan.Kics = SecurityKICSConfig{} },
	},
}

// ComponentSection names one row of the component section table.
type ComponentSection struct {
	// Component is the owning node catalog id.
	Component string
	// Section is the dotted TOML table.
	Section string
}

// ComponentSections lists the config sections optional components own, in
// table order (the coverage tests and the docs read it).
func ComponentSections() []ComponentSection {
	out := make([]ComponentSection, 0, len(componentSections))
	for _, s := range componentSections {
		out = append(out, ComponentSection{Component: s.component, Section: s.section})
	}
	return out
}

// ComponentGate reports whether the catalog component id is active for the
// [components] block sel. It must answer false for an id it does not know
// (an optional module fails invisible, componentstate.Snapshot.ModuleActive).
type ComponentGate func(sel ComponentsConfig, id string) bool

var componentGate atomic.Pointer[ComponentGate]

// SetComponentGate registers the resolver Load uses to decide whether a
// component-owned section is validated. internal/componentstate calls it once
// when linked; nil removes it (every row is then validated, the strict
// behaviour). It returns the previous gate so a test can restore it.
func SetComponentGate(g ComponentGate) ComponentGate {
	var prev *ComponentGate
	if g == nil {
		prev = componentGate.Swap(nil)
	} else {
		prev = componentGate.Swap(&g)
	}
	if prev == nil {
		return nil
	}
	return *prev
}

// validateComponentSections is Validate's strict pass over the table.
func validateComponentSections(c *Config) error {
	for _, s := range componentSections {
		if err := s.validate(c); err != nil {
			return err
		}
	}
	return nil
}

// setAsideInactiveSections is Load's component-aware pass: every row that
// does not validate and whose component the registered gate says is not
// active is reset to its defaults on c, with one line each, in table order.
// The gate is consulted only for a row that fails, so a valid config costs no
// component resolution.
func setAsideInactiveSections(c *Config) []string {
	gp := componentGate.Load()
	if gp == nil {
		return nil
	}
	var out []string
	for _, s := range componentSections {
		err := s.validate(c)
		if err == nil || (*gp)(c.Components, s.component) {
			continue
		}
		s.reset(c)
		out = append(out, fmt.Sprintf("[%s] is not used while component %s is not active, so this setting is ignored: %v. Fix the value before turning %s on (Settings > Components).", s.section, s.component, err, s.component))
	}
	return out
}
