//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxsetup"
)

// sandbox_setup_coverage_test.go holds the coverage tests a new sandbox
// backend's setup rows must pass (docs/sandbox-backend-checklist.md,
// section B, boxes B3 and B4). Each one turns a 2026-11-07 live defect
// class into a table check, so the next provider fails here instead of on a
// rented host.

// sandboxSetupProbeOnly are the prerequisites with no passive fact rule:
// only the active check (the driver's probe) can judge them, so a passive
// plan reads them unknown ("set up, not checked" once the enable step is
// done) and a step of theirs settles from the check after exit 0
// (sandboxSettleRules checked_done). Each entry says what a stat or a read
// cannot know without exec or dial (ruling R1).
var sandboxSetupProbeOnly = map[string]string{
	"userns":                  "whether the kernel lets this user create user and network namespaces: only creating one (bwrap's canary) tells",
	"landlock-abi":            "the running kernel's Landlock ABI: read by a syscall in the driver's probe",
	"kvm-device":              "whether /dev/kvm is usable: the vm probe opens it",
	"kvm-group":               "whether this user can open /dev/kvm: the vm probe opens it (a group read alone misses a login that predates the change)",
	"oci-image":               "whether the engine holds the image by digest: only asking the engine over its socket tells",
	"runsc-registered":        "whether Docker has runsc registered with host-uds open: only asking the engine tells",
	"openshell-supervisor":    "whether the systemd user manager runs for this user: the gateway probe asks it",
	"macos-12":                "the macOS version: the seatbelt probe reads it (a passive sysctl read was suggested in D-L5-1 and not built)",
	"macos-26-arm":            "the macOS version, the architecture and the hypervisor: the Apple probe reads them",
	"apple-container-service": "whether Apple's container system service runs: only `container system status` tells",
	"apple-container-image":   "whether Apple's image store holds the configured digest: only `container image list` tells",
	"win-build-psec":          "whether this Windows build offers the MXC container tier: the MXC library answers it",
}

// firstFactRule is the name of the first fact rule matching p ("" when none).
func firstFactRule(p sandboxsetup.Prereq) string {
	for _, r := range factRules {
		if r.match(p) {
			return r.name
		}
	}
	return ""
}

// TestSandboxSetupEveryPrereqHasAFactOrIsProbeOnly (box B3): every
// prerequisite of the table is judged by a passive fact rule or is declared
// probe-only above, never both; a probe-only prerequisite has a verdict a
// check can stop at (else nothing could ever read it missing: F15); a
// Detect.PathKey has its reader (else a placed file is never seen: F4); a
// config prerequisite's key has its reader.
func TestSandboxSetupEveryPrereqHasAFactOrIsProbeOnly(t *testing.T) {
	for _, id := range sandboxsetup.IDs() {
		p, _ := sandboxsetup.Lookup(id)
		rule := firstFactRule(p)
		why, probeOnly := sandboxSetupProbeOnly[id]
		switch {
		case rule == "" && !probeOnly:
			t.Errorf("%s: no passive fact rule matches its Detect shape and it is not declared probe-only; add a factRules row or a sandboxSetupProbeOnly entry saying what a stat cannot know", id)
		case rule != "" && probeOnly:
			t.Errorf("%s: declared probe-only but fact rule %q matches it; drop the stale entry", id, rule)
		case probeOnly && why == "":
			t.Errorf("%s: probe-only with no reason", id)
		}
		if probeOnly && len(p.Detect.Verdicts) == 0 {
			t.Errorf("%s: probe-only, yet no verdict map row names it, so no check can ever read it missing", id)
		}
		if p.Detect.PathKey != "" && sandboxPathKeys[p.Detect.PathKey] == nil {
			t.Errorf("%s: Detect.PathKey %q has no reader in sandboxPathKeys", id, p.Detect.PathKey)
		}
		if p.Kind == sandboxsetup.KindConfig && sandboxConfigKeyFacts[p.Detect.ConfigKey] == nil {
			t.Errorf("%s: config prerequisite key %q has no reader in sandboxConfigKeyFacts", id, p.Detect.ConfigKey)
		}
	}
	for id := range sandboxSetupProbeOnly {
		if _, ok := sandboxsetup.Lookup(id); !ok {
			t.Errorf("probe-only %q is not a prerequisite", id)
		}
	}
}

// TestSandboxSetupRemedyPackagesHaveRunners (box B4): a remedy that reads
// runnable can run. A pinned download's pin is compiled in, the runner
// knows the config key it writes, and that key is the prerequisite's own
// Detect.PathKey (so the placed file is detected, F4); a config remedy's
// key has a setter and a reader; an oci_pull remedy's engine has a pull
// verb (else the step reads runnable and is refused, D-L5b-1).
func TestSandboxSetupRemedyPackagesHaveRunners(t *testing.T) {
	for _, id := range sandboxsetup.IDs() {
		p, _ := sandboxsetup.Lookup(id)
		for _, r := range p.Remedies {
			switch r.Channel {
			case sandboxsetup.ChPinned:
				if _, ok := sandboxsetup.PinFor(r.Package); !ok {
					t.Errorf("%s: pinned remedy %q has no compiled pin", id, r.Package)
				}
				key, ok := sandboxPinConfigKeys[r.Package]
				if !ok {
					t.Errorf("%s: pin %q has no sandboxPinConfigKeys entry (where the placed path is written)", id, r.Package)
				} else if key != p.Detect.PathKey {
					t.Errorf("%s: the runner writes %q but Detect.PathKey is %q, so the placed file would read missing", id, key, p.Detect.PathKey)
				}
			case sandboxsetup.ChConfig:
				if _, ok := sandboxConfigKeySetters[r.Package]; !ok {
					t.Errorf("%s: config remedy key %q has no sandboxConfigKeySetters entry", id, r.Package)
				}
				if sandboxConfigKeyFacts[r.Package] == nil {
					t.Errorf("%s: config remedy key %q has no sandboxConfigKeyFacts reader", id, r.Package)
				}
			case sandboxsetup.ChOCIPull:
				if _, ok := sandboxPullArgv[r.Package]; !ok {
					t.Errorf("%s: oci_pull remedy engine %q has no sandboxPullArgv verb, so the step would read runnable and be refused", id, r.Package)
				}
			}
		}
	}
}
