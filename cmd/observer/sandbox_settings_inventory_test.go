//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam/nodegov"
	"github.com/marmutapp/superbased-observer/internal/policyfam/terminalsisolation"
	"github.com/marmutapp/superbased-observer/internal/testsupport/publictree"
)

// adminHome is where an admin sets a [terminal.sandbox] key in web2 (sandbox
// plan v2 section 10.1). Exactly one field is set per row.
type adminHome struct {
	// Pin: the key is a settings.pin row (Node governance pin panel).
	Pin string
	// Floor: an org floor of terminals.isolation (Node features, isolation
	// floors section).
	Floor string
	// FeatureGate: the node.features lever named here.
	FeatureGate string
	// Owed: the admin home is built by a later lane (named), on the managed
	// pull or Node detail; only the keys in owedAdminHomes may say so.
	Owed string
	// Nested: the key is a sub-table with its own inventory (named).
	Nested string
	// Managed: the key's admin home is this field of the managed sandbox
	// body (web2's Sandbox section, SandboxManagedSection.tsx).
	Managed string
	// Local: the key is local-only by design (named reason): an org has no
	// fleet-wide value for it, so no admin home exists or may be built.
	Local string
	// OrgPin: the key is an org-only settings.pin row whose local value no
	// launch ever reads (the proxy.maintain_routes precedent), so it has no
	// node home by design: a card control would edit a value nothing reads.
	OrgPin string
}

// sandboxSettingsInventory is the section 9 / 10.1 inventory: every
// [terminal.sandbox] key with its admin home. Its node home is the Sandbox
// isolation card, checked against the card's source below.
var sandboxSettingsInventory = map[string]adminHome{
	"enabled":                  {FeatureGate: "terminals.sandbox_required"},
	"backend":                  {Pin: "terminal.sandbox.backends"},
	"backends":                 {Pin: "terminal.sandbox.backends"},
	"home_mode":                {Pin: "terminal.sandbox.home_mode"},
	"default_on":               {Pin: "terminal.sandbox.default_on"},
	"allow_remote_clone":       {Pin: "terminal.sandbox.allow_remote_clone"},
	"remote_allowed_hosts":     {Pin: "terminal.sandbox.remote_allowed_hosts"},
	"allow_worktree_source":    {Pin: "terminal.sandbox.allow_worktree_source"},
	"workspaces_dir":           {Owed: "SBX-P1C (per-node path override on the managed pull, Node detail)"},
	"workspace_retention_days": {Pin: "terminal.sandbox.workspace_retention_days"},
	"mask_paths":               {Pin: "terminal.sandbox.mask_paths"},
	"extra_ro_binds":           {Pin: "terminal.sandbox.extra_ro_binds"},
	"extra_rw_binds":           {Pin: "terminal.sandbox.extra_rw_binds"},
	"prep_timeout_seconds":     {Pin: "terminal.sandbox.prep_timeout_seconds"},
	"live_run_update_policy":   {Pin: "terminal.sandbox.live_run_update_policy"},
	"egress":                   {Floor: "min_egress"},
	"egress_allow_cidrs":       {Pin: "terminal.sandbox.egress_allow_cidrs"},
	"egress_allow_hosts":       {Pin: "terminal.sandbox.egress_allow_hosts"},
	"allow_tool_config_writes": {Pin: "terminal.sandbox.allow_tool_config_writes"},
	// The developer's own environment variables (WINFIX2 R-167): local-only.
	"pass_env": {Local: "names the developer's own environment variables; an org has no fleet-wide value and cannot widen a box's environment"},
	// The developer's own clipboard through the terminal (ruling P-175):
	// local-only.
	// The developer's own consent to copying a tool's sign-in into a box
	// (lane BOXSIGNIN): the org cannot turn it on; it can only forbid it,
	// through the managed body's sign_in_seed_forbidden.
	"sign_in_seed_tools":    {Local: "the developer's own consent to copy a sign-in they hold; an org has no fleet-wide value and can only forbid seeding (the managed body's sign_in_seed_forbidden)"},
	"allow_osc52_clipboard": {Local: "the developer's own clipboard through their own terminal; an org has no fleet-wide value and cannot widen what a box reaches"},
	// What a vendor-forced native sandbox does (lane SBX-P3D).
	"vendor_forced_native": {Pin: "terminal.sandbox.vendor_forced_native"},
	// The organization's direct provider egress posture (DEC-9, OBS-8a):
	// honoured only as a pin on a managed node; the node sees its effect in
	// the computed capture per tier.
	"provider_direct": {OrgPin: "terminal.sandbox.provider_direct"},
	"min_isolation":   {Floor: "min_isolation"},
	// The container driver's block (lane SBX-P3A) has its own inventory.
	"oci": {Nested: "sandboxOCISettingsInventory"},
	// The macOS drivers' blocks (lane SBX-P5) have their own inventories
	// (terminal_sandbox_seatbelt_test.go).
	"seatbelt":        {Nested: "sandboxMacSettingsInventory"},
	"apple_container": {Nested: "sandboxMacSettingsInventory"},
	// The Windows driver's block (lane SBX-P6) has its own inventory.
	"mxc": {Nested: "sandboxMXCSettingsInventory"},
	// The Landlock-only row's block (lane SBX-P3B) has its own inventory.
	"landlock": {Nested: "sandboxLandlockSettingsInventory"},
	// The hosted rows' block (lane SBX-P7) has its own inventory
	// (terminal_sandbox_hosted_test.go).
	"hosted": {Nested: "sandboxHostedSettingsInventory"},
	// The microVM row's block (lane SBX-P4) has its own inventory
	// (terminal_sandbox_vm_test.go).
	"vm": {Nested: "sandboxVMSettingsInventory"},
	// Lane GATES-SBX's blocks have their own inventory
	// (sandbox_gates_inventory_test.go).
	"readopt": {Nested: "sandboxGatesSettingsInventory"},
	"wslc":    {Nested: "sandboxGatesSettingsInventory"},
	"hcs":     {Nested: "sandboxGatesSettingsInventory"},
	"windows": {Nested: "sandboxGatesSettingsInventory"},
}

// sandboxLandlockSettingsInventory is the [terminal.sandbox.landlock]
// inventory: its node home is the Landlock-only sandboxes panel
// (SandboxLandlockPanel.tsx).
var sandboxLandlockSettingsInventory = map[string]adminHome{
	"min_abi": {Pin: "terminal.sandbox.landlock.min_abi"},
}

// sandboxMXCSettingsInventory is the [terminal.sandbox.mxc] inventory: its
// node home is the Windows sandboxes panel (SandboxWindowsPanel.tsx).
var sandboxMXCSettingsInventory = map[string]adminHome{
	"stop_grace_seconds":    {Pin: "terminal.sandbox.mxc.stop_grace_seconds"},
	"probe_timeout_seconds": {Pin: "terminal.sandbox.mxc.probe_timeout_seconds"},
}

// sandboxOCISettingsInventory is the [terminal.sandbox.oci] inventory: its
// node home is the Container sandboxes panel (SandboxOCIPanel.tsx).
var sandboxOCISettingsInventory = map[string]adminHome{
	"allow_rootful":            {Pin: "terminal.sandbox.oci.allow_rootful"},
	"allow_devcontainer_image": {Pin: "terminal.sandbox.oci.allow_devcontainer_image"},
	"podman_userns":            {Pin: "terminal.sandbox.oci.podman_userns"},
	"stop_grace_seconds":       {Pin: "terminal.sandbox.oci.stop_grace_seconds"},
	"socket":                   {Owed: "a machine path: a per-node override on the managed pull, never a fleet pin"},
	"image":                    {Pin: "terminal.sandbox.oci.image"},
	"install_cache":            {Pin: "terminal.sandbox.oci.install_cache"},
	// Lane LEFT-SBX (ruling P-136): the mode is a governance pin and a body
	// floor; the tool list and the pins are body fields; the version is a
	// per-node choice with no fleet value.
	"install_scripts":       {Pin: "terminal.sandbox.oci.install_scripts"},
	"install_scripts_tools": {Managed: "install_scripts.tools"},
	"install_script_pins":   {Managed: "install_scripts.pins"},
	"install_versions":      {Owed: "a per-node choice of the version to install; an org has no fleet-wide value for it"},
}

// owedAdminHomes are the only keys whose admin home may still be owed: a
// machine path has no fleet-wide pin, and its per-node override arrives
// with the managed pull.
var owedAdminHomes = map[string]bool{"workspaces_dir": true, "oci.socket": true, "oci.install_versions": true}

// TestSandboxSettingsInventory walks every [terminal.sandbox] key in the
// config schema and fails when a key has no row, no node home in the
// Sandbox isolation card, or no admin home that exists in this build.
func TestSandboxSettingsInventory(t *testing.T) {
	card, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxSettingsCard.tsx"))
	if err != nil {
		t.Fatalf("read the card: %v", err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxConfig{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		if key == "" || key == "-" {
			continue
		}
		seen[key] = true
		home, ok := sandboxSettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox].%s has no inventory row (no node or admin home)", key)
			continue
		}
		if home.OrgPin == "" && !strings.Contains(string(card), "draft."+key) && !strings.Contains(string(card), `"`+key+`"`) {
			t.Errorf("[terminal.sandbox].%s has no node home: the Sandbox isolation card does not edit it", key)
		}
		switch {
		case home.Pin != "":
			if !nodegov.IsPinnableKey(home.Pin) {
				t.Errorf("%s: admin home pin %q is not a settings.pin row", key, home.Pin)
			}
		case home.OrgPin != "":
			if !nodegov.IsPinnableKey(home.OrgPin) {
				t.Errorf("%s: org-only pin %q is not a settings.pin row", key, home.OrgPin)
			}
		case home.Floor != "":
			if _, ok := terminalsisolation.LookupFloorKey(home.Floor); !ok {
				t.Errorf("%s: admin home floor %q is not a terminals.isolation key", key, home.Floor)
			}
		case home.FeatureGate != "":
		case home.Nested != "":
		case home.Local != "":
			if nodegov.IsPinnableKey(sandboxPinPrefix + key) {
				t.Errorf("%s: a local-only key is a settings.pin row", key)
			}
		case home.Owed != "":
			if !owedAdminHomes[key] {
				t.Errorf("%s: only %v may have an owed admin home", key, owedAdminHomes)
			}
		default:
			t.Errorf("[terminal.sandbox].%s has no admin home", key)
		}
	}
	for key := range sandboxSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no [terminal.sandbox] key", key)
		}
	}
	// Every sandbox pin row is an inventory admin home (no pin row without
	// a config key it governs).
	for _, k := range nodegov.PinnableKeys {
		if !strings.HasPrefix(k.Key, sandboxPinPrefix) {
			continue
		}
		rest := strings.TrimPrefix(k.Key, sandboxPinPrefix)
		if sub, ok := strings.CutPrefix(rest, "oci."); ok {
			if _, ok := sandboxOCISettingsInventory[sub]; !ok {
				t.Errorf("pin row %s has no inventory row", k.Key)
			}
			continue
		}
		if sub, ok := strings.CutPrefix(rest, "mxc."); ok {
			if _, ok := sandboxMXCSettingsInventory[sub]; !ok {
				t.Errorf("pin row %s has no inventory row", k.Key)
			}
			continue
		}
		if sub, ok := strings.CutPrefix(rest, "landlock."); ok {
			if _, ok := sandboxLandlockSettingsInventory[sub]; !ok {
				t.Errorf("pin row %s has no inventory row", k.Key)
			}
			continue
		}
		if _, ok := sandboxMacSettingsInventory[rest]; ok {
			continue
		}
		if _, ok := sandboxGatesSettingsInventory[rest]; ok {
			continue
		}
		if sub, ok := strings.CutPrefix(rest, "hosted."); ok {
			if _, ok := sandboxHostedSettingsInventory[sub]; !ok {
				t.Errorf("pin row %s has no inventory row", k.Key)
			}
			continue
		}
		if _, ok := sandboxSettingsInventory[rest]; !ok {
			t.Errorf("pin row %s has no inventory row", k.Key)
		}
	}
}

// TestSandboxOCISettingsInventory is the same walk over [terminal.sandbox.oci].
func TestSandboxOCISettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxOCIPanel.tsx"))
	if err != nil {
		t.Fatalf("read the panel: %v", err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxOCIConfig{})
	// web2 (the admin dashboard) is private-only: on the public tree the
	// managed-body editor check is skipped and the rest of the walk runs.
	public := publictree.In(publictree.RepoRoot(t))
	var managedSection []byte
	if !public {
		managedSection, err = os.ReadFile(filepath.Join("..", "..", "web2", "src", "components", "SandboxManagedSection.tsx"))
		if err != nil {
			t.Fatalf("read the managed section: %v", err)
		}
	}
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		if key == "-" {
			continue // filled by the managed compose, never a file key
		}
		seen[key] = true
		home, ok := sandboxOCISettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox.oci].%s has no inventory row", key)
			continue
		}
		if !strings.Contains(string(panel), `"`+key+`"`) {
			t.Errorf("[terminal.sandbox.oci].%s has no node home in the Container sandboxes panel", key)
		}
		switch {
		case home.Pin != "":
			if !nodegov.IsPinnableKey(home.Pin) {
				t.Errorf("%s: pin %q is not a settings.pin row", key, home.Pin)
			}
		case home.Managed != "":
			if !public && !strings.Contains(string(managedSection), home.Managed) {
				t.Errorf("oci.%s: the managed body field %q has no editor in web2's Sandbox section", key, home.Managed)
			}
		case home.Owed != "":
			if !owedAdminHomes["oci."+key] {
				t.Errorf("oci.%s: only %v may have an owed admin home", key, owedAdminHomes)
			}
		default:
			t.Errorf("[terminal.sandbox.oci].%s has no admin home", key)
		}
	}
	for key := range sandboxOCISettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no [terminal.sandbox.oci] key", key)
		}
	}
}

// TestSandboxMXCSettingsInventory is the same walk over [terminal.sandbox.mxc].
func TestSandboxMXCSettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxWindowsPanel.tsx"))
	if err != nil {
		t.Fatalf("read the panel: %v", err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxMXCConfig{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		seen[key] = true
		home, ok := sandboxMXCSettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox.mxc].%s has no inventory row", key)
			continue
		}
		if !strings.Contains(string(panel), `"`+key+`"`) {
			t.Errorf("[terminal.sandbox.mxc].%s has no node home in the Windows sandboxes panel", key)
		}
		if !nodegov.IsPinnableKey(home.Pin) {
			t.Errorf("%s: admin home pin %q is not a settings.pin row", key, home.Pin)
		}
	}
	for key := range sandboxMXCSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no [terminal.sandbox.mxc] key", key)
		}
	}
}

// TestSandboxLandlockSettingsInventory is the same walk over
// [terminal.sandbox.landlock] (lane SBX-P3B).
func TestSandboxLandlockSettingsInventory(t *testing.T) {
	panel, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "components", "SandboxLandlockPanel.tsx"))
	if err != nil {
		t.Fatalf("read the panel: %v", err)
	}
	typ := reflect.TypeOf(config.TerminalSandboxLandlockConfig{})
	seen := map[string]bool{}
	for i := 0; i < typ.NumField(); i++ {
		key := strings.SplitN(typ.Field(i).Tag.Get("toml"), ",", 2)[0]
		seen[key] = true
		home, ok := sandboxLandlockSettingsInventory[key]
		if !ok {
			t.Errorf("[terminal.sandbox.landlock].%s has no inventory row", key)
			continue
		}
		if !strings.Contains(string(panel), key) {
			t.Errorf("[terminal.sandbox.landlock].%s has no node home in the Landlock-only sandboxes panel", key)
		}
		if home.Pin == "" || !nodegov.IsPinnableKey(home.Pin) {
			t.Errorf("[terminal.sandbox.landlock].%s: pin %q is not a settings.pin row", key, home.Pin)
		}
	}
	for key := range sandboxLandlockSettingsInventory {
		if !seen[key] {
			t.Errorf("inventory row %q names no [terminal.sandbox.landlock] key", key)
		}
	}
}
