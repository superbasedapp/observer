package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/BurntSushi/toml"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/policyfam"
)

// The managed write hold (plans decision P-047, SEC-E merge step 9).

// releasedLoaderFamilies is the closed family set of the released loaders,
// copied from v1.34.0-rc.11 internal/config (v1.36.0 accepts these and
// node.components): a family outside it in accept_families or
// preauthorize_enforce makes those binaries refuse the whole config.
var releasedLoaderFamilies = []string{
	"admission.input", "egress.routing_guardrail", "gateway.providers", "node.features",
	"node.governance", "planeb.admission", "tools.mcp_access",
}

// releasedLoad reproduces the released loader's rules for [org_client.policy]
// (v1.34.0-rc.11 and v1.36.0, internal/config mergeTOMLFile and
// validateOrgClientPolicy): BurntSushi toml.Decode into the config struct
// with NO undecoded-key check, so an unknown key is ignored, then the
// closed-set check on the two keys it knows.
func releasedLoad(raw string) error {
	var c struct {
		OrgClient struct {
			Policy struct {
				AcceptFamilies      []string `toml:"accept_families"`
				PreauthorizeEnforce []string `toml:"preauthorize_enforce"`
			} `toml:"policy"`
		} `toml:"org_client"`
	}
	if _, err := toml.Decode(raw, &c); err != nil {
		return err
	}
	accepted := map[string]bool{}
	for _, f := range c.OrgClient.Policy.AcceptFamilies {
		if !slices.Contains(releasedLoaderFamilies, f) {
			return fmt.Errorf("accept_families contains unsupported family %q", f)
		}
		accepted[f] = true
	}
	for _, f := range c.OrgClient.Policy.PreauthorizeEnforce {
		if !slices.Contains(releasedLoaderFamilies, f) || !accepted[f] {
			return fmt.Errorf("preauthorize_enforce contains %q", f)
		}
	}
	return nil
}

// TestReleasedPolicyFamiliesAreFrozen pins config's released set to the
// released loaders' own list, and both module families outside it.
func TestReleasedPolicyFamiliesAreFrozen(t *testing.T) {
	for _, f := range releasedLoaderFamilies {
		if !config.IsReleasedPolicyFamily(f) {
			t.Errorf("%s is accepted by every released loader", f)
		}
	}
	for _, f := range []string{policyfam.FamilySecurityScanning, policyfam.FamilyTerminalsIsolation, policyfam.FamilyNodeComponents} {
		if config.IsReleasedPolicyFamily(f) {
			t.Errorf("%s is not known to every released loader; it must go to the module keys", f)
		}
	}
}

// TestTheReleasedLoaderRefusesAModuleFamilyInTheOldKey is the hazard the
// hold existed for, reproduced: the released rules refuse the old key with
// a module family and ignore the new key.
func TestTheReleasedLoaderRefusesAModuleFamilyInTheOldKey(t *testing.T) {
	if err := releasedLoad("[org_client.policy]\naccept_families = [\"security.scanning\"]\n"); err == nil {
		t.Fatal("the released rules must refuse a module family in accept_families")
	}
	if err := releasedLoad("[org_client.policy]\naccept_module_families = [\"security.scanning\"]\npreauthorize_module_enforce = [\"security.scanning\"]\n"); err != nil {
		t.Fatalf("the released rules must ignore the unknown module keys: %v", err)
	}
}

// TestModuleFamiliesGoToTheModuleKeys: the backfill adds the module
// families to the additive keys only; the old keys' bytes are unchanged, a
// config the new code wrote still loads under the released rules, and this
// build reads both keys together.
func TestModuleFamiliesGoToTheModuleKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	const oldKeys = "accept_families = [\"node.features\", \"node.governance\"]   # the developer's own note\n" +
		"preauthorize_enforce = [\"node.features\"]\n"
	orig := "[org_client]\nenabled = false\n\n[org_client.policy]\n" + oldKeys + "node_workspace = \"ws\"\n"
	if err := os.WriteFile(path, []byte(orig), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	add := []string{policyfam.FamilySecurityScanning, policyfam.FamilyTerminalsIsolation}
	if err := addManagedPolicyFamilies(path, cfg.OrgClient.Policy, add); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(raw)
	if !strings.Contains(got, oldKeys) {
		t.Fatalf("the old keys' bytes changed:\n%s", got)
	}
	for _, want := range []string{
		`accept_module_families = ["security.scanning", "terminals.isolation"]`,
		`preauthorize_module_enforce = ["security.scanning", "terminals.isolation"]`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s in:\n%s", want, got)
		}
	}
	if err := releasedLoad(got); err != nil {
		t.Fatalf("a config written by the new code must load under the released rules: %v\n%s", err, got)
	}
	cfg, err = config.Load(config.LoadOptions{GlobalPath: path})
	if err != nil {
		t.Fatal(err)
	}
	acc := cfg.OrgClient.Policy.AcceptedFamilies()
	sort.Strings(acc)
	if strings.Join(acc, ",") != "node.features,node.governance,security.scanning,terminals.isolation" {
		t.Fatalf("accepted = %v", acc)
	}
	if pre := cfg.OrgClient.Policy.PreauthorizedFamilies(); !slices.Contains(pre, policyfam.FamilySecurityScanning) || slices.Contains(pre, "node.governance") {
		t.Fatalf("preauthorized = %v", pre)
	}
}

// TestTheEnrolmentWriteSplitsTheFamilies: the enrolment write puts a mixed
// family list into the two pairs of keys, and the result loads under the
// released rules and in this build.
func TestTheEnrolmentWriteSplitsTheFamilies(t *testing.T) {
	for _, tc := range []struct {
		name string
		orig string
	}{
		{"no table", ""},
		{"table without the keys", "[org_client.policy]\nnode_workspace = \"ws\"\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if tc.orig != "" {
				if err := os.WriteFile(path, []byte(tc.orig), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			families := []string{"node.features", policyfam.FamilySecurityScanning, "node.governance", policyfam.FamilyTerminalsIsolation}
			if added, err := ensureManagedPolicyBlock(path, families); err != nil || !added {
				t.Fatalf("ensureManagedPolicyBlock = %v %v", added, err)
			}
			raw, _ := os.ReadFile(path)
			got := string(raw)
			for _, want := range []string{
				`accept_families = ["node.features", "node.governance"]`,
				`preauthorize_enforce = ["node.features", "node.governance"]`,
				`accept_module_families = ["security.scanning", "terminals.isolation"]`,
				`preauthorize_module_enforce = ["security.scanning", "terminals.isolation"]`,
			} {
				if !strings.Contains(got, want) {
					t.Fatalf("missing %s in:\n%s", want, got)
				}
			}
			if err := releasedLoad(got); err != nil {
				t.Fatalf("released rules: %v\n%s", err, got)
			}
			cfg, err := config.Load(config.LoadOptions{GlobalPath: path})
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.OrgClient.Policy.AcceptedFamilies()) != 4 {
				t.Fatalf("accepted = %v", cfg.OrgClient.Policy.AcceptedFamilies())
			}
			// A second write finds every key and changes nothing.
			if added, err := ensureManagedPolicyBlock(path, families); err != nil || added {
				t.Fatalf("second write = %v %v", added, err)
			}
		})
	}
}

// TestTheWriteHoldIsReleased: neither module family is held any more; a
// linked one is offered by the managed write.
func TestTheWriteHoldIsReleased(t *testing.T) {
	for _, f := range []string{policyfam.FamilySecurityScanning, policyfam.FamilyTerminalsIsolation} {
		if why := managedFamilyWriteHeld[f]; why != "" {
			t.Errorf("%s is still held: %s", f, why)
		}
		if got := linkedManagedFamilies([]string{f}); policyfam.IsFamilyLinked(f) != (len(got) == 1) {
			t.Errorf("%s: linked %v, offered %v", f, policyfam.IsFamilyLinked(f), got)
		}
	}
}
