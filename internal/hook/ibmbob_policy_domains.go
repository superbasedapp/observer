package hook

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
)

// IBM Bob's macOS preferences domains, read by key NAME for reporting
// (surface-gap arc FU-105, operator decision 2026-10-27; MAC-4 report item
// 4). Bob Shell 2.0.6's native policy watcher reads the com.ibm.bob domain
// through CFPreferences, so a value the user wrote with `defaults write
// com.ibm.bob ...` (~/Library/Preferences/com.ibm.bob.plist, user-writable)
// is applied as policy just like the MDM plists under /Library/Managed
// Preferences. Observer reads that user domain as UNTRUSTED and report-only:
// it never makes the per-node registration stand down (ReadIBMBobPolicy and
// ibmBobPolicyStandDown read the managed plists only), it only lets the
// doctor and the effective-layer evaluator say "user-set, not tamper-proof"
// and, on an org-managed node, the managed-integrity report carry the closed
// ibm-bob/user_policy_override label. No value is read beyond deciding that
// a policy key is present.
//
// Linux (/etc/bob/policy.json, root-owned) has no user twin. Windows
// (FU-115, ruling AW-79): Bob 2.2.3 applies EnforcedHooks from
// HKCU\Software\Policies\IBM\Bob as well as from HKLM (Windows rig run
// 2026-10-29, proved live). The HKCU key is the User Configuration ADMX
// target, and on a host whose signed-in user holds write access to
// HKCU\Software\Policies (the rig's user had FullControl) it is
// user-writable. So it is read exactly like the macOS user domain: by key
// NAME, as untrusted, report-only, never for stand-down (the HKLM reader,
// ReadIBMBobPolicy, is unchanged), and the HKLM key's names are the managed
// side. A value under HKCU is reported as user-set policy, never as
// machine-enforced.

// IBMBobPolicyGatewayURL, IBMBobPolicyDisabledAutoApprovalGroups and
// IBMBobPolicyUpdateMode are the Bob policy names the catalogue records
// beyond the three IBMBobPolicy reduces to (bob.ibm.com group-policies page;
// agentconfig catalog_ibm_bob.go).
const (
	IBMBobPolicyGatewayURL                 = "GatewayUrl"
	IBMBobPolicyDisabledAutoApprovalGroups = "DisabledAutoApprovalGroups"
	IBMBobPolicyUpdateMode                 = "UpdateMode"
)

// ibmBobPolicyNames is the closed set of Bob policy names a preferences
// domain is searched for. A key outside it (an Electron window-state key
// the Bob IDE may keep in the same domain) is not policy and is ignored.
// diag.TestIBMBobPolicyNamesMatchTheCatalogue pins it to the catalogue's
// ibm-bob/policy rows.
var ibmBobPolicyNames = map[string]bool{
	IBMBobPolicyEnforcedHooks:              true,
	IBMBobPolicyOtelConfiguration:          true,
	IBMBobPolicyEnableTelemetry:            true,
	IBMBobPolicyGatewayURL:                 true,
	IBMBobPolicyDisabledAutoApprovalGroups: true,
	IBMBobPolicyUpdateMode:                 true,
}

// IBMBobPolicyNames returns the closed Bob policy names, sorted.
func IBMBobPolicyNames() []string {
	out := make([]string, 0, len(ibmBobPolicyNames))
	for n := range ibmBobPolicyNames {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// ibmBobTool is Bob's tool id (the registry row and the effective-layer
// families).
const ibmBobTool = "ibm-bob"

// ibmBobPolicyMaxBytes caps a policy read (a real one is a few KB).
const ibmBobPolicyMaxBytes = 1 << 20

// IBMBobHKLMPolicySource and IBMBobHKCUPolicySource name Bob's Windows
// policy keys as reports show them (FU-115): the machine key an
// administrator writes, and the per-user key the signed-in user may be able
// to write.
const (
	IBMBobHKLMPolicySource = `HKLM\SOFTWARE\Policies\IBM\Bob`
	IBMBobHKCUPolicySource = `HKCU\Software\Policies\IBM\Bob`
)

// IBMBobEnforcedHooksPrecedence is the live-grounded Windows precedence of
// EnforcedHooks between the two keys (FU-115 precedence, the FU-177 Windows
// GUI run, docs/handovers/surface-gap-windows-fu177-run-2026-10-29.md
// section 3): Bob does not merge them. Which value Bob applies for any
// other key both set is not verified live (FU-206).
const IBMBobEnforcedHooksPrecedence = "Bob 2.3.0 takes EnforcedHooks from " + IBMBobHKLMPolicySource +
	" whenever that key sets it, even as {}, and reads " + IBMBobHKCUPolicySource +
	" only when HKLM has no value (FU-177 Windows GUI run, 2026-10-30)"

// IBMBobUserPrefsPath is the user's own com.ibm.bob preferences plist under
// home (macOS).
func IBMBobUserPrefsPath(home string) string {
	return filepath.Join(home, "Library", "Preferences", "com.ibm.bob.plist")
}

// IBMBobPolicyDomains is what Bob's macOS preferences domains, or its
// Windows HKLM and HKCU policy keys (FU-115), carry, by policy NAME only.
// The zero value is "nothing read" (Linux, and a sandboxed run).
type IBMBobPolicyDomains struct {
	// ManagedKeys are the policy names the trusted (root-owned) managed
	// plists set, device and per-user together, or the HKLM key sets on
	// Windows, sorted.
	ManagedKeys []string
	// UserSource is the user-domain plist when it exists, or
	// IBMBobHKCUPolicySource when that key exists (Windows).
	UserSource string
	// UserKeys are the policy names the user's own domain (or HKCU key)
	// sets, sorted.
	// Bob applies them as policy; they are user-set, not tamper-proof.
	UserKeys []string
	// UserProblem is non-empty when the user-domain plist exists but could
	// not be read (not a regular file, too large, not convertible); its keys
	// are then unknown, never "none".
	UserProblem string
}

// UserIsRegistry reports whether the user-writable source is Bob's Windows
// HKCU policy key (FU-115) rather than the macOS user preferences domain.
func (d IBMBobPolicyDomains) UserIsRegistry() bool {
	return d.UserSource == IBMBobHKCUPolicySource
}

// AdminAlsoSets reports whether a managed plist sets name too. CFPreferences
// gives a forced (managed) value precedence over the user domain, so the
// admin's value is expected to win there (not verified live on Bob).
func (d IBMBobPolicyDomains) AdminAlsoSets(name string) bool {
	for _, k := range d.ManagedKeys {
		if k == name {
			return true
		}
	}
	return false
}

// LayerTrees returns the domains as effective-layer runtime trees (one per
// domain that sets a key, values replaced by agentconfig.KeyPresent). Nothing
// is returned without a user key: the evaluator's only Bob policy finding is
// a user-set key, and the managed tree only says which side wins.
func (d IBMBobPolicyDomains) LayerTrees() []agentconfig.RuntimeTree {
	if len(d.UserKeys) == 0 {
		return nil
	}
	out := []agentconfig.RuntimeTree{{Tool: ibmBobTool, Layer: agentconfig.RuntimeUserPrefs, Tree: keyPresentTree(d.UserKeys)}}
	if len(d.ManagedKeys) > 0 {
		out = append(out, agentconfig.RuntimeTree{Tool: ibmBobTool, Layer: agentconfig.RuntimeManagedPrefs, Tree: keyPresentTree(d.ManagedKeys)})
	}
	return out
}

func keyPresentTree(keys []string) map[string]any {
	m := make(map[string]any, len(keys))
	for _, k := range keys {
		m[k] = agentconfig.KeyPresent{}
	}
	return m
}

// ibmBobPolicyDomainsReader reads this host's Bob preferences domains under
// home; system=false skips the managed plists (a sandboxed doctor run). A
// test binary never reads the host: tests pass domains in directly.
var ibmBobPolicyDomainsReader = func(home string, system bool) IBMBobPolicyDomains {
	if testing.Testing() {
		return IBMBobPolicyDomains{}
	}
	return readIBMBobPolicyDomainsOS(home, system)
}

// ReadIBMBobPolicyDomains returns Bob's preferences domains under home on
// macOS, or its HKLM and HKCU policy keys on Windows (the zero value on
// every other OS).
func ReadIBMBobPolicyDomains(home string, system bool) IBMBobPolicyDomains {
	if home == "" {
		return IBMBobPolicyDomains{}
	}
	return ibmBobPolicyDomainsReader(home, system)
}

// PolicyDomainLayers returns the effective-layer runtime trees of every OS
// preferences domain this package reads under home (today IBM Bob's on
// macOS), for agentconfigsvc.LayerOptions.Runtime. Key names only.
func PolicyDomainLayers(home string, system bool) []agentconfig.RuntimeTree {
	return ReadIBMBobPolicyDomains(home, system).LayerTrees()
}

// ibmBobPolicyDomainsAt composes the domains from the managed plists and the
// user plist under home: convert turns a plist into JSON, ownerUntrusted
// (nil: none) refuses a managed plist a non-root user could have written. A
// refused or unreadable managed plist contributes no keys.
func ibmBobPolicyDomainsAt(home string, managed []string, convert func([]byte) ([]byte, error), ownerUntrusted func(path string, fi os.FileInfo) string) IBMBobPolicyDomains {
	var d IBMBobPolicyDomains
	set := map[string]bool{}
	for _, p := range managed {
		keys, _, problem := readIBMBobPrefsKeys(p, convert, ownerUntrusted)
		if problem != "" {
			continue
		}
		for _, k := range keys {
			set[k] = true
		}
	}
	for k := range set {
		d.ManagedKeys = append(d.ManagedKeys, k)
	}
	sort.Strings(d.ManagedKeys)
	user := IBMBobUserPrefsPath(home)
	keys, found, problem := readIBMBobPrefsKeys(user, convert, nil)
	if found {
		d.UserSource, d.UserKeys, d.UserProblem = user, keys, problem
	}
	return d
}

// readIBMBobPrefsKeys reads one preferences plist (no symlink, regular,
// size-capped) and returns the Bob policy names it sets. found reports that
// the file exists; problem that it exists but was not read.
func readIBMBobPrefsKeys(path string, convert func([]byte) ([]byte, error), ownerUntrusted func(path string, fi os.FileInfo) string) (keys []string, found bool, problem string) {
	fi, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, ""
		}
		return nil, true, path + " could not be inspected"
	}
	switch {
	case !fi.Mode().IsRegular():
		return nil, true, path + " is not a regular file"
	case fi.Size() > ibmBobPolicyMaxBytes:
		return nil, true, path + " is too large"
	}
	if ownerUntrusted != nil {
		if u := ownerUntrusted(path, fi); u != "" {
			return nil, true, u
		}
	}
	f, err := os.Open(path) //nolint:gosec // G304: a fixed preferences path.
	if err != nil {
		return nil, true, path + " could not be read"
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, ibmBobPolicyMaxBytes+1))
	if err != nil || len(data) > ibmBobPolicyMaxBytes {
		return nil, true, path + " could not be read"
	}
	if convert != nil {
		if data, err = convert(data); err != nil {
			return nil, true, path + " could not be converted from a property list"
		}
	}
	keys, ok := ibmBobPolicyKeysIn(data)
	if !ok {
		return nil, true, path + " is not a property list dictionary"
	}
	return keys, true, ""
}

// ibmBobPolicyKeysIn returns the Bob policy names a JSON object sets,
// sorted; ok is false when data is not a JSON object.
func ibmBobPolicyKeysIn(data []byte) ([]string, bool) {
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil || doc == nil {
		return nil, false
	}
	var out []string
	for k := range doc {
		if ibmBobPolicyNames[k] {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out, true
}

// ibmBobRegistryKey lists the value names of one Bob Windows policy key:
// found is false when the key does not exist, problem is non-empty when it
// exists but its names could not be listed. It is the seam between the
// Windows registry (ibmbob_policy_windows.go) and the composition below, so
// the tests pass fakes and never touch a real registry.
type ibmBobRegistryKey func() (names []string, found bool, problem string)

// ibmBobPolicyDomainsFromRegistry composes Bob's Windows policy layers
// (FU-115): the HKLM key's policy names are the managed side, the HKCU key's
// the user side (UserSource IBMBobHKCUPolicySource). Registry value names
// are case-insensitive, so a name is matched without case and reported in
// the catalogue's spelling. A machine key that cannot be listed contributes
// no names; a user key that cannot be listed is a UserProblem (its keys are
// unknown, never "none"). Names only: no value is read here.
func ibmBobPolicyDomainsFromRegistry(machine, user ibmBobRegistryKey) IBMBobPolicyDomains {
	var d IBMBobPolicyDomains
	if machine != nil {
		if names, found, problem := machine(); found && problem == "" {
			d.ManagedKeys = ibmBobPolicyNamesFold(names)
		}
	}
	if user != nil {
		names, found, problem := user()
		if found {
			d.UserSource = IBMBobHKCUPolicySource
			if problem != "" {
				d.UserProblem = IBMBobHKCUPolicySource + " " + problem
			} else {
				d.UserKeys = ibmBobPolicyNamesFold(names)
			}
		}
	}
	return d
}

// ibmBobPolicyNamesFold returns the Bob policy names among names, matched
// without case, in the catalogue's spelling, sorted and deduplicated.
func ibmBobPolicyNamesFold(names []string) []string {
	set := map[string]bool{}
	for _, n := range names {
		for k := range ibmBobPolicyNames {
			if strings.EqualFold(n, k) {
				set[k] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
