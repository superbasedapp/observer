package diag

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/agentconfig"
	"github.com/marmutapp/superbased-observer/internal/agentconfigsvc"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/hook"
)

// TestIBMBobPolicyNamesMatchTheCatalogue pins the hook package's closed Bob
// policy names (what a preferences domain is searched for) to the
// catalogue's ibm-bob/policy rows, which the effective-layer families are
// built from (FU-105).
func TestIBMBobPolicyNamesMatchTheCatalogue(t *testing.T) {
	t.Parallel()
	var fams []string
	for _, f := range agentconfig.Families() {
		if f.Concern == agentconfig.ConcernUserPolicy && f.Tool == "ibm-bob" {
			fams = append(fams, f.Key[0])
		}
	}
	sort.Strings(fams)
	if got := hook.IBMBobPolicyNames(); !reflect.DeepEqual(got, fams) {
		t.Fatalf("hook.IBMBobPolicyNames = %v, the catalogue's ibm-bob/policy families = %v", got, fams)
	}
}

// TestCheckIBMBobTeamsUserDomain (FU-105): a Bob policy key the user's own
// preferences domain sets is named "user-set, not tamper-proof", never as
// administrator policy; WARN on an org-managed node, informational on an
// individual one; a key the admin also sets is worded as the managed value
// winning; no value is ever shown.
func TestCheckIBMBobTeamsUserDomain(t *testing.T) {
	t.Parallel()
	managed := config.Config{}
	managed.Guard.Lock.Managed = true
	const src = "/Users/dev/Library/Preferences/com.ibm.bob.plist"
	userOnly := hook.IBMBobPolicyDomains{UserSource: src, UserKeys: []string{"GatewayUrl", "UpdateMode"}}
	override := hook.IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}, UserSource: src, UserKeys: []string{"GatewayUrl"}}
	unreadable := hook.IBMBobPolicyDomains{UserSource: src, UserProblem: src + " is not a regular file"}
	deployed := hook.IBMBobPolicy{Source: "/Library/Managed Preferences/com.ibm.bob.plist", Found: true, OtelExport: true}
	cases := []struct {
		name   string
		cfg    config.Config
		pol    hook.IBMBobPolicy
		dom    hook.IBMBobPolicyDomains
		status Status
		msg    string
		want   []string
	}{
		{"no user keys", managed, hook.IBMBobPolicy{}, hook.IBMBobPolicyDomains{}, StatusOK, "not deployed", nil},
		{"individual node, no admin policy", config.Config{}, hook.IBMBobPolicy{}, userOnly, StatusOK, "administrator policy not deployed", []string{"GatewayUrl, UpdateMode", "user-set, not tamper-proof", "individual node"}},
		{"managed node, no admin policy", managed, hook.IBMBobPolicy{}, userOnly, StatusWarn, "administrator policy not deployed", []string{"GatewayUrl, UpdateMode", "user-set, not tamper-proof", "ibm-bob/user_policy_override"}},
		{"managed node, the admin also sets the key", managed, deployed, override, StatusWarn, "see warnings", []string{"also sets GatewayUrl", "managed value is expected to win", "not tamper-proof"}},
		{"admin-provisioned node counts as managed", func() config.Config { c := config.Config{}; c.OrgClient.Share.AdminManaged = true; return c }(), deployed, userOnly, StatusWarn, "see warnings", []string{"ibm-bob/user_policy_override"}},
		{"individual node, admin policy deployed", config.Config{}, deployed, userOnly, StatusOK, "all checks passed", []string{"user-set, not tamper-proof"}},
		{"an unreadable user domain is unknown, not none", managed, hook.IBMBobPolicy{}, unreadable, StatusWarn, "administrator policy not deployed", []string{"was not read", "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := checkIBMBobTeamsPolicy(tc.cfg, tc.pol, tc.dom, t.TempDir())
			if c.Status != tc.status || !strings.Contains(c.Message, tc.msg) {
				t.Fatalf("status %v message %q, want %v containing %q (details %v)", c.Status, c.Message, tc.status, tc.msg, c.Details)
			}
			all := joined(c)
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Fatalf("missing %q in %s", w, all)
				}
			}
			if strings.Contains(all, "administrator policy sets") || strings.Contains(all, "https://") {
				t.Fatalf("a user-set key was worded as admin policy or a value leaked: %s", all)
			}
		})
	}
}

// TestConfigLayersRowNamesUserSetPolicy (FU-105): the config.layers row
// warns on a user-set Bob policy key and names the key and the runtime
// source, never a value.
func TestConfigLayersRowNamesUserSetPolicy(t *testing.T) {
	t.Parallel()
	rep := agentconfigsvc.LayerReport{Findings: []agentconfig.LayerFinding{{
		Family: "ibm-bob/policy.GatewayUrl", Tool: "ibm-bob", Code: agentconfig.FindingUserPolicyOverride,
		Key: agentconfig.KeyPath{"GatewayUrl"}, Class: "set", Winning: agentconfig.SourceRef{Runtime: agentconfig.RuntimeUserPrefs},
	}}}
	c := configLayersCheck("config.layers", rep, 0, "darwin")
	all := joined(c)
	if c.Status != StatusWarn || !strings.Contains(all, "ibm-bob GatewayUrl: user_policy_override") ||
		!strings.Contains(all, "runtime:user_prefs") || !strings.Contains(all, "not tamper-proof") {
		t.Fatalf("%+v", c)
	}
}

// TestConfigLayersUserPolicyWordingPerOS (FU-187): the user-set policy row
// names the macOS preferences domain on macOS and the HKCU policy key on
// Windows, never the other OS's mechanism; the warning and the source stay
// the same.
func TestConfigLayersUserPolicyWordingPerOS(t *testing.T) {
	t.Parallel()
	rep := agentconfigsvc.LayerReport{Findings: []agentconfig.LayerFinding{{
		Family: "ibm-bob/policy.GatewayUrl", Tool: "ibm-bob", Code: agentconfig.FindingUserPolicyOverride,
		Key: agentconfig.KeyPath{"GatewayUrl"}, Class: "set", Winning: agentconfig.SourceRef{Runtime: agentconfig.RuntimeUserPrefs},
	}}}
	for _, tc := range []struct {
		goos      string
		want, not []string
	}{
		{"darwin", []string{"preferences domain"}, []string{"HKCU"}},
		// FU-206: EnforcedHooks' precedence is the FU-177 GUI run's
		// (HKLM wins whenever it sets the key, even {}); any other key's
		// stays not verified live.
		{"windows", []string{hook.IBMBobHKCUPolicySource, hook.IBMBobHKLMPolicySource, "takes EnforcedHooks from " + hook.IBMBobHKLMPolicySource + " whenever that key sets it, even as {}", "only when HKLM has no value", "FU-177 Windows GUI run, 2026-10-30", "for any other key, which value the tool applies is not verified live"}, []string{"preferences domain", "expected to win"}},
	} {
		c := configLayersCheck("config.layers", rep, 0, tc.goos)
		all := joined(c)
		if c.Status != StatusWarn || !strings.Contains(all, "runtime:user_prefs") || !strings.Contains(all, "not tamper-proof") {
			t.Errorf("%s: %+v", tc.goos, c)
		}
		for _, w := range tc.want {
			if !strings.Contains(all, w) {
				t.Errorf("%s: missing %q in %s", tc.goos, w, all)
			}
		}
		for _, n := range tc.not {
			if strings.Contains(all, n) {
				t.Errorf("%s: names %q: %s", tc.goos, n, all)
			}
		}
	}
	for code, byOS := range layerAdviceByOS {
		if _, ok := layerAdvice[code]; !ok {
			t.Errorf("%s has per-OS wording but no default row", code)
		}
		for goos, s := range byOS {
			if s == "" {
				t.Errorf("%s on %s: empty wording", code, goos)
			}
		}
	}
}

// TestCheckIBMBobTeamsHKCUPolicy (FU-115, ruling AW-79): on Windows a Bob
// policy key under the per-user HKCU key is reported as user-set and
// user-level, never as machine-enforced administrator policy; EnforcedHooks
// there is named as hooks Observer never stands down for; a key HKLM also
// sets is worded without the macOS CFPreferences claim.
func TestCheckIBMBobTeamsHKCUPolicy(t *testing.T) {
	t.Parallel()
	managed := config.Config{}
	managed.Guard.Lock.Managed = true
	src := hook.IBMBobHKCUPolicySource
	hooksOnly := hook.IBMBobPolicyDomains{UserSource: src, UserKeys: []string{"EnforcedHooks"}}
	shadow := hook.IBMBobPolicyDomains{ManagedKeys: []string{"EnforcedHooks"}, UserSource: src, UserKeys: []string{"EnforcedHooks"}}
	shadowGateway := hook.IBMBobPolicyDomains{ManagedKeys: []string{"GatewayUrl"}, UserSource: src, UserKeys: []string{"GatewayUrl"}}
	unreadable := hook.IBMBobPolicyDomains{UserSource: src, UserProblem: src + " could not be opened"}
	deployed := hook.IBMBobPolicy{Source: hook.IBMBobHKLMPolicySource, Found: true, OtelExport: true}
	cases := []struct {
		name   string
		cfg    config.Config
		pol    hook.IBMBobPolicy
		dom    hook.IBMBobPolicyDomains
		status Status
		msg    string
		want   []string
	}{
		{"individual node, HKCU hooks only", config.Config{}, hook.IBMBobPolicy{}, hooksOnly, StatusOK, "from the per-user policy key", []string{src, "EnforcedHooks", "user-set, not tamper-proof", "user-level, not machine-enforced", "never stands its per-node Bob hooks down"}},
		{"managed node, HKCU hooks only", managed, hook.IBMBobPolicy{}, hooksOnly, StatusWarn, "administrator policy not deployed", []string{"ibm-bob/user_policy_override", "user-level, not machine-enforced"}},
		{"managed node, HKLM sets it too", managed, deployed, shadow, StatusWarn, "see warnings", []string{"per-user policy key (" + src + ") also sets EnforcedHooks", hook.IBMBobHKLMPolicySource, hook.IBMBobEnforcedHooksPrecedence, "the per-user hooks do not run"}},
		{"managed node, HKLM sets another key too", managed, deployed, shadowGateway, StatusWarn, "see warnings", []string{"per-user policy key (" + src + ") also sets GatewayUrl", "which value Bob applies is not verified live"}},
		{"an unreadable HKCU key is unknown", managed, hook.IBMBobPolicy{}, unreadable, StatusWarn, "administrator policy not deployed", []string{"per-user policy key", "was not read", "unknown"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := checkIBMBobTeamsPolicy(tc.cfg, tc.pol, tc.dom, t.TempDir())
			if c.Status != tc.status || !strings.Contains(c.Message, tc.msg) {
				t.Fatalf("status %v message %q, want %v containing %q (details %v)", c.Status, c.Message, tc.status, tc.msg, c.Details)
			}
			all := joined(c)
			for _, w := range tc.want {
				if !strings.Contains(all, w) {
					t.Fatalf("missing %q in %s", w, all)
				}
			}
			if strings.Contains(all, "CFPreferences") || strings.Contains(all, "preferences domain") {
				t.Fatalf("an HKCU key was worded as a macOS preferences domain: %s", all)
			}
		})
	}
}
