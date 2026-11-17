package guard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestManagedLockWithoutOrgBundle (review finding 1, 2026-11-12): the
// managed-node lock exists whenever the tenancy is managed, so a node whose
// organization has published no guard bundle (or whose first fetch has not
// landed) still ignores a local disable and a local relaxation of a built-in,
// and the start-time strip names the stale disable. An individual node and a
// process with no resolved tenancy are unchanged.
func TestManagedLockWithoutOrgBundle(t *testing.T) {
	t.Parallel()
	yes, no := true, false
	for _, tc := range []struct {
		name        string
		managed     *bool
		wantR101    bool
		wantIgnored string
		wantDropped bool
	}{
		{"managed, no bundle", &yes, true, "R-101", true},
		{"individual, no bundle", &no, false, "", false},
		{"tenancy unresolved, no bundle", nil, false, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			cfg.Rules.Disable = []string{"R-101"}
			files := map[string]string{
				"/home/u/.observer/guard-policy.toml": "[[override]]\nrule = \"R-102\"\ndecision = \"allow\"\n",
			}
			opts := Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(files)}
			if tc.managed != nil {
				m := *tc.managed
				opts.ManagedTenancy = func() bool { return m }
			}
			g, err := New(opts)
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			if got := ruleIDsOf(g.EffectiveRules())["R-101"]; got != tc.wantR101 {
				t.Errorf("R-101 loaded = %v, want %v (issues %v)", got, tc.wantR101, g.LoadIssues())
			}
			if got := strings.Join(g.ManagedIgnoredConfigDisables(cfg.Rules.Disable), ","); got != tc.wantIgnored {
				t.Errorf("ManagedIgnoredConfigDisables = %q, want %q", got, tc.wantIgnored)
			}
			dropped := strings.Contains(strings.Join(g.LoadIssues(), "\n"), "user override on R-102 dropped")
			if dropped != tc.wantDropped {
				t.Errorf("user relaxation of R-102 dropped = %v, want %v: %v", dropped, tc.wantDropped, g.LoadIssues())
			}
		})
	}
}

// TestLocalRuleChangesJudgesLikeTheMerge (review finding 2, 2026-11-12): a
// change is judged against the reference the merge uses, so a user file
// that sets an org-raised rule (R-104, ask raised to deny) back to its
// built-in ask is a loosening the machine does not apply (and the org's
// local_weakening check sees it), and a [[rule]] row whose id the org
// already defines is reported as not applied.
func TestLocalRuleChangesJudgesLikeTheMerge(t *testing.T) {
	t.Parallel()
	const orgBody = "[[override]]\nrule = \"R-104\"\ndecision = \"deny\"\n" +
		"[[rule]]\nid = \"O-1\"\ncategory = \"destructive\"\nseverity = \"high\"\ndecision = \"deny\"\n" +
		"[rule.match]\ncommand_regex = \"^touch /tmp/o1$\"\n"
	const userBody = "[[override]]\nrule = \"R-104\"\ndecision = \"ask\"\n" +
		"[[rule]]\nid = \"O-1\"\ncategory = \"destructive\"\nseverity = \"high\"\ndecision = \"flag\"\n" +
		"[rule.match]\ncommand_regex = \"^touch /tmp/o1x$\"\n" +
		"[[rule]]\nid = \"U-2\"\ncategory = \"destructive\"\nseverity = \"high\"\ndecision = \"deny\"\n" +
		"[rule.match]\ncommand_regex = \"^touch /tmp/u2$\"\n"
	type key struct{ kind, id string }
	type want struct{ loosens, applied bool }
	yes, no := true, false
	for _, tc := range []struct {
		name    string
		managed *bool
		want    map[key]want
	}{
		{"managed", &yes, map[key]want{
			{"override", "R-104"}: {true, false},
			{"rule", "O-1"}:       {false, false},
			{"rule", "U-2"}:       {false, true},
		}},
		{"individual", &no, map[key]want{
			{"override", "R-104"}: {true, false},
			{"rule", "O-1"}:       {false, false},
			{"rule", "U-2"}:       {false, true},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env, pin := signedEnvelope(t, 7, orgBody)
			cfg := guardCfgOrg()
			cfg.Mode = "enforce"
			files := map[string]string{orgBundlePath: env, "/home/u/.observer/guard-policy.toml": userBody}
			opts := Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(files), OrgKeyPinHash: pin}
			m := *tc.managed
			opts.ManagedTenancy = func() bool { return m }
			g, err := New(opts)
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			changes, _ := g.LocalRuleChanges(cfg, nil, nil)
			if len(changes) != len(tc.want) {
				t.Fatalf("got %d changes, want %d: %+v", len(changes), len(tc.want), changes)
			}
			for _, c := range changes {
				w, ok := tc.want[key{c.Kind, c.RuleID}]
				if !ok {
					t.Errorf("unexpected change %+v", c)
					continue
				}
				if c.Loosens != w.loosens || c.Applied != w.applied {
					t.Errorf("%s %s: loosens=%v applied=%v, want %v/%v", c.Kind, c.RuleID, c.Loosens, c.Applied, w.loosens, w.applied)
				}
			}
			// The refused loosening raises the organization's finding.
			p := &orgcontract.LocalGuardPosture{RuleChanges: changes}
			if len(orgcontract.LocalRuleLoosenings(p)) == 0 {
				t.Errorf("a refused loosening must count toward local_weakening")
			}
		})
	}
}

// TestLocalRuleChangesTrustedRootsFromTheLayer (review finding 10,
// 2026-11-12): a trusted per-project file is reported for its root even
// when the store knows no session for it, via the root record beside it;
// a trusted file whose root nothing names marks the report truncated.
func TestLocalRuleChangesTrustedRootsFromTheLayer(t *testing.T) {
	t.Parallel()
	hash := func(r string) string { s := sha256.Sum256([]byte(r)); return hex.EncodeToString(s[:]) }
	cfg := guardCfg()
	cfg.Mode = "enforce"
	cfg.Rules.TrustedProjectDir = "~/.observer/guard-trusted"
	known := "/home/u/fresh"
	trusted := strings.ReplaceAll(TrustedProjectPolicyPath(cfg, "/home/u", known), "\\", "/")
	record := strings.ReplaceAll(TrustedProjectRootRecordPath(cfg, "/home/u", known), "\\", "/")
	orphan := strings.ReplaceAll(TrustedProjectPolicyPath(cfg, "/home/u", "/home/u/elsewhere"), "\\", "/")
	for _, tc := range []struct {
		name          string
		files         map[string]string
		wantChanges   int
		wantTruncated bool
	}{
		{"recorded root", map[string]string{trusted: "disable = [\"R-103\"]\n", record: known + "\n"}, 1, false},
		{"root record names another root", map[string]string{trusted: "disable = [\"R-103\"]\n", record: "/home/u/other\n"}, 0, true},
		{"no record", map[string]string{orphan: "disable = [\"R-103\"]\n"}, 0, true},
		{"empty layer", map[string]string{}, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g, err := New(Options{Config: cfg, Home: "/home/u", ReadFile: fsMap(tc.files), ReadDir: fsMapDir(tc.files)})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			changes, truncated := g.LocalRuleChanges(cfg, nil, hash)
			if len(changes) != tc.wantChanges || truncated != tc.wantTruncated {
				t.Fatalf("changes=%+v truncated=%v, want %d/%v", changes, truncated, tc.wantChanges, tc.wantTruncated)
			}
			for _, c := range changes {
				if c.Layer != orgcontract.LocalRuleLayerTrustedProject || c.ProjectRootHash != hash(known) {
					t.Errorf("change %+v not on the recorded root", c)
				}
			}
		})
	}
}
