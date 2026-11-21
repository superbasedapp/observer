package secrules_test

// An external test package: it imports internal/guard, which imports this
// package (internal/guard/orgpack.go), so an in-package test would be an
// import cycle.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/guard"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secrules"
)

// orgGateBundlePath is where the test's in-memory filesystem holds the
// cached org bundle envelope.
const orgGateBundlePath = "/home/u/.observer/org-policy-bundle.json"

// signedGateBundle is a verifiable org bundle envelope around bundleTOML, and
// the signing key's pin.
func signedGateBundle(t *testing.T, bundleTOML string) (envelope, pin string) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	b := orgcontract.PolicyBundle{
		Version: 7, BundleTOML: bundleTOML,
		Signature: orgcontract.SignPolicyBundle(priv, 7, []byte(bundleTOML)),
		PublicKey: base64.RawURLEncoding.EncodeToString(pub), SignedAt: "2026-11-11T09:00:00Z",
	}
	raw, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw), orgcontract.PublicKeyPinHash(pub)
}

// TestOrgBundleRelaxesTheCommitGateOnAManagedNode (R3-24): the commit gate
// (S-791 to S-794, source pack:security) stays org-locked on a managed node,
// and the organization relaxes it through its guard bundle. On a managed
// node, with a local approval of the rule on file:
//
//   - `enforce = false` on S-793 stops the ask (the row is capped at flag);
//   - `overridable = true` lets the developer's local approval apply despite
//     the org lock;
//   - with no override the rule stays locked: the ask stands and the local
//     approval is refused with the managed-tenancy note.
func TestOrgBundleRelaxesTheCommitGateOnAManagedNode(t *testing.T) {
	dirty := &policy.Security{Posture: policy.SecurityPostureDirty, QuickScan: policy.QuickScanBlocking}
	unknown := &policy.Security{Posture: policy.SecurityPostureUnknown}
	blocking := &policy.Security{Posture: policy.SecurityPostureBlocking, Blocking: 1}
	cases := []struct {
		name       string
		bundle     string
		cmd        string
		st         *policy.Security
		rule       string
		wantStops  bool // the verdict still asks or denies
		wantLocked bool // the local approval was refused by the org lock
	}{
		{"S-793 enforce = false stops the ask", "[[override]]\nrule = \"S-793\"\nenforce = false\n", "git commit -m x", dirty, "S-793", false, false},
		{"S-793 overridable lets the local approval apply", "[[override]]\nrule = \"S-793\"\noverridable = true\n", "git commit -m x", dirty, "S-793", false, false},
		{"S-793 with no override stays locked", "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n", "git commit -m x", dirty, "S-793", true, true},
		{"S-794 enforce = false stops the ask", "[[override]]\nrule = \"S-794\"\nenforce = false\n", "git commit -m x", unknown, "S-794", false, false},
		{"S-794 overridable lets the local approval apply", "[[override]]\nrule = \"S-794\"\noverridable = true\n", "git commit -m x", unknown, "S-794", false, false},
		{"S-794 with no override stays locked", "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n", "git commit -m x", unknown, "S-794", true, true},
		{"S-791 enforce = false stops the deny", "[[override]]\nrule = \"S-791\"\nenforce = false\n", "git commit -m x", blocking, "S-791", false, false},
		{"S-791 overridable lets the local approval apply", "[[override]]\nrule = \"S-791\"\noverridable = true\n", "git commit -m x", blocking, "S-791", false, false},
		{"S-791 with no override stays locked", "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n", "git commit -m x", blocking, "S-791", true, true},
		{"S-792 overridable lets the local approval apply", "[[override]]\nrule = \"S-792\"\noverridable = true\n", "git push origin main", blocking, "S-792", false, false},
		{"S-792 with no override stays locked", "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n", "git push origin main", blocking, "S-792", true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env, pin := signedGateBundle(t, tc.bundle)
			cfg := config.GuardConfig{
				Enabled: true, Mode: "enforce", RetentionDays: 365,
				Rules: config.GuardRulesConfig{OrgBundle: "~/.observer/org-policy-bundle.json"},
			}
			g, err := guard.New(guard.Options{
				Config: cfg, Home: "/home/u", KnownProjectRoots: []string{"/home/u/proj"},
				PackRules: secrules.GateRules(),
				ReadFile: func(p string) ([]byte, error) {
					if strings.ReplaceAll(p, "\\", "/") == orgGateBundlePath {
						return []byte(env), nil
					}
					return nil, os.ErrNotExist
				},
				OrgKeyPinHash: pin, ManagedTenancy: func() bool { return true },
			})
			if err != nil {
				t.Fatalf("guard.New: %v", err)
			}
			if issues := g.LoadIssues(); len(issues) > 0 {
				t.Fatalf("load issues: %v", issues)
			}
			// A local approval of every rule is on file.
			g.SetApprovalLookup(func(string, string, string) (bool, error) { return true, nil })
			av, _ := g.EvaluateHook(policy.Event{
				Security: tc.st,
				Kind:     policy.KindShellExec, ActionType: "run_command", Target: tc.cmd,
				SessionID: "s1", ProjectRoot: "/home/u/proj", Cwd: "/home/u/proj",
				Caps: policy.Capabilities{PreExecution: true, CanBlock: true, CanAsk: true},
				Now:  time.Unix(1, 0),
			})
			stops := av.Verdict.Decision >= policy.DecisionAsk
			if stops != tc.wantStops {
				t.Fatalf("verdict %s %v (%q): stops = %v, want %v", av.Verdict.RuleID, av.Verdict.Decision, av.Verdict.Reason, stops, tc.wantStops)
			}
			// The gate row matched in every case (a relaxed row still names
			// itself on its flag or approved verdict).
			if av.Verdict.RuleID != tc.rule {
				t.Fatalf("verdict rule = %q (%v, %q), want %s", av.Verdict.RuleID, av.Verdict.Decision, av.Verdict.Reason, tc.rule)
			}
			locked := strings.Contains(av.Verdict.Reason, "[org_locked: ")
			if locked != tc.wantLocked || av.OrgLocked != tc.wantLocked {
				t.Fatalf("org lock: note %v, OrgLocked %v, want %v (reason %q)", locked, av.OrgLocked, tc.wantLocked, av.Verdict.Reason)
			}
			if tc.wantLocked && !strings.Contains(av.Verdict.Reason, "this node is managed by its organization") {
				t.Errorf("locked reason does not name the managed tenancy: %q", av.Verdict.Reason)
			}
		})
	}
}
