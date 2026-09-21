package guard

import (
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/policy"
)

// Org-layer forward compatibility (the pre-v1.34.0 defect): a strict
// unknown-key parse on the ORG layer was fail-OPEN — bundle.go turns a
// parse error into "running without the org layer", so the first
// bundle using a key only a newer server knows (e.g. `overridable` on
// an [[override]] row) silently disarmed the org guard floor on every
// older node. The org layer now IGNORES unknown keys and notes them;
// user and project files stay strict (a hand-edited typo must fail
// loudly).

// orgCompatCase is one TOML exercised on all three layers.
type orgCompatCase struct {
	name string
	body string
	// wantNotes are the ignored key paths, in decoder order.
	wantNotes []string
	// wantRules / wantOverrides are the KNOWN entries that must still
	// compile exactly as they would without the unknown keys.
	wantRules     []string
	wantOverrides []string
}

// orgCompatCases is shared by the org-accepts and the
// user/project-still-reject halves so the two can never drift.
var orgCompatCases = []orgCompatCase{
	{
		name: "unknown key on an [[override]] row",
		body: "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\nquarantine = true\n",
		// `overridable` is now a KNOWN key, so the regression uses a
		// stand-in for the next one the server adds.
		wantNotes:     []string{"override.quarantine"},
		wantOverrides: []string{"R-110"},
	},
	{
		name:      "unknown key on a [[rule]] row",
		body:      "[[rule]]\nid = \"ORG-1\"\ncategory = \"boundary\"\ndecision = \"flag\"\nmatch.command_base = \"scp\"\nnotify_channel = \"#sec\"\nmatch.shiny = 1\n",
		wantNotes: []string{"rule.notify_channel", "rule.match.shiny"},
		wantRules: []string{"ORG-1"},
	},
	{
		name:          "unknown top-level table",
		body:          "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\n\n[telemetry]\nlevel = \"high\"\n\n[[telemetry.sink]]\nurl = \"https://x/y\"\n",
		wantNotes:     []string{"telemetry", "telemetry.level", "telemetry.sink", "telemetry.sink.url"},
		wantOverrides: []string{"R-110"},
	},
	{
		// `disable` is a DECODED key (the trusted-project layer honours
		// it), so it never reaches meta.Undecoded(); the org layer must
		// still IGNORE + note it rather than reject the bundle — a
		// rejection strands every node on its stale bundle (GUARD-FWD-1).
		// The user / project halves keep rejecting it (unknown keys).
		name:          "top-level disable list (trusted-project-only key)",
		body:          "disable = [\"R-101\"]\n\n[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n",
		wantNotes:     []string{"disable"},
		wantOverrides: []string{"R-110"},
	},
	{
		name:          "clean bundle carries no notes",
		body:          "[[rule]]\nid = \"ORG-2\"\ncategory = \"exfil\"\ndecision = \"ask\"\nmatch.url_domain = \"paste.example\"\n\n[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\noverridable = true\n",
		wantNotes:     nil,
		wantRules:     []string{"ORG-2"},
		wantOverrides: []string{"R-110"},
	},
}

// TestParsePolicyFile_OrgLayerIgnoresUnknownKeys: the org layer parses
// through, compiles the KNOWN rules/overrides unchanged, and names
// every ignored key path on policyFile.notes.
func TestParsePolicyFile_OrgLayerIgnoresUnknownKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range orgCompatCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pf, err := parsePolicyFile([]byte(tc.body), layerOrg)
			if err != nil {
				t.Fatalf("parsePolicyFile(org) = %v, want the bundle to load", err)
			}
			if !reflect.DeepEqual(pf.notes, tc.wantNotes) {
				t.Errorf("notes = %q, want %q", pf.notes, tc.wantNotes)
			}
			var gotRules []string
			for _, r := range pf.rules {
				gotRules = append(gotRules, r.ID)
			}
			if !reflect.DeepEqual(gotRules, tc.wantRules) {
				t.Errorf("compiled rules = %q, want %q", gotRules, tc.wantRules)
			}
			var gotOverrides []string
			for _, ov := range pf.overrides {
				gotOverrides = append(gotOverrides, ov.RuleID)
				if ov.Decision != policy.DecisionDeny || !ov.HasDec {
					t.Errorf("override %s decision = %v (has=%v), want deny", ov.RuleID, ov.Decision, ov.HasDec)
				}
			}
			if !reflect.DeepEqual(gotOverrides, tc.wantOverrides) {
				t.Errorf("compiled overrides = %q, want %q", gotOverrides, tc.wantOverrides)
			}
		})
	}
}

// TestParsePolicyFile_LocalLayersStayStrict: the SAME bodies still
// fail loudly on the hand-edited layers, naming every unknown key.
func TestParsePolicyFile_LocalLayersStayStrict(t *testing.T) {
	t.Parallel()
	for _, tc := range orgCompatCases {
		tc := tc
		for _, layer := range []string{layerUser, layerProject} {
			layer := layer
			t.Run(tc.name+"/"+layer, func(t *testing.T) {
				t.Parallel()
				_, err := parsePolicyFile([]byte(tc.body), layer)
				if len(tc.wantNotes) == 0 {
					if err != nil {
						t.Fatalf("parsePolicyFile(%s) = %v, want a clean parse", layer, err)
					}
					return
				}
				if err == nil {
					t.Fatalf("parsePolicyFile(%s) accepted unknown keys %q", layer, tc.wantNotes)
				}
				if !strings.Contains(err.Error(), "unknown keys") {
					t.Errorf("error = %q, want the strict unknown-keys error", err)
				}
				for _, k := range tc.wantNotes {
					if !strings.Contains(err.Error(), k) {
						t.Errorf("error = %q, want it to name %q", err, k)
					}
				}
			})
		}
	}
}

// TestNew_OrgBundleUnknownKeysStayArmed is the end-to-end half: a
// SIGNED envelope whose TOML carries a key this binary predates loads
// (loaded == true), records NO load issue, keeps its known override in
// force, and surfaces the ignored key on PolicyState.Notes.
func TestNew_OrgBundleUnknownKeysStayArmed(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 9, `
[[override]]
rule = "R-110"
decision = "deny"
enforce = true
quarantine = true
`)
	g := orgGuard(t, map[string]string{orgBundlePath: env}, pin)
	if issues := g.LoadIssues(); len(issues) != 0 {
		t.Fatalf("load issues = %v, want none (an ignored key is a note, not an issue)", issues)
	}

	// The parse/verify half reports the layer as LOADED.
	_, st, issue, loaded := g.parseOrgBundle(orgBundlePath, pin)
	if !loaded || issue != "" {
		t.Fatalf("parseOrgBundle loaded=%v issue=%q, want loaded with no issue", loaded, issue)
	}
	if len(st.Notes) != 1 ||
		!strings.Contains(st.Notes[0], "override.quarantine") ||
		!strings.Contains(st.Notes[0], "ignored 1 unknown key(s)") {
		t.Errorf("PolicyState.Notes = %q, want the one ignored-key line naming override.quarantine", st.Notes)
	}

	// Same note on the live snapshot the status surfaces read.
	var found bool
	for _, ps := range g.PolicyStates() {
		if ps.Layer == layerOrg {
			found = true
			if len(ps.Notes) != 1 {
				t.Errorf("PolicyStates org notes = %q, want one line", ps.Notes)
			}
		}
	}
	if !found {
		t.Fatal("org layer missing from PolicyStates — the bundle was dropped (the fail-open defect)")
	}

	// And the org floor is still ARMED: R-110 denies + is enforced
	// even in observe mode, attributed to the org layer.
	v, _ := g.Evaluate(policy.Event{
		Kind: policy.KindShellExec, ActionType: "run_command",
		Target: "git push --force origin main", ProjectRoot: "/home/u/proj",
	})
	if v.RuleID != "R-110" || v.Source != layerOrg || v.Decision != policy.DecisionDeny {
		t.Errorf("verdict = %+v, want R-110/org/deny", v)
	}
}

// TestNew_OrgBundleCleanHasNoNotes: a bundle this binary fully
// understands produces no notes at all.
func TestNew_OrgBundleCleanHasNoNotes(t *testing.T) {
	t.Parallel()
	env, pin := signedEnvelope(t, 9, "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\noverridable = true\n")
	g := orgGuard(t, map[string]string{orgBundlePath: env}, pin)
	for _, ps := range g.PolicyStates() {
		if ps.Layer == layerOrg && len(ps.Notes) != 0 {
			t.Errorf("clean org bundle notes = %q, want none", ps.Notes)
		}
	}
}

// TestLint_OrgLayerStaysStrictOnUnknownKeys is the authoring half of
// the asymmetry: Lint refuses on EVERY layer, org included, in the
// unchanged "unknown keys: …" wording. The server's publish gate
// (internal/orgserver/api.LintOrgBundle → guard.Lint(toml, "org"))
// must never gain the loader's tolerance — a typo like `overidable`
// has to be caught before the bundle is signed, stored and shipped.
func TestLint_OrgLayerStaysStrictOnUnknownKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range orgCompatCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			problems := Lint([]byte(tc.body), layerOrg)
			if len(tc.wantNotes) == 0 {
				if len(problems) != 0 {
					t.Fatalf("Lint(org) = %v, want clean", problems)
				}
				return
			}
			if len(problems) != 1 {
				t.Fatalf("Lint(org) = %v, want exactly one unknown-keys problem", problems)
			}
			want := "unknown keys: " + strings.Join(tc.wantNotes, ", ")
			if problems[0] != want {
				t.Errorf("Lint(org)[0] = %q, want %q", problems[0], want)
			}

			// …while the NODE still loads the very same bundle, with
			// the ignored keys surfaced as notes rather than dropped.
			pf, err := parsePolicyFile([]byte(tc.body), layerOrg)
			if err != nil {
				t.Fatalf("parsePolicyFile(org) = %v, want the node to load it", err)
			}
			if !reflect.DeepEqual(pf.notes, tc.wantNotes) {
				t.Errorf("loader notes = %q, want %q", pf.notes, tc.wantNotes)
			}
		})
	}
}

// TestAcceptOrgBundleTOML_MatchesLintMinusUnknownKeys is the
// anti-drift pin for the authoring/consumer pair (GUARD-FWD-1): for
// every case in the corpus, Lint's output is exactly
// AcceptOrgBundleTOML's problems plus the one unknown-keys line, and
// the notes are the ignored key paths. Both run lintParsed, so a new
// fatal check added to one is automatically in the other; this test
// fails if someone re-forks them.
func TestAcceptOrgBundleTOML_MatchesLintMinusUnknownKeys(t *testing.T) {
	t.Parallel()
	for _, tc := range orgCompatCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			problems, notes := AcceptOrgBundleTOML([]byte(tc.body))
			if len(problems) != 0 {
				t.Fatalf("AcceptOrgBundleTOML problems = %v, want accept", problems)
			}
			if !reflect.DeepEqual(notes, tc.wantNotes) {
				t.Errorf("notes = %q, want %q", notes, tc.wantNotes)
			}

			var want []string
			if len(tc.wantNotes) > 0 {
				want = append(want, unknownKeysProblem(tc.wantNotes))
			}
			want = append(want, problems...)
			got := Lint([]byte(tc.body), layerOrg)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("Lint(org) = %v, want Accept.problems + the unknown-keys line = %v", got, want)
			}
		})
	}
}

// TestAcceptOrgBundleTOML_FatalProblemsMatchLint: with no unknown keys
// in play, the two gates must agree EXACTLY — a bundle the server
// would refuse is a bundle the node refuses, for the same reason.
func TestAcceptOrgBundleTOML_FatalProblemsMatchLint(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		body string
		want string // problem substring; "" = must be accepted
	}{
		{"clean escalating floor", "[[override]]\nrule = \"R-110\"\ndecision = \"deny\"\nenforce = true\n", ""},
		{"not TOML at all", "[[override\nrule =\n", "parse"},
		{"override on an unknown rule id", "[[override]]\nrule = \"R-999\"\ndecision = \"deny\"\n", "R-999"},
		{"relaxing override violates the org floor", "[[override]]\nrule = \"R-110\"\ndecision = \"allow\"\n", "override"},
		{"rule id collides with a built-in", "[[rule]]\nid = \"R-101\"\ncategory = \"destructive\"\ndecision = \"deny\"\nmatch.command_base = \"rm\"\n", "collides with built-in"},
		{"invalid decision", "[[rule]]\nid = \"ORG-9\"\ncategory = \"boundary\"\ndecision = \"maybe\"\nmatch.command_base = \"rm\"\n", "unknown decision"},
		{"rule that could never fire", "[[rule]]\nid = \"ORG-9\"\ncategory = \"boundary\"\ndecision = \"deny\"\n", "no matchers"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			problems, notes := AcceptOrgBundleTOML([]byte(tc.body))
			if len(notes) != 0 {
				t.Errorf("notes = %q, want none (no unknown keys in this body)", notes)
			}
			if tc.want == "" {
				if len(problems) != 0 {
					t.Fatalf("problems = %v, want accept", problems)
				}
			} else {
				if len(problems) == 0 {
					t.Fatalf("problems = none, want one naming %q", tc.want)
				}
				if !strings.Contains(strings.Join(problems, "; "), tc.want) {
					t.Errorf("problems = %v, want one naming %q", problems, tc.want)
				}
			}
			if got := Lint([]byte(tc.body), layerOrg); !reflect.DeepEqual(got, problems) {
				t.Errorf("Lint(org) = %v, AcceptOrgBundleTOML problems = %v — the gates drifted", got, problems)
			}
		})
	}
}
