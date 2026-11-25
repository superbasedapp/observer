package invariant

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudserver/store"
	"github.com/marmutapp/superbased-observer/internal/entitlements"
)

// personal_pro_name_test.go pins the one customer-facing name of the paid
// individual plan (operator ruling 2026-11-24): "Personal Pro", everywhere.
// Internally the purchase is two catalog plans, the account plan plus_beta
// (Cloud Intelligence; what the Paddle price maps to) and the personal org
// plan personal_pro (the hosted personal dashboard and AI Apps), and the
// account plan was labelled "Plus", the September beta's name. The internal
// ids, the Paddle price mapping and the budget pool keep plus_beta.
//
// The table names every place the plan's name is produced for a customer and
// what it produces. Surfaces that only relay a produced name (the portal's
// Usage page, `observer cloud status`, the node dashboard's Cloud
// Intelligence section, all showing GET /v1/usage's plan_label verbatim) are
// covered by the row that produces it, and their files are listed below so
// they never grow a literal of their own. The portal's own renders are also
// pinned by webcloud's tests (src/lib/labels.test.ts,
// src/components/billing/PlanName.test.tsx). Docs: lane note
// docs/audits/personal-pro-name-2026-11-24.md.

const personalPro = "Personal Pro"

// plusWord matches "Plus" as a word: an identifier such as isPlusPlan or
// PlanPlusBeta does not match.
var plusWord = regexp.MustCompile(`\bPlus\b`)

func TestPersonalProIsTheOnlyNameOfThePaidIndividualPlan(t *testing.T) {
	root := repoRoot(t)
	read := func(t *testing.T, rel string) string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		return string(b)
	}
	catalogLabels := func(name string) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			var out []string
			for _, k := range entitlements.Kinds() {
				for _, b := range entitlements.PlansOfKind(k) {
					if b.Plan.Name == name {
						out = append(out, b.Plan.Label)
					}
				}
			}
			if len(out) == 0 {
				t.Fatalf("no catalog plan %s", name)
			}
			return out
		}
	}
	tsLabel := func(rel, token string) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			m := regexp.MustCompile(`(?m)^\s*` + token + `:\s*"([^"]*)"`).FindStringSubmatch(read(t, rel))
			if m == nil {
				t.Fatalf("%s has no %s entry", rel, token)
			}
			return []string{m[1]}
		}
	}
	tsCopy := func(rel string, re *regexp.Regexp) func(t *testing.T) []string {
		return func(t *testing.T) []string {
			m := re.FindStringSubmatch(read(t, rel))
			if m == nil {
				t.Fatalf("%s: no match for %s", rel, re)
			}
			return []string{m[1]}
		}
	}

	sources := []struct {
		source string
		names  func(t *testing.T) []string
	}{
		{
			// The account plan's label, every catalog version.
			source: "catalog plus_beta label (cloud plans.label, GET /v1/usage plan_label)",
			names:  catalogLabels(store.PlanPlusBeta),
		},
		{
			source: "the plans row the generator writes for plus_beta (cloud 0156 makes the label copy)",
			names: func(t *testing.T) []string {
				plans, err := store.GeneratedPlans()
				if err != nil {
					t.Fatalf("GeneratedPlans: %v", err)
				}
				var out []string
				for _, p := range plans {
					if p.Name == store.PlanPlusBeta {
						out = append(out, p.Label)
					}
				}
				return out
			},
		},
		{
			// An org's plan label in the console; the plans an SDK plan
			// refusal says have more.
			source: "catalog personal_pro label (the personal org's document and console)",
			names:  catalogLabels("personal_pro"),
		},
		{
			source: "webcloud PLAN_LABELS.plus_beta (Billing, Subscription card, header pill)",
			names:  tsLabel("webcloud/src/lib/labels.ts", "plus_beta"),
		},
		{
			source: "webcloud PLAN_LABELS.personal_pro (a re-keyed subscription; org billing card)",
			names:  tsLabel("webcloud/src/lib/labels.ts", "personal_pro"),
		},
		{
			source: "webcloud plan comparison card heading",
			names:  tsCopy("webcloud/src/components/billing/PlanComparison.tsx", regexp.MustCompile(`<h3[^>]*>(Personal Pro)</h3>`)),
		},
		{
			source: "node dashboard locked weekly-digest card",
			names:  tsCopy("web/src/components/CloudDigestCard.tsx", regexp.MustCompile(`Part of (Personal Pro)\b`)),
		},
		{
			source: "node dashboard Settings, Cloud Intelligence, weekly digest line",
			names:  tsCopy("web/src/pages/settings/CloudIntelligenceSection.tsx", regexp.MustCompile(`"(Personal Pro) only"`)),
		},
	}
	for _, src := range sources {
		t.Run(src.source, func(t *testing.T) {
			names := src.names(t)
			if len(names) == 0 {
				t.Fatal("the source produced no name")
			}
			for _, n := range names {
				if n != personalPro {
					t.Errorf("name = %q, want %q", n, personalPro)
				}
			}
		})
	}

	// No catalog plan of any kind is labelled with the old name.
	for _, k := range entitlements.Kinds() {
		for _, b := range entitlements.PlansOfKind(k) {
			if plusWord.MatchString(b.Plan.Label) {
				t.Errorf("catalog %s v%d is labelled %q", b.Plan.Name, b.Plan.Version, b.Plan.Label)
			}
		}
	}

	// Files that render a plan name, or relay the server's: none carries
	// the word, in copy or in a comment that would teach it back.
	for _, rel := range []string{
		"webcloud/src/lib/labels.ts",
		"webcloud/src/pages/Billing.tsx",
		"webcloud/src/pages/Usage.tsx",
		"webcloud/src/pages/Overview.tsx",
		"webcloud/src/components/billing/SubscriptionCard.tsx",
		"webcloud/src/components/billing/PlanComparison.tsx",
		"webcloud/src/components/orgs/OrgBillingCard.tsx",
		"web/src/components/CloudDigestCard.tsx",
		"web/src/components/CloudEnrichmentSummary.tsx",
		"web/src/pages/settings/CloudIntelligenceSection.tsx",
		"cmd/observer/cloud_status.go",
		"internal/intelligence/dashboard/cloud.go",
	} {
		if loc := plusWord.FindStringIndex(read(t, rel)); loc != nil {
			t.Errorf("%s says Plus at byte %d: the paid individual plan is %q", rel, loc[0], personalPro)
		}
	}
}
