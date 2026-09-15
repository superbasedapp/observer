package main

import (
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// One case per row of pricingSourceRules, plus the two orderings the table's
// ORDER is an argument about (enterprise-pricing plan §3.3, criterion 5).
//
// The posture is what an admin reads to answer "is the cap I authored being
// enforced in the currency I authored it in". Every wrong answer here is a
// budget that looks like it is holding and is not, or the reverse.
func TestResolvePricingSourceTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   pricingSourceInput
		want string
		why  string
	}{
		{
			name: "never opted in, nothing authored locally",
			in:   pricingSourceInput{state: orgcontract.PricingFetchDisabled},
			want: orgcontract.PricingSourceSeed,
			why:  "the ordinary individual node: the compiled table, unmodified",
		},
		{
			name: "never opted in, but the developer priced things themselves",
			in:   pricingSourceInput{state: orgcontract.PricingFetchDisabled, localOverrides: true},
			want: orgcontract.PricingSourceLocal,
			why:  "'nobody priced anything here' and 'this developer did' are different facts",
		},
		{
			name: "org rows in force on an individual node",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchVerified, orgRowsInForce: true,
			},
			want: orgcontract.PricingSourceOrg,
			why:  "the org's rates apply, under any override the developer set",
		},
		{
			name: "org rows in force on a managed node holding enforce.budget",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchVerified,
				orgRowsInForce: true, authoritative: true, localOverrides: true,
			},
			want: orgcontract.PricingSourceOrgAuthoritative,
			why:  "the org's rates sit ABOVE the developer's, which is the whole point of the managed ladder",
		},
		{
			name: "the org signed an empty document",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchNoPricing,
			},
			want: orgcontract.PricingSourceNoPricing,
			why:  "an explicit none, distinct from 'we never asked' and from 'we could not tell'",
		},
		{
			name: "a body arrived and was refused",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchUnverified,
			},
			want: orgcontract.PricingSourceUnverified,
			why:  "the actionable fact: something was served that this node would not trust",
		},
		{
			name: "the org server predates the rail",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchNotSupported,
			},
			want: orgcontract.PricingSourceNotSupported,
			why:  "not this node's failure, and not a reason to clear anything",
		},
		{
			name: "opted in but nothing has arrived yet",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchUnreachable,
			},
			want: orgcontract.PricingSourceSeed,
			why:  "what the node IS doing is running its own table; the outage is reported on the budget posture's fetch_state",
		},
		{
			// THE ORDERING ARGUMENT, first direction. A transient refusal over
			// a node that is correctly applying LAST week's verified document
			// must not read as "org pricing not applied": the rates are in
			// force, and telling an admin otherwise sends them chasing a
			// problem that does not exist.
			name: "a failed poll does not unseat rates that are in force",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchUnverified, orgRowsInForce: true,
			},
			want: orgcontract.PricingSourceOrg,
			why:  "what is IN FORCE answers the question, not how the last poll went",
		},
		{
			// THE ORDERING ARGUMENT, second direction. With NOTHING of the
			// org's in force, the refusal is the whole story and must be
			// named rather than collapsed into "seed".
			name: "a refusal with nothing in force is named, never softened to seed",
			in: pricingSourceInput{
				fromOrg: true, state: orgcontract.PricingFetchUnverified, localOverrides: true,
			},
			want: orgcontract.PricingSourceUnverified,
			why:  "'seed' here would read as 'all fine' over a node refusing the org's document",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := resolvePricingSource(tc.in); got != tc.want {
				t.Errorf("resolvePricingSource = %q, want %q — %s", got, tc.want, tc.why)
			}
		})
	}
}

// The posture pair must reach the wire row through the budget boundary, and
// an unwired node must publish an ABSENCE rather than a guess.
func TestNodePricingPostureIsAbsentUntilPublished(t *testing.T) {
	// Not parallel: nodePricingPosture is process-wide state.
	saved := nodePricingPosture.Load()
	t.Cleanup(func() { nodePricingPosture.Store(saved) })

	nodePricingPosture.Store(nil)
	if src, ver := nodePricingPostureFor(); src != "" || ver != 0 {
		t.Fatalf("an unpublished posture reported (%q, %d) — 'not determined' must never render as a verdict", src, ver)
	}

	setNodePricingPosture(orgcontract.PricingSourceOrgAuthoritative, 12)
	if src, ver := nodePricingPostureFor(); src != orgcontract.PricingSourceOrgAuthoritative || ver != 12 {
		t.Fatalf("published posture = (%q, %d), want (org_authoritative, 12)", src, ver)
	}
}
