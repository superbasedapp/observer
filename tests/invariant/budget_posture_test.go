package invariant

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// TestBudgetPostureRowWireShapeIsEnumOnly pins the org-budget posture row
// (docs/plans/org-budget-enforcement-and-token-display-plan-2026-09-07.md
// §3.3d, wave W3b): the ONLY thing a node discloses about whether the org's
// budget is holding may be closed enums and booleans.
//
// The two things it must NEVER carry, and why each is worse than it looks:
//
//   - A CAP VALUE. The cap is a number an admin can correlate straight back to
//     one team's budget row, and it is a number the SERVER already knows (it
//     resolved and signed it). Echoing it adds nothing and lets a compromised
//     node assert numbers about somebody else's team.
//   - A RESOLVED SCOPE. That field is literally the string "team:<id>". It
//     would put team membership on the push wire, which no other row there
//     discloses.
//
// Modeled on TestUpdatePostureRowWireShapeIsEnumOnly, including the exact-count
// assertion: merely allow-listing a name is not enough, the SET must match, so
// a field cannot be added without a deliberate edit here.
func TestBudgetPostureRowWireShapeIsEnumOnly(t *testing.T) {
	t.Parallel()
	allowed := map[string]bool{
		"EnforcementPoint": true, // closed enum ("guard")
		"Mode":             true, // closed enum off|observe|enforce
		"Source":           true, // closed enum local|org_lowered|org_authoritative
		"FetchState":       true, // closed orgcontract.BudgetFetch* enum
		"FromOrg":          true, // boolean: did this node opt in
		"LastFetchOK":      true, // boolean: did the last fetch verify
		"Hard":             true, // boolean: does a breach deny or flag
		"Capped":           true, // boolean: is ANY window capped — never the ceiling
		"Coverage":         true, // closed enum ("proxy_only")
		// Direct-vendor intervention is a second coverage axis. The field is a
		// closed aggregate enum only; per-surface process/path details stay on
		// the node, and the vocabulary deliberately has no ready value.
		"DirectControl": true, // closed enum not_reported|pending_control|partial|control_unavailable|not_required
		// Pricing arc §3.3 (F7/F8). PricingSource is a closed
		// orgcontract.PricingSource* enum. PricingVersion is the ONE number
		// admitted onto this row, and only under the rationale spelled out in
		// orgcontract/budgetposture.go's header: the ban targets cap VALUES
		// and resolved SCOPES — facts the server already knows, or facts a
		// compromised node could assert about SOMEBODY ELSE. A monotonic
		// version of this node's OWN applied pricing document is neither; it
		// is the one datum the server cannot derive, because the server knows
		// what it published and not whether this node ever applied it.
		//
		// Adding a field here is not a formality: the exact-count assertion
		// below means a new field is a deliberate edit, and anything shaped
		// like a rate ("InputPerMTok", "CapUSD") must be refused — a PRICE on
		// this row would be a number about the org's commercial terms
		// travelling back up the wire for no reason at all.
		"PricingSource":  true, // closed enum seed|local|org|org_authoritative|unverified|not_supported|no_pricing
		"PricingVersion": true, // this node's OWN applied document version; never a rate
		// ResolvedScopeNone (server migration 148, fundamentals finding M2).
		// A BOOL, and it belongs here for the same reason Capped does: it
		// answers "what is the shape of what you applied", not "what is in
		// it". Specifically it says the verified body carried NO caps - the
		// org signed an explicit none for this developer - which the server
		// cannot derive, because Capped=false is ALSO what a real
		// `rolling_30d` cap composes to (that period maps to no node window)
		// and the Budgets page must say opposite things about the two.
		//
		// It names no scope. The "Scope" in its name is the wire vocabulary's
		// own `resolved_scope` FIELD being reported as ABSENT - the value it
		// carries is `true`/`false`, never a team id, never a label. That is
		// the exact inversion of what the substring guard below is for, which
		// is why the guard needs the explicit exemption two blocks down
		// rather than a quiet rename that would hide the connection.
		"ResolvedScopeNone": true,
		// PushIntervalSeconds (SF-19). The node's OWN reporting cadence, and
		// the second number admitted here under the same narrow reading as
		// PricingVersion: the ban targets cap VALUES and resolved SCOPES —
		// facts the server already knows because it signed them, or facts a
		// compromised node could assert about SOMEBODY ELSE. A cadence is
		// neither. It names no team, quantifies no spend and no ceiling, and
		// says nothing about any other member.
		//
		// It is admitted because the DirectControl half of this row has a
		// MINUTES-long freshness horizon (a process controller can die between
		// pushes), and a horizon shorter than the reporter's cadence turns
		// every delivered posture into an expired one — the live estate pushes
		// every 15 minutes against a 5-minute horizon and a correctly
		// reporting node read as not_reported forever. Only the node knows its
		// cadence.
		//
		// What must still be refused: anything shaped like a BUDGET period
		// ("PeriodSeconds", "WindowSeconds", "ResetAt"). This field is about
		// the PUSH LOOP, not about any cap's window — which is why it is named
		// for the loop and why the substring guard below keeps rejecting
		// "Period".
		"PushIntervalSeconds": true,
		// PRICING COVERAGE (ruling A3, 2026-09-15, server migration 151).
		// Three fields, and the third is the first FREE TEXT ever admitted onto
		// this row, so each is justified separately:
		//
		//   UnpricedRows — a count of ROWS. The ban this test enforces targets
		//     cap VALUES and resolved SCOPES: numbers an admin can correlate to
		//     one team's budget row, or facts a compromised node could assert
		//     about somebody else. A row count is neither. It quantifies no
		//     spend, names no team, and asserts nothing about any other member.
		//   PricingCoverage — a closed enum (complete|fallback|partial), with
		//     "" meaning NOT MEASURED. Exactly the shape of every other enum
		//     here.
		//   UnpricedModels — vendor model identifiers. It is admitted because
		//     it discloses NOTHING NEW: model ids already travel on this same
		//     push wire, ungated by any share flag, on every sessions,
		//     api_turns and token_usage row (internal/store/orgpush.go). It is
		//     bounded at 8 and sorted, so it is a fact and not a log, and it is
		//     re-bounded server-side at the write seam because a wire value is
		//     never the authority on its own size.
		//
		// WHY AT ALL: without them the org's Budgets page cannot distinguish
		// "your $2 cap is measured in the rates you authored" from "your $2 cap
		// is measured in family-fallback estimates because none of this
		// developer's models are quoted". That difference was previously
		// discovered as an OUTAGE — the guard read unpriced rows as unavailable
		// accounting and TERMed the developer's processes at $0.26 of $2 — and
		// this row is what replaces the denial with a sentence.
		"UnpricedRows":    true,
		"UnpricedModels":  true,
		"PricingCoverage": true,
		// FallbackRows / FallbackModels (BUDGET-COV-3, server migration 152).
		// The same two shapes as the pair above - a ROW COUNT and BOUNDED,
		// SORTED vendor model ids that already travel ungated on this wire - for
		// the OTHER class: rows priced by a rung the org did not author, whose
		// dollars DO count against the cap. They are admitted separately because
		// one merged list made a correctly family-priced model that had just
		// tripped a live cap read as "no rate at all", and an admin acts on the
		// two classes differently: quote a rate for a fallback model, close a
		// $0 hole for an unpriced one.
		"FallbackRows":   true,
		"FallbackModels": true,
		// ORG BASELINE (bundle BUD-N / P1-9). Two fields, both the shapes this
		// row already admits:
		//
		//   OrgBaseline — a closed orgcontract.BudgetBaseline* enum
		//     (applied|stale|absent|unverified), with "" meaning a node that
		//     predates the field. Exactly the shape of Coverage and
		//     DirectControl, and for the same purpose: a developer running two
		//     machines whose node applied NO baseline is enforcing a fleet cap
		//     against one machine's rows, and without this the wire cannot tell
		//     that apart from a cap that is holding.
		//   OrgBaselineUnattributed — a bool about the SHAPE of what was
		//     applied (the baseline counted rows the server could not attribute
		//     to a machine, so it may overlap this node's own), never the
		//     number and never whose rows they were.
		//
		// WHAT IS STILL REFUSED, and note this is the exact field the server
		// SENT DOWN: the spend numbers themselves. The org shipped SpentUSD /
		// SpentTokens to this node on the signed budget body; echoing them back
		// would be a quantity of spend on a row whose whole rule is that it
		// carries none, and it would tell the server nothing it did not already
		// measure itself.
		"OrgBaseline":             true,
		"OrgBaselineUnattributed": true,
		// OrgSubjectUnmatched (adversarial review of BUD-N, P1-3). A BOOL about
		// the SHAPE of what was applied, exactly like Capped and
		// OrgBaselineUnattributed: at least one per-tool / per-model cap's id
		// never appeared in this node's own accounting keys, so a cap that
		// reads as "in force" is governing nothing here. It names NO subject —
		// the id is the org's own authored value, so echoing it back would add
		// nothing the server does not know while widening what a compromised
		// node can assert about somebody else's cap.
		"OrgSubjectUnmatched": true,
	}
	typ := reflect.TypeOf(orgcontract.BudgetPostureRow{})
	if typ.NumField() != len(allowed) {
		t.Errorf("BudgetPostureRow has %d fields, want exactly %d (§3.3d allow-list)", typ.NumField(), len(allowed))
	}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if !allowed[name] {
			t.Errorf("BudgetPostureRow gained non-allow-listed field %q — the §3.3d wire shape is "+
				"closed enums and booleans ONLY: no cap value, no resolved scope, no spend, "+
				"no period, no timezone, no free text", name)
		}
	}
	// Named-shape guard: a field whose NAME implies a number or a scope label
	// fails even if somebody adds it to the allow-list above without thinking.
	forbiddenSubstrings := []string{
		"Cap" + "Tokens", "Cap" + "USD", "Scope", "Spend", "Used", "Remaining",
		"Team", "Period", "Timezone", "Threshold", "Amount", "Limit",
	}
	// The ONE exemption, named rather than pattern-matched so adding another
	// is a deliberate edit with a reason beside it. ResolvedScopeNone reports
	// that the wire's `resolved_scope` is ABSENT; its value is a bool and can
	// never be a label. Any OTHER field carrying "Scope" is the thing the
	// guard exists to catch.
	exempt := map[string]bool{"ResolvedScopeNone": true}
	for i := 0; i < typ.NumField(); i++ {
		name := typ.Field(i).Name
		if exempt[name] {
			if typ.Field(i).Type.Kind() != reflect.Bool {
				t.Errorf("exempted field %q is %s, not a bool — the exemption only holds for a presence FLAG",
					name, typ.Field(i).Type.Kind())
			}
			continue
		}
		for _, bad := range forbiddenSubstrings {
			if strings.Contains(name, bad) {
				t.Errorf("BudgetPostureRow field %q contains %q — the posture reports POSTURE, never numbers or scope labels",
					name, bad)
			}
		}
	}
}

// TestDirectControlVocabularyHasNoReadyState pins the complete wire enum.
// Adding a favourable catch-all such as "ready" would let an aggregate hide
// unsupported direct-vendor paths, which this report exists to prevent.
func TestDirectControlVocabularyHasNoReadyState(t *testing.T) {
	t.Parallel()
	want := []string{
		"not_reported",
		"pending_control",
		"partial",
		"control_unavailable",
		"not_required",
	}
	got := []string{
		orgcontract.DirectControlNotReported,
		orgcontract.DirectControlPending,
		orgcontract.DirectControlPartial,
		orgcontract.DirectControlUnavailable,
		orgcontract.DirectControlNotRequired,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("direct-control vocabulary = %v, want %v", got, want)
	}
	for _, state := range got {
		if state == "ready" {
			t.Fatal("direct-control vocabulary must not contain ready")
		}
	}
}

// TestOrgPushSeamNamesNoBudgetSource pins the module boundary the budget
// posture rides on (CLAUDE.md #4, the routing_summaries precedent):
// internal/store/orgpush.go composes the posture through the func seam in
// budgetposture.go and must never itself name a budget source.
//
// There is no node-local budget TABLE today — the org body is cached in
// memory — so this guards the shape of the seam rather than a table name: if a
// future wave gives the rail durable storage, the read must land in
// budgetposture.go, not in the push SELECT.
func TestOrgPushSeamNamesNoBudgetSource(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile("../../internal/store/orgpush.go")
	if err != nil {
		t.Fatalf("read orgpush.go: %v", err)
	}
	for _, forbidden := range []string{
		"org_budget", "budget_policy", "budget_alert_events", "budgets",
		"guard.budget", "internal/orgbudget",
	} {
		if strings.Contains(string(src), forbidden) {
			t.Errorf("internal/store/orgpush.go names %q — the budget posture must be composed through the "+
				"Store.composeBudgetPosture func seam (internal/store/budgetposture.go), never read here",
				forbidden)
		}
	}
}
