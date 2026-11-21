package personalmig

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// base is an in-scope, active account with a subject and nothing else.
func base() Footprint {
	return Footprint{AccountID: "a1", AccountStatus: AccountActive, OwnerSubject: "user_01", Devices: 1}
}

func plusSub(id, status string) Subscription {
	return Subscription{ID: id, PlanName: AccountPaidPlan, PlanVersion: 5, Status: status}
}

func TestScopeRules(t *testing.T) {
	cases := []struct {
		name   string
		f      Footprint
		in     bool
		reason string
	}{
		{"analysis_results", Footprint{AccountStatus: AccountActive, Results: 2}, true, "analysis_results"},
		{"account_subscription", Footprint{AccountStatus: AccountActive, AccountSubscriptions: []Subscription{plusSub("s", "canceled")}}, true, "account_subscription"},
		{"rekeyed_subscription", Footprint{AccountStatus: AccountActive, RekeyedSubscriptions: []Subscription{plusSub("s", "active")}}, true, "rekeyed_subscription"},
		{"device_registration", Footprint{AccountStatus: AccountActive, Devices: 1}, true, "device_registration"},
		{"plan_above_floor", Footprint{AccountStatus: AccountActive, PlanName: "plus_beta", PlanSource: "beta_manual"}, true, "plan_above_floor"},
		{"floor plan only is out of scope", Footprint{AccountStatus: AccountActive, PlanName: "free"}, false, ""},
		{"nothing is out of scope", Footprint{AccountStatus: AccountActive}, false, ""},
	}
	if len(cases)-2 != len(scopeRules) {
		t.Fatalf("one case per scope rule: %d rules", len(scopeRules))
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(c.f)
			if d.InScope != c.in || d.ScopeReason != c.reason {
				t.Fatalf("Decide = in %v reason %q, want %v %q", d.InScope, d.ScopeReason, c.in, c.reason)
			}
			if !c.in && (d.Skip != "" || len(d.Needs) != 0) {
				t.Fatalf("out of scope decision carries %+v", d)
			}
		})
	}
}

func TestSkipRules(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Footprint)
		want string
	}{
		{"account_gone deleted", func(f *Footprint) { f.AccountStatus = AccountDeleted }, "account is deleted"},
		{"account_gone closed", func(f *Footprint) { f.AccountStatus = AccountClosed }, "account is closed"},
		{"account_not_active", func(f *Footprint) { f.AccountStatus = AccountSuspended }, `account is "suspended", not active`},
		{"no_subject", func(f *Footprint) { f.OwnerSubject = " " }, "no WorkOS subject"},
		{"org_unusable", func(f *Footprint) { f.Org = &PersonalOrg{OrgID: "o1", Slug: "u-abcdefgh", Status: "purged"} }, "personal org o1 is purged"},
		{"several_live", func(f *Footprint) {
			f.AccountSubscriptions = []Subscription{plusSub("s1", "active"), plusSub("s2", "past_due")}
		}, "2 live account subscriptions"},
		{"live_not_plus", func(f *Footprint) {
			f.AccountSubscriptions = []Subscription{{ID: "s1", PlanName: "legacy", PlanVersion: 1, Status: "active"}}
		}, "is on legacy, not plus_beta"},
		{"org_already_paid", func(f *Footprint) {
			f.AccountSubscriptions = []Subscription{plusSub("s1", "active")}
			f.RekeyedSubscriptions = []Subscription{{ID: "s9", PlanName: OrgPlanName, PlanVersion: 1, Status: "active", OrgID: "o1"}}
		}, "already holds live subscription s9"},
	}
	ids := map[string]bool{}
	for _, r := range skipRules {
		ids[r.id] = true
	}
	for _, c := range cases {
		delete(ids, strings.Fields(c.name)[0])
	}
	if len(ids) != 0 {
		t.Fatalf("skip rules without a case: %v", ids)
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := base()
			c.mut(&f)
			d := Decide(f)
			if !d.InScope || !strings.Contains(d.Skip, c.want) {
				t.Fatalf("Skip = %q, want it to contain %q", d.Skip, c.want)
			}
			if len(d.Needs) != 0 || d.Rekey != nil {
				t.Fatalf("a skipped account needs nothing: %+v", d)
			}
		})
	}
	// A canceled subscription beside a re-keyed live one is not a conflict,
	// and a usable org is not a skip.
	f := base()
	f.Org = &PersonalOrg{OrgID: "o1", Slug: "u-abcdefgh", Status: "provisioning"}
	f.AccountSubscriptions = []Subscription{plusSub("s0", "canceled")}
	f.RekeyedSubscriptions = []Subscription{plusSub("s1", "active")}
	if d := Decide(f); d.Skip != "" {
		t.Fatalf("unexpected skip %q", d.Skip)
	}
}

func TestNeedRules(t *testing.T) {
	org := &PersonalOrg{OrgID: "o1", Slug: "u-abcdefgh", Status: "active"}
	cases := []struct {
		name  string
		mut   func(*Footprint)
		needs []Need
	}{
		{"ensure_org when there is none", func(*Footprint) {}, []Need{NeedEnsureOrg}},
		{"rekey a live plus_beta", func(f *Footprint) {
			f.Org = org
			f.AccountSubscriptions = []Subscription{plusSub("s1", "trialing")}
		}, []Need{NeedRekey}},
		{"export results", func(f *Footprint) { f.Org = org; f.Results = 3 }, []Need{NeedExport}},
		{"all three in order", func(f *Footprint) {
			f.Results = 1
			f.AccountSubscriptions = []Subscription{plusSub("s1", "active")}
		}, []Need{NeedEnsureOrg, NeedRekey, NeedExport}},
		{"nothing: org there, sub canceled, no results", func(f *Footprint) {
			f.Org = org
			f.AccountSubscriptions = []Subscription{plusSub("s1", "canceled")}
		}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := base()
			c.mut(&f)
			d := Decide(f)
			if d.Skip != "" {
				t.Fatalf("skip %q", d.Skip)
			}
			if !reflect.DeepEqual(d.Needs, c.needs) {
				t.Fatalf("Needs = %v, want %v", d.Needs, c.needs)
			}
			if d.Has(NeedRekey) != (d.Rekey != nil) {
				t.Fatalf("Rekey %+v does not match the need", d.Rekey)
			}
			if d.Rekey != nil && d.Rekey.ID != "s1" {
				t.Fatalf("Rekey = %+v", d.Rekey)
			}
		})
	}
}

func TestNoteRules(t *testing.T) {
	f := base()
	f.PlanName, f.PlanSource = "plus_beta", "beta_manual"
	if d := Decide(f); len(d.Notes) != 1 || !strings.Contains(d.Notes[0], "grant-plan org") {
		t.Fatalf("Notes = %v", d.Notes)
	}
	f.PlanSource = PaddlePlanSource
	if d := Decide(f); len(d.Notes) != 0 {
		t.Fatalf("a Paddle plan needs no note: %v", d.Notes)
	}
}

func TestCanMove(t *testing.T) {
	all := append([]Stage{StageNone}, KnownStages()...)
	allowed := map[[2]Stage]bool{}
	for from, tos := range stageMoves {
		for _, to := range tos {
			allowed[[2]Stage{from, to}] = true
		}
	}
	want := map[[2]Stage]bool{
		{StageNone, StagePlanned}: true, {StageNone, StageSkipped}: true,
		{StageSkipped, StageSkipped}: true, {StageSkipped, StagePlanned}: true,
		{StagePlanned, StagePlanned}: true, {StagePlanned, StageOrgReady}: true, {StagePlanned, StageSkipped}: true,
		{StageOrgReady, StageOrgReady}: true, {StageOrgReady, StageRekeyed}: true, {StageOrgReady, StageSkipped}: true,
		{StageRekeyed, StageRekeyed}: true, {StageRekeyed, StageExported}: true, {StageRekeyed, StageVerified}: true, {StageRekeyed, StageSkipped}: true,
		{StageExported, StageExported}: true, {StageExported, StageVerified}: true,
		{StageVerified, StageVerified}: true, {StageVerified, StagePlanned}: true,
	}
	for _, from := range all {
		for _, to := range all {
			k := [2]Stage{from, to}
			if got := CanMove(from, to); got != want[k] || got != allowed[k] {
				t.Errorf("CanMove(%q, %q) = %v, want %v", from, to, got, want[k])
			}
		}
	}
	if CanMove(StageVerified, StageSkipped) || CanMove(StageExported, StageSkipped) {
		t.Fatal("verified only reopens to planned; exported never skips")
	}
	for _, s := range KnownStages() {
		if !s.Valid() {
			t.Errorf("%q not valid", s)
		}
	}
	if StageNone.Valid() || Stage("done").Valid() {
		t.Fatal("unknown stage valid")
	}
}

func TestNextStep(t *testing.T) {
	skip := Decision{InScope: true, Skip: "account is deleted"}
	export := Decision{InScope: true, Needs: []Need{NeedExport}}
	plain := Decision{InScope: true}
	drift := Decision{InScope: true, Drift: []string{"new_results"}}
	cases := []struct {
		stage Stage
		d     Decision
		step  Step
	}{
		{StageNone, skip, StepSkip},
		{StageNone, plain, StepPlan},
		{StageSkipped, skip, StepSkip},
		{StageSkipped, plain, StepPlan},
		{StagePlanned, skip, StepSkip},
		{StagePlanned, plain, StepEnsureOrg},
		{StageOrgReady, skip, StepSkip},
		{StageOrgReady, plain, StepRekey},
		{StageRekeyed, skip, StepSkip},
		{StageRekeyed, export, StepExport},
		{StageRekeyed, plain, StepFinish},
		{StageExported, skip, StepAwaitReceipt},
		{StageVerified, drift, StepReopen},
		{StageVerified, skip, StepDone},
		{Stage("bogus"), plain, StepDone},
	}
	if len(cases)-1 != len(stepRules) {
		t.Fatalf("one case per step rule: %d rules", len(stepRules))
	}
	for _, c := range cases {
		if got := NextStep(c.stage, c.d); got != c.step {
			t.Errorf("NextStep(%q, %+v) = %q, want %q", c.stage, c.d, got, c.step)
		}
		if st, ok := StageAfter(c.step); ok && !CanMove(c.stage, st) {
			t.Errorf("step %q from %q records %q, which the stage machine refuses", c.step, c.stage, st)
		}
	}
	for _, s := range []Step{StepAwaitReceipt, StepDone} {
		if _, ok := StageAfter(s); ok {
			t.Errorf("%q records a stage", s)
		}
	}
}

func validResult(title string) []byte {
	b, _ := json.Marshal(cloudcontract.Result{
		Title: title, TaxonomyTags: []string{}, SuggestedTags: []string{"go"}, Description: "did a thing",
		Confidence: cloudcontract.ConfidenceHigh, EvidenceRefs: []string{}, Limitations: []string{},
		SchemaVersion: cloudcontract.ResultSchemaVersion,
	})
	return b
}

func TestResultRules(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	ok := ResultFacts{ID: "r-ok", Kind: ResultKindSessionEnrichment, CloudSessionID: "cs1", CreatedAt: t0, Result: validResult("kept")}
	cases := []struct {
		name   string
		mut    func(*ResultFacts)
		reason string
	}{
		{ResultSkipKind, func(r *ResultFacts) { r.Kind = "project_digest" }, ResultSkipKind},
		{ResultSkipTombstoned, func(r *ResultFacts) { r.Tombstoned = true }, ResultSkipTombstoned},
		{ResultSkipSuperseded, func(r *ResultFacts) { r.Superseded = true }, ResultSkipSuperseded},
		{ResultSkipNoSession, func(r *ResultFacts) { r.CloudSessionID = "" }, ResultSkipNoSession},
		{"invalid json", func(r *ResultFacts) { r.Result = []byte(`{"title":`) }, ResultSkipInvalid},
		{"invalid result", func(r *ResultFacts) { r.Result = []byte(`{"title":"x","schema_version":"old"}`) }, ResultSkipInvalid},
		{"invalid correction", func(r *ResultFacts) { r.Revisions = []Revision{{Seq: 1, Correction: []byte(`{"bogus":1}`)}} }, ResultSkipInvalid},
		{"exported", func(*ResultFacts) {}, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := ok
			c.mut(&r)
			e, err := BuildExport([]ResultFacts{r})
			if err != nil {
				t.Fatal(err)
			}
			if e.Total != 1 {
				t.Fatalf("Total = %d", e.Total)
			}
			if c.reason == "" {
				if len(e.Records) != 1 || e.SkippedTotal() != 0 {
					t.Fatalf("export = %+v", e)
				}
				rec := e.Records[0]
				if rec.ImportRef != "personal:r-ok" || rec.CloudSessionID != "cs1" || rec.CreatedAt != "2026-10-01T12:00:00Z" || rec.Corrected {
					t.Fatalf("record = %+v", rec)
				}
				return
			}
			if len(e.Records) != 0 || e.Skipped[c.reason] != 1 {
				t.Fatalf("export = %+v, want one %q", e, c.reason)
			}
		})
	}
}

func TestEffectiveResultFoldsCorrectionsInOrder(t *testing.T) {
	revs := []Revision{
		{Seq: 3, Correction: []byte(`{"description":""}`)},
		{Seq: 1, Correction: []byte(`{"title":"first","suggested_tags":["a"]}`)},
		{Seq: 2, Correction: []byte(`{"title":"second","taxonomy_tags":[]}`)},
	}
	got, corrected, err := EffectiveResult(validResult("ai"), revs)
	if err != nil || !corrected {
		t.Fatalf("EffectiveResult: corrected=%v err=%v", corrected, err)
	}
	if got.Title != "second" || got.Description != "" || !reflect.DeepEqual(got.SuggestedTags, []string{"a"}) ||
		len(got.TaxonomyTags) != 0 || got.Confidence != cloudcontract.ConfidenceHigh {
		t.Fatalf("effective = %+v", got)
	}
	same, corrected, err := EffectiveResult(validResult("ai"), nil)
	if err != nil || corrected || same.Title != "ai" {
		t.Fatalf("no revisions: %+v %v %v", same, corrected, err)
	}
}

func TestBuildExportIsDeterministic(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	rows := []ResultFacts{
		{ID: "b", Kind: ResultKindSessionEnrichment, CloudSessionID: "cs2", CreatedAt: t0, Result: validResult("b")},
		{
			ID: "c", Kind: ResultKindSessionEnrichment, CloudSessionID: "cs3", CreatedAt: t0.Add(-time.Hour), Result: validResult("c"),
			Revisions: []Revision{{Seq: 1, Correction: []byte(`{"title":"fixed"}`)}},
		},
		{ID: "a", Kind: ResultKindSessionEnrichment, CloudSessionID: "cs1", CreatedAt: t0, Result: validResult("a")},
	}
	e1, err := BuildExport(rows)
	if err != nil {
		t.Fatal(err)
	}
	rev := []ResultFacts{rows[2], rows[0], rows[1]}
	e2, err := BuildExport(rev)
	if err != nil {
		t.Fatal(err)
	}
	b1, s1, err := cloudcontract.EncodePersonalImportRecords(e1.Records)
	if err != nil {
		t.Fatal(err)
	}
	b2, s2, _ := cloudcontract.EncodePersonalImportRecords(e2.Records)
	if s1 != s2 || string(b1) != string(b2) {
		t.Fatal("the bundle digest depends on input order")
	}
	var order []string
	for _, r := range e1.Records {
		order = append(order, r.ImportRef)
	}
	if !reflect.DeepEqual(order, []string{"personal:c", "personal:a", "personal:b"}) {
		t.Fatalf("order = %v", order)
	}
	if !e1.Records[0].Corrected || e1.Records[0].Result.Title != "fixed" {
		t.Fatalf("correction not applied: %+v", e1.Records[0])
	}
}

func TestDecideBundle(t *testing.T) {
	sha := strings.Repeat("a", 64)
	other := strings.Repeat("b", 64)
	same := ExistingBundle{Found: true, Manifest: cloudcontract.PersonalImportManifest{OrgID: "o1", RecordsSHA256: sha}, RecordsSHA256: sha}
	cases := []struct {
		name    string
		e       ExistingBundle
		replace bool
		want    BundleAction
	}{
		{"none there", ExistingBundle{}, false, BundleWrite},
		{"same bundle", same, false, BundleKeep},
		{"same bundle with replace", same, true, BundleKeep},
		{"different with replace", ExistingBundle{Found: true, Manifest: cloudcontract.PersonalImportManifest{OrgID: "o1", RecordsSHA256: other}, RecordsSHA256: other}, true, BundleWrite},
		{"different without replace", ExistingBundle{Found: true, Manifest: cloudcontract.PersonalImportManifest{OrgID: "o1", RecordsSHA256: other}, RecordsSHA256: other}, false, BundleRefuse},
		{"manifest matches but records file differs", ExistingBundle{Found: true, Manifest: same.Manifest, RecordsSHA256: other}, false, BundleRefuse},
	}
	for _, c := range cases {
		if got := DecideBundle(c.e, "o1", sha, c.replace); got != c.want {
			t.Errorf("%s: DecideBundle = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestReceiptGap(t *testing.T) {
	sha := strings.Repeat("c", 64)
	m := NewManifest("a1", PersonalOrg{OrgID: "o1", Slug: "u-abcdefgh"}, "user_01", 3, sha, time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC))
	if err := m.Validate(); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	good := cloudcontract.PersonalImportReceipt{Format: cloudcontract.PersonalImportFormat, OrgID: "o1", RecordsSHA256: strings.ToUpper(sha), RecordCount: 3, Inserted: 2, AlreadyPresent: 1, Present: 3}
	cases := []struct {
		name string
		mut  func(*cloudcontract.PersonalImportReceipt)
		want string
	}{
		{"format", func(r *cloudcontract.PersonalImportReceipt) { r.Format = "v0" }, "format"},
		{"org", func(r *cloudcontract.PersonalImportReceipt) { r.OrgID = "o2" }, "another org"},
		{"digest", func(r *cloudcontract.PersonalImportReceipt) { r.RecordsSHA256 = strings.Repeat("d", 64) }, "digest"},
		{"count", func(r *cloudcontract.PersonalImportReceipt) { r.RecordCount = 4 }, "record count"},
		{"present", func(r *cloudcontract.PersonalImportReceipt) { r.Present = 2 }, "not every record"},
		{"complete", func(*cloudcontract.PersonalImportReceipt) {}, ""},
	}
	if len(cases)-1 != len(receiptRules) {
		t.Fatalf("one case per receipt rule: %d rules", len(receiptRules))
	}
	for _, c := range cases {
		r := good
		c.mut(&r)
		gap := ReceiptGap(m, r)
		if (c.want == "" && gap != "") || !strings.Contains(gap, c.want) {
			t.Errorf("%s: ReceiptGap = %q, want %q", c.name, gap, c.want)
		}
		if (gap == "") != r.Complete(m) {
			t.Errorf("%s: ReceiptGap %q disagrees with Complete %v", c.name, gap, r.Complete(m))
		}
	}
}

func TestDriftRules(t *testing.T) {
	cases := []struct {
		name string
		f    Footprint
		rec  Recorded
		want int
	}{
		{"new_subscription", Footprint{AccountSubscriptions: []Subscription{plusSub("s", "active")}}, Recorded{}, 1},
		{"a canceled subscription is not drift", Footprint{AccountSubscriptions: []Subscription{plusSub("s", "canceled")}}, Recorded{}, 0},
		{"new_results", Footprint{Results: 3}, Recorded{ResultsTotal: 2}, 1},
		{"results already recorded", Footprint{Results: 2}, Recorded{ResultsTotal: 2}, 0},
		{"both", Footprint{Results: 3, AccountSubscriptions: []Subscription{plusSub("s", "active")}}, Recorded{ResultsTotal: 1}, 2},
		{"nothing", Footprint{}, Recorded{}, 0},
	}
	if len(driftRules) != 2 {
		t.Fatalf("one case per drift rule: %d rules", len(driftRules))
	}
	for _, c := range cases {
		if got := DriftReasons(c.f, c.rec); len(got) != c.want {
			t.Errorf("%s: DriftReasons = %v, want %d reason(s)", c.name, got, c.want)
		}
	}
}

func TestDecideVerified(t *testing.T) {
	f := base()
	f.Results = 3
	if d := DecideVerified(f, Recorded{ResultsTotal: 2}); len(d.Drift) != 1 || !d.Has(NeedExport) {
		t.Fatalf("drifted: %+v", d)
	}
	if d := DecideVerified(f, Recorded{ResultsTotal: 3}); len(d.Drift) != 0 {
		t.Fatalf("unchanged: %+v", d)
	}
	closed := f
	closed.AccountStatus = AccountClosed
	if d := DecideVerified(closed, Recorded{}); d.Skip == "" || len(d.Drift) != 0 {
		t.Fatalf("a closed account has nothing to move: %+v", d)
	}
}

func TestRetirementGate(t *testing.T) {
	cases := []struct {
		name  string
		stage Stage
		d     Decision
		want  Gate
	}{
		{"drift blocks", StageVerified, Decision{InScope: true, Drift: []string{"new_results"}}, GateDrift},
		{"verified is clear", StageVerified, Decision{InScope: true}, GateClear},
		{"verified then closed is clear", StageVerified, Decision{InScope: true, Skip: "account is closed"}, GateClear},
		{"skipped ledger row", StageSkipped, Decision{InScope: true, Skip: "no subject"}, GateSkipped},
		{"not yet ledgered but skippable", StageNone, Decision{InScope: true, Skip: "no subject"}, GateSkipped},
		{"exported awaits a receipt", StageExported, Decision{InScope: true}, GateUnfinished},
		{"no ledger row", StageNone, Decision{InScope: true}, GateUnfinished},
	}
	for _, c := range cases {
		if got := RetirementGate(c.stage, c.d); got != c.want {
			t.Errorf("%s: RetirementGate = %q, want %q", c.name, got, c.want)
		}
	}
}
