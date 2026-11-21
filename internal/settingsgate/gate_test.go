package settingsgate

import "testing"

func TestDecideTable(t *testing.T) {
	cases := []struct {
		name     string
		key, val string
		verdict  Verdict
		category Category
	}{
		{"unknown key", "no.such.key", "1", Refuse, CategoryNone},
		{"ordinary plain key", "observability.alerts.eval_interval_minutes", "5", Apply, CategoryNone},
		// E-24 (D29): egress- or safety-changing keys that used to apply.
		{"online sample rate proposes", "observability.eval.online_sample_rate", "1", Propose, CategoryEgress},
		{"online scorers propose", "observability.eval.online_scorers", "llm_judge", Propose, CategoryEgress},
		{"judge model proposes", "observability.eval.judge_model", "gpt-5", Propose, CategoryEgress},
		{"proxy turn traces proposes", "observability.proxy_turn_traces", "true", Propose, CategoryCapture},
		{"alerting switch proposes", "observability.alerts.enabled", "false", Propose, CategorySensitive},
		{"database path proposes", "observer.db_path", "/tmp/x.db", Propose, CategorySensitive},
		{"destination local applies", "observability.sdk.destination", "local", Apply, CategoryNone},
		{"destination default proposes (signed in it resolves to both)", "observability.sdk.destination", "", Propose, CategoryDestination},
		{"destination online proposes", "observability.sdk.destination", "online", Propose, CategoryDestination},
		{"destination both proposes", "observability.sdk.destination", "both", Propose, CategoryDestination},
		{"gateway url proposes", "observability.sdk.gateway_url", "https://gw.example.com", Propose, CategoryDestination},
		{"store content proposes", "observability.store_content", "true", Propose, CategoryCapture},
		{"admission mode proposes", "observability.admission.mode", "enforce", Propose, CategoryAdmission},
		{"admission budget proposes", "observability.admission.budget.per_user_5h_usd", "3", Propose, CategoryBudget},
		{"guard proposes", "guard.mode", "observe", Propose, CategoryGuard},
		{"share proposes", "org_client.share.full_content", "true", Propose, CategorySharing},
		{"egress proposes", "observability.egress.mode", "enforce", Propose, CategoryEgress},
		{"judge base url proposes", "observability.judge.base_url", "https://judge.example.com", Propose, CategoryEgress},
		{"file-only rules refused", "observability.egress.rules", "x", Refuse, CategoryNone},
		// R-B07: the rest of the admission block, and the subsystem switch.
		{"admission scope proposes", "observability.admission.scope", "all", Propose, CategoryAdmission},
		{"admission secret remote judge proposes", "observability.admission.secret_remote_judge", "true", Propose, CategoryAdmission},
		{"admission prefilter proposes", "observability.admission.prefilter.max_message_bytes", "10", Propose, CategoryAdmission},
		{"observability switch proposes", "observability.enabled", "false", Propose, CategoryAdmission},
		// R-B07: sensitive-tier leaves outside the families still propose.
		{"scope denylist proposes", "org_client.scope.project_root_denylist", "", Propose, CategorySensitive},
		{"alert webhook proposes", "observability.alerts.webhook_url", "https://x.example.com", Propose, CategorySensitive},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := Decide(c.key, c.val, nil)
			if d.Verdict != c.verdict || d.Category != c.category {
				t.Fatalf("Decide(%q,%q) = %s/%s (%s), want %s/%s", c.key, c.val, d.Verdict, d.Category, d.Reason, c.verdict, c.category)
			}
			if d.Reason == "" {
				t.Fatal("every decision carries a reason")
			}
		})
	}
}

// TestEveryApprovalPrefixNamesARealKey keeps the family table honest: a
// prefix no schema leaf starts with is a typo that gates nothing.
func TestEveryApprovalPrefixNamesARealKey(t *testing.T) {
	for _, p := range Prefixes() {
		if !prefixHasLeaf(p) {
			t.Errorf("approval prefix %q matches no config key", p)
		}
	}
}
