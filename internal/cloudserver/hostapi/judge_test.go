package hostapi

import (
	"encoding/json"
	"testing"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

const testOrg = "11111111-2222-3333-4444-555555555555"

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return b
}

func queuedCreate() Queued {
	return Queued{OrgID: testOrg, Verb: VerbCreateTenant, IdempotencyKey: testOrg, Payload: []byte(`{"tenant_id":"` + testOrg + `","name":"Acme"}`)}
}

func verified(body []byte) Answer { return Answer{Kind: AnswerVerified, Body: body, HTTPStatus: 200} }

func refusalBody(t *testing.T, code pc.ErrorCode) []byte {
	t.Helper()
	return mustJSON(t, pc.ErrorResponse{Code: code})
}

// TestJudgeRules is one case per answerRules row, in table order.
func TestJudgeRules(t *testing.T) {
	t.Parallel()
	createOK := mustJSON(t, pc.CreateTenantResponse{TenantID: testOrg, Outcome: pc.CreateReady, State: pc.StateActive, LifecycleGen: 1})
	createFailed := mustJSON(t, pc.CreateTenantResponse{TenantID: testOrg, Outcome: pc.CreateFailed, State: pc.StateProvisioning})
	cases := []struct {
		rule   string
		answer Answer
		action Action
		class  string
	}{
		{"not_sent_invalid", Answer{Kind: AnswerNotSent, Reason: "build", Permanent: true}, ActionPark, "bad_intent"},
		{"not_sent", Answer{Kind: AnswerNotSent, Reason: "resolve"}, ActionRetry, "not_sent:resolve"},
		{"transport", Answer{Kind: AnswerTransport, Reason: "timeout"}, ActionRetry, "transport:timeout"},
		{"unverified", Answer{Kind: AnswerUnverified, Reason: "signature", Body: createOK, HTTPStatus: 200}, ActionRetry, "unverified:signature"},
		{"bad_body", verified([]byte(`not json`)), ActionRetry, "bad_response"},
		{"replayed", verified(refusalBody(t, pc.CodeReplayed)), ActionRetryNewRequest, "refused:replayed"},
		{"idempotency_in_progress", verified(refusalBody(t, pc.CodeIdempotencyInProgress)), ActionRetryNewRequest, "refused:idempotency_in_progress"},
		{"capacity_waitlist", verified(refusalBody(t, pc.CodeCapacityWaitlist)), ActionWaitlist, "refused:capacity_waitlist"},
		{"unavailable", verified(refusalBody(t, pc.CodeUnavailable)), ActionRetry, "refused:unavailable"},
		{"internal", verified(refusalBody(t, pc.CodeInternal)), ActionRetry, "refused:internal"},
		{"unknown_code", verified([]byte(`{"code":"from_the_future"}`)), ActionPark, "refused:unknown_code"},
		{"refused", verified(refusalBody(t, pc.CodeUnknownTenant)), ActionPark, "refused:unknown_tenant"},
		{"create_failed", verified(createFailed), ActionRetry, "create_failed"},
		{"ok", verified(createOK), ActionAck, ""},
	}
	if len(cases) != len(answerRules) {
		t.Fatalf("%d cases for %d rules: one case per row", len(cases), len(answerRules))
	}
	for i, tc := range cases {
		if answerRules[i].name != tc.rule {
			t.Fatalf("case %d is %q but rule %d is %q (keep table order)", i, tc.rule, i, answerRules[i].name)
		}
		t.Run(tc.rule, func(t *testing.T) {
			t.Parallel()
			d := Judge(queuedCreate(), tc.answer)
			if d.Rule != tc.rule || d.Action != tc.action || d.Class != tc.class {
				t.Fatalf("Judge = %+v, want rule %s action %s class %q", d, tc.rule, tc.action, tc.class)
			}
		})
	}
}

// TestJudgeOkReportsObservedState: an ack carries what the host reported.
func TestJudgeOkReportsObservedState(t *testing.T) {
	t.Parallel()
	body := mustJSON(t, pc.CreateTenantResponse{TenantID: testOrg, Outcome: pc.CreateReplayed, State: pc.StateActive, LifecycleGen: 3})
	d := Judge(queuedCreate(), verified(body))
	if d.Action != ActionAck || !d.Observed.HasState || d.Observed.State != pc.StateActive || d.Observed.LifecycleGen != 3 {
		t.Fatalf("Judge = %+v", d)
	}
}

// TestJudgeNeverAcksAnUnverifiedAnswer: whatever the body and status say, an
// answer that is not AnswerVerified is never a success.
func TestJudgeNeverAcksAnUnverifiedAnswer(t *testing.T) {
	t.Parallel()
	good := mustJSON(t, pc.CreateTenantResponse{TenantID: testOrg, Outcome: pc.CreateReady, State: pc.StateActive})
	for _, k := range []AnswerKind{0, AnswerNotSent, AnswerTransport, AnswerUnverified, AnswerVerified + 1} {
		d := Judge(queuedCreate(), Answer{Kind: k, Body: good, HTTPStatus: 200})
		if d.Action == ActionAck {
			t.Errorf("kind %d with a success body was acked: %+v", k, d)
		}
	}
}

// TestJudgeBodyWinsOverStatus: the HTTP status is not signed, so it decides
// nothing; a signed refusal under a 200 is a refusal and a signed success
// under a 503 is a success.
func TestJudgeBodyWinsOverStatus(t *testing.T) {
	t.Parallel()
	refused := Answer{Kind: AnswerVerified, Body: refusalBody(t, pc.CodeInvalid), HTTPStatus: 200}
	if d := Judge(queuedCreate(), refused); d.Action != ActionPark {
		t.Errorf("signed refusal under 200 = %+v, want park", d)
	}
	ok := Answer{Kind: AnswerVerified, Body: mustJSON(t, pc.CreateTenantResponse{TenantID: testOrg, Outcome: pc.CreateReady, State: pc.StateActive}), HTTPStatus: 503}
	if d := Judge(queuedCreate(), ok); d.Action != ActionAck {
		t.Errorf("signed success under 503 = %+v, want ack", d)
	}
}

// TestJudgePerVerbSuccess: each verb's success body acks; a body that is not
// the verb's answer retries as bad_response.
func TestJudgePerVerbSuccess(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		q    Queued
		body []byte
		want Action
	}{
		{"create other tenant", queuedCreate(), mustJSON(t, pc.CreateTenantResponse{TenantID: "other", Outcome: pc.CreateReady, State: pc.StateActive}), ActionRetry},
		{"state applied", Queued{OrgID: testOrg, Verb: VerbSetState}, mustJSON(t, pc.SetStateResponse{State: pc.StateSuspended, LifecycleGen: 2, Applied: true}), ActionAck},
		{"state stale is success", Queued{OrgID: testOrg, Verb: VerbSetState}, mustJSON(t, pc.SetStateResponse{State: pc.StateActive, LifecycleGen: 9, Applied: false}), ActionAck},
		{"state bad enum", Queued{OrgID: testOrg, Verb: VerbSetState}, []byte(`{"state":"weird","lifecycle_gen":1}`), ActionRetry},
		{"entitlements", Queued{OrgID: testOrg, Verb: VerbSetEntitlements}, mustJSON(t, pc.SetEntitlementsResponse{Version: 4, Applied: true}), ActionAck},
		{"deactivate", Queued{OrgID: testOrg, Verb: VerbMembersDeactivate}, mustJSON(t, pc.DeactivateMemberResponse{}), ActionAck},
		{"evict", Queued{OrgID: testOrg, Verb: VerbEvict}, mustJSON(t, pc.EvictResponse{Evicted: true}), ActionAck},
		{"array body", Queued{OrgID: testOrg, Verb: VerbEvict}, []byte(`[]`), ActionRetry},
		{"null body", Queued{OrgID: testOrg, Verb: VerbSetEntitlements}, []byte(`null`), ActionRetry},
		{"unknown verb", Queued{OrgID: testOrg, Verb: "export"}, []byte(`{}`), ActionRetry},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if d := Judge(tc.q, verified(tc.body)); d.Action != tc.want {
				t.Fatalf("Judge = %+v, want %s", d, tc.want)
			}
		})
	}
}
