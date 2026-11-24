package hostapi

import (
	"encoding/json"
	"errors"
	"testing"

	pc "github.com/marmutapp/superbased-observer/internal/platformcontract"
)

func TestAvailabilityPush(t *testing.T) {
	t.Parallel()
	doc := pc.AvailabilityDocument{Version: 7, Body: []byte(`{}`), Signature: make([]byte, 64), KeyID: "k"}
	r, err := AvailabilityPush(doc)
	if err != nil {
		t.Fatal(err)
	}
	if r.Method != methodPut || r.Path != pc.PathAvailability || r.RawQuery != "" {
		t.Fatalf("request = %s %s?%s", r.Method, r.Path, r.RawQuery)
	}
	var back pc.SetAvailabilityRequest
	if err := json.Unmarshal(r.Body, &back); err != nil || back.Document.Version != 7 || back.Document.KeyID != "k" {
		t.Fatalf("body = %s (%v)", r.Body, err)
	}
	if _, err := AvailabilityPush(pc.AvailabilityDocument{}); !errors.Is(err, ErrBadIntent) {
		t.Fatalf("an empty document: %v, want ErrBadIntent", err)
	}
}

func availVerified(v any) Answer {
	b, _ := json.Marshal(v)
	return Answer{Kind: AnswerVerified, Body: b}
}

// TestJudgeAvailability: one case per outcome the answer table can give an
// availability push.
func TestJudgeAvailability(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		a       Answer
		outcome DeliveryOutcome
		inForce int64
		class   string
	}{
		{"applied", availVerified(pc.SetAvailabilityResponse{Version: 9, Applied: true}), DeliveryInForce, 9, ""},
		{"already newer on the host", availVerified(pc.SetAvailabilityResponse{Version: 11, Applied: false}), DeliveryInForce, 11, ""},
		{"no version in force", availVerified(pc.SetAvailabilityResponse{Version: 0}), DeliveryRetry, 0, "bad_response"},
		{"not JSON", Answer{Kind: AnswerVerified, Body: []byte(`nope`)}, DeliveryRetry, 0, "bad_response"},
		{"refused: invalid", availVerified(pc.ErrorResponse{Code: pc.CodeInvalid, Field: "document"}), DeliveryRefused, 0, "refused:invalid"},
		{"refused: unknown code", availVerified(map[string]string{"code": "mystery"}), DeliveryRefused, 0, "refused:unknown_code"},
		{"host unavailable", availVerified(pc.ErrorResponse{Code: pc.CodeUnavailable}), DeliveryRetry, 0, "refused:unavailable"},
		{"replayed", availVerified(pc.ErrorResponse{Code: pc.CodeReplayed}), DeliveryRetry, 0, "refused:replayed"},
		{"unverified answer", Answer{Kind: AnswerUnverified, Reason: "signature"}, DeliveryRetry, 0, "unverified:signature"},
		{"transport", Answer{Kind: AnswerTransport, Reason: "dial"}, DeliveryRetry, 0, "transport:dial"},
		{"not sent", Answer{Kind: AnswerNotSent, Reason: "sign"}, DeliveryRetry, 0, "not_sent:sign"},
		{"not sendable", Answer{Kind: AnswerNotSent, Reason: "build", Permanent: true}, DeliveryRefused, 0, "bad_intent"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			got := JudgeAvailability(c.a)
			if got.Outcome != c.outcome || got.InForce != c.inForce || got.Class != c.class {
				t.Fatalf("JudgeAvailability = %+v, want %s in force %d class %q", got, c.outcome, c.inForce, c.class)
			}
		})
	}
}

// TestEveryAnswerActionHasADeliveryOutcome: a new action in the answer table
// must be given a delivery outcome.
func TestEveryAnswerActionHasADeliveryOutcome(t *testing.T) {
	t.Parallel()
	for _, r := range answerRules {
		d := r.decide(answerFacts{refusal: &pc.ErrorResponse{Code: pc.CodeInvalid}})
		if _, ok := deliveryOutcomes[d.Action]; !ok {
			t.Errorf("rule %s decides %q, which has no delivery outcome", r.name, d.Action)
		}
	}
}
