package cloudlane

import (
	"reflect"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/cloudagents"
	"github.com/marmutapp/superbased-observer/internal/models"
)

func TestTierOf(t *testing.T) {
	cases := []struct {
		source string
		want   cloudagents.TokenSourceKind
	}{
		{models.TokenSourceJSONL, cloudagents.TokenFromSandboxTranscript},
		{models.TokenSourceProxy, cloudagents.TokenFromSandboxTranscript},
		{"", cloudagents.TokenFromSandboxTranscript},
		{"some_future_source", cloudagents.TokenFromSandboxTranscript},
		{models.TokenSourceSessionSummary, cloudagents.TokenFromProviderRunTotal},
		{models.TokenSourceOTel, cloudagents.TokenFromOTelProvisional},
		{models.TokenSourceEstimated, cloudagents.TokenFromOrgDailyReport},
	}
	for _, tc := range cases {
		if got := TierOf(tc.source); got != tc.want {
			t.Errorf("TierOf(%q) = %q, want %q", tc.source, got, tc.want)
		}
	}
}

func TestSupersededTurns(t *testing.T) {
	off := map[string]bool{"cloud": true, "worker": true}
	isOff := func(sid string) bool { return off[sid] }
	cases := []struct {
		name  string
		turns []FoldTurn
		want  []bool
	}{
		{
			name: "transcript beats provider run total on a cloud session",
			turns: []FoldTurn{
				{SessionID: "cloud", TokenSource: models.TokenSourceJSONL},
				{SessionID: "cloud", TokenSource: models.TokenSourceSessionSummary},
				{SessionID: "cloud", TokenSource: models.TokenSourceJSONL},
			},
			want: []bool{false, true, false},
		},
		{
			name: "provider run total beats otel and org report",
			turns: []FoldTurn{
				{SessionID: "cloud", TokenSource: models.TokenSourceOTel},
				{SessionID: "cloud", TokenSource: models.TokenSourceSessionSummary},
				{SessionID: "cloud", TokenSource: models.TokenSourceEstimated},
			},
			want: []bool{true, false, true},
		},
		{
			name: "a single tier is kept whole",
			turns: []FoldTurn{
				{SessionID: "cloud", TokenSource: models.TokenSourceSessionSummary},
				{SessionID: "worker", TokenSource: models.TokenSourceOTel},
			},
			want: []bool{false, false},
		},
		{
			name: "a local session is never folded",
			turns: []FoldTurn{
				{SessionID: "local", TokenSource: models.TokenSourceJSONL},
				{SessionID: "local", TokenSource: models.TokenSourceSessionSummary},
			},
			want: []bool{false, false},
		},
		{
			name: "a session-less turn is never dropped",
			turns: []FoldTurn{
				{SessionID: "", TokenSource: models.TokenSourceSessionSummary},
				{SessionID: "", TokenSource: models.TokenSourceJSONL},
			},
			want: []bool{false, false},
		},
		{
			name: "sessions fold independently",
			turns: []FoldTurn{
				{SessionID: "cloud", TokenSource: models.TokenSourceJSONL},
				{SessionID: "worker", TokenSource: models.TokenSourceSessionSummary},
				{SessionID: "cloud", TokenSource: models.TokenSourceSessionSummary},
			},
			want: []bool{false, false, true},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := SupersededTurns(tc.turns, isOff); !reflect.DeepEqual(got, tc.want) {
				t.Errorf("got %v, want %v", got, tc.want)
			}
		})
	}
	if got := SupersededTurns([]FoldTurn{{SessionID: "cloud", TokenSource: models.TokenSourceOTel}}, nil); !reflect.DeepEqual(got, []bool{false}) {
		t.Errorf("nil offMachine: got %v", got)
	}
}

func TestOffMachine(t *testing.T) {
	for loc, want := range map[string]bool{
		models.ExecutionLocal: false, models.ExecutionVendorCloud: true,
		models.ExecutionCustomerWorker: true, "": false, "unknown": false,
	} {
		if got := OffMachine(loc); got != want {
			t.Errorf("OffMachine(%q) = %v, want %v", loc, got, want)
		}
	}
}
