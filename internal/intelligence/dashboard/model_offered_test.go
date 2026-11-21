package dashboard

import (
	"context"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestModelOfferedMatchesThePicker pins the one membership rule
// (dashapi.ModelOffered, which the launch route and `observer launch
// --model` apply) to the list the New Terminal picker shows
// (modelSuggestionsFor): the tool's history plus its registry Known list.
func TestModelOfferedMatchesThePicker(t *testing.T) {
	recent := func(_ context.Context, tool string) ([]store.RecentToolModel, error) {
		if tool == "claude-code" {
			return []store.RecentToolModel{{Model: "claude-from-history"}}, nil
		}
		return nil, nil
	}
	cases := []struct {
		tool, model string
		want        bool
	}{
		{"claude-code", "opus", true},
		{"claude-code", "claude-from-history", true},
		{"claude-code", "made-up-model", false},
		{"no-such-tool", "opus", false},
		{"codex", "o3", true},
	}
	for _, tc := range cases {
		got := dashapi.ModelOffered(context.Background(), recent, tc.tool, tc.model)
		if got != tc.want {
			t.Errorf("ModelOffered(%s, %s) = %v, want %v", tc.tool, tc.model, got, tc.want)
		}
		_, picker := modelSuggestionsFor(context.Background(), recent, tc.tool)
		inPicker := false
		for _, s := range picker {
			inPicker = inPicker || s.Model == tc.model
		}
		if inPicker != got {
			t.Errorf("%s/%s: the picker lists it %v, the rule says %v", tc.tool, tc.model, inPicker, got)
		}
	}
	if dashapi.ModelOffered(context.Background(), nil, "claude-code", "opus") {
		t.Error("no history seam offers a model; the picker offers none")
	}
}
