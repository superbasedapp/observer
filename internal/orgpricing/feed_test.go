package orgpricing

import "testing"

func TestFeedAppliesTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		enrolled bool
		want     bool
		why      string
	}{
		{
			name: "a standalone node consults the public feed",
			want: true,
			why:  "§C.3: the standalone case is the only one that needs a node->internet price path",
		},
		{
			name:     "an enrolled node ignores the public feed",
			enrolled: true,
			want:     false,
			why:      "§C.3/D8: the org rail is the one authority per enrolled node; a second public source would be two answers",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := FeedApplies(tc.enrolled); got != tc.want {
				t.Errorf("FeedApplies(%v) = %v, want %v — %s", tc.enrolled, got, tc.want, tc.why)
			}
		})
	}
}
