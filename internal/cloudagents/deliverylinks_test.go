package cloudagents

import (
	"reflect"
	"testing"
)

func TestPullRequestFromURL(t *testing.T) {
	cases := []struct {
		raw    string
		remote string
		n      int64
	}{
		{"https://github.com/acme/app/pull/7", "github.com/acme/app", 7},
		{"https://github.com/acme/app/pulls/7/", "github.com/acme/app", 7},
		{"https://gitlab.com/acme/app/-/merge_requests/12", "gitlab.com/acme/app", 12},
		{"https://bitbucket.org/acme/app/pull-requests/3", "bitbucket.org/acme/app", 3},
		{"https://github.com/acme/app", "github.com/acme/app", 0},
		{"https://github.com/acme/app/pull/x", "github.com/acme/app", 0},
		{"https://github.com/acme/app/pull/7/files", "github.com/acme/app", 0},
		{"https://github.com/acme/app/pull/0", "github.com/acme/app", 0},
		{"not a url", "", 0},
	}
	for _, tc := range cases {
		remote, n := PullRequestFromURL(tc.raw)
		if remote != tc.remote || n != tc.n {
			t.Errorf("PullRequestFromURL(%q) = %q %d, want %q %d", tc.raw, remote, n, tc.remote, tc.n)
		}
	}
}

// TestDeliveryLinks is one case per mapping row (stated PR, run branch)
// plus the pointers that must be dropped.
func TestDeliveryLinks(t *testing.T) {
	cases := []struct {
		name string
		task Task
		want []DeliveryLink
	}{
		{
			"stated PR on the PR URL's repository",
			Task{PullRequestNumber: 7, PullRequestURL: "https://github.com/acme/app/pull/7", RepoRemote: "github.com/acme/other"},
			[]DeliveryLink{{Remote: "github.com/acme/app", PRNumber: 7}},
		},
		{
			"stated PR on the task repository when the URL is absent",
			Task{PullRequestNumber: 7, RepoRemote: "github.com/acme/app"},
			[]DeliveryLink{{Remote: "github.com/acme/app", PRNumber: 7}},
		},
		{
			"a PR number with no repository is dropped",
			Task{PullRequestNumber: 7},
			nil,
		},
		{
			"a URL naming another number is not trusted",
			Task{PullRequestNumber: 7, PullRequestURL: "https://github.com/acme/app/pull/8"},
			nil,
		},
		{
			"run branches, deduplicated",
			Task{Runs: []Run{
				{ID: "r1", Remote: "github.com/acme/app", Branch: "cursor/fix-a"},
				{ID: "r2", Remote: "github.com/acme/app", Branch: "cursor/fix-a"},
				{ID: "r3", Remote: "", Branch: "cursor/x"},
				{ID: "r4", Remote: "github.com/acme/app"},
			}},
			[]DeliveryLink{{Remote: "github.com/acme/app", Branch: "cursor/fix-a"}},
		},
		{"a Codex task carries no pointer", Task{Connector: ConnectorCodexCloud, EnvironmentLabel: "acme/app"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := DeliveryLinks(tc.task); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}
