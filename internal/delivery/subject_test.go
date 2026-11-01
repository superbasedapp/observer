package delivery

import "testing"

func TestPRNumberFromSubject(t *testing.T) {
	t.Parallel()
	cases := []struct {
		subject string
		want    int64
		ok      bool
	}{
		// Grounded (12.1): cli/cli merge commit, vercel/next.js squash.
		{"Merge pull request #14706 from cli/dependabot/github_actions/actions/create-github-app-token-3.3.0", 14706, true},
		{"Make error overlay editor actions easier to discover (#100206)", 100206, true},
		{"fix: thing (#12)  ", 12, true},
		{"Merge branch 'main' into feature", 0, false},
		{"Refs #12 in the middle", 0, false},
		{"Merge pull request #0 from x/y", 0, false},
		{"", 0, false},
	}
	for _, tc := range cases {
		got, ok := PRNumberFromSubject(tc.subject)
		if got != tc.want || ok != tc.ok {
			t.Errorf("PRNumberFromSubject(%q) = (%d, %v), want (%d, %v)", tc.subject, got, ok, tc.want, tc.ok)
		}
	}
}

func TestMergeMethodFromCommit(t *testing.T) {
	t.Parallel()
	const mergeSubj = "Merge pull request #14706 from cli/branch"
	const squashSubj = "Make error overlay editor actions easier to discover (#100206)"
	cases := []struct {
		name    string
		parents int
		subject string
		pr      int64
		want    MergeMethod
	}{
		{"merge commit", 2, mergeSubj, 14706, MergeCommit},
		{"merge commit, pr unknown", 2, mergeSubj, 0, MergeCommit},
		{"merge subject, one parent", 1, mergeSubj, 14706, ""},
		{"squash", 1, squashSubj, 100206, MergeSquash},
		{"squash suffix on a merge", 2, squashSubj, 100206, ""},
		{"other pr number", 1, squashSubj, 5, ""},
		{"rebase leaves no number", 1, "plain subject", 7, ""},
	}
	for _, tc := range cases {
		if got := MergeMethodFromCommit(tc.parents, tc.subject, tc.pr); got != tc.want {
			t.Errorf("%s: MergeMethodFromCommit = %q, want %q", tc.name, got, tc.want)
		}
	}
}
