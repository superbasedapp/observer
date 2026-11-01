package secciwf

import (
	"reflect"
	"strings"
	"testing"
)

// TestRuleTable is one case per rule row, plus clean shapes that must not
// fire.
func TestRuleTable(t *testing.T) {
	cases := []struct {
		name string
		wf   string
		want []string
	}{
		{"S-771 prt checks out head", `
on: pull_request_target
permissions: {contents: read}
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, []string{"S-771"}},
		{"S-771 not on pull_request", `
on: pull_request
permissions: {contents: read}
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
`, nil},
		{"S-772 title into run", `
on: issues
permissions: {contents: read}
jobs:
  t:
    steps:
      - run: |
          echo hello
          echo "${{ github.event.issue.title }}"
`, []string{"S-772"}},
		{"S-772 head_ref into run", `
on: pull_request
permissions: read-all
jobs:
  t:
    steps:
      - run: git checkout ${{ github.head_ref }}
`, []string{"S-772"}},
		{"env indirection is clean", `
on: issues
permissions: {contents: read}
jobs:
  t:
    steps:
      - env:
          TITLE: ${{ github.event.issue.title }}
        run: echo "$TITLE"
`, nil},
		{"S-773 issue body into an agent prompt", `
on: issue_comment
permissions: {contents: read}
jobs:
  a:
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          prompt: "Fix this: ${{ github.event.comment.body }}"
`, []string{"S-773"}},
		{"S-774 tag pin", `
on: push
permissions: {contents: read}
jobs:
  a:
    steps:
      - uses: some-org/some-action@v2
      - uses: actions/setup-go@v5
      - uses: ./local-action
      - uses: other/x@0123456789abcdef0123456789abcdef01234567
`, []string{"S-774"}},
		{"S-775 write-all", `
on: push
permissions: write-all
jobs:
  a:
    permissions: write-all
    steps:
      - run: make
`, []string{"S-775", "S-775"}},
		{"S-776 no permissions", `
on: push
jobs:
  a:
    steps:
      - run: make
`, []string{"S-776"}},
		{"S-777 secret with PR code", `
on: pull_request_target
permissions: {contents: read}
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: make deploy
        env:
          TOKEN: ${{ secrets.DEPLOY_TOKEN }}
`, []string{"S-771", "S-777"}},
		{"GITHUB_TOKEN alone is not S-777", `
on: pull_request_target
permissions: {contents: read}
jobs:
  b:
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.ref }}
      - run: make
        env:
          GH_TOKEN: ${{ secrets.GITHUB_TOKEN }}
`, []string{"S-771"}},
		{"S-778 bypass flag in run", `
on: push
permissions: {contents: read}
jobs:
  a:
    steps:
      - run: npx claude -p "fix the build" --dangerously-skip-permissions
`, []string{"S-778"}},
		{"S-778 bypass flag in action args", `
on: push
permissions: {contents: read}
jobs:
  a:
    steps:
      - uses: anthropics/claude-code-action@0123456789abcdef0123456789abcdef01234567
        with:
          claude_args: --dangerously-skip-permissions
`, []string{"S-778"}},
		{"bypass flag without an agent", `
on: push
permissions: {contents: read}
jobs:
  a:
    steps:
      - run: ./deploy --yolo
`, nil},
		{"not yaml", "::: not yaml [", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			for _, f := range Check([]byte(tc.wf)).Findings {
				got = append(got, f.RuleID)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v (%+v)", got, tc.want, Check([]byte(tc.wf)))
			}
		})
	}
}

func TestFindingLineAndFixedMessage(t *testing.T) {
	wf := "on: issues\npermissions: {contents: read}\njobs:\n  t:\n    steps:\n      - run: |\n          echo a\n          echo \"${{ github.event.issue.title }}\"\n"
	fs := Check([]byte(wf)).Findings
	if len(fs) != 1 || fs[0].Line != 8 {
		t.Fatalf("findings = %+v, want S-772 on line 8", fs)
	}
	if strings.Contains(fs[0].Message, "issue.title") {
		t.Fatal("message carries repository text")
	}
}

func TestIsWorkflowPath(t *testing.T) {
	cases := map[string]bool{
		".github/workflows/ci.yml":       true,
		".github/workflows/release.yaml": true,
		".github/workflows/sub/x.yml":    false,
		".github/dependabot.yml":         false,
		"src/.github/workflows/x.yml":    false,
	}
	for p, want := range cases {
		if IsWorkflowPath(p) != want {
			t.Errorf("IsWorkflowPath(%q) != %v", p, want)
		}
	}
}

func TestRuleIDsInRange(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range Rules {
		if !strings.HasPrefix(r.ID, "S-77") || r.ID == "S-770" || seen[r.ID] {
			t.Fatalf("rule id %q out of the S-771 to S-779 range or duplicated", r.ID)
		}
		seen[r.ID] = true
	}
}

// TestCheckStatus (P-003, SEC-C2 milestone 1e): a workflow over the cap or
// one that does not parse is reported, never a silent "no findings".
func TestCheckStatus(t *testing.T) {
	danger := "on: pull_request_target\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n        with: {ref: \"${{ github.event.pull_request.head.sha }}\"}\n"
	padded := "# " + strings.Repeat("x", MaxWorkflowBytes) + "\n" + danger
	cases := []struct {
		name string
		wf   string
		want Status
	}{
		{"over the cap", padded, StatusOverCap},
		{"not yaml", "a: [1, 2\n  b: {\n", StatusUnparsed},
		{"not a workflow", "a: 1\n", StatusComplete},
		{"empty", "", StatusComplete},
		{"workflow", danger, StatusComplete},
	}
	for _, tc := range cases {
		r := Check([]byte(tc.wf))
		if r.Status != tc.want {
			t.Errorf("%s: status %s, want %s", tc.name, r.Status, tc.want)
		}
		if r.Status != StatusComplete && (r.Complete() || len(r.Findings) != 0) {
			t.Errorf("%s: an incomplete check reads complete: %+v", tc.name, r)
		}
	}
}
