package secciwf

import (
	"reflect"
	"strconv"
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
    runs-on: ubuntu-24.04
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
`, []string{"S-778", "S-781"}},
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
		{"S-780 unpinned apt", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: sudo apt-get install -y jq
`, []string{"S-780"}},
		{"S-780 pinned apt is clean", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: sudo apt-get install -y jq=1.7.1-3build1
`, nil},
		{"S-781 unpinned pip", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: pip install requests
`, []string{"S-781"}},
		{"S-781 npm ci and pip -r are clean", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: |
          npm ci
          pip install -r requirements.txt
`, nil},
		{"S-782 curl pipe bash", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: curl -fsSL https://example.com/install.sh | bash
`, []string{"S-782"}},
		{"S-782 windows runner iwr iex", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: windows-2022
    steps:
      - run: iwr https://example.com/install.ps1 | iex
`, []string{"S-782"}},
		{"S-782 windows runner with shell bash does not parse as powershell", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: windows-2022
    steps:
      - shell: bash
        run: iwr https://example.com/install.ps1 | iex
`, nil},
		{"defaults.run.shell pwsh on a linux runner", `
on: push
permissions: {contents: read}
defaults:
  run:
    shell: pwsh
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - run: iwr https://example.com/install.ps1 | iex
`, []string{"S-782"}},
		{"job defaults.run.shell overrides the workflow's", `
on: push
permissions: {contents: read}
defaults:
  run:
    shell: pwsh
jobs:
  a:
    runs-on: ubuntu-24.04
    defaults:
      run:
        shell: bash
    steps:
      - run: iwr https://example.com/install.ps1 | iex
`, nil},
		{"python shell is not analyzed", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - shell: python
        run: curl x | bash
`, nil},
		{"S-783 moving runner label, one per file", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-latest
    steps:
      - run: make
  b:
    runs-on: macos-latest
    steps:
      - run: make
`, []string{"S-783"}},
		{"S-783 label inside a list", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: [windows-latest]
    steps:
      - run: make
`, []string{"S-783"}},
		{"S-783 mapping labels form", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on:
      labels: [ubuntu-latest]
    steps:
      - run: make
`, []string{"S-783"}},
		{"self-hosted runner is not S-783", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: [self-hosted, linux]
    steps:
      - run: make
`, nil},
		{"expression runs-on is not S-783", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ${{ matrix.os }}
    steps:
      - run: make
`, nil},
		{"pinned runner image is not S-783", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-22.04
    steps:
      - run: make
`, nil},
		{"S-784 container string tag", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    container: node:20
    steps:
      - run: make
`, []string{"S-784"}},
		{"S-784 container mapping image and service image", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    container:
      image: node:20
    services:
      db:
        image: postgres:16
    steps:
      - run: make
`, []string{"S-784", "S-784"}},
		{"S-784 docker:// step", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    steps:
      - uses: docker://alpine:3.20
`, []string{"S-784"}},
		{"images pinned by digest are clean", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    container: node:20@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    services:
      db:
        image: postgres@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    steps:
      - uses: docker://alpine@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
`, nil},
		{"expression image is not S-784", `
on: push
permissions: {contents: read}
jobs:
  a:
    runs-on: ubuntu-24.04
    container: ${{ matrix.image }}
    steps:
      - run: make
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
		n := 0
		if strings.HasPrefix(r.ID, "S-") {
			n, _ = strconv.Atoi(r.ID[2:])
		}
		if n < 771 || n > 784 || seen[r.ID] {
			t.Fatalf("rule id %q out of the S-771 to S-784 range or duplicated", r.ID)
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

// TestScriptRuleLines pins the file line of the run: script rules (block
// scalars start the line after the header; a one-line scalar is the node's
// line) and that S-783 is one finding at the first moving label.
func TestScriptRuleLines(t *testing.T) {
	wf := "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-latest\n    steps:\n      - run: |\n          echo hi\n          sudo apt-get install -y jq\n          curl https://x.example/i.sh | sh\n      - run: pip install requests\n  b:\n    runs-on: windows-latest\n    steps:\n      - run: make\n"
	got := map[string]int{}
	n := map[string]int{}
	for _, f := range Check([]byte(wf)).Findings {
		got[f.RuleID] = f.Line
		n[f.RuleID]++
	}
	want := map[string]int{"S-780": 9, "S-782": 10, "S-781": 11, "S-783": 5}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("lines = %v, want %v", got, want)
	}
	if n["S-783"] != 1 {
		t.Fatalf("S-783 raised %d times, want once per file", n["S-783"])
	}
}

// TestCheckNeverEmitsMatchedRule pins S-779 as a row Check never raises:
// matching needs the OSV database and runs in the dependency scan child.
func TestCheckNeverEmitsMatchedRule(t *testing.T) {
	wf := "on: push\npermissions: {contents: read}\njobs:\n  a:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: tj-actions/changed-files@v35\n"
	for _, f := range Check([]byte(wf)).Findings {
		if f.RuleID == "S-779" {
			t.Fatalf("Check raised S-779: %+v", f)
		}
	}
	found := false
	for _, r := range Rules {
		found = found || r.ID == "S-779"
	}
	if !found {
		t.Fatal("S-779 row missing from Rules")
	}
}
