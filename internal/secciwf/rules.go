package secciwf

import (
	"path"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secshellrisk"
)

// Severity is a finding's severity.
type Severity string

const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Finding is one rule hit. Message is fixed rule text; it never carries
// repository text.
type Finding struct {
	RuleID   string
	Severity Severity
	// Line is the 1-based line in the workflow file (0: file level).
	Line int
	// FlagOnly marks a finding that never blocks (S-776).
	FlagOnly bool
	Message  string
}

// Rule is one row of the closed rule table.
type Rule struct {
	ID       string
	Severity Severity
	FlagOnly bool
	Message  string
}

// Rules is THE rule table.
var Rules = []Rule{
	{ID: "S-771", Severity: SeverityHigh, Message: "a pull_request_target or workflow_run workflow checks out the pull request's head, so untrusted code runs with the base repository's token and secrets"},
	{ID: "S-772", Severity: SeverityHigh, Message: "an event field an outsider controls (github.event.*, github.head_ref) is interpolated into a run: script, which allows script injection; pass it through an environment variable"},
	{ID: "S-773", Severity: SeverityHigh, Message: "an event field an outsider controls is interpolated into an AI agent step's prompt, which allows prompt injection"},
	{ID: "S-774", Severity: SeverityMedium, Message: "a third-party action is pinned by a tag or branch, which its owner can move; pin it to a full commit SHA"},
	{ID: "S-775", Severity: SeverityHigh, Message: "permissions: write-all grants the workflow token every write scope; list only the scopes the job needs"},
	{ID: "S-776", Severity: SeverityLow, FlagOnly: true, Message: "no permissions block: the token's permissions depend on your organization's default token permissions"},
	{ID: "S-777", Severity: SeverityHigh, Message: "a job that runs the pull request's code also reads a secret, so untrusted code can read it"},
	{ID: "S-778", Severity: SeverityHigh, Message: "an AI agent step runs with a permission-bypass flag, so the agent acts with no approval in CI"},
	// S-779 is matched, not checked: Check never emits it (Check stays
	// database-free). The dependency scan child, where an OSV database is
	// installed, matches ActionRefs against the GitHub Actions ecosystem and
	// raises the finding with the advisory's own severity (this row's
	// SeverityHigh is the ceiling and the default for policy and feedback
	// code that only knows the rule id).
	{ID: "S-779", Severity: SeverityHigh, Message: "an action this workflow uses, at the version it pins, has a known advisory in OSV's GitHub Actions ecosystem; move to a fixed version"},
	// S-780 to S-782 classify run: scripts through internal/secshellrisk.Analyze
	// (the one owner of the three script classifications).
	{ID: "S-780", Severity: SeverityLow, FlagOnly: true, Message: "a run: script installs operating system packages with no version, so the build changes when the package does; pin a version"},
	{ID: "S-781", Severity: SeverityLow, FlagOnly: true, Message: "a run: script installs a language package with no version or lock, so the build changes when the package does; pin a version or install from a lockfile"},
	{ID: "S-782", Severity: SeverityMedium, Message: "a run: script pipes remote content into an interpreter, so whatever the server returns runs in the build; download, verify a checksum, then run"},
	// S-783 is one finding per file, at the first moving runner label.
	{ID: "S-783", Severity: SeverityLow, FlagOnly: true, Message: "runs-on names a moving runner label (ubuntu-latest, windows-latest, macos-latest), so the runner image changes under the workflow; name a specific image version"},
	{ID: "S-784", Severity: SeverityMedium, Message: "a container, service or docker:// action image is not pinned by an @sha256: digest, which its owner can move; pin it by digest"},
}

// MaxWorkflowBytes caps the workflow text read.
const MaxWorkflowBytes = 512 << 10

// IsWorkflowPath reports whether rel (slash-separated, repository-relative)
// is a GitHub Actions workflow file.
func IsWorkflowPath(rel string) bool {
	rel = strings.ToLower(strings.ReplaceAll(rel, "\\", "/"))
	dir, file := path.Split(rel)
	if dir != ".github/workflows/" {
		return false
	}
	return strings.HasSuffix(file, ".yml") || strings.HasSuffix(file, ".yaml")
}

// untrustedExpr matches an expression that reads outsider-controlled event
// data: github.event.* (titles, bodies, branch names, commit messages) and
// github.head_ref.
var untrustedExpr = regexp.MustCompile(`\$\{\{[^}]*\b(github\.event\.|github\.head_ref\b|github\.event\[)[^}]*\}\}`)

// secretExpr matches a secret read other than the workflow's own token.
var secretExpr = regexp.MustCompile(`\$\{\{[^}]*\bsecrets\.([A-Za-z0-9_]+)`)

// prHeadRef matches a checkout ref that names the pull request's head.
var prHeadRef = regexp.MustCompile(`github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|refs/pull/|github\.event\.workflow_run\.head_(sha|branch)`)

// commitSHA matches a full commit SHA pin.
var commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)

// aiAgentActions are the action repositories (owner/name, lowercased) that
// run an AI coding agent. Only actions known to exist are listed; a new
// one is a row here, and an agent CLI started from run: is caught by
// aiAgentCLIs instead.
var aiAgentActions = map[string]bool{
	"anthropics/claude-code-action":          true,
	"anthropics/claude-code-base-action":     true,
	"anthropics/claude-code-security-review": true,
	"openai/codex-action":                    true,
	"google-github-actions/run-gemini-cli":   true,
	"qodo-ai/pr-agent":                       true,
	"coderabbitai/ai-pr-reviewer":            true,
}

// aiAgentCLIs are command names that start an AI coding agent in run:.
var aiAgentCLIs = []string{"claude", "codex", "gemini", "qwen", "copilot", "cursor-agent", "droid", "opencode", "kilo", "goose", "aider", "qodercli", "amp", "crush"}

// bypassFlags are the permission-bypass flags of AI agent CLIs.
var bypassFlags = []string{
	"--dangerously-skip-permissions", "--dangerously-bypass-approvals-and-sandbox", "--yolo",
	"--full-auto", "--allow-all-tools", "--trust-all-tools", "--skip-permissions-unsafe",
	"bypasspermissions", "--approval-mode=yolo", "--auto-approve",
}

// promptKeys are the `with:` keys an AI agent action reads as its prompt.
var promptKeys = map[string]bool{"prompt": true, "direct_prompt": true, "override_prompt": true, "custom_instructions": true, "system_prompt": true, "append_system_prompt": true}

// Status says whether a check read the whole workflow.
type Status string

const (
	// StatusComplete: the whole file was read; no findings means none.
	StatusComplete Status = "complete"
	// StatusOverCap: the file is larger than MaxWorkflowBytes and was not
	// checked. Never read as "no findings" (a padded workflow must not
	// hide a dangerous job past the cap): callers report it unknown.
	StatusOverCap Status = "over_cap"
	// StatusUnparsed: the file does not parse as YAML, so no rule could
	// run (actionlint reports the syntax). Unknown, never clean.
	StatusUnparsed Status = "unparsed"
)

// Report is one workflow file's check result.
type Report struct {
	Status   Status
	Findings []Finding
}

// Complete reports a check that read the whole file.
func (r Report) Complete() bool { return r.Status == StatusComplete }

// Check runs every rule over one workflow file. A file over the cap is not
// checked (StatusOverCap) and a file that does not parse as YAML has no
// findings (StatusUnparsed); neither is a clean answer. A YAML file with
// no jobs mapping is not a workflow: complete, with no findings.
func Check(content []byte) Report {
	if len(content) > MaxWorkflowBytes {
		return Report{Status: StatusOverCap}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(content, &doc); err != nil {
		return Report{Status: StatusUnparsed}
	}
	if len(doc.Content) == 0 {
		return Report{Status: StatusComplete}
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return Report{Status: StatusComplete}
	}
	if j := get(root, "jobs"); j == nil || j.Kind != yaml.MappingNode {
		return Report{Status: StatusComplete} // not a workflow (no jobs mapping)
	}
	c := &checker{}
	triggers := triggerSet(get(root, "on"))
	privileged := triggers["pull_request_target"] || triggers["workflow_run"]
	topPerms := get(root, "permissions")
	if isWriteAll(topPerms) {
		c.add("S-775", topPerms.Line)
	}
	wfShell := defaultShell(root)
	jobs := get(root, "jobs")
	anyPerms := topPerms != nil
	if jobs != nil && jobs.Kind == yaml.MappingNode {
		for i := 1; i < len(jobs.Content); i += 2 {
			job := jobs.Content[i]
			if job.Kind != yaml.MappingNode {
				continue
			}
			if p := get(job, "permissions"); p != nil {
				anyPerms = true
				if isWriteAll(p) {
					c.add("S-775", p.Line)
				}
			}
			c.checkJob(job, privileged, wfShell)
		}
	}
	if !anyPerms {
		c.add("S-776", 0)
	}
	sort.SliceStable(c.out, func(i, j int) bool {
		if c.out[i].Line != c.out[j].Line {
			return c.out[i].Line < c.out[j].Line
		}
		return c.out[i].RuleID < c.out[j].RuleID
	})
	return Report{Status: StatusComplete, Findings: c.out}
}

type checker struct {
	out  []Finding
	seen map[string]bool
}

func (c *checker) add(id string, line int) {
	key := id + "@" + itoa(line)
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	for _, r := range Rules {
		if r.ID == id {
			c.out = append(c.out, Finding{RuleID: id, Severity: r.Severity, Line: line, FlagOnly: r.FlagOnly, Message: r.Message})
			return
		}
	}
}

// checkJob runs the job- and step-level rules.
func (c *checker) checkJob(job *yaml.Node, privileged bool, wfShell string) {
	c.checkRunner(get(job, "runs-on"))
	c.checkJobImages(job)
	jobShell := defaultShell(job)
	if jobShell == "" {
		jobShell = wfShell
	}
	windows := runsOnWindows(get(job, "runs-on"))
	steps := get(job, "steps")
	headCheckout := false
	secretLine := 0
	if steps != nil && steps.Kind == yaml.SequenceNode {
		for _, st := range steps.Content {
			if st.Kind != yaml.MappingNode {
				continue
			}
			if c.checkStep(st, privileged, jobShell, windows) {
				headCheckout = true
			}
			if l := secretRef(st); l > 0 && secretLine == 0 {
				secretLine = l
			}
		}
	}
	if l := secretRef(get(job, "env")); l > 0 && secretLine == 0 {
		secretLine = l
	}
	if privileged && headCheckout && secretLine > 0 {
		c.add("S-777", secretLine)
	}
}

// checkStep runs the step-level rules on one step and reports whether the
// step checks out (or fetches) the pull request's head in a privileged
// workflow.
func (c *checker) checkStep(st *yaml.Node, privileged bool, jobShell string, windows bool) (head bool) {
	uses := scalar(get(st, "uses"))
	with := get(st, "with")
	if isCheckout(uses) && privileged {
		if ref := get(with, "ref"); ref != nil && prHeadRef.MatchString(scalar(ref)) {
			head = true
			c.add("S-771", ref.Line)
		}
	}
	if uses != "" {
		c.checkPin(uses, get(st, "uses").Line)
	}
	if strings.HasPrefix(uses, "docker://") {
		c.checkImage(uses[len("docker://"):], get(st, "uses").Line)
	}
	if run := get(st, "run"); run != nil {
		if untrustedExpr.MatchString(scalar(run)) {
			c.add("S-772", run.Line+lineOf(scalar(run), untrustedExpr))
		}
		if runsPRCode(scalar(run)) && privileged {
			head = true
		}
		if hasAIBypass(scalar(run)) && mentionsAgentCLI(scalar(run)) {
			c.add("S-778", run.Line)
		}
		shell := scalar(get(st, "shell"))
		if shell == "" {
			shell = jobShell
		}
		c.checkScript(run, shell, windows)
	}
	if isAIAgentAction(uses) && with != nil && with.Kind == yaml.MappingNode {
		for i := 0; i+1 < len(with.Content); i += 2 {
			k, v := strings.ToLower(with.Content[i].Value), with.Content[i+1]
			if promptKeys[k] && untrustedExpr.MatchString(scalar(v)) {
				c.add("S-773", v.Line)
			}
			if hasAIBypass(scalar(v)) {
				c.add("S-778", v.Line)
			}
		}
	}
	return head
}

// checkPin flags a remote action not pinned to a full commit SHA.
func (c *checker) checkPin(uses string, line int) {
	if strings.HasPrefix(uses, "./") || strings.HasPrefix(uses, "docker://") {
		return
	}
	repo, ref, ok := strings.Cut(uses, "@")
	if !ok {
		c.add("S-774", line)
		return
	}
	owner, _, _ := strings.Cut(strings.ToLower(repo), "/")
	if owner == "actions" || owner == "github" {
		return // first-party actions are outside S-774 (third-party only)
	}
	if !commitSHA.MatchString(ref) {
		c.add("S-774", line)
	}
}

func isCheckout(uses string) bool {
	repo, _, _ := strings.Cut(strings.ToLower(uses), "@")
	return repo == "actions/checkout"
}

func isAIAgentAction(uses string) bool {
	repo, _, _ := strings.Cut(strings.ToLower(uses), "@")
	if aiAgentActions[repo] {
		return true
	}
	parts := strings.Split(repo, "/")
	return len(parts) > 2 && aiAgentActions[parts[0]+"/"+parts[1]]
}

// runsPRCode reports a run: script that fetches and checks out the pull
// request's head by hand.
func runsPRCode(run string) bool {
	l := strings.ToLower(run)
	if strings.Contains(l, "gh pr checkout") {
		return true
	}
	return (strings.Contains(l, "git fetch") || strings.Contains(l, "git checkout")) && prHeadRef.MatchString(run)
}

func hasAIBypass(s string) bool {
	l := strings.ToLower(s)
	for _, f := range bypassFlags {
		if strings.Contains(l, f) {
			return true
		}
	}
	return false
}

func mentionsAgentCLI(run string) bool {
	for _, line := range strings.Split(run, "\n") {
		f := strings.Fields(line)
		for i, w := range f {
			base := path.Base(strings.Trim(w, `"'`))
			for _, a := range aiAgentCLIs {
				if base == a && (i == 0 || f[i-1] == "npx" || f[i-1] == "exec" || strings.HasSuffix(f[i-1], "|") || f[i-1] == "&&" || f[i-1] == "run") {
					return true
				}
			}
		}
	}
	return false
}

// secretRef returns the line of the first secret read under n other than
// secrets.GITHUB_TOKEN (0 when none).
func secretRef(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	if n.Kind == yaml.ScalarNode {
		for _, m := range secretExpr.FindAllStringSubmatch(n.Value, -1) {
			if !strings.EqualFold(m[1], "GITHUB_TOKEN") {
				return n.Line
			}
		}
		return 0
	}
	for _, ch := range n.Content {
		if l := secretRef(ch); l > 0 {
			return l
		}
	}
	return 0
}

// triggerSet reads the `on:` value (a string, a list or a mapping).
func triggerSet(n *yaml.Node) map[string]bool {
	out := map[string]bool{}
	if n == nil {
		return out
	}
	switch n.Kind {
	case yaml.ScalarNode:
		out[n.Value] = true
	case yaml.SequenceNode:
		for _, c := range n.Content {
			out[c.Value] = true
		}
	case yaml.MappingNode:
		for i := 0; i < len(n.Content); i += 2 {
			out[n.Content[i].Value] = true
		}
	}
	return out
}

func isWriteAll(n *yaml.Node) bool {
	return n != nil && n.Kind == yaml.ScalarNode && strings.EqualFold(strings.TrimSpace(n.Value), "write-all")
}

// get returns the value node of key in a mapping (YAML 1.1 reads a bare
// `on` key as true, so "on" also matches "true").
func get(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i].Value
		if k == key || (key == "on" && k == "true") {
			return m.Content[i+1]
		}
	}
	return nil
}

func scalar(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

// lineOf returns how many lines into s the first match of re starts (0 for
// a match on the first line); a block scalar's first content line is the
// node's line plus one.
func lineOf(s string, re *regexp.Regexp) int {
	loc := re.FindStringIndex(s)
	if loc == nil {
		return 0
	}
	n := strings.Count(s[:loc[0]], "\n")
	if strings.Contains(s, "\n") {
		n++
	}
	return n
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// defaultShell returns the defaults.run.shell of a workflow or job node
// ("" when unset).
func defaultShell(n *yaml.Node) string {
	return scalar(get(get(get(n, "defaults"), "run"), "shell"))
}

// runnerLabels lists the label scalars of a runs-on value (a scalar, a
// sequence, or a mapping's labels: value).
func runnerLabels(n *yaml.Node) []*yaml.Node {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return []*yaml.Node{n}
	case yaml.SequenceNode:
		var out []*yaml.Node
		for _, c := range n.Content {
			if c.Kind == yaml.ScalarNode {
				out = append(out, c)
			}
		}
		return out
	case yaml.MappingNode:
		return runnerLabels(get(n, "labels"))
	}
	return nil
}

// isExpression reports a value that is a ${{ }} expression (not known at
// parse time).
func isExpression(s string) bool { return strings.Contains(s, "${{") }

// gitHubHostedPrefixes are the GitHub-hosted runner families.
var gitHubHostedPrefixes = []string{"ubuntu-", "windows-", "macos-"}

// isMovingRunnerLabel reports a GitHub-hosted label that tracks the newest
// image (ubuntu-latest, macos-latest-xlarge).
func isMovingRunnerLabel(label string) bool {
	l := strings.ToLower(strings.TrimSpace(label))
	if isExpression(l) {
		return false
	}
	hosted := false
	for _, p := range gitHubHostedPrefixes {
		if strings.HasPrefix(l, p) {
			hosted = true
		}
	}
	return hosted && (strings.HasSuffix(l, "-latest") || strings.Contains(l, "-latest-"))
}

// checkRunner raises S-783 (once per file) at the first moving runner label.
// A runs-on that names self-hosted is the owner's own runner and is not
// flagged.
func (c *checker) checkRunner(runsOn *yaml.Node) {
	labels := runnerLabels(runsOn)
	for _, n := range labels {
		if strings.EqualFold(strings.TrimSpace(n.Value), "self-hosted") {
			return
		}
	}
	for _, n := range labels {
		if isMovingRunnerLabel(n.Value) {
			c.addOnce("S-783", n.Line)
			return
		}
	}
}

// runsOnWindows reports a runs-on that names a Windows runner label.
func runsOnWindows(runsOn *yaml.Node) bool {
	for _, n := range runnerLabels(runsOn) {
		l := strings.ToLower(strings.TrimSpace(n.Value))
		if l == "windows" || strings.HasPrefix(l, "windows-") {
			return true
		}
	}
	return false
}

// addOnce adds a finding of id unless one of that rule is already there.
func (c *checker) addOnce(id string, line int) {
	for _, f := range c.out {
		if f.RuleID == id {
			return
		}
	}
	c.add(id, line)
}

// checkJobImages raises S-784 for a job container image and each service
// image.
func (c *checker) checkJobImages(job *yaml.Node) {
	if ct := get(job, "container"); ct != nil {
		switch ct.Kind {
		case yaml.ScalarNode:
			c.checkImage(ct.Value, ct.Line)
		case yaml.MappingNode:
			if img := get(ct, "image"); img != nil && img.Kind == yaml.ScalarNode {
				c.checkImage(img.Value, img.Line)
			}
		}
	}
	if sv := get(job, "services"); sv != nil && sv.Kind == yaml.MappingNode {
		for i := 1; i < len(sv.Content); i += 2 {
			if img := get(sv.Content[i], "image"); img != nil && img.Kind == yaml.ScalarNode {
				c.checkImage(img.Value, img.Line)
			}
		}
	}
}

// checkImage raises S-784 for an image reference with no @sha256: digest.
// An empty reference or an expression is not known and is not flagged.
func (c *checker) checkImage(image string, line int) {
	image = strings.TrimSpace(image)
	if image == "" || isExpression(image) {
		return
	}
	if strings.Contains(strings.ToLower(image), "@sha256:") {
		return
	}
	c.add("S-784", line)
}

// scriptDialect maps a step's effective shell (and the runner) to a parse
// dialect. ok is false for a shell that is not a command shell (python and
// so on): its run: text is not shell script and is not analyzed.
func scriptDialect(shell string, windows bool) (policy.Dialect, bool) {
	fields := strings.Fields(strings.ToLower(shell))
	if len(fields) == 0 {
		if windows {
			return policy.DialectPowerShell, true
		}
		return policy.DialectPosix, true
	}
	name := strings.TrimSuffix(path.Base(strings.ReplaceAll(fields[0], "\\", "/")), ".exe")
	switch name {
	case "pwsh", "powershell":
		return policy.DialectPowerShell, true
	case "bash", "sh", "zsh", "wsl":
		return policy.DialectPosix, true
	case "cmd":
		return policy.DialectCmd, true
	}
	return "", false
}

// checkScript classifies one run: script through secshellrisk (the one
// owner of the three classifications) and raises S-780 to S-782.
func (c *checker) checkScript(run *yaml.Node, shell string, windows bool) {
	script := scalar(run)
	if script == "" {
		return
	}
	dialect, ok := scriptDialect(shell, windows)
	if !ok {
		return
	}
	hits, _ := secshellrisk.Analyze(script, dialect)
	base := run.Line
	if run.Style&(yaml.LiteralStyle|yaml.FoldedStyle) != 0 {
		base++ // a block scalar's content starts on the line after its header
	}
	for _, h := range hits {
		id := ""
		switch h.Kind {
		case secshellrisk.OSInstallUnpinned:
			id = "S-780"
		case secshellrisk.LangInstallUnpinned:
			id = "S-781"
		case secshellrisk.RemotePipe:
			id = "S-782"
		}
		if id != "" {
			c.add(id, base+h.Line)
		}
	}
}
