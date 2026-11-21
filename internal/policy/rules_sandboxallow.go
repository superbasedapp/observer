package policy

import (
	"regexp"
	"strings"
)

// R-167 (OpenShell build plan 05 section 3.5, lane N5): an agent widening
// its own sandbox egress. The Terminals page offers the developer "allow
// this host" on a refused connection, applied through the dashboard's
// owner-local refusal advisor route; the same host list
// ([terminal.sandbox].egress_allow_hosts) is also written by the sandbox
// config editor, the config keys route and `observer config set`. The two
// section routes matched below (/api/config/section/terminal.sandbox and
// /api/config/section/terminal) cannot write it today (terminal.sandbox is
// not a known section, and the terminal section writes only
// [terminal.attach]); they are matched as defence in depth, so a later
// section writer does not open a path the rule never saw. A sandboxed run that was refused a host is exactly the run that
// would like to lift the refusal, so the human decides it: every one of
// those writes is denied to an agent under enforce, in the R-165 pattern
// (a grant is the developer's, never the agent's). There is no request
// form: the deny text points the agent at telling the developer. Reading
// the refusals and the offers stays allowed. Writing config.toml itself is
// R-160's. R-167 is in the guard's integrity set (IsIntegrityRuleID,
// operator ruling OB-029): no layer below the org may disable or relax it.

// sandboxAllowHostKey is the config key the rule guards.
const sandboxAllowHostKey = "terminal.sandbox.egress_allow_hosts"

// sandboxAllowHostMember is the key's member name in a section body.
const sandboxAllowHostMember = "egress_allow_hosts"

// sandboxAllowRoutes are the dashboard routes that write the host list, or
// (the two section rows) could if their section writer grew it, matched as
// an exact path (urlPath's decoded, cleaned form); body, when set, narrows the row to a request
// whose body names the list (an unreadable body counts).
var sandboxAllowRoutes = []struct {
	path string
	body func(cmd *Command) bool
	desc string
}{
	{path: "/api/sandbox/refusals/allow", desc: "the refusal advisor's apply, which adds a refused host to the sandbox host allow-list"},
	{path: "/api/terminal/sandbox/config", body: sandboxAllowSectionBody, desc: "the sandbox settings editor, writing the sandbox host allow-list"},
	{path: "/api/config/section/terminal.sandbox", body: sandboxAllowSectionBody, desc: "the [terminal.sandbox] settings section, a route that names the sandbox host allow-list (matched as defence in depth)"},
	{path: "/api/config/section/terminal", body: sandboxAllowSectionBody, desc: "the [terminal] settings section, a route that names the sandbox host allow-list (matched as defence in depth)"},
	{path: "/api/config/keys", body: sandboxAllowKeyBody, desc: "the sandbox host allow-list setting"},
}

// sandboxAllowMemberText and sandboxAllowKeyText are the text fallbacks
// behind the decoded body (the R-165 body rows' second reading).
var (
	// A value of null keeps the saved list, so the member text counts only
	// with a value that does not start with "n".
	sandboxAllowMemberText = regexp.MustCompile(`(?i)\\?["']?` + sandboxAllowHostMember + `\\?["']?\s*[:=]\s*[^\sn]`)
	sandboxAllowKeyText    = regexp.MustCompile(`(?i)\bkey\\?["']?\s*[:=]\s*\\?["']?\s*` + regexp.QuoteMeta(sandboxAllowHostKey) + `(?:\\?["'\s,}&]|$)`)
)

// isSandboxAllowHostKey reports whether a dotted config key is the host
// list.
func isSandboxAllowHostKey(key string) bool {
	return strings.EqualFold(strings.TrimSpace(key), sandboxAllowHostKey)
}

// sandboxAllowSectionBody: a section body that sets the host list (any
// value but null, which keeps the saved list), at any depth, or a body the
// matcher cannot read.
func sandboxAllowSectionBody(cmd *Command) bool {
	setsList := func(v *jsonNode) bool { return v.kind != jsonNull }
	return bodyMemberLowers(cmd, sandboxAllowHostMember, setsList) || bodyMatches(cmd, sandboxAllowMemberText)
}

// sandboxAllowKeyBody: a config keys request that names the host list.
func sandboxAllowKeyBody(cmd *Command) bool {
	return bodyMemberLowers(cmd, "key", jsonStringJudged(isSandboxAllowHostKey)) || bodyMatches(cmd, sandboxAllowKeyText)
}

// matchSandboxAllowHTTP is the R-167 route matcher: a write to a loopback
// dashboard route that writes the host list.
func matchSandboxAllowHTTP(_ *MatchContext, cmd *Command) (bool, string) {
	// loopbackWriteURLs is the one reading of an HTTP client's loopback
	// targets R-165 and R-168 share (every spelling of this machine the
	// dashboard answers, sweep finding UI-1).
	method, urls := loopbackWriteURLs(cmd)
	for _, u := range urls {
		p, decoded := u.path, u.decoded
		if !decoded {
			return true, method + " " + p + " (a path that does not percent-decode, read as a route that writes the sandbox host allow-list)"
		}
		for _, r := range sandboxAllowRoutes {
			if p != r.path {
				continue
			}
			if r.body != nil && !r.body(cmd) {
				continue
			}
			return true, method + " " + p + " (" + r.desc + ")"
		}
	}
	return false, ""
}

// matchSandboxAllowCLI is the R-167 CLI matcher: `observer config set` of
// the host list (the CLI has no verb of its own for the advisor), with a
// flag before or between the subcommand words read the way cobra may read
// it (cobraPathWords, OSH-141).
func matchSandboxAllowCLI(_ *MatchContext, cmd *Command) (bool, string) {
	args, ok := observerArgs(cmd)
	if !ok {
		return false, ""
	}
	for _, w := range cobraPathWords(args, cliWords(args), []string{"config", "set"}) {
		if len(w) > 2 && isSandboxAllowHostKey(w[2]) {
			return true, "observer config set " + sandboxAllowHostKey + " changes the sandbox host allow-list"
		}
	}
	return false, ""
}

// sandboxAllowRules returns the R-167 rows (appended to the boundary
// table).
func sandboxAllowRules() []Rule {
	shell := []EventKind{KindShellExec}
	const advice = "Only the developer allows a host for sandboxed runs, from the refused connection on the Observer dashboard's Terminals page. Stop and tell the developer which host the run needs and why."
	return []Rule{
		{
			ID: "R-167", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSandboxAllowHTTP,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent calling the local dashboard to add a host to the sandbox egress allow-list (the refusal advisor's apply, or a settings route that writes the list)",
			Advice: advice,
		},
		{
			ID: "R-167", Category: CategoryBoundary, Severity: SeverityHigh,
			AppliesTo: shell, MatchCmd: matchSandboxAllowCLI,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "agent setting the sandbox egress host allow-list with observer config set",
			Advice: advice,
		},
	}
}
