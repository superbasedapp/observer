package policy

import (
	"net/url"
	"strconv"
	"strings"
	"unicode"

	"github.com/marmutapp/superbased-observer/internal/ipclass"
)

// Exfiltration & network rules R-170…R-173 (spec §5.3) — the exfil
// category table, deferred from G1 to G9 where its proxy half lands.
//
// R-172 spans THREE rows under one public ID (approved deviation 3):
// the shell-arg half (secrets in network-command arguments, evaluated
// on every shell event), the api_request half (typed detector
// findings stamped onto proxy egress events by the guard layer,
// §8.2), and — since F1 (phase-3a review) — a third row for the
// prompt-submit-intervention surface (typed detector findings on the
// developer's own KindUserPrompt event). All three rows agree on
// category/severity per validateRules; each carries its own
// surface-specific Doc text (the api_request and prompt rows used to
// share one AppliesTo=[KindAPIRequest,KindUserPrompt] row and one Doc
// string trying to describe both surfaces at once — split apart so
// `observer guard rules` / docs/guard-rules.md render an honest,
// single-surface description per row instead).
//
// Category note: spec §4.3 declares CategorySecrets "secrets egress
// (§8.2)" while the §5.3 catalog table places R-172 under exfil. One
// ID cannot span two categories (validateRules), so ALL THREE R-172
// rows use CategoryExfil — the §5.3 table is the catalog of record.
// CategorySecrets stays declared-but-reserved.
//
// R-190 (prompt-submit intervention, docs/plans/
// prompt-submit-intervention-exploration-2026-09-07.md §5.6) is a
// separate row appended to this same table: deterministic PII in the
// developer's OWN prompt text (KindUserPrompt, Event.PIIFindings),
// CategoryPII. Secret-shaped content typed into the SAME prompt is
// deliberately NOT folded into R-190 — it stays on R-172's own
// dedicated KindUserPrompt row above, since matchSecretsOnAPIRequest
// already keys off Event.Secrets regardless of which kind carried it.
// R-190 and R-172 therefore never double-report the same finding:
// PIIFindings drives R-190, Secrets drives R-172, on the same event.

// remoteFetchBases are the canonical download-command bases R-170/
// R-171 treat as remote-content sources. psparse resolves the
// PowerShell aliases (curl/wget/iwr/irm) to the invoke-* cmdlet names
// before matching. Table-driven per Module rule 5.
var remoteFetchBases = map[string]bool{
	"curl": true, "wget": true,
	"invoke-webrequest": true, "invoke-restmethod": true,
}

// pipeInterpreterBases are the interpreter bases that turn piped
// remote content into code execution (the R-170 sink set).
var pipeInterpreterBases = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true,
	"fish": true, "csh": true, "tcsh": true,
	"python": true, "python2": true, "python3": true,
	"node": true, "nodejs": true, "perl": true, "ruby": true, "php": true,
	"pwsh": true, "powershell": true, "invoke-expression": true,
	"cmd": true,
}

// dnsLookupBases are the DNS-query bases R-173 watches.
// resolve-dnsname is the PowerShell cmdlet (no common alias).
var dnsLookupBases = map[string]bool{
	"nslookup": true, "dig": true, "host": true, "resolve-dnsname": true,
}

// exfilRules assembles the §5.3 table rows in catalog order.
func exfilRules() []Rule {
	return []Rule{
		{
			ID: "R-170", Category: CategoryExfil, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindShellExec},
			Match:     matchRemoteCodePipe,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "remote content piped into an interpreter (curl|sh-class remote-code execution)",
			Advice: "Download to a file, review it, then execute - or pin the script to a checksum you have verified.",
		},
		{
			ID: "R-171", Category: CategoryExfil, Severity: SeverityHigh,
			AppliesTo: []EventKind{KindShellExec},
			Match:     nil, MatchCmd: matchFileUpload,
			SafePat: []SafeFn{safeUploadLocalhostOnly},
			Observe: DecisionFlag, Enforce: DecisionAsk,
			Doc:    "shell command uploading file contents to a remote destination",
			Advice: "Confirm the destination is one you intend to receive this file; project files leaving the machine is the classic exfil shape.",
		},
		{
			ID: "R-172", Category: CategoryExfil, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindShellExec},
			Match:     nil, MatchCmd: matchSecretsInNetworkArgs,
			Observe: DecisionFlag, Enforce: DecisionDeny,
			Doc:    "secret-shaped value in the arguments of a network-touching command",
			Advice: "Pass credentials via files with restrictive permissions or environment configuration the command reads itself - never inline on a network command line.",
		},
		{
			// The §8.2 proxy half: the guard layer runs the typed
			// detectors over the final outbound request body and
			// stamps Event.Secrets; this row turns the findings into
			// the R-172 verdict (mask/deny resolution happens at the
			// proxy seam per [guard.proxy].egress_action).
			ID: "R-172", Category: CategoryExfil, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindAPIRequest},
			Match:     matchSecretsOnAPIRequest,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "secret-shaped content in an outbound LLM API request",
			Advice: "Check what placed the secret in the conversation (a file read, a shell output); rotate it if it already left, and add an Egress allow pattern (Observer dashboard Settings > Guard, Proxy scans; [guard.proxy] egress_allow) only for known-fake fixtures.",
		},
		{
			// F1 (phase-3a review): the prompt-submit-intervention
			// surface (docs/plans/
			// prompt-submit-intervention-exploration-2026-09-07.md
			// §5.6/§9 Phase 1) is a THIRD R-172 row, split out from
			// the proxy-egress row above rather than sharing its Doc
			// text — the original single api_request row had
			// AppliesTo covering both KindAPIRequest and
			// KindUserPrompt with one Doc string trying to describe
			// both surfaces at once ("...in an outbound LLM API
			// request, or typed directly into a prompt"), which read
			// oddly on a prompt-submit block (nothing has gone
			// "outbound" yet — see matchSecretsOnAPIRequest's own
			// kind-aware detail text, which already drew this same
			// distinction for the runtime reason's SUFFIX; this row
			// does the same for the catalog-level Doc PREFIX). Same
			// matcher (matchSecretsOnAPIRequest keys off
			// Event.Secrets regardless of which kind carried it,
			// keying the surface-specific "in the prompt text" vs
			// "in the outbound request body" detail off
			// ctx.Event.Kind) and same Category/Severity as the
			// sibling rows (validateRules requires same-ID rows to
			// agree on both) — approved deviation 3 extended by one
			// more sub-shape.
			ID: "R-172", Category: CategoryExfil, Severity: SeverityCritical,
			AppliesTo: []EventKind{KindUserPrompt},
			Match:     matchSecretsOnAPIRequest,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "secret-shaped content typed directly into a prompt to your coding-agent tool, before it reaches the model",
			Advice: "Check what placed the secret in the conversation (a file read, a shell output, a pasted value); rotate it if it's real, and add an Allow pattern (Observer dashboard Settings > Guard, Prompt-submit intervention; a [guard.prompt] allow pattern) only for known-fake test data.",
		},
		{
			ID: "R-173", Category: CategoryExfil, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindShellExec},
			Match:     nil, MatchCmd: matchDNSExfilShape,
			Observe: DecisionFlag, Enforce: DecisionFlag,
			Doc:    "DNS lookup of an encoded-looking subdomain (DNS-tunnel exfil shape)",
			Advice: "Long random-looking DNS labels are the classic low-bandwidth exfil channel; verify the domain is one your tooling legitimately queries.",
		},
		{
			// R-190 (prompt-submit intervention, docs/plans/
			// prompt-submit-intervention-exploration-2026-09-07.md
			// §5.6): deterministic PII in the developer's own prompt
			// text. The reconsider-once mode vocabulary
			// (off/warn/ask-once/block/redact, [guard.prompt]) is
			// layered on TOP of this baseline observe/enforce verdict
			// by the guard layer's prompt-reconsider engine — this row
			// only supplies the standard category/severity/reason
			// machinery every other rule gets (org policy compilation,
			// overrides, guard_events shape).
			//
			// Severity is SeverityWarn, NOT SeverityCritical (round-2
			// review F2; superseding the contract's own original text,
			// which asserted "SeverityHigh... so a routine ask-once does
			// not also raise a toast the developer is already seeing
			// inline" — that premise doesn't hold: [guard.alerts]
			// defaults to min_severity="high" + desktop=true, and
			// notify.Desktop's MaybeAlert fires on severity >=
			// min_severity (guard.go:446, "<" not "<="), so
			// SeverityHigh toasts exactly as much as SeverityCritical
			// does. The only severity that does NOT double-notify under
			// the DEFAULT config is one strictly below "high" — hence
			// SeverityWarn, matching R-173's own "flag, don't also
			// alert" posture. (MaybeAlert isn't wired to PromptVerdict
			// yet — phase 1 has no hook/proxy caller — so this doesn't
			// change observable behavior today; it's the correct value
			// for when phase 2/3 wires it.)
			ID: "R-190", Category: CategoryPII, Severity: SeverityWarn,
			AppliesTo: []EventKind{KindUserPrompt},
			Match:     matchPromptFindings,
			Observe:   DecisionFlag, Enforce: DecisionDeny,
			Doc:    "deterministic PII (credit card, SSN, IBAN, ...) in the developer's own prompt text",
			Advice: "Remove or redact the value before sending, or add an Allow pattern (Observer dashboard Settings > Guard, Prompt-submit intervention; a [guard.prompt] allow pattern) only for known-fake test data.",
		},
	}
}

// RemoteCodePipe reports whether parsed command units pipe remote content
// into an interpreter, by R-170's own shapes, with R-170's reason. It is the
// one matcher internal/secshellrisk reuses for scripts in CI workflows and
// Dockerfiles, so the two never drift.
func RemoteCodePipe(cmds []Command) (bool, string) {
	return matchRemoteCodePipe(&MatchContext{Cmds: cmds})
}

// sourceEvaluatorBases run their operand (or their arguments) as shell code
// in the current shell: `source <(curl ...)`, `eval "$(curl ...)"`.
var sourceEvaluatorBases = map[string]bool{"source": true, ".": true, "eval": true}

// matchRemoteCodePipe implements R-170 over five shapes (documented
// approximations: static analysis of substituted content is best-effort by
// design, gap F1). Each shape needs the fetched bytes to REACH an executor;
// a fetch that only writes a file something else reads (grep, cat, jq) is
// not remote-code execution (demo finding #22, 2026-11-10: `bash -lc 'curl
// -o /tmp/x.json URL; grep ... /tmp/x.json'` used to deny as "bash -c
// executing substituted curl output", because the -c payload's own units sit
// one unwrap level down exactly like a substitution's do).
//
//  1. `curl … | sh` / `irm … | iex`: a remote-fetch unit marked as a
//     pipeline segment followed by an interpreter pipeline segment at
//     the same unwrap depth.
//  2. `iex (irm …)`: an invoke-expression unit whose raw text carries
//     a fetch form, or with a fetch unit elsewhere in the same event
//     (PowerShell paren grouping does not lex into substitution
//     units, so the raw-text check is load-bearing).
//  3. `sh -c "$(curl …)"`, `eval "$(curl …)"`: an interpreter with a
//     -c/-Command payload (or eval) whose own text lost a command
//     substitution, and a fetch that IS the top level of a substitution
//     one level deeper. A fetch the -c payload merely runs is not this
//     shape.
//  4. `bash <(curl …)`, `source <(curl …)`: an interpreter or source
//     reading a process substitution whose first command fetches.
//  5. `curl -o x.sh URL; bash x.sh`, `curl -O URL/i.sh && ./i.sh`: a fetch
//     that writes a file, and a later unit in the same event that runs
//     that file (an interpreter or source operand, or the command word
//     itself).
func matchRemoteCodePipe(ctx *MatchContext) (bool, string) {
	cmds := ctx.Cmds
	if ok, reason := shapeFetchPipedToInterpreter(cmds); ok {
		return true, reason
	}
	// Shapes 2-4 are evaluated per unit, in unit order, each unit trying
	// the shapes in table order (the first match names the reason).
	for i := range cmds {
		for _, shape := range perUnitRemoteCodeShapes {
			if ok, reason := shape(cmds, i); ok {
				return true, reason
			}
		}
	}
	return shapeDownloadThenRun(cmds)
}

// perUnitRemoteCodeShapes are R-170's shapes 2-4, each judged from one unit
// (cmds[i]) and the rest of the event, tried in this order per unit.
var perUnitRemoteCodeShapes = []func(cmds []Command, i int) (bool, string){
	shapeInvokeExpression,
	shapeSubstitutedPayload,
	shapeProcessSubstitution,
}

// shapeFetchPipedToInterpreter is shape 1: a remote-fetch pipeline segment
// followed by an interpreter pipeline segment at the same unwrap depth.
func shapeFetchPipedToInterpreter(cmds []Command) (bool, string) {
	for i := range cmds {
		c := &cmds[i]
		if !remoteFetchBases[c.Base] || !c.Pipeline {
			continue
		}
		for j := i + 1; j < len(cmds); j++ {
			n := &cmds[j]
			if n.Depth == c.Depth && n.Pipeline && pipeInterpreterBases[n.Base] {
				return true, c.Base + " output piped into " + n.Base
			}
		}
	}
	return false, ""
}

// invokeExpressionFetchForms are the fetch forms whose presence in an
// invoke-expression unit's raw text (lower-cased) marks shape 2.
var invokeExpressionFetchForms = []string{
	"irm ", "iwr ", "invoke-restmethod", "invoke-webrequest", "curl ", "wget ",
}

// shapeInvokeExpression is shape 2: invoke-expression over fetched content,
// either named in its own raw text or fetched by another unit of the event.
func shapeInvokeExpression(cmds []Command, i int) (bool, string) {
	c := &cmds[i]
	if c.Base != "invoke-expression" {
		return false, ""
	}
	lr := strings.ToLower(c.Raw)
	for _, form := range invokeExpressionFetchForms {
		if strings.Contains(lr, form) {
			return true, "invoke-expression over fetched content"
		}
	}
	for j := range cmds {
		if j != i && remoteFetchBases[cmds[j].Base] {
			return true, "invoke-expression with a remote fetch in the same command"
		}
	}
	return false, ""
}

// shapeSubstitutedPayload is shape 3: an interpreter -c payload (or eval)
// built from a substitution whose top level fetches.
func shapeSubstitutedPayload(cmds []Command, i int) (bool, string) {
	c := &cmds[i]
	runsPayload := pipeInterpreterBases[c.Base] && (c.HasShortFlag('c') || hasPSCommandFlag(c))
	if !(runsPayload || c.Base == "eval") || !c.hadSub {
		return false, ""
	}
	for j := range cmds {
		n := &cmds[j]
		if n.Depth == c.Depth+1 && n.fromSubst && remoteFetchBases[n.Base] {
			if c.Base == "eval" {
				return true, "eval executing substituted " + n.Base + " output"
			}
			return true, c.Base + " -c executing substituted " + n.Base + " output"
		}
	}
	return false, ""
}

// shapeProcessSubstitution is shape 4: an interpreter or source reading a
// process substitution whose first command fetches.
func shapeProcessSubstitution(cmds []Command, i int) (bool, string) {
	c := &cmds[i]
	if !c.procSubIn || !(pipeInterpreterBases[c.Base] || sourceEvaluatorBases[c.Base]) {
		return false, ""
	}
	for j := i + 1; j < len(cmds); j++ {
		n := &cmds[j]
		if n.Depth == c.Depth && n.procSubSrc && remoteFetchBases[n.Base] {
			return true, c.Base + " running a process substitution of " + n.Base + " output"
		}
	}
	return false, ""
}

// shapeDownloadThenRun is shape 5: a fetch that writes a file, and a later
// unit of the same event that runs that file.
func shapeDownloadThenRun(cmds []Command) (bool, string) {
	for i := range cmds {
		c := &cmds[i]
		if !remoteFetchBases[c.Base] {
			continue
		}
		for _, f := range fetchOutputFiles(c) {
			for j := i + 1; j < len(cmds); j++ {
				if runsFile(&cmds[j], f) {
					return true, c.Base + " download " + f + " then executed by " + cmds[j].Base
				}
			}
		}
	}
	return false, ""
}

// fetchOutputFiles names the files a fetch unit writes the downloaded body
// to: curl -o/--output (or the remote name under -O/--remote-name), wget
// -O/--output-document (or the remote name when absent), PowerShell
// -OutFile, and any `> file` redirect. "-" (stdout) is not a file.
func fetchOutputFiles(c *Command) []string {
	var out []string
	add := func(f string) {
		if f != "" && f != "-" {
			out = append(out, f)
		}
	}
	for _, r := range c.RedirectTargets {
		add(r)
	}
	switch c.Base {
	case "curl":
		if v, ok := shortOrLongValue(c, 'o', "--output"); ok {
			add(v)
		}
		if c.HasShortFlag('O') || c.HasLongFlag("--remote-name", "--remote-name-all") {
			for _, u := range urlOperands(c) {
				add(urlBaseName(u))
			}
		}
	case "wget":
		if v, ok := shortOrLongValue(c, 'O', "--output-document"); ok {
			add(v)
		} else {
			for _, u := range urlOperands(c) {
				add(urlBaseName(u))
			}
		}
	case "invoke-webrequest", "invoke-restmethod":
		for i := 1; i+1 < len(c.Argv); i++ {
			if strings.EqualFold(c.Argv[i], "-outfile") {
				add(c.Argv[i+1])
			}
		}
	}
	return out
}

// shortOrLongValue reads a value flag in its long form (`--output f`,
// `--output=f`) or from a short cluster (`-o f`, `-sSLo f`, and the
// attached `-of`): the bytes after the letter are its value, else the next
// word is.
func shortOrLongValue(c *Command, short byte, long string) (string, bool) {
	if v, ok := c.FlagValue(long); ok {
		return v, true
	}
	for i := 1; i < len(c.Argv); i++ {
		t := c.Argv[i]
		if t == "--" {
			break
		}
		if len(t) < 2 || t[0] != '-' || t[1] == '-' {
			continue
		}
		k := strings.IndexByte(t[1:], short)
		if k < 0 {
			continue
		}
		if rest := t[k+2:]; rest != "" {
			return rest, true
		}
		if i+1 < len(c.Argv) {
			return c.Argv[i+1], true
		}
	}
	return "", false
}

// urlOperands are the unit's http(s)/ftp URL arguments.
func urlOperands(c *Command) []string {
	var out []string
	for _, t := range c.Args() {
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "http://") || strings.HasPrefix(lt, "https://") || strings.HasPrefix(lt, "ftp://") {
			out = append(out, t)
		}
	}
	return out
}

// urlBaseName is the file name a remote-name download saves to: the URL
// path's last segment, without query or fragment ("" when there is none).
func urlBaseName(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	i := strings.IndexByte(u, '/')
	if i < 0 {
		return ""
	}
	p := strings.TrimRight(u[i:], "/")
	return p[strings.LastIndexByte(p, '/')+1:]
}

// runsFile reports whether unit n executes the file f: as the command word
// itself (`./x.sh`, `/tmp/x`), or as an operand of an interpreter or of
// source/. (`bash x.sh`, `python3 /tmp/x.py`, `. ./x.sh`). Reading the
// file (grep, cat, jq, chmod) is not running it.
func runsFile(n *Command, f string) bool {
	if len(n.Argv) == 0 {
		return false
	}
	if samePathLoose(n.Argv[0], f) {
		return true
	}
	if !pipeInterpreterBases[n.Base] && !sourceEvaluatorBases[n.Base] {
		return false
	}
	for _, a := range n.Args() {
		if samePathLoose(a, f) {
			return true
		}
	}
	return false
}

// samePathLoose compares two shell path words without a filesystem: equal
// after cleaning, or equal base names when either side is relative (a cd in
// between can make `./i.sh` the `/tmp/i.sh` a download named). It errs
// toward a match: R-170 is a deny rule for a remote-code shape, and a false
// match needs a download and an execution of a same-named file in one
// command line.
func samePathLoose(a, b string) bool {
	ca, cb := cleanShellPath(a), cleanShellPath(b)
	if ca == "" || cb == "" {
		return false
	}
	if ca == cb {
		return true
	}
	ba, bb := ca[strings.LastIndexByte(ca, '/')+1:], cb[strings.LastIndexByte(cb, '/')+1:]
	if ba == "" || ba != bb {
		return false
	}
	return !absShellPath(ca) || !absShellPath(cb)
}

// cleanShellPath normalizes a path word for samePathLoose: backslashes to
// slashes, leading "./" dropped; a flag or an empty word is "".
func cleanShellPath(p string) string {
	p = strings.ReplaceAll(strings.TrimSpace(p), `\`, "/")
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	if p == "" || p == "." || strings.HasPrefix(p, "-") {
		return ""
	}
	return p
}

// absShellPath reports a path that does not depend on the working
// directory: rooted, home-relative or a Windows drive path.
func absShellPath(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || (len(p) > 2 && p[1] == ':')
}

// hasPSCommandFlag reports a PowerShell-style -Command/-EncodedCommand
// parameter on the unit (case-insensitive — PS parameters are).
func hasPSCommandFlag(c *Command) bool {
	for _, t := range c.Args() {
		lt := strings.ToLower(t)
		if lt == "-command" || lt == "-encodedcommand" || lt == "-c" {
			return true
		}
	}
	return false
}

// uploadDataFlags are the curl-family flags whose @-prefixed value
// posts file contents (table-driven; extend here).
var uploadDataFlags = []string{"-d", "--data", "--data-binary", "--data-ascii", "--data-urlencode"}

// matchFileUpload implements R-171: curl-family upload forms plus
// scp/sftp/rsync with a remote destination.
//
// Documented approximations: the §5.3 "non-allowlisted domains"
// qualifier is narrowed to a localhost safe-pattern in v1 — a domain
// allowlist vocabulary joins when [guard.proxy] grows one; "scp/rsync
// to NEW hosts" needs host history the pure engine cannot hold, so
// every remote destination matches (observe-mode default keeps this a
// flag).
func matchFileUpload(ctx *MatchContext, cmd *Command) (bool, string) {
	switch cmd.Base {
	case "curl":
		if cmd.HasLongFlag("--upload-file") || cmd.HasShortFlag('T') {
			return true, "curl --upload-file"
		}
		for _, f := range uploadDataFlags {
			if v, ok := cmd.FlagValue(f); ok && strings.HasPrefix(v, "@") {
				return true, "curl " + f + " " + v
			}
		}
		if v, ok := cmd.FlagValue("-F", "--form"); ok && strings.Contains(v, "=@") {
			return true, "curl --form " + v
		}
	case "wget":
		if flag, file, ok := wgetUploadFile(cmd.Args()); ok {
			return true, "wget " + flag + " " + file
		}
	case "invoke-webrequest", "invoke-restmethod":
		// PS parameters are case-insensitive and not in the posix
		// flag tables; scan argv directly.
		for i := 1; i < len(cmd.Argv); i++ {
			if strings.EqualFold(cmd.Argv[i], "-infile") {
				return true, cmd.Base + " -InFile"
			}
		}
	case "scp", "sftp", "rsync":
		for _, p := range cmd.Positionals() {
			if isRemoteCopySpec(p) {
				return true, cmd.Base + " to " + p
			}
		}
	}
	return false, ""
}

// wgetUploadOptions are the wget options that send a file's contents as
// the request body (NF-4, guard-parser lane 2026-11-22): the long option,
// the shortest prefix of it GNU getopt accepts (wget takes any unambiguous
// prefix: `--post-` is ambiguous with --post-data, `--post-f` is not), and
// the wgetrc command that does the same through -e/--execute (wgetrc
// command names ignore case, `_` and `-`).
var wgetUploadOptions = []struct{ long, minPrefix, wgetrc string }{
	{long: "--post-file", minPrefix: "--post-f", wgetrc: "postfile"},
	{long: "--body-file", minPrefix: "--body-f", wgetrc: "bodyfile"},
}

// wgetExecute is wget's option that runs a wgetrc command, and the
// shortest prefix getopt accepts (`--ex` is ambiguous with --exclude-*).
const wgetExecute, wgetExecuteMin = "--execute", "--exe"

// wgetUploadFile reports a wget upload form among wget's arguments: the
// option (or wgetrc command) that sends a file and the file it names. The
// walk follows wget's option table (posixHostSpecs) so a value is never
// read as an option, and stops at `--`.
func wgetUploadFile(args []string) (flag, file string, ok bool) {
	spec := posixHostSpecs["wget"]
	value := func(i int, val string, hasEq bool) string {
		if hasEq || i+1 >= len(args) {
			return val
		}
		return args[i+1]
	}
	for i := 0; i < len(args); i++ {
		t := args[i]
		if t == "--" {
			break
		}
		if len(t) < 2 || t[0] != '-' {
			continue
		}
		if strings.HasPrefix(t, "--") {
			name, val, hasEq := strings.Cut(t, "=")
			for _, o := range wgetUploadOptions {
				if len(name) >= len(o.minPrefix) && strings.HasPrefix(o.long, name) {
					return o.long, value(i, val, hasEq), true
				}
			}
			if len(name) >= len(wgetExecuteMin) && strings.HasPrefix(wgetExecute, name) {
				if f, v, hit := wgetrcUpload(value(i, val, hasEq)); hit {
					return f, v, true
				}
			}
			if !hasEq && spec.longValued[name] {
				i++
			}
			continue
		}
		for k := 1; k < len(t); k++ {
			if strings.IndexByte(spec.shortValued, t[k]) < 0 {
				continue
			}
			v := t[k+1:]
			if v == "" && i+1 < len(args) {
				i++
				v = args[i]
			}
			if t[k] == 'e' {
				if f, fv, hit := wgetrcUpload(v); hit {
					return f, fv, true
				}
			}
			break
		}
	}
	return "", "", false
}

// wgetrcUpload reports a wgetrc command (`post_file = ./a.bin`) that sends
// a file (wgetUploadOptions).
func wgetrcUpload(command string) (flag, file string, ok bool) {
	name, val, hasEq := strings.Cut(command, "=")
	if !hasEq {
		return "", "", false
	}
	name = strings.Map(func(r rune) rune {
		switch r {
		case '_', '-', ' ', '\t':
			return -1
		}
		return unicode.ToLower(r)
	}, name)
	for _, o := range wgetUploadOptions {
		if name == o.wgetrc {
			return "-e " + o.wgetrc, strings.TrimSpace(val), true
		}
	}
	return "", "", false
}

// isRemoteCopySpec reports an scp/rsync remote-destination operand
// (user@host:path or host:path). Single-letter prefixes before ':'
// are treated as Windows drive paths, never hosts.
func isRemoteCopySpec(p string) bool {
	i := strings.IndexByte(p, ':')
	if i <= 1 {
		return false // no colon, or a drive letter ("C:\x")
	}
	host := p[:i]
	if strings.ContainsAny(host, "/\\") {
		return false // a path with a stray colon, not host:path
	}
	return true
}

// safeUploadLocalhostOnly exempts R-171 uploads whose every destination is
// loopback — posting a file to a local dev server is routine.
//
// The exemption is narrow on purpose (NEW-03 / NEW-F-02, 2026-11-22). It
// used to cut a URL's host at the first of `/:?#`, so
// `http://127.0.0.1:1@evil.example/` (userinfo 127.0.0.1:1, host
// evil.example) read as loopback, and it ignored every destination that
// was not an http(s) URL. Now:
//
//   - only a URL tool is ever exempt (curl, Invoke-WebRequest,
//     Invoke-RestMethod); scp/sftp/rsync name a remote spec, not a URL,
//     so a stray `http://localhost/` beside one exempts nothing;
//   - a URL is parsed with net/url, a URL carrying userinfo is never
//     loopback, and the host must be a loopback literal or `localhost`
//     (ipclass.IsLoopbackHost; `0.0.0.0` is not loopback);
//   - for curl, EVERY URL operand counts (positional, scheme-less,
//     any scheme, `--url`), so `http://localhost/ evil.example` is not
//     exempt;
//   - an option or variable that can send a request for a loopback URL
//     to another host voids the exemption whatever its value: a proxy,
//     `--connect-to`, `--resolve`, a DNS override, a config file
//     (uploadRouteFlags, uploadRouteEnv);
//   - a unit that had a command substitution is never exempt (FR-SEC-1,
//     review 2026-11-22): the parser strips the substitution out of the
//     word, so `http://127.0.0.1$(echo .evil.example)/` reads as
//     `http://127.0.0.1/` while curl is given 127.0.0.1.evil.example. The
//     guard cannot know what the substitution prints, wherever it sits.
//
// A routing variable set by ANOTHER unit of the same event voids the
// exemption too (FR-SEC-3, review 2026-11-22): `export ALL_PROXY=...;
// curl -T f http://127.0.0.1:9/` sends the file to the proxy
// (eventSetsRouteEnv).
func safeUploadLocalhostOnly(ctx *MatchContext, cmd *Command) bool {
	if cmd == nil || cmd.hadSub || uploadRerouteEnv(cmd.Env) || eventSetsRouteEnv(ctx) {
		return false
	}
	switch cmd.Base {
	case "curl":
		return curlLoopbackOnly(cmd.Args())
	case "invoke-webrequest", "invoke-restmethod":
		return psLoopbackOnly(cmd.Base, cmd.Args())
	}
	return false
}

// uploadRouteFlags are the curl options that can send a request for a
// loopback URL to another host: proxies, connection and address
// overrides, DNS overrides, and a config file (which can set any of
// them). Each voids the R-171 loopback exemption whatever its value.
// An unambiguous prefix of one (`--resol`, which older curl accepts) and
// its `--expand-` form (curl 8.3+) void it too. `--ipfs-gateway` names the
// host an ipfs:// URL is rewritten onto, and `--alt-svc` / `--hsts` read a
// cache file that can move the request, the same class as a config file
// (FR-SEC-9, review 2026-11-22).
var uploadRouteFlags = []string{
	"--proxy", "--preproxy", "--proxy1.0", "--socks4", "--socks4a", "--socks5", "--socks5-hostname",
	"--connect-to", "--resolve", "--doh-url", "--dns-servers", "--config",
	"--ipfs-gateway", "--alt-svc", "--hsts",
}

// uploadRouteShort are curl's short spellings of uploadRouteFlags
// (`-x` proxy, `-K` config).
const uploadRouteShort = "xK"

// uploadRouteEnv are the environment variables (lower-cased) that can
// send a curl request elsewhere: the proxy variables, the IPFS gateway, and
// the ones that move where curl reads its config file from (USERPROFILE and
// APPDATA are where curl on Windows looks after HOME).
var uploadRouteEnv = setOf("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "ipfs_gateway",
	"curl_home", "home", "xdg_config_home", "userprofile", "appdata")

// uploadRerouteEnv reports an environment assignment on the unit that
// can reroute an upload (uploadRouteEnv).
func uploadRerouteEnv(env []string) bool {
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if uploadRouteEnv[strings.ToLower(name)] {
			return true
		}
	}
	return false
}

// routeEnvSetter is one way a unit of a command line can put a variable
// into the environment of the commands after it. names returns the
// variable names the unit sets (any case; uploadRouteEnv is matched
// lower-cased), or routeEnvAny when the unit may set any variable.
type routeEnvSetter struct {
	shape string
	names func(c *Command) []string
}

// routeEnvSetters is walked over every unit of the event by
// eventSetsRouteEnv. A row that over-reads (a declaration that only
// re-exports, an assignment to a variable that is not exported) can only
// refuse the exemption, never grant it. The bare assignment `NAME=value;`
// yields no unit; the parser records it on the line's step sequence
// (seqStep.assigns) and lineAssignNames reads it.
var routeEnvSetters = []routeEnvSetter{
	// `. FILE` / `source FILE` (POSIX shells, csh, fish, and PowerShell's
	// dot-source operator): the file runs in the current shell and can
	// export anything, which the guard does not read (FR-SEC-3 open
	// question 2; lead ruling 2026-11-22, guard-parser lane).
	{"sourced file", func(c *Command) []string {
		if !sourceBases[c.Base] {
			return nil
		}
		return []string{routeEnvAny}
	}},
	// export / declare -x / typeset -x / local / readonly NAME[=value]:
	// every operand that is not an option names a variable.
	{"declaration builtin", func(c *Command) []string {
		if !declarationBases[c.Base] {
			return nil
		}
		return operandNames(c.Args())
	}},
	// csh/tcsh setenv NAME value.
	{"setenv", func(c *Command) []string {
		if c.Base != "setenv" {
			return nil
		}
		if p := c.Positionals(); len(p) > 0 {
			return p[:1]
		}
		return nil
	}},
	// cmd `set NAME=value`, fish `set -x NAME value` (and POSIX `set`,
	// whose operands set positional parameters: over-reading is safe).
	{"set", func(c *Command) []string {
		if c.Base != "set" {
			return nil
		}
		return operandNames(c.Args())
	}},
	// PowerShell `$env:NAME = v`, `${env:NAME} = v`, `$env:NAME += v`.
	{"PowerShell $env: assignment", func(c *Command) []string {
		return psEnvAssignNames(strings.ToLower(c.Raw))
	}},
	// PowerShell Set-Item / New-Item / Set-Content / Add-Content on the
	// Env: drive (`Set-Item -Path Env:HTTP_PROXY -Value v`).
	{"PowerShell Env: drive", func(c *Command) []string {
		if !psEnvDriveWriters[c.Base] {
			return nil
		}
		var out []string
		for _, a := range c.Args() {
			if n, ok := envDriveItem(a); ok {
				out = append(out, n)
			}
		}
		return out
	}},
	// [Environment]::SetEnvironmentVariable('NAME', v[, target]).
	{"SetEnvironmentVariable", func(c *Command) []string {
		raw := strings.ToLower(c.Raw)
		var out []string
		for {
			i := strings.Index(raw, "setenvironmentvariable(")
			if i < 0 {
				return out
			}
			raw = raw[i+len("setenvironmentvariable("):]
			arg := raw
			if j := strings.IndexAny(arg, ",)"); j >= 0 {
				arg = arg[:j]
			}
			out = append(out, strings.Trim(arg, " '\""))
		}
	}},
}

// routeEnvAny is the name a routeEnvSetters row returns for a unit that
// may set ANY variable (a sourced file), so the guard cannot tell which.
const routeEnvAny = "*"

// sourceBases are the commands that run a file in the current shell: the
// POSIX `.` (also PowerShell's dot-source operator) and `source`.
var sourceBases = setOf(".", "source")

// declarationBases are the shell builtins that declare or export
// variables.
var declarationBases = setOf("export", "declare", "typeset", "local", "readonly")

// psEnvDriveWriters are the canonical PowerShell cmdlets that can write an
// item of the Env: drive (aliases resolve to these in the PowerShell
// dialect).
var psEnvDriveWriters = setOf("set-item", "new-item", "set-content", "add-content")

// operandNames returns the variable names a declaration or `set` names:
// every argument that is not an option, cut at '='.
func operandNames(args []string) []string {
	var out []string
	for _, a := range args {
		if a == "" || a[0] == '-' || a[0] == '+' || a[0] == '/' {
			continue
		}
		name, _, _ := strings.Cut(a, "=")
		out = append(out, name)
	}
	return out
}

// envDriveItem reads an Env: drive path argument (`Env:NAME`, `env:\NAME`,
// or the colon form `-Path:Env:NAME`) and returns NAME.
func envDriveItem(a string) (string, bool) {
	la := strings.ToLower(a)
	if strings.HasPrefix(la, "-") {
		_, v, ok := strings.Cut(la, ":")
		if !ok {
			return "", false
		}
		la = v
	}
	rest, ok := strings.CutPrefix(la, "env:")
	if !ok {
		return "", false
	}
	return strings.TrimLeft(rest, `\/`), true
}

// psEnvAssignNames returns the variables a lower-cased PowerShell unit
// text assigns through the env: scope (`$env:name =`, `${env:name}=`,
// `$env:name +=`). Reading `$env:name` assigns nothing.
func psEnvAssignNames(raw string) []string {
	var out []string
	for i := 0; ; {
		j := strings.Index(raw[i:], "env:")
		if j < 0 {
			return out
		}
		j += i
		i = j + len("env:")
		if j == 0 || (raw[j-1] != '$' && raw[j-1] != '{') {
			continue
		}
		k := i
		for k < len(raw) && (raw[k] == '_' || isASCIILetter(raw[k]) || raw[k] >= '0' && raw[k] <= '9') {
			k++
		}
		rest := strings.TrimLeft(strings.TrimPrefix(raw[k:], "}"), " ")
		if strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==") || strings.HasPrefix(rest, "+=") {
			out = append(out, raw[i:k])
		}
	}
}

// eventSetsRouteEnv reports whether any unit of the event puts an
// uploadRouteEnv variable into the environment, or may put any variable
// there (a sourced file): routeEnvSetters, and the bare assignments the
// parser recorded on each unit's step sequence.
// The whole event is read, before or after the upload: a later unit can
// only refuse the exemption.
func eventSetsRouteEnv(ctx *MatchContext) bool {
	if ctx == nil {
		return false
	}
	seen := map[*unitSeq]bool{}
	for i := range ctx.Cmds {
		c := &ctx.Cmds[i]
		for _, row := range routeEnvSetters {
			for _, n := range row.names(c) {
				if n == routeEnvAny || uploadRouteEnv[strings.ToLower(n)] {
					return true
				}
			}
		}
		for s := c.seq; s != nil && !seen[s]; s = s.parent {
			seen[s] = true
			for _, st := range s.steps {
				if uploadRerouteEnv(st.assigns) {
					return true
				}
			}
		}
	}
	return false
}

// curlRouteOption reports whether a long curl option name is, starts, or
// is the --expand- form of an uploadRouteFlags entry.
func curlRouteOption(name string) bool {
	if rest, ok := strings.CutPrefix(name, "--expand-"); ok {
		name = "--" + rest
	}
	if len(name) <= 2 {
		return false
	}
	for _, f := range uploadRouteFlags {
		if strings.HasPrefix(f, name) {
			return true
		}
	}
	return false
}

// curlLoopbackOnly walks curl's arguments with the curl option table
// (posixHostSpecs) and reports whether every URL operand (positional,
// after `--`, or `--url`) is loopback, at least one exists, and no
// rerouting option is present. A value an option takes is never read as
// a URL; an option the table does not know leaves its value to be read as
// a URL, which can only refuse the exemption.
func curlLoopbackOnly(args []string) bool {
	spec := posixHostSpecs["curl"]
	targets := 0
	for i := 0; i < len(args); i++ {
		t := args[i]
		if t == "--" {
			for _, p := range args[i+1:] {
				targets++
				if !isLoopbackOperand(p) {
					return false
				}
			}
			break
		}
		if len(t) < 2 || t[0] != '-' {
			targets++
			if !isLoopbackOperand(t) {
				return false
			}
			continue
		}
		if strings.HasPrefix(t, "--") {
			name, val, hasEq := strings.Cut(t, "=")
			if curlRouteOption(name) {
				return false
			}
			takesValue := spec.longValued[name] || spec.hostOpts[name] != nil
			if name == "--url" {
				if !hasEq {
					if i+1 >= len(args) {
						continue
					}
					i++
					val = args[i]
				}
				targets++
				if !isLoopbackOperand(val) {
					return false
				}
				continue
			}
			if takesValue && !hasEq {
				i++
			}
			continue
		}
		for k := 1; k < len(t); k++ {
			if strings.IndexByte(uploadRouteShort, t[k]) >= 0 {
				return false
			}
			if strings.IndexByte(spec.shortValued, t[k]) >= 0 {
				if k == len(t)-1 {
					i++
				}
				break
			}
		}
	}
	return targets > 0
}

// psLoopbackOnly is the R-171 exemption for Invoke-WebRequest and
// Invoke-RestMethod. The destination is ONLY what the cmdlet binds to
// -Uri (an explicit -Uri, or else its first positional): it must be
// present, a literal (psLiteralURL) and loopback. No other token adds a
// destination (FR-SEC-2, review 2026-11-22: a loopback URL in -UserAgent
// used to count as one, so `iwr -Uri $u -InFile f -UserAgent
// http://localhost/` was exempt while the guard could not read $u). Any
// other URL-shaped token that is not loopback still refuses, and so does a
// -Proxy parameter (any prefix of it).
func psLoopbackOnly(base string, args []string) bool {
	for _, t := range args {
		lt := strings.ToLower(t)
		if strings.HasPrefix(lt, "-prox") {
			return false
		}
		if hasURLScheme(t) && !isLoopbackURL(t) {
			return false
		}
	}
	spec, ok := netPSSpecs[base]
	if !ok {
		return false
	}
	uris := spec.bound(args)
	if len(uris) == 0 {
		return false
	}
	for _, u := range uris {
		if !psLiteralURL(u) || !isLoopbackOperand(u) {
			return false
		}
	}
	return true
}

// psNonLiteral are the characters that make a PowerShell argument
// something other than literal text: a variable or subexpression ($), a
// grouping or call ((), splatting or an array or hash literal (@), a
// script block ({) and the escape character (`).
const psNonLiteral = "$(@{`"

// psLiteralURL reports a -Uri value the guard can read as written.
func psLiteralURL(v string) bool {
	return v != "" && !strings.ContainsAny(v, psNonLiteral)
}

// exemptSchemes are the URL schemes an R-171 destination may have and still
// be exempt (FR-SEC-9, review 2026-11-22). Another scheme with a loopback
// host is not a loopback upload: curl rewrites ipfs:// and ipns:// onto a
// gateway, and smtp://localhost hands the file to a relay.
var exemptSchemes = setOf("http", "https", "ws", "wss")

// isLoopbackOperand reports whether a URL operand (scheme-less allowed:
// curl and PowerShell default it to http) is an exempt scheme
// (exemptSchemes) and targets loopback.
func isLoopbackOperand(t string) bool {
	if !hasURLScheme(t) {
		t = "http://" + t
	}
	scheme, _, _ := strings.Cut(t, "://")
	return exemptSchemes[strings.ToLower(scheme)] && isLoopbackURL(t)
}

// hasURLScheme reports whether t starts with an RFC 3986 scheme and
// "://".
func hasURLScheme(t string) bool {
	i := strings.Index(t, "://")
	if i <= 0 {
		return false
	}
	for k := 0; k < i; k++ {
		c := t[k]
		switch {
		case isASCIILetter(c):
		case k > 0 && (c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.'):
		default:
			return false
		}
	}
	return true
}

// isLoopbackURL reports whether a URL targets loopback: it parses with
// net/url, carries no userinfo (whose `@` would move the real host after
// it), and its host is a loopback literal or `localhost`, in any case
// (ipclass.IsLoopbackHost). Anything that does not parse is not loopback.
func isLoopbackURL(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" {
		return false
	}
	return ipclass.IsLoopbackHost(u.Hostname())
}

// matchSecretsInNetworkArgs implements the R-172 shell-arg half: the
// injected typed detector (Config.SecretDetect) over every argument
// and heredoc of a network-touching command. Pattern-certain types
// only — the provider excludes entropy hits (random-looking tokens
// are routine in shell args).
func matchSecretsInNetworkArgs(ctx *MatchContext, cmd *Command) (bool, string) {
	if ctx.Cfg.SecretDetect == nil || !networkCommandBases[cmd.Base] {
		return false, ""
	}
	for _, a := range cmd.Args() {
		if types := ctx.Cfg.SecretDetect(a); len(types) > 0 {
			return true, "secret-shaped value (" + strings.Join(types, ", ") + ") in " + cmd.Base + " arguments"
		}
	}
	if cmd.Heredoc != "" {
		if types := ctx.Cfg.SecretDetect(cmd.Heredoc); len(types) > 0 {
			return true, "secret-shaped value (" + strings.Join(types, ", ") + ") in " + cmd.Base + " heredoc input"
		}
	}
	return false, ""
}

// matchSecretsOnAPIRequest implements the R-172 proxy half: the guard
// layer ran the typed detectors over the final outbound body and
// stamped the findings; any finding is a hit. The detail names types
// and counts only — never values.
func matchSecretsOnAPIRequest(ctx *MatchContext) (bool, string) {
	if len(ctx.Event.Secrets) == 0 {
		return false, ""
	}
	// FIX-6 (phase-2 review): this row's AppliesTo covers BOTH
	// KindAPIRequest (the proxy egress seam) and KindUserPrompt (the
	// prompt-submit intervention hook lane) — two genuinely different
	// surfaces sharing one detector. "in the outbound request body"
	// is accurate for the proxy but nonsensical for a developer who
	// just typed a prompt into their coding-agent CLI (nothing has
	// gone "outbound" yet); the vocabulary must match the surface
	// that actually produced this Event, not always assume the proxy.
	surface := "in the outbound request body"
	if ctx.Event.Kind == KindUserPrompt {
		surface = "in the prompt text"
	}
	return true, "detected " + SummarizeSecretFindings(ctx.Event.Secrets) + " " + surface
}

// SummarizeSecretFindings renders findings as a stable, content-free
// "type×count" summary ("github_pat×2, entropy×1"), in first-seen
// type order. Exported for the guard layer's verdict reasons and the
// per-session dedup signature — both sides must render identically.
func SummarizeSecretFindings(findings []SecretFinding) string {
	var order []string
	counts := map[string]int{}
	for _, f := range findings {
		if counts[f.Type] == 0 {
			order = append(order, f.Type)
		}
		counts[f.Type]++
	}
	var b strings.Builder
	for i, ty := range order {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(ty)
		if counts[ty] > 1 {
			b.WriteString("×")
			b.WriteString(strconv.Itoa(counts[ty]))
		}
	}
	return b.String()
}

// matchPromptFindings implements the R-190 prompt-submit half
// (docs/plans/prompt-submit-intervention-exploration-2026-09-07.md
// §5.6): the guard layer ran the typed PII detectors over the
// developer's own prompt text and stamped Event.PIIFindings; any
// finding is a hit. The detail names types and counts only — never
// values. Distinct from matchSecretsOnAPIRequest (R-172), which stays
// keyed on Event.Secrets on the same KindUserPrompt events — the two
// matchers never read each other's slice, so a prompt carrying both a
// secret and PII fires both rules independently.
func matchPromptFindings(ctx *MatchContext) (bool, string) {
	if len(ctx.Event.PIIFindings) == 0 {
		return false, ""
	}
	return true, "detected " + SummarizePIIFindings(ctx.Event.PIIFindings) + " in the prompt text"
}

// SummarizePIIFindings renders findings as a stable, content-free
// "type×count" summary, mirroring SummarizeSecretFindings exactly (in
// first-seen type order) — the guard layer's verdict reasons and
// per-session dedup/fingerprint signature depend on both rendering
// identically in shape.
func SummarizePIIFindings(findings []PIIFinding) string {
	var order []string
	counts := map[string]int{}
	for _, f := range findings {
		if counts[f.Type] == 0 {
			order = append(order, f.Type)
		}
		counts[f.Type]++
	}
	var b strings.Builder
	for i, ty := range order {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(ty)
		if counts[ty] > 1 {
			b.WriteString("×")
			b.WriteString(strconv.Itoa(counts[ty]))
		}
	}
	return b.String()
}

// matchDNSExfilShape implements R-173: a DNS-lookup command whose
// queried name carries an encoded-looking leading label (≥20 chars of
// base64-ish alphabet with a digit or mixed case — plain English
// labels and PTR lookups stay quiet). Single-event analysis cannot
// see the §5.3 "in loops" qualifier; per-lookup shape is the v1
// approximation (severity warn, flag in both modes).
func matchDNSExfilShape(_ *MatchContext, cmd *Command) (bool, string) {
	if !dnsLookupBases[cmd.Base] {
		return false, ""
	}
	for _, p := range cmd.Positionals() {
		if !strings.Contains(p, ".") {
			continue
		}
		label := p[:strings.IndexByte(p, '.')]
		if encodedLabel(label) {
			return true, cmd.Base + " of encoded-looking label " + label + "."
		}
	}
	return false, ""
}

// encodedLabel grades one DNS label: ≥20 chars of [A-Za-z0-9_-] AND
// (a digit present, or both cases present). "internationalization"
// stays quiet; base64/hex payload labels do not.
func encodedLabel(label string) bool {
	if len(label) < 20 {
		return false
	}
	var hasDigit, hasUpper, hasLower bool
	for i := 0; i < len(label); i++ {
		c := label[i]
		switch {
		case c >= '0' && c <= '9':
			hasDigit = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c == '-' || c == '_':
		default:
			return false
		}
	}
	return hasDigit || (hasUpper && hasLower)
}
