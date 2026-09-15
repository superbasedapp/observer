package cloudevidence

import (
	"sort"
	"strings"

	"github.com/marmutapp/superbased-observer/internal/cloudcontract"
)

// structuralfacts.go turns a session's RAW node-local action facts into the
// bounded, label-only structural signal an envelope carries: the per-action
// category, the milestone timeline, the test/build outcomes, and the
// whole-session activity mix.
//
// It is PURE (CLAUDE.md §1): no SQL, no HTTP, no clock. The store seam
// (internal/store/cloudlocal.go) reads the rows; cmd/observer maps them into
// RawAction and calls these functions; nothing here ever sees a *Store.
//
// PRIVACY RULE FOR EVERY FUNCTION HERE: the output vocabulary is CLOSED. A
// command class, a milestone kind, and a mix key are all drawn from tables
// spelled out in this file — no substring of a command, a path, or a prompt is
// ever returned as a label. That is what makes "a shell command leaked into an
// action category" structurally impossible rather than merely unlikely: an
// unrecognized command yields the fixed label "shell", never its own text.

// RawAction is one node-local action fact, already ordered by time. It carries
// raw local values (the real command string, the real path); the functions in
// this file consume them and return only closed-vocabulary labels.
type RawAction struct {
	// Ref is the stable in-envelope reference for this action ("a0", "a17"…).
	// It encodes the action's ORIGINAL position in the whole session, so a
	// sampled envelope's ref gaps honestly show that sampling happened.
	Ref string
	// Kind is the normalized action kind (the actions.action_type value).
	Kind string
	// Success is the recorded outcome.
	Success bool
	// Target is the raw local target: a path for file actions, the COMMAND
	// STRING for run_command, a tool name otherwise. Never emitted verbatim.
	Target string
	// RawToolName is the raw tool identifier (e.g. an "mcp__server__tool" name).
	RawToolName string
	// ElapsedSeconds is whole seconds from the session start, clamped at 0.
	ElapsedSeconds int
}

// -- action categories -------------------------------------------------------

// categoryStrategy names how one action kind's category is derived. Branching
// on the STRATEGY (a capability of the kind) rather than on the kind name at
// each call site is CLAUDE.md §3/§5: one table, walked once.
type categoryStrategy int

const (
	// categoryOther is the fixed "other" bucket: conversational and lifecycle
	// kinds whose target is prose or a sentinel, never a classifiable artifact.
	// It is the ZERO VALUE deliberately, so an action kind absent from the
	// table below buckets to "other" and its raw target is withheld — the safe
	// direction for a kind nobody has classified yet.
	categoryOther categoryStrategy = iota
	// categoryFromPath derives the category from the target's file extension
	// (the builder's existing deriveCategory). The raw path is also handed to
	// the builder so a path-correlation grant can hash it.
	categoryFromPath
	// categoryFromCommand derives a closed-vocabulary command class. The raw
	// command is NEVER handed on as a path — hashing a command under the
	// path-correlation grant would be a category error.
	categoryFromCommand
	// categoryFromToolName derives a bounded server label from the raw tool
	// name (MCP), falling back to "mcp".
	categoryFromToolName
	// categoryFixed emits a fixed label for kinds whose target is neither a
	// path nor a command (a URL, a query, a glob).
	categoryFixed
)

// actionCategoryStrategies is the closed kind → strategy table. A kind absent
// from it falls back to categoryOther, which is the safe direction: an unknown
// kind buckets to "other" rather than shipping its target through a derivation
// that was never designed for it.
var actionCategoryStrategies = map[string]categoryStrategy{
	// Real file paths: the extension IS the useful label.
	"read_file":  categoryFromPath,
	"edit_file":  categoryFromPath,
	"write_file": categoryFromPath,
	// Shell commands: a closed-vocabulary class, never the command text.
	"run_command": categoryFromCommand,
	// Tool names: a bounded server label.
	"mcp_call": categoryFromToolName,
	// Targets that are patterns, globs, queries, or URLs — classifiable, but
	// never as a path and never by echoing the target.
	"search_text":    categoryFixed,
	"search_files":   categoryFixed,
	"tool_search":    categoryFixed,
	"web_search":     categoryFixed,
	"web_fetch":      categoryFixed,
	"browser_action": categoryFixed,
	// A harness call is the AI CLIENT's own built-in machinery (a todo update,
	// a plan-mode exit, a skill invocation), not an MCP server call. Routing it
	// through the MCP derivation reported every one of them as the fixed "mcp"
	// bucket — a label that is simply false: no MCP server was involved (N6).
	"harness_call": categoryFixed,
}

// fixedActionCategories is the label each categoryFixed kind emits.
var fixedActionCategories = map[string]string{
	"search_text":    "search",
	"search_files":   "search",
	"tool_search":    "search",
	"web_search":     "web",
	"web_fetch":      "web",
	"browser_action": "browser",
	"harness_call":   "harness",
}

// ActionCategory returns the closed-vocabulary category label for one action,
// and whether the raw target may be carried on as a PATH (i.e. it really is a
// path, not a command or a prose target). An empty returned category means
// "let the builder derive it from the path".
func ActionCategory(a RawAction) (category string, pathIsSafe bool) {
	switch actionCategoryStrategies[a.Kind] {
	case categoryOther:
		return "other", false
	case categoryFromPath:
		// Empty ⇒ the builder's deriveCategory takes the extension. The path is
		// a genuine path, so it may ride along for the path-correlation grant.
		return "", true
	case categoryFromCommand:
		return CommandClass(a.Target), false
	case categoryFromToolName:
		return MCPCategory(a.RawToolName), false
	case categoryFixed:
		if label, ok := fixedActionCategories[a.Kind]; ok {
			return label, false
		}
		return "other", false
	default:
		return "other", false
	}
}

// commandRule is one row of the command-class table: a set of program base
// names that all resolve to the same closed-vocabulary label.
type commandRule struct {
	label    string
	programs []string
}

// commandRules is the ordered command-class table. The LABEL is what ships; the
// program names are only ever compared against, never emitted. Anything not
// listed becomes "shell" — an honest "some other shell command", never a
// fragment of the command itself.
var commandRules = []commandRule{
	{"git", []string{"git", "gh", "hub"}},
	{"go", []string{"go", "gofmt", "gofumpt", "golangci-lint", "goimports"}},
	{"npm", []string{"npm", "npx", "pnpm", "yarn", "bun", "node", "tsc", "vite", "eslint", "prettier"}},
	{"python", []string{"python", "python3", "pip", "pip3", "uv", "uvx", "poetry", "ruff", "mypy"}},
	{"rust", []string{"cargo", "rustc", "rustup"}},
	{"make", []string{"make", "cmake", "ninja", "bazel", "just"}},
	{"docker", []string{"docker", "docker-compose", "podman", "kubectl", "helm"}},
	{"cloud", []string{"az", "aws", "gcloud", "wrangler", "terraform", "flyctl", "vercel", "heroku"}},
	{"search", []string{"grep", "rg", "ag", "ack", "find", "fd", "fzf"}},
	{"fs", []string{"cd", "ls", "cat", "head", "tail", "cp", "mv", "rm", "mkdir", "touch", "chmod", "pwd", "wc", "du", "df", "tree", "stat", "diff", "tar", "zip", "unzip"}},
	{"text", []string{"sed", "awk", "jq", "yq", "sort", "uniq", "tr", "cut", "xargs", "echo", "printf"}},
	{"db", []string{"sqlite3", "psql", "mysql", "redis-cli", "mongosh"}},
	{"net", []string{"curl", "wget", "ssh", "scp", "rsync", "nc", "ping", "dig"}},
	// "timeout" is deliberately NOT here: it is a WRAPPER (see commandWrappers),
	// so `timeout 60 go test ./...` classifies as the test run it is.
	{"proc", []string{"ps", "kill", "pkill", "pgrep", "top", "htop", "sleep", "wait", "systemctl", "journalctl"}},
	{"observer", []string{"observer", "observer-org", "observer-cloud"}},
}

// commandProgramLabel is the flattened lookup built once from commandRules.
var commandProgramLabel = func() map[string]string {
	m := make(map[string]string, 128)
	for _, r := range commandRules {
		for _, p := range r.programs {
			m[p] = r.label
		}
	}
	return m
}()

// commandWrappers are prefix programs that delegate to the real command; they
// are skipped so `sudo make test` classifies as a test run, not as "proc".
var commandWrappers = map[string]bool{
	"sudo": true, "env": true, "time": true, "nohup": true,
	"command": true, "exec": true, "nice": true, "stdbuf": true,
	"timeout": true, "xvfb-run": true, "doas": true,
}

// wrapperValueOptions names, per wrapper, the OPTIONS that consume the token
// after them. Skipping a wrapper's flags but not its flag VALUES left the value
// standing where the program should be, so `sudo -u ci make test` parsed `ci`
// as the program and reported a test run as "shell" (N2). Only the option
// SPELLINGS are compared against; nothing here is ever emitted.
var wrapperValueOptions = map[string]map[string]bool{
	"sudo": {
		"-u": true, "-g": true, "-U": true, "-C": true, "-p": true,
		"-r": true, "-t": true, "-T": true, "-D": true, "-R": true, "-h": true,
		"--user": true, "--group": true, "--prompt": true, "--chdir": true,
		"--role": true, "--type": true, "--host": true, "--close-from": true,
	},
	"doas": {"-u": true, "-C": true},
	"env": {
		"-u": true, "-C": true, "-S": true,
		"--unset": true, "--chdir": true, "--split-string": true,
	},
	"timeout":  {"-s": true, "-k": true, "--signal": true, "--kill-after": true},
	"nice":     {"-n": true, "--adjustment": true},
	"stdbuf":   {"-i": true, "-o": true, "-e": true, "--input": true, "--output": true, "--error": true},
	"time":     {"-f": true, "-o": true, "--format": true, "--output": true},
	"exec":     {"-a": true},
	"xvfb-run": {"-s": true, "-n": true, "-f": true, "--server-args": true, "--server-num": true},
}

// wrapperNumericArg names the wrappers whose FIRST POSITIONAL argument belongs
// to the wrapper rather than to the command: `timeout 60 go test` and
// `nice 5 cargo build`.
var wrapperNumericArg = map[string]bool{"timeout": true, "nice": true}

// shellInterpreters are the programs whose `-c` argument IS a command line.
// `bash -c 'cd api && make test'` is a test run; parsing it positionally makes
// it "shell", because the only thing in program position is the interpreter.
var shellInterpreters = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true, "fish": true,
}

// navigationPrograms are the segments that only MOVE or CONFIGURE the shell.
// They are skipped when choosing WHICH segment names a compound command's class,
// because `cd web && npm test` is a test run, not a directory change — reporting
// it as "fs" was the single largest classification error in the corpus (N1).
// They are NOT skipped for test/build detection, which considers every segment.
var navigationPrograms = map[string]bool{
	"cd": true, "pushd": true, "popd": true, "export": true,
	"source": true, ".": true, "set": true, "unset": true, "umask": true,
}

// testRunnerPhrases are the two-token phrases that mean "this command ran a
// test suite". Phrase matching (program + subcommand) is what separates
// `go test ./...` from `go build ./...`.
var testRunnerPhrases = [][2]string{
	{"go", "test"},
	{"npm", "test"},
	{"npm", "t"},
	{"pnpm", "test"},
	{"yarn", "test"},
	{"bun", "test"},
	{"cargo", "test"},
	{"make", "test"},
	{"make", "check"},
	{"dotnet", "test"},
	{"mvn", "test"},
	{"gradle", "test"},
	{"swift", "test"},
}

// testRunnerPrograms are programs whose whole purpose IS running tests, so the
// program alone is enough.
var testRunnerPrograms = map[string]bool{
	"pytest": true, "vitest": true, "jest": true, "mocha": true,
	"phpunit": true, "rspec": true, "tox": true, "nose": true, "nose2": true,
}

// buildPhrases are the two-token phrases that mean "this command built the
// project".
var buildPhrases = [][2]string{
	{"go", "build"},
	{"npm", "build"},
	{"pnpm", "build"},
	{"yarn", "build"},
	{"cargo", "build"},
	{"make", "build"},
	{"make", "all"},
	{"docker", "build"},
	{"tsc", "--build"},
	{"go", "install"},
}

// scriptRunnerPrograms are the programs whose subcommand is itself a runner:
// `npm run <script>` means the SCRIPT names the work, not the word "run".
var scriptRunnerPrograms = map[string]bool{
	"npm": true, "pnpm": true, "yarn": true, "bun": true, "deno": true,
}

// commandShape is a parsed shell command reduced to the only two positions that
// may influence a label: the PROGRAM and its SUBCOMMAND.
//
// WHY POSITIONS AND NOT A SCAN (the F8 fix). The previous parser lowercased and
// PATH-STRIPPED every retained token and then asked "does any of them equal
// 'test'?" — so `go build ./test` (a build, in a directory named test) counted
// as a successful test run, and `cp -r test build` looked like both. Arguments
// are user data: a directory, a file, a flag value. Only the position that
// actually selects the tool's behaviour may be matched, so only that position is
// parsed.
type commandShape struct {
	// Program is the invoked program's base name, lowercased (path stripped,
	// since `/usr/bin/git` and `git` are the same program). It is a LOOKUP KEY,
	// never a label.
	Program string
	// Subcommands are the candidate subcommand tokens, in order: the first
	// argument verbatim, plus — for `npm run <script>` and friends — the script
	// name. They are lowercased but NOT path-stripped: `./test` must stay
	// `./test` so it cannot masquerade as the subcommand `test`.
	Subcommands []string
	// Status is what the recorded exit status of the WHOLE line can honestly say
	// about THIS segment. See SegmentStatus.
	Status SegmentStatus
}

// SegmentStatus is the honest outcome attribution for ONE segment of a shell
// line (A3).
//
// A recorded action carries ONE exit status for a whole command line, and the
// shell gives that status to exactly one segment. Which one depends on how the
// segments were joined, and for two joins it is not knowable at all:
//
//	go test ./... || true          exits 0 whether or not the suite passed
//	true || go test ./...          exits 0 with the suite never run
//	go test ./... 2>&1 | tail      exits with tail's status, not the suite's
//	make build && go test ./...    a non-zero exit is the TEST's, not the build's
//
// Every one of those was previously credited to the test or the build. The
// three states below are the honest reading: a segment is OK, Failed, or its
// outcome is simply not in the evidence.
type SegmentStatus int

const (
	// SegmentUnknown means the recorded status does not belong to this segment
	// (or the line's shape makes attribution impossible). It is the ZERO VALUE
	// deliberately: a code path that forgets to attribute a status claims
	// nothing rather than claiming success.
	SegmentUnknown SegmentStatus = iota
	// SegmentOK means this segment is known to have succeeded.
	SegmentOK
	// SegmentFailed means this segment is known to have failed.
	SegmentFailed
)

// Bounds on shell parsing. A recorded command is untrusted, possibly enormous
// text, so the work it can cause is capped: only the leading bytes are lexed
// (program and subcommand positions are at the FRONT of each segment), only the
// first segments are parsed, and `sh -c` bodies nest a fixed depth.
const (
	maxCommandScanBytes = 4096
	maxShellSegments    = 32
	maxShellRecursion   = 2
)

// shellToken is one lexed token of a command line: a WORD (with quoting already
// removed, and a flag saying it was quoted) or a control OPERATOR.
type shellToken struct {
	text   string
	quoted bool
	op     bool
}

// tokenizeShell lexes a command line into words and the control operators
// `&&`, `||`, `;`, `|` (and a newline, which separates commands the same way).
// It is quote-aware: an operator INSIDE single or double quotes is ordinary
// text, which is what lets `bash -c 'a && b'` stay one token and
// `git commit -m 'a; b'` stay one command.
//
// It also recognizes the two constructs that make some of a line NOT A COMMAND
// (A4):
//
//   - an UNQUOTED `#` at a word boundary starts a comment that runs to the end
//     of the line. `echo hello # ignored ; go test ./...` runs no test, and
//     lexing it as one did — the `;` inside a comment became a real separator
//     and `go test` a real segment, so the session was credited a test run that
//     never happened.
//   - a `<<`/`<<-` HEREDOC body is DATA the command reads, not commands the
//     shell runs. `cat <<'EOF' > f` followed by `go test ./...` and `EOF` is a
//     file being written, and every line of its body was previously parsed as a
//     command line.
//
// ok=false means ABSTAIN: a heredoc was opened whose terminator never arrived,
// so the boundary between command and data is unknown and no classification of
// this line can be trusted. Callers treat that as "shell" / no outcome, which is
// the safe direction — the alternative is to guess, and guessing is what
// produced the fabricated test runs.
//
// It remains a classifier's lexer, not a shell: it expands nothing, does not
// interpret redirections (`2>&1` is simply a word), and never evaluates.
//
// gocyclo: one branch per shell lexing construct by design (quoting,
// operators, comments, heredocs); complexity tracks the character-class count
// a shell lexer must recognize, not logic depth.
//
//nolint:gocyclo // see the note above
func tokenizeShell(s string) ([]shellToken, bool) {
	var (
		out     []shellToken
		cur     strings.Builder
		quoted  bool
		started bool
		pending []string // heredoc terminators whose bodies have not been consumed
	)
	flush := func() {
		if started {
			out = append(out, shellToken{text: cur.String(), quoted: quoted})
			cur.Reset()
			quoted = false
			started = false
		}
	}
	addOp := func(text string) {
		flush()
		out = append(out, shellToken{text: text, op: true})
	}
	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case c == '\'' || c == '"':
			q := c
			i++
			started, quoted = true, true
			for i < len(s) && s[i] != q {
				if q == '"' && s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
				i++
			}
			if i < len(s) {
				i++ // the closing quote
			}
		case c == '\\' && i+1 < len(s):
			started = true
			cur.WriteByte(s[i+1])
			i += 2
		case c == '#' && !started:
			// A comment: everything to the end of the line is prose. The newline
			// itself is left for the operator case below, so the NEXT line is
			// still a command.
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case c == '<' && !started && isHeredocOpener(s, i):
			term, next, ok := heredocDelimiter(s, i)
			if !ok {
				return nil, false
			}
			pending = append(pending, term)
			i = next
		case c == ' ' || c == '\t' || c == '\r':
			flush()
			i++
		case c == '\n' || c == ';':
			addOp(";")
			i++
			if c == '\n' && len(pending) > 0 {
				next, ok := skipHeredocBodies(s, i, pending)
				if !ok {
					return nil, false
				}
				pending = pending[:0]
				i = next
			}
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			addOp("&&")
			i += 2
		case c == '|':
			if i+1 < len(s) && s[i+1] == '|' {
				addOp("||")
				i += 2
			} else {
				addOp("|")
				i++
			}
		default:
			started = true
			cur.WriteByte(c)
			i++
		}
	}
	flush()
	if len(pending) > 0 {
		// A heredoc was opened and its body never arrived (a truncated recording
		// is the common cause). Abstain rather than classify half a document.
		return nil, false
	}
	return out, true
}

// isHeredocOpener reports whether s[i:] begins a heredoc redirection (`<<` or
// `<<-`) rather than a here-STRING (`<<<`, whose body is on the same line and
// is an ordinary word).
func isHeredocOpener(s string, i int) bool {
	if i+1 >= len(s) || s[i+1] != '<' {
		return false
	}
	return i+2 >= len(s) || s[i+2] != '<'
}

// heredocDelimiter parses the `<<`/`<<-` redirection at s[i] and returns the
// terminator word plus the index just past the delimiter. The delimiter may be
// quoted (`<<'EOF'`), which in a real shell only suppresses expansion — the
// terminator is the unquoted text either way.
func heredocDelimiter(s string, i int) (term string, next int, ok bool) {
	i += 2 // past "<<"
	if i < len(s) && s[i] == '-' {
		i++
	}
	for i < len(s) && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	if i >= len(s) {
		return "", 0, false
	}
	var b strings.Builder
	if q := s[i]; q == '\'' || q == '"' {
		i++
		for i < len(s) && s[i] != q {
			b.WriteByte(s[i])
			i++
		}
		if i >= len(s) {
			return "", 0, false // unterminated quote in the delimiter
		}
		i++ // the closing quote
	} else {
		for i < len(s) && !strings.ContainsRune(" \t\r\n;|&()<>", rune(s[i])) {
			b.WriteByte(s[i])
			i++
		}
	}
	if b.Len() == 0 {
		return "", 0, false
	}
	return b.String(), i, true
}

// skipHeredocBodies consumes the bodies of the pending heredocs, in the order
// they were opened, returning the index just past the last terminator line.
// ok=false means a terminator never appeared.
func skipHeredocBodies(s string, i int, terms []string) (int, bool) {
	for _, term := range terms {
		found := false
		for i <= len(s) {
			end := strings.IndexByte(s[i:], '\n')
			line := s[i:]
			nextLine := len(s)
			if end >= 0 {
				line = s[i : i+end]
				nextLine = i + end + 1
			}
			// TrimSpace covers the `<<-` form (a tab-indented terminator) and
			// trailing whitespace, without needing to track which form opened it.
			if strings.TrimSpace(line) == term {
				i = nextLine
				found = true
				break
			}
			if end < 0 {
				i = len(s)
				break
			}
			i = nextLine
		}
		if !found {
			return 0, false
		}
	}
	return i, true
}

// The operator sets each level of splitting cuts on. They are separate levels
// because shell PRECEDENCE is what decides who owns the exit status: `|` binds
// tighter than `&&`/`||`, which bind tighter than `;`.
var (
	listSeparators  = map[string]bool{";": true}
	andOrSeparators = map[string]bool{"&&": true, "||": true}
	pipeSeparators  = map[string]bool{"|": true}
)

// splitTokensOn cuts a token stream at the operators in ops, returning the
// parts and the separators BETWEEN them (len(seps) == len(parts)-1). Operators
// not in ops stay inside their part, for the next level down to cut on.
//
// Unlike the previous splitter it KEEPS the separators, because which operator
// joined two segments is exactly the fact outcome attribution turns on.
func splitTokensOn(toks []shellToken, ops map[string]bool) (parts [][]shellToken, seps []string) {
	var cur []shellToken
	for _, t := range toks {
		if t.op && ops[t.text] {
			parts = append(parts, cur)
			seps = append(seps, t.text)
			cur = nil
			continue
		}
		cur = append(cur, t)
	}
	return append(parts, cur), seps
}

// trimTrailingEmpty drops trailing parts that carry no tokens, so a dangling
// `cmd &&` does not make `cmd` look like an earlier link of a chain that
// reached its end (which would credit it a success it never earned).
func trimTrailingEmpty(parts [][]shellToken) [][]shellToken {
	for len(parts) > 0 && len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	return parts
}

// parseCommand reduces a shell command line to the shapes of the commands it
// actually runs — one per segment of a compound line.
//
// WHY SEGMENTS (the N1 fix). The previous parser took the whole line's FIRST
// token as the program, so `cd web && npm test` was a `cd`: class "fs", not a
// test run. On a real corpus roughly two thirds of test invocations are shaped
// that way (`cd <dir> && <runner>`, `<runner> 2>&1 | tail`, `sh -c '…'`), so the
// outcome block under-reported test and build runs by that margin. Splitting on
// the unquoted control operators and parsing each segment POSITIONALLY keeps the
// F8 guarantee intact — an argument still never matches, because matching still
// only ever looks at a segment's program and subcommand positions.
func parseCommand(cmd string) []commandShape {
	return parseCommandLine(cmd, SegmentUnknown, 0)
}

// parseCommandLine parses cmd and attributes `status` — the exit status
// recorded for the WHOLE line — to the one segment it belongs to, per the shell's
// own precedence (A3):
//
//	`;` / newline  the status is the LAST list's; earlier lists are discarded
//	`&&`           the last pipeline owns it; earlier links are known-SUCCESS,
//	               because the last one only ran if they all succeeded
//	`||`           NOBODY owns it: `a || b` exits with a's status when a
//	               succeeded and b's when it did not, and which happened is not
//	               recorded. Every segment of such a list is unknown.
//	`|`            the LAST STAGE owns it; earlier stages ran but their status
//	               was discarded by the pipeline
//
// A status of SegmentUnknown propagates: passing it in yields shapes that claim
// nothing, which is what CommandClass (a pure classification, no outcome) uses.
func parseCommandLine(cmd string, status SegmentStatus, depth int) []commandShape {
	if depth > maxShellRecursion || strings.TrimSpace(cmd) == "" {
		return nil
	}
	if len(cmd) > maxCommandScanBytes {
		cmd = cmd[:maxCommandScanBytes]
		// The tail that was cut may hold the segment the status belongs to, so
		// no surviving segment may claim it.
		status = SegmentUnknown
	}
	toks, ok := tokenizeShell(cmd)
	if !ok {
		return nil // abstain: an unterminated heredoc body is not command text
	}
	lists, _ := splitTokensOn(toks, listSeparators)
	lists = trimTrailingEmpty(lists)
	out := make([]commandShape, 0, len(lists))
	truncated := false
	for li, list := range lists {
		listStatus := SegmentUnknown
		if li == len(lists)-1 {
			listStatus = status
		}
		for _, sh := range parseList(list, listStatus, depth) {
			if len(out) >= maxShellSegments {
				truncated = true
				break
			}
			out = append(out, sh)
		}
		if truncated {
			break
		}
	}
	if truncated {
		// The segment the status belonged to fell outside the bound, so nothing
		// that survived may claim it.
		for i := range out {
			out[i].Status = SegmentUnknown
		}
	}
	return out
}

// parseList parses ONE `;`-separated list: a chain of pipelines joined by `&&`
// and `||`, with status attributed per the rules in parseCommandLine.
func parseList(toks []shellToken, status SegmentStatus, depth int) []commandShape {
	pipelines, seps := splitTokensOn(toks, andOrSeparators)
	pipelines = trimTrailingEmpty(pipelines)
	if len(pipelines) == 0 {
		return nil
	}
	shortCircuit := false
	for _, s := range seps {
		if s == "||" {
			shortCircuit = true
		}
	}
	var out []commandShape
	for pi, pl := range pipelines {
		var st SegmentStatus
		switch {
		case shortCircuit || status == SegmentUnknown:
			// An `||` anywhere in the list means the recorded status could have
			// come from either side of it, and nothing distinguishes them.
			st = SegmentUnknown
		case pi == len(pipelines)-1:
			st = status
		default:
			// Only reached on a pure `&&` chain whose last link ran: every
			// earlier link must therefore have succeeded.
			st = SegmentOK
		}
		out = append(out, parsePipeline(pl, st, depth)...)
	}
	return out
}

// parsePipeline parses ONE pipeline. Only the LAST stage's status is the
// pipeline's: `go test ./... | tail` reports tail's exit code, which is why a
// failing suite piped into a pager used to count as a passing one.
func parsePipeline(toks []shellToken, status SegmentStatus, depth int) []commandShape {
	stages, _ := splitTokensOn(toks, pipeSeparators)
	stages = trimTrailingEmpty(stages)
	var out []commandShape
	for si, stage := range stages {
		st := SegmentUnknown
		if si == len(stages)-1 {
			st = status
		}
		out = append(out, parseSegment(stage, st, depth)...)
	}
	return out
}

// parseSegment reduces ONE segment (no control operators inside) to its shape,
// skipping the noise a shell line carries in front of the program: leading
// VAR=value assignments and wrapper programs with their options and values. A
// shell interpreter's `-c` body — and `env -S`'s string, which is the same
// thing under a different spelling — is a command line in its own right and is
// recursed into rather than parsed as an argument.
func parseSegment(toks []shellToken, status SegmentStatus, depth int) []commandShape {
	i, splitString, hasSplitString := skipCommandPrefix(toks)
	if hasSplitString {
		return parseCommandLine(splitString, status, depth+1)
	}
	if i >= len(toks) {
		return nil
	}
	program := programBase(toks[i].text)
	if program == "" {
		return nil
	}
	args := toks[i+1:]
	if shellInterpreters[program] {
		if body, ok := shellDashCBody(args); ok {
			return parseCommandLine(body, status, depth+1)
		}
	}
	shape := commandShape{Program: program, Status: status}
	if len(args) == 0 {
		return []commandShape{shape}
	}
	first := normalizeArgToken(args[0].text)
	if first == "" {
		return []commandShape{shape}
	}
	shape.Subcommands = append(shape.Subcommands, first)
	// `npm run build` / `pnpm run test`: the script name is the real subcommand.
	if scriptRunnerPrograms[shape.Program] && first == "run" && len(args) > 1 {
		if script := normalizeArgToken(args[1].text); script != "" {
			shape.Subcommands = append(shape.Subcommands, script)
		}
	}
	return []commandShape{shape}
}

// splitStringOptions names, per wrapper, the options whose VALUE is a whole
// command line rather than a flag value (A4). `env -S 'go test ./...'` is the
// documented way to give env a single-string command; skipping the flag and its
// value left nothing in program position at all, so the test run classified as
// "shell" and counted for nothing.
var splitStringOptions = map[string]map[string]bool{
	"env": {"-S": true, "--split-string": true},
}

// skipCommandPrefix returns the index of the real program token, past any
// leading NAME=value assignments and wrapper invocations. `env FOO=1 sudo -u ci
// make test` needs assignments and wrappers in either order, so this is a loop
// rather than a pair of special cases.
//
// When a wrapper carries a split-string option, its value is returned instead:
// the caller re-parses it as a command line.
func skipCommandPrefix(toks []shellToken) (idx int, splitString string, hasSplitString bool) {
	i := 0
	for i < len(toks) {
		if !toks[i].quoted && isEnvAssignment(toks[i].text) {
			i++
			continue
		}
		base := programBase(toks[i].text)
		if !commandWrappers[base] {
			break
		}
		next, body, ok := skipWrapperArgs(base, toks, i+1)
		if ok {
			return 0, body, true
		}
		i = next
	}
	return i, "", false
}

// skipWrapperArgs advances past one wrapper's own options (and the values those
// options consume), plus the numeric positional `timeout`/`nice` take. It
// returns early with ok=true when it meets a split-string option, handing the
// caller the command line that option carries.
func skipWrapperArgs(wrapper string, toks []shellToken, i int) (next int, splitString string, ok bool) {
	for i < len(toks) {
		t := toks[i]
		if len(t.text) < 2 || t.text[0] != '-' {
			break
		}
		name, inline := optionName(t.text)
		// The split-string test comes BEFORE the ordinary unquoted-option test:
		// its value is a command line, so it is routinely written with quotes
		// (`--split-string='go test ./...'`), and a quoted token is not an
		// "option token" by the stricter rule below.
		if splitStringOptions[wrapper][name] {
			if inline {
				if v := t.text[len(name)+1:]; strings.TrimSpace(v) != "" {
					return i, v, true
				}
			} else if i+1 < len(toks) && strings.TrimSpace(toks[i+1].text) != "" {
				return i, toks[i+1].text, true
			}
		}
		if !isOptionToken(t) {
			break
		}
		i++
		if !inline && wrapperValueOptions[wrapper][name] && i < len(toks) && !isOptionToken(toks[i]) {
			i++
		}
	}
	if wrapperNumericArg[wrapper] && i < len(toks) && isDurationToken(toks[i].text) {
		i++
	}
	return i, "", false
}

// isOptionToken reports whether a token is an unquoted `-…` option.
func isOptionToken(t shellToken) bool {
	return !t.quoted && len(t.text) > 1 && t.text[0] == '-'
}

// optionName splits `--user=ci` into its name and reports that the value was
// given INLINE (so the following token is not the option's value).
func optionName(tok string) (name string, inline bool) {
	if i := strings.IndexByte(tok, '='); i > 0 {
		return tok[:i], true
	}
	return tok, false
}

// isDurationToken reports whether a token is a plain number, optionally with a
// single time-unit suffix — the shape of `timeout 60` and `timeout 1.5h`.
func isDurationToken(tok string) bool {
	if tok == "" {
		return false
	}
	switch tok[len(tok)-1] {
	case 's', 'm', 'h', 'd':
		tok = tok[:len(tok)-1]
	}
	if tok == "" {
		return false
	}
	dots := 0
	for i := 0; i < len(tok); i++ {
		switch {
		case tok[i] >= '0' && tok[i] <= '9':
		case tok[i] == '.' && dots == 0 && i > 0:
			dots++
		default:
			return false
		}
	}
	return true
}

// shellDashCBody returns the command line an interpreter's `-c` option carries
// (`bash -c 'cd api && make test'`), accepting the common short-flag clusters
// that end in c (`-lc`, `-ec`). It returns ok=false when there is no such body.
func shellDashCBody(args []shellToken) (string, bool) {
	for i := 0; i < len(args); i++ {
		t := args[i]
		if !isOptionToken(t) {
			return "", false
		}
		flags := t.text
		if strings.HasPrefix(flags, "--") {
			if flags != "--command" || i+1 >= len(args) {
				continue
			}
			return args[i+1].text, true
		}
		if strings.HasSuffix(flags, "c") && i+1 < len(args) {
			return args[i+1].text, true
		}
	}
	return "", false
}

// normalizeArgToken lowercases an argument token and trims quoting, WITHOUT
// stripping any path segments — that stripping is precisely what let a directory
// argument impersonate a subcommand.
func normalizeArgToken(tok string) string {
	tok = strings.TrimSpace(tok)
	tok = strings.Trim(tok, "\"'`()")
	return strings.ToLower(tok)
}

// isEnvAssignment reports whether f looks like a leading NAME=value shell
// assignment (the name part must be a plain identifier, so a path with an '='
// in it never qualifies).
func isEnvAssignment(f string) bool {
	i := strings.IndexByte(f, '=')
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := f[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && j > 0:
		default:
			return false
		}
	}
	return true
}

// programBase reduces a token to a comparable program name: the last path
// segment, lowercased, with a Windows executable suffix dropped. The result is
// only ever used as a LOOKUP KEY — it is never returned as a label.
func programBase(tok string) string {
	tok = strings.TrimSpace(tok)
	tok = strings.Trim(tok, "\"'`()")
	tok = strings.ReplaceAll(tok, "\\", "/")
	if i := strings.LastIndexByte(tok, '/'); i >= 0 {
		tok = tok[i+1:]
	}
	tok = strings.ToLower(tok)
	tok = strings.TrimSuffix(tok, ".exe")
	tok = strings.TrimSuffix(tok, ".cmd")
	return tok
}

// CommandClass returns the closed-vocabulary class of a shell command:
// "test"/"build" when the command ran a test suite or a build, else the
// program's family label, else "shell". It NEVER returns any part of the
// command text.
//
// On a COMPOUND line the class is the first segment that is not pure shell
// navigation (`cd`, `pushd`, `export`, `source`), falling back to the first
// segment when every segment is navigation. That is what makes `cd web && npm
// test` a test run and `cd test && ls` an "fs" — the class names the WORK, and
// getting there is not the work.
func CommandClass(cmd string) string {
	shapes := parseCommand(cmd)
	if len(shapes) == 0 {
		return "shell"
	}
	lead := shapes[0]
	for _, s := range shapes {
		if !navigationPrograms[s.Program] {
			lead = s
			break
		}
	}
	return lead.class()
}

// class is one parsed segment's closed-vocabulary label.
func (s commandShape) class() string {
	if s.Program == "" {
		return "shell"
	}
	if s.isTest() {
		return "test"
	}
	if s.isBuild() {
		return "build"
	}
	if label, ok := commandProgramLabel[s.Program]; ok {
		return label
	}
	return "shell"
}

// matchesPhrase reports whether the shape's (program, subcommand) matches one of
// the phrases. ONLY a subcommand position is compared against the phrase's
// second element — an argument never is.
func (s commandShape) matchesPhrase(phrases [][2]string) bool {
	if s.Program == "" || len(s.Subcommands) == 0 {
		return false
	}
	for _, p := range phrases {
		if s.Program != p[0] {
			continue
		}
		for _, sub := range s.Subcommands {
			if sub == p[1] {
				return true
			}
		}
	}
	return false
}

// isTest reports whether the parsed shape ran a test suite.
func (s commandShape) isTest() bool {
	if s.Program == "" {
		return false
	}
	if testRunnerPrograms[s.Program] {
		return true
	}
	return s.matchesPhrase(testRunnerPhrases)
}

// isBuild reports whether the parsed shape built the project. A shape that is
// ALSO a test run is not a build (a test run that compiles is still a test run).
func (s commandShape) isBuild() bool {
	if s.Program == "" || s.isTest() {
		return false
	}
	return s.matchesPhrase(buildPhrases)
}

// IsTestCommand reports whether a command line ran a test suite — in ANY of its
// segments, so `cd web && npm test` and `go test ./... 2>&1 | tail` both count.
func IsTestCommand(cmd string) bool {
	for _, s := range parseCommand(cmd) {
		if s.isTest() {
			return true
		}
	}
	return false
}

// IsBuildCommand reports whether a command line built the project, in any of its
// segments. A segment that is itself a test run is never also a build.
func IsBuildCommand(cmd string) bool {
	for _, s := range parseCommand(cmd) {
		if s.isBuild() {
			return true
		}
	}
	return false
}

// mcpToolNamePrefix is the conventional MCP tool-name prefix; the server id is
// the segment after it.
const mcpToolNamePrefix = "mcp__"

// mcpServerLabels is the CLOSED table of KNOWN MCP server identifiers to the
// fixed label each one ships as.
//
// WHY A TABLE AND NOT THE ID ITSELF (the F3 fix). The server segment of an MCP
// tool name is whatever the developer wrote in their own MCP config: it is
// routinely a filename (`payroll.csv`), a client name, or an unreleased project
// codename. Echoing it — even bounded to a short "plausible slug" — uploads a
// user-authored string, which is exactly what this lane promises never to do.
// A shape check cannot fix that (`payroll.csv` and `..` are both plausible
// slugs); only membership in a table WE wrote can. Anything not listed here is
// the fixed bucket "mcp", which is honest: "an MCP call to some server".
// Every VALUE below is a cloudcontract constant, never a literal (A10). The
// hosted prompt renders the family vocabulary from cloudcontract.MCPFamilyLabels;
// a value spelled independently here — "monitoring" where the contract says
// "observability" — would ship a label the model was never told the meaning of,
// and no test that derived its allowed set from THIS map could ever notice.
// TestMCPMappingOutputsAreContractVocabulary pins the direction.
var mcpServerLabels = map[string]string{
	// Observer's own server.
	"observer":            cloudcontract.MCPFamilyObserver,
	"superbased-observer": cloudcontract.MCPFamilyObserver,
	// Code hosting.
	"github":            cloudcontract.MCPFamilyGitHub,
	"github-mcp-server": cloudcontract.MCPFamilyGitHub,
	// Browser automation.
	"playwright":       cloudcontract.MCPFamilyPlaywright,
	"chrome":           cloudcontract.MCPFamilyBrowser,
	"claude-in-chrome": cloudcontract.MCPFamilyBrowser,
	"chrome-devtools":  cloudcontract.MCPFamilyBrowser,
	"browser":          cloudcontract.MCPFamilyBrowser,
	"browserbase":      cloudcontract.MCPFamilyBrowser,
	"puppeteer":        cloudcontract.MCPFamilyBrowser,
	// Files.
	"filesystem": cloudcontract.MCPFamilyFilesystem,
	// Databases.
	"postgres":   cloudcontract.MCPFamilyDB,
	"postgresql": cloudcontract.MCPFamilyDB,
	"sqlite":     cloudcontract.MCPFamilyDB,
	"mysql":      cloudcontract.MCPFamilyDB,
	"mongodb":    cloudcontract.MCPFamilyDB,
	// Issue trackers.
	"jira":      cloudcontract.MCPFamilyTracker,
	"linear":    cloudcontract.MCPFamilyTracker,
	"atlassian": cloudcontract.MCPFamilyTracker,
	"asana":     cloudcontract.MCPFamilyTracker,
	// Chat.
	"slack":   cloudcontract.MCPFamilyChat,
	"discord": cloudcontract.MCPFamilyChat,
	// Docs / knowledge.
	"notion":   cloudcontract.MCPFamilyDocs,
	"context7": cloudcontract.MCPFamilyDocs,
	// Ops.
	"sentry":     cloudcontract.MCPFamilyObservability,
	"grafana":    cloudcontract.MCPFamilyObservability,
	"kubernetes": cloudcontract.MCPFamilyInfra,
	"git":        cloudcontract.MCPFamilyGit,
	"fetch":      cloudcontract.MCPFamilyFetch,
	"memory":     cloudcontract.MCPFamilyMemory,
	"time":       cloudcontract.MCPFamilyTime,
}

// mcpFallbackLabel is the bucket an unknown MCP server lands in.
const mcpFallbackLabel = cloudcontract.MCPFamilyFallback

// mcpServerPrefixLabels is the small ordered PREFIX table, for vendors that ship
// a family of servers under one name (`cloudflare-bindings`,
// `cloudflare-observability`, …). A prefix rule still emits OUR label, never the
// matched id.
var mcpServerPrefixLabels = []struct {
	prefix string
	label  string
}{
	{"cloudflare", cloudcontract.MCPFamilyCloudflare},
}

// MCPCategory returns a CLOSED-VOCABULARY label for an MCP tool name
// ("mcp__claude-in-chrome__navigate" → "browser"), or the fixed "mcp" bucket for
// any server this file does not know. It never returns the server id and never
// returns the tool half of the name.
func MCPCategory(rawToolName string) string {
	name := strings.TrimSpace(rawToolName)
	if !strings.HasPrefix(name, mcpToolNamePrefix) {
		return mcpFallbackLabel
	}
	rest := name[len(mcpToolNamePrefix):]
	server := rest
	if i := strings.Index(rest, "__"); i >= 0 {
		server = rest[:i]
	}
	server = strings.ToLower(strings.TrimSpace(server))
	if label, ok := mcpServerLabels[server]; ok {
		return label
	}
	for _, r := range mcpServerPrefixLabels {
		if strings.HasPrefix(server, r.prefix) {
			return r.label
		}
	}
	return mcpFallbackLabel
}

// -- milestones --------------------------------------------------------------

// milestoneRule is one row of the milestone table: the emitted kind and the
// predicate that recognizes the FIRST action satisfying it.
type milestoneRule struct {
	kind  string
	match func(RawAction) bool
}

// milestoneRules is the ordered milestone table. Each rule fires at most ONCE,
// on the earliest matching action; the emitted list stays in the table's order
// so two rebuilds of the same session always produce the same milestones.
var milestoneRules = []milestoneRule{
	{"first_edit", func(a RawAction) bool {
		return a.Kind == "edit_file" || a.Kind == "write_file"
	}},
	{"first_command", func(a RawAction) bool { return a.Kind == "run_command" }},
	{"first_test", func(a RawAction) bool {
		return a.Kind == "run_command" && IsTestCommand(a.Target)
	}},
	{"first_error", func(a RawAction) bool { return !a.Success || a.Kind == "tool_failure" }},
	{"first_task_complete", func(a RawAction) bool { return a.Kind == "task_complete" }},
	{"session_end", func(a RawAction) bool { return a.Kind == "session_end" }},
}

// DeriveMilestones walks the time-ordered actions ONCE and emits at most one
// milestone per rule, in table order, bounded by MaxMilestones. Elapsed seconds
// come from the caller-computed RawAction.ElapsedSeconds (already clamped at
// 0), so this function needs no clock.
func DeriveMilestones(actions []RawAction) []MilestoneInput {
	elapsed := make([]int, len(milestoneRules))
	found := make([]bool, len(milestoneRules))
	for _, a := range actions {
		for i, rule := range milestoneRules {
			if found[i] || !rule.match(a) {
				continue
			}
			found[i] = true
			elapsed[i] = a.ElapsedSeconds
		}
	}
	out := make([]MilestoneInput, 0, len(milestoneRules))
	for i, rule := range milestoneRules {
		if !found[i] {
			continue
		}
		if len(out) >= cloudcontract.MaxMilestones {
			break
		}
		out = append(out, MilestoneInput{
			Ref:            "m" + refIndex(len(out)+1),
			Kind:           rule.kind,
			ElapsedSeconds: elapsed[i],
		})
	}
	return out
}

// -- outcomes ----------------------------------------------------------------

// CommandOutcome is what ONE recorded command line's exit status says about the
// test and build work in it. A status of SegmentUnknown alongside Has=true means
// "this line ran a suite / a build, and the evidence cannot say how it went".
type CommandOutcome struct {
	// HasTest reports that some segment ran a test suite.
	HasTest bool
	// TestStatus is the LAST test segment's known status, or SegmentUnknown.
	TestStatus SegmentStatus
	// HasBuild reports that some segment built the project.
	HasBuild bool
	// BuildStatus is the LAST build segment's known status, or SegmentUnknown.
	BuildStatus SegmentStatus
}

// ClassifyCommandOutcome attributes one recorded command's exit status to the
// segments that actually did test or build work (A3). `success` is the status
// the action recorded for the whole line.
//
// Two INDEPENDENT results, not a choice: one compound line can genuinely do both
// (`make build && go test ./...`) — and that line is exactly where the old
// whole-line attribution was worst, marking the BUILD failed when it was the
// test that failed.
func ClassifyCommandOutcome(cmd string, success bool) CommandOutcome {
	recorded := SegmentFailed
	if success {
		recorded = SegmentOK
	}
	var out CommandOutcome
	for _, s := range parseCommandLine(cmd, recorded, 0) {
		if s.isTest() {
			out.HasTest = true
			if s.Status != SegmentUnknown {
				out.TestStatus = s.Status
			}
			continue
		}
		if s.isBuild() {
			out.HasBuild = true
			if s.Status != SegmentUnknown {
				out.BuildStatus = s.Status
			}
		}
	}
	return out
}

// OutcomeTally accumulates a session's test/build outcomes over a STREAM of
// run_command rows, keeping only counters — never the rows.
//
// It exists because the outcome block is a WHOLE-SESSION claim and the store
// cannot materialize a 60,000-command session to make it (A5). The store scans
// row by row and feeds each one here; the memory cost is this struct.
type OutcomeTally struct {
	out         OutcomesInput
	sawBuild    bool
	lastBuildOK bool
}

// AddCommand folds one recorded run_command row into the tally.
func (t *OutcomeTally) AddCommand(target string, success bool) {
	o := ClassifyCommandOutcome(target, success)
	if o.HasTest {
		switch o.TestStatus {
		case SegmentUnknown:
			t.out.TestsUnknown++
		case SegmentOK:
			t.out.TestsRun++
			t.out.TestsPassed++
		case SegmentFailed:
			t.out.TestsRun++
		}
	}
	if o.HasBuild {
		if o.BuildStatus == SegmentUnknown {
			t.out.BuildsUnknown++
			return
		}
		t.sawBuild = true
		t.lastBuildOK = o.BuildStatus == SegmentOK
	}
}

// Outcomes returns the accumulated outcomes. Build stays "" when no build whose
// outcome was KNOWABLE ran — an absent outcome is honest; a fabricated "passed"
// is not, and neither is a "failed" inherited from a test that failed after it.
func (t *OutcomeTally) Outcomes() OutcomesInput {
	out := t.out
	if t.sawBuild {
		out.Build = "failed"
		if t.lastBuildOK {
			out.Build = "passed"
		}
	}
	return out
}

// DeriveOutcomes is the in-memory form of OutcomeTally, for callers that already
// hold the population (and for the pure tests).
func DeriveOutcomes(actions []RawAction) OutcomesInput {
	var tally OutcomeTally
	for _, a := range actions {
		if a.Kind != "run_command" {
			continue
		}
		tally.AddCommand(a.Target, a.Success)
	}
	return tally.Outcomes()
}

// -- activity mix ------------------------------------------------------------

// ActivityMixInput is one whole-session action-kind count, as read from the
// store. Kind is the raw local action_type; the builder normalizes it.
type ActivityMixInput struct {
	Kind  string
	Count int
}

// unclassifiedMixKey is where a kind that cannot be normalized into a category
// slug is folded — the same "never lose the count, never ship the string"
// discipline the structural snapshot uses.
const unclassifiedMixKey = "unclassified"

// knownActionKinds is the CLOSED allow-list of action kinds that may appear as
// an activity-mix key. It mirrors the Action* constants in internal/models
// (which this pure package may not import — see imports_test.go);
// TestKnownActionKindsMirrorsModels parses that file and fails if a constant is
// missing here, so the mirror cannot silently go stale.
//
// WHY AN ALLOW-LIST (the N7 fix). The mix key was whatever survived
// NormalizeMixKey — a shape check, not a membership check. action_type is
// closed TODAY by convention, but nothing structural enforces it: an adapter
// bug, a hand-written row, or a future kind derived from a tool name would
// upload its own string as a key, and `payroll.csv` normalizes to a perfectly
// valid slug. Membership in a table WE wrote is the only check that cannot be
// satisfied by a well-shaped attacker value. An unknown kind folds into
// "unclassified", so the COUNT survives and the STRING does not.
var knownActionKinds = map[string]bool{
	"read_file": true, "write_file": true, "edit_file": true, "run_command": true,
	"search_text": true, "search_files": true, "web_search": true, "web_fetch": true,
	"browser_action": true, "mcp_call": true, "spawn_subagent": true, "todo_update": true,
	"task_complete": true, "ask_user": true, "user_prompt": true, "assistant_message": true,
	"turn_aborted": true, "context_compacted": true, "system_prompt": true,
	"prompt_context": true, "api_error": true, "tool_failure": true,
	"subagent_start": true, "subagent_stop": true, "session_start": true, "session_end": true,
	"notification": true, "cwd_change": true, "user_prompt_expansion": true,
	"post_tool_batch": true, "permission_request": true, "permission_denied": true,
	"permission_mode": true, "setup": true, "instructions_loaded": true,
	"config_change": true, "worktree_create": true, "worktree_remove": true,
	"rate_limit": true, "subagent_wait": true, "agent_message": true,
	"agent_control": true, "skill_invoke": true, "schedule": true, "tool_search": true,
	"stdin_write": true, "harness_call": true, "unknown": true,
	// The CLI's own fallback for a row whose action_type is empty
	// (cmd/observer/cloud.go::cloudRawActions).
	"action": true,
}

// buildActivityMix normalizes, merges, sorts and bounds a whole-session
// activity mix. Keys that fail NormalizeMixKey fold into "unclassified" rather
// than failing the whole envelope; zero/negative counts are dropped (the
// contract requires positive counts). When more than MaxStructuralMixEntries
// distinct kinds survive, the LARGEST counts are kept (ties broken by key) so
// the truncation is deterministic and keeps the meaningful shape.
func buildActivityMix(in []ActivityMixInput) []cloudcontract.StructuralMixEntry {
	if len(in) == 0 {
		return nil
	}
	merged := make(map[string]int, len(in))
	for _, e := range in {
		if e.Count <= 0 {
			continue
		}
		key := unclassifiedMixKey
		if knownActionKinds[strings.ToLower(strings.TrimSpace(e.Kind))] {
			// Known kinds still pass the shape check: membership and shape are
			// independent guarantees, and the contract owns the shape.
			if normalized, err := cloudcontract.NormalizeMixKey("activity_mix.key", e.Kind); err == nil {
				key = normalized
			}
		}
		merged[key] += e.Count
	}
	if len(merged) == 0 {
		return nil
	}
	out := make([]cloudcontract.StructuralMixEntry, 0, len(merged))
	for k, c := range merged {
		out = append(out, cloudcontract.StructuralMixEntry{Key: k, Count: c})
	}
	if len(out) > cloudcontract.MaxStructuralMixEntries {
		sort.Slice(out, func(i, j int) bool {
			if out[i].Count != out[j].Count {
				return out[i].Count > out[j].Count
			}
			return out[i].Key < out[j].Key
		})
		out = out[:cloudcontract.MaxStructuralMixEntries]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Key < out[j].Key })
	return out
}

// refIndex is a tiny non-negative int formatter for milestone refs, so this
// pure file needs no fmt (which would invite formatting raw values into labels).
func refIndex(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
