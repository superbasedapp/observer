package secdockerfile

import (
	"encoding/json"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/marmutapp/superbased-observer/internal/policy"
	"github.com/marmutapp/superbased-observer/internal/secshellrisk"
)

// Severity is a finding's severity.
type Severity string

// The severities the rules use.
const (
	SeverityHigh   Severity = "high"
	SeverityMedium Severity = "medium"
	SeverityLow    Severity = "low"
)

// Finding is one rule hit. Message is the rule's fixed text and Detail, for
// S-752, names the product, cycle and date from the compiled end-of-life
// table; neither ever carries repository text.
type Finding struct {
	RuleID   string
	Severity Severity
	// Line is the 1-based line of the instruction in the Dockerfile.
	Line int
	// FlagOnly marks a finding that never blocks (S-753, S-754).
	FlagOnly bool
	Message  string
	Detail   string
}

// Rule is one row of the closed rule table.
type Rule struct {
	ID string
	// Severity is the rule's severity; S-752 reports NearEOLSeverity
	// instead while the base is only within NearEOLWindow of end of life.
	Severity Severity
	FlagOnly bool
	Message  string
}

// Rules is THE rule table.
var Rules = []Rule{
	{ID: "S-750", Severity: SeverityMedium, Message: "a FROM line names no tag or the latest tag, so each build can get a different base image; pin a version tag and its digest"},
	{ID: "S-751", Severity: SeverityLow, Message: "a FROM line names a tag but no digest, and the publisher can move the tag; pin the image by @sha256: digest"},
	{ID: "S-752", Severity: SeverityHigh, Message: "a FROM line's base image is built on a distribution release or language runtime that no longer gets security updates; move to a supported release"},
	{ID: "S-753", Severity: SeverityLow, FlagOnly: true, Message: "a RUN step installs OS packages with no version, so each build can install different packages; pin versions or build from a locked base"},
	{ID: "S-754", Severity: SeverityLow, FlagOnly: true, Message: "a RUN step installs a language package with no version or lockfile, so each build can install a different release"},
	{ID: "S-755", Severity: SeverityMedium, Message: "a RUN step pipes content downloaded at build time into an interpreter, so whoever serves it runs code in the image; download, verify a checksum, then run"},
}

// NearEOLSeverity is S-752's severity while the base is within
// NearEOLWindow of its end of life.
const NearEOLSeverity = SeverityMedium

// NearEOLMessage is S-752's text while the base is within NearEOLWindow of
// its end of life.
const NearEOLMessage = "a FROM line's base image is built on a distribution release or language runtime that stops getting security updates within 90 days; plan the move to a supported release"

// RuleByID returns the rule table row with the given id.
func RuleByID(id string) (Rule, bool) {
	for _, r := range Rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// MaxDockerfileBytes caps the Dockerfile text read (the same cap as the CI
// workflow rules, so one reader capped for either serves both).
const MaxDockerfileBytes = 512 << 10

// IsDockerfilePath reports whether rel (slash- or backslash-separated,
// repository-relative) is a Dockerfile: Dockerfile, Dockerfile.<name>,
// <name>.dockerfile or Containerfile. A Dockerfile.dockerignore (the
// per-Dockerfile ignore list) is not one. It is the one owner of the
// Dockerfile path class (internal/seciac's IaC trigger table calls it).
func IsDockerfilePath(rel string) bool {
	b := path.Base(strings.ReplaceAll(rel, `\`, "/"))
	if strings.HasSuffix(b, ".dockerignore") {
		return false
	}
	return b == "Dockerfile" || strings.HasPrefix(b, "Dockerfile.") || strings.HasSuffix(b, ".dockerfile") || b == "Containerfile"
}

// Status says whether a check read the whole Dockerfile.
type Status string

const (
	// StatusComplete: the whole file was read; no findings means none
	// (apart from the FROM lines counted in UncheckedFrom and the RUN
	// scripts counted in TruncatedRuns).
	StatusComplete Status = "complete"
	// StatusOverCap: the file is larger than MaxDockerfileBytes and was
	// not checked. Never read as "no findings": callers report it unknown.
	StatusOverCap Status = "over_cap"
)

// Report is one Dockerfile's check result.
type Report struct {
	Status   Status
	Findings []Finding
	// UncheckedFrom counts the FROM lines whose image names a build
	// argument with no literal default before the first FROM: their image
	// is decided at build time, so they were not checked. They are not a
	// partial read of the file; callers say so in a note.
	UncheckedFrom int
	// TruncatedRuns counts the RUN scripts longer than the shell
	// classifier's cap, read only up to it: their tail was not checked.
	TruncatedRuns int
}

// Complete reports a check that read the whole file.
func (r Report) Complete() bool { return r.Status == StatusComplete }

// Check runs every rule over one Dockerfile as of now.
func Check(content []byte) Report { return CheckAt(content, time.Now()) }

// CheckAt runs every rule over one Dockerfile, judging end of life (S-752)
// at now. A file over the cap is not checked (StatusOverCap).
func CheckAt(content []byte, now time.Time) Report {
	if len(content) > MaxDockerfileBytes {
		return Report{Status: StatusOverCap}
	}
	c := &checker{now: now, stages: map[string]bool{}, args: map[string]string{}, dialect: policy.DialectPosix}
	for _, in := range parseInstructions(string(content)) {
		c.instruction(in)
	}
	sort.SliceStable(c.out, func(i, j int) bool {
		if c.out[i].Line != c.out[j].Line {
			return c.out[i].Line < c.out[j].Line
		}
		return c.out[i].RuleID < c.out[j].RuleID
	})
	return Report{Status: StatusComplete, Findings: c.out, UncheckedFrom: c.uncheckedFrom, TruncatedRuns: c.truncated}
}

// checker is one Check's state.
type checker struct {
	now           time.Time
	out           []Finding
	seen          map[string]bool
	stages        map[string]bool
	args          map[string]string
	sawFrom       bool
	dialect       policy.Dialect
	uncheckedFrom int
	truncated     int
}

func (c *checker) add(id string, line int, sev Severity, msg, detail string) {
	key := id + "@" + itoa(line)
	if c.seen == nil {
		c.seen = map[string]bool{}
	}
	if c.seen[key] {
		return
	}
	c.seen[key] = true
	r, ok := RuleByID(id)
	if !ok {
		return
	}
	if sev == "" {
		sev = r.Severity
	}
	if msg == "" {
		msg = r.Message
	}
	c.out = append(c.out, Finding{RuleID: id, Severity: sev, Line: line, FlagOnly: r.FlagOnly, Message: msg, Detail: detail})
}

// instructionHandlers is the instruction table: the keyword (upper case)
// to its handler. An instruction not listed has no rule.
var instructionHandlers = map[string]func(c *checker, in instruction){
	"ARG":   (*checker).arg,
	"FROM":  (*checker).from,
	"SHELL": (*checker).shell,
	"RUN":   (*checker).run,
}

func (c *checker) instruction(in instruction) {
	if h, ok := instructionHandlers[in.keyword]; ok {
		h(c, in)
	}
}

// arg records a global build argument's literal default (only ARG lines
// before the first FROM are visible to FROM).
func (c *checker) arg(in instruction) {
	if c.sawFrom {
		return
	}
	for _, tok := range splitFields(in.args) {
		name, val, hasVal := strings.Cut(tok, "=")
		if name == "" {
			continue
		}
		val = unquote(val)
		if !hasVal || strings.Contains(val, "$") {
			delete(c.args, name)
			continue
		}
		c.args[name] = val
	}
}

// from checks one FROM line's image.
func (c *checker) from(in instruction) {
	c.sawFrom = true
	c.dialect = policy.DialectPosix // SHELL is per stage
	f := splitFields(in.args)
	i := 0
	for i < len(f) && strings.HasPrefix(f[i], "--") {
		i++
	}
	if i >= len(f) {
		return
	}
	raw := f[i]
	if i+2 < len(f) && strings.EqualFold(f[i+1], "AS") {
		defer func() { c.stages[strings.ToLower(f[i+2])] = true }()
	}
	ref, ok := c.expand(raw)
	if !ok {
		c.uncheckedFrom++
		return
	}
	if strings.EqualFold(ref, "scratch") || c.stages[strings.ToLower(ref)] {
		return
	}
	img := parseImageRef(ref)
	if img.repo == "" {
		return
	}
	switch {
	case img.digest != "":
	case img.tag == "" || img.tag == "latest":
		c.add("S-750", in.line, "", "", "")
	default:
		c.add("S-751", in.line, "", "", "")
	}
	if v := judgeEOL(img, c.now); v.hit {
		if v.past {
			c.add("S-752", in.line, "", "", eolDetail(v))
		} else {
			c.add("S-752", in.line, NearEOLSeverity, NearEOLMessage, eolDetail(v))
		}
	}
}

// varRE matches ${NAME}, ${NAME:-word} and $NAME.
var varRE = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)(:-[^}$]*)?\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// expand substitutes the global build arguments into a FROM ref; ok is
// false when a variable has no literal value (the ref is not checked).
func (c *checker) expand(raw string) (string, bool) {
	if !strings.Contains(raw, "$") {
		return raw, true
	}
	ok := true
	out := varRE.ReplaceAllStringFunc(raw, func(m string) string {
		sm := varRE.FindStringSubmatch(m)
		name := sm[1]
		if name == "" {
			name = sm[3]
		}
		if v, has := c.args[name]; has && v != "" {
			return v
		}
		if def, has := strings.CutPrefix(sm[2], ":-"); has && sm[2] != "" {
			return def
		}
		ok = false
		return ""
	})
	if !ok || strings.Contains(out, "$") {
		return "", false
	}
	return out, true
}

// shellDialects maps a SHELL instruction's executable onto the dialect
// RUN scripts are read in; any other shell reads as POSIX.
var shellDialects = map[string]policy.Dialect{
	"pwsh": policy.DialectPowerShell, "pwsh.exe": policy.DialectPowerShell,
	"powershell": policy.DialectPowerShell, "powershell.exe": policy.DialectPowerShell,
	"cmd": policy.DialectCmd, "cmd.exe": policy.DialectCmd,
}

func shellDialect(exe string) policy.Dialect {
	b := strings.ToLower(path.Base(strings.ReplaceAll(exe, `\`, "/")))
	if d, ok := shellDialects[b]; ok {
		return d
	}
	return policy.DialectPosix
}

// shell records the SHELL instruction's dialect for the stage.
func (c *checker) shell(in instruction) {
	var argv []string
	if err := json.Unmarshal([]byte(strings.TrimSpace(in.args)), &argv); err != nil || len(argv) == 0 {
		return
	}
	c.dialect = shellDialect(argv[0])
}

// posixShells are the executables whose -c payload is a POSIX script.
var posixShells = map[string]bool{"sh": true, "bash": true, "ash": true, "dash": true, "zsh": true, "ksh": true, "busybox": true}

// hitRules maps a shell risk onto its rule.
var hitRules = map[secshellrisk.Kind]string{
	secshellrisk.OSInstallUnpinned:   "S-753",
	secshellrisk.LangInstallUnpinned: "S-754",
	secshellrisk.RemotePipe:          "S-755",
}

// run classifies one RUN step's script.
func (c *checker) run(in instruction) {
	body := strings.TrimSpace(in.args)
	// RUN's own flags (--mount=, --network=, --security=) come first.
	for strings.HasPrefix(body, "--") {
		sp := strings.IndexAny(body, " \t")
		if sp < 0 {
			return
		}
		body = strings.TrimSpace(body[sp:])
	}
	if strings.HasPrefix(body, "[") {
		var argv []string
		if err := json.Unmarshal([]byte(body), &argv); err == nil {
			c.runExec(in.line, argv)
			return
		}
		// Not valid JSON: Docker runs it as a shell-form command.
	}
	if len(in.heredocs) > 0 {
		prefix := body
		if at := strings.Index(body, "<<"); at >= 0 {
			prefix = body[:at]
		}
		prefix = strings.TrimSpace(prefix)
		if !heredocIsScript(prefix) {
			// The heredoc is another program's input (cat <<EOF > file,
			// python3 <<EOF): only the command line is a shell script.
			c.analyze(in.line, stripHeredocMarkers(body), c.dialect)
			return
		}
		if prefix != "" {
			c.analyze(in.line, stripHeredocMarkers(body), c.dialect)
		}
		for _, h := range in.heredocs {
			c.analyze(h.line, h.body, c.dialect)
		}
		return
	}
	c.analyze(in.line, body, c.dialect)
}

// heredocIsScript reports whether a RUN heredoc's body is the script: no
// command before it (RUN <<EOF), or a POSIX shell reading it (RUN bash
// <<EOF, RUN sh -e <<EOF).
func heredocIsScript(prefix string) bool {
	if prefix == "" {
		return true
	}
	f := strings.Fields(prefix)
	if !posixShells[strings.ToLower(path.Base(f[0]))] {
		return false
	}
	for _, a := range f[1:] {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return true
}

// runExec classifies an exec-form RUN: a shell's -c payload, or the argv
// itself read as one quoted command line.
func (c *checker) runExec(line int, argv []string) {
	if len(argv) == 0 {
		return
	}
	exe := strings.ToLower(path.Base(strings.ReplaceAll(argv[0], `\`, "/")))
	d := shellDialect(argv[0])
	isShell := posixShells[exe] || d != policy.DialectPosix
	if isShell {
		for i := 1; i < len(argv)-1; i++ {
			a := argv[i]
			if a == "-c" || strings.EqualFold(a, "-Command") || strings.EqualFold(a, "/c") ||
				(len(a) > 1 && a[0] == '-' && a[1] != '-' && strings.HasSuffix(a, "c") && d == policy.DialectPosix) {
				c.analyze(line, argv[i+1], d)
				return
			}
		}
	}
	quoted := make([]string, len(argv))
	for i, a := range argv {
		quoted[i] = shellQuote(a)
	}
	c.analyze(line, strings.Join(quoted, " "), policy.DialectPosix)
}

// analyze runs the shell risk classifier over a script whose first line is
// at line.
func (c *checker) analyze(line int, script string, d policy.Dialect) {
	hits, truncated := secshellrisk.Analyze(script, d)
	if truncated {
		c.truncated++
	}
	for _, h := range hits {
		if id, ok := hitRules[h.Kind]; ok {
			c.add(id, line+h.Line, "", "", "")
		}
	}
}

func shellQuote(s string) string {
	if s != "" && !strings.ContainsAny(s, " \t\n'\"\\$`|&;<>()*?[]{}#~!") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// heredocMarkerRE matches a heredoc marker: <<EOF, <<-EOF, <<"EOF",
// <<'EOF' (never a here-string, <<<).
var heredocMarkerRE = regexp.MustCompile(`(?:^|[^<])<<(-?)(["']?)([A-Za-z_][A-Za-z0-9_]*)(["']?)`)

func stripHeredocMarkers(s string) string {
	return heredocMarkerRE.ReplaceAllStringFunc(s, func(m string) string {
		if m != "" && m[0] != '<' {
			return m[:1]
		}
		return ""
	})
}

// imageRef is a parsed image reference.
type imageRef struct {
	registry, repo, tag, digest string
}

// parseImageRef splits [registry/]repo[:tag][@digest]. The first path
// element is a registry when it has a dot or a port, or is localhost; a
// colon in it is a port, never a tag.
func parseImageRef(ref string) imageRef {
	var r imageRef
	name := ref
	if at := strings.IndexByte(name, '@'); at >= 0 {
		r.digest = name[at+1:]
		name = name[:at]
	}
	slash := strings.LastIndexByte(name, '/')
	if colon := strings.LastIndexByte(name, ':'); colon > slash {
		r.tag = name[colon+1:]
		name = name[:colon]
	}
	if first, rest, ok := strings.Cut(name, "/"); ok && (strings.ContainsAny(first, ".:") || first == "localhost") {
		r.registry, name = first, rest
	}
	r.repo = name
	return r
}

// instruction is one Dockerfile instruction, continuations joined.
type instruction struct {
	keyword  string
	args     string
	line     int
	heredocs []heredoc
}

// heredoc is one heredoc body with the line its first body line is on.
type heredoc struct {
	line int
	body string
}

// directiveRE matches a parser directive line.
var directiveRE = regexp.MustCompile(`^#\s*([A-Za-z][A-Za-z0-9_]*)\s*=\s*(\S*)\s*$`)

// heredocKeywords are the instructions that take heredocs.
var heredocKeywords = map[string]bool{"RUN": true, "COPY": true, "ADD": true}

// parseInstructions splits a Dockerfile into instructions: parser
// directives first (escape= sets the line continuation character), then
// comments and blank lines skipped, continuation lines joined (comment
// lines inside a continuation dropped, as the builder does) and heredoc
// bodies collected.
func parseInstructions(text string) []instruction {
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	escape := byte('\\')
	i := 0
	for ; i < len(lines); i++ {
		m := directiveRE.FindStringSubmatch(strings.TrimSpace(lines[i]))
		if m == nil {
			break
		}
		if strings.EqualFold(m[1], "escape") && (m[2] == "`" || m[2] == `\`) {
			escape = m[2][0]
		}
	}
	var out []instruction
	for ; i < len(lines); i++ {
		t := strings.TrimSpace(lines[i])
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		start := i
		var b strings.Builder
		cur := strings.TrimLeft(lines[i], " \t")
		for {
			r := strings.TrimRight(cur, " \t")
			if r == "" || r[len(r)-1] != escape {
				b.WriteString(cur)
				break
			}
			b.WriteString(r[:len(r)-1])
			// The next line that is not a comment or blank continues it.
			i++
			for i < len(lines) {
				nt := strings.TrimSpace(lines[i])
				if nt != "" && !strings.HasPrefix(nt, "#") {
					break
				}
				i++
			}
			if i >= len(lines) {
				break
			}
			cur = lines[i]
		}
		full := strings.TrimSpace(b.String())
		kw, args := full, ""
		if sp := strings.IndexAny(full, " \t"); sp >= 0 {
			kw, args = full[:sp], full[sp+1:]
		}
		in := instruction{keyword: strings.ToUpper(kw), args: strings.TrimSpace(args), line: start + 1}
		if heredocKeywords[in.keyword] && !strings.HasPrefix(in.args, "[") {
			for _, m := range heredocMarkerRE.FindAllStringSubmatch(in.args, -1) {
				strip, delim := m[1] == "-", m[3]
				var body []string
				first := i + 2
				for i++; i < len(lines); i++ {
					l := lines[i]
					if strip {
						l = strings.TrimLeft(l, "\t")
					}
					if strings.TrimRight(l, " \t") == delim {
						break
					}
					body = append(body, l)
				}
				in.heredocs = append(in.heredocs, heredoc{line: first, body: strings.Join(body, "\n")})
			}
		}
		out = append(out, in)
	}
	return out
}

// splitFields splits on blanks, keeping a quoted value whole.
func splitFields(s string) []string {
	var out []string
	var b strings.Builder
	var quote byte
	flush := func() {
		if b.Len() > 0 {
			out = append(out, b.String())
			b.Reset()
		}
	}
	for i := 0; i < len(s); i++ {
		ch := s[i]
		switch {
		case quote != 0:
			if ch == quote {
				quote = 0
			}
			b.WriteByte(ch)
		case ch == '"' || ch == '\'':
			quote = ch
			b.WriteByte(ch)
		case ch == ' ' || ch == '\t':
			flush()
		default:
			b.WriteByte(ch)
		}
	}
	flush()
	return out
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
