package secassess

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Start plan (depth plan W4.1): how the project's development server starts,
// read from the project's own files and never invented. The command is an ARGV
// LIST, not a shell string: a developer edit is split on spaces and checked,
// and a command that needs quoting cannot be expressed (the dialog then says
// "start it yourself and tell the agent").
//
// The FILE LIST (DevServerFiles), the port table (scriptRules, explicitPorts)
// and the per-file port rows (splCandFiles) are standard-library COPIES of
// internal/secdast's devservers.go, kept here because secdast belongs to the
// optional security.dast component and a pure package that stays in the omit
// build may not import it; secassesssvc's drift test holds the copies to
// secdast's on one shared case table. The COMMANDS (what to run for each
// source) are this file's own and have no counterpart there.

// The start sources: Candidate.Source and StartPlan.Source values. The first
// eight are secdast's own candidate sources, spelt the same.
const (
	StartSourceLaunchJSON  = "launch.json"
	StartSourcePackageJSON = "package.json"
	StartSourceViteConfig  = "vite.config"
	StartSourceDjango      = "manage.py"
	StartSourceFlask       = "flask"
	StartSourceRails       = "rails"
	StartSourceHugo        = "hugo"
	StartSourceJekyll      = "jekyll"
	StartSourceProcfile    = "procfile"
	StartSourceMakefile    = "makefile"
)

// DevServerFiles are the project-relative files the dev-server readers read,
// in the order a caller should offer them. An entry ending in "*" is a prefix:
// every top-level file starting with it (vite.config.ts, vite.config.mjs, ...).
// A copy of secdast.DevServerFiles, pinned by secassesssvc's drift test.
var DevServerFiles = []string{
	".claude/launch.json", "package.json", "vite.config*", "manage.py", ".flaskenv",
	"bin/rails", "config/puma.rb", "hugo.toml", "hugo.yaml", "_config.yml",
}

// splReads reports whether the start table reads the project-relative file
// rel: a dev-server file, the Procfile or the Makefile.
func splReads(rel string) bool {
	if rel == "Procfile" || rel == "Makefile" {
		return true
	}
	for _, p := range DevServerFiles {
		if strings.HasSuffix(p, "*") {
			if strings.HasPrefix(rel, strings.TrimSuffix(p, "*")) {
				return true
			}
			continue
		}
		if rel == p {
			return true
		}
	}
	return false
}

// scriptRule is one row of the package.json script table: a script whose
// command matches re runs a dev server on port unless the command names its
// own port. A copy of secdast's table of the same name.
type scriptRule struct {
	name string
	re   *regexp.Regexp
	port int
}

// scriptRules is THE script table, walked top-down; the first row whose
// pattern matches a command gives its default port. An explicit port in the
// command wins over the row.
var scriptRules = []scriptRule{
	{"next", regexp.MustCompile(`(^|\s|/)next\s+(dev|start)\b`), 3000},
	{"nuxt", regexp.MustCompile(`(^|\s|/)(nuxt|nuxi)\s+dev\b`), 3000},
	{"remix", regexp.MustCompile(`(^|\s|/)remix\s+(vite:)?dev\b`), 3000},
	{"react-scripts", regexp.MustCompile(`(^|\s|/)react-scripts\s+start\b`), 3000},
	{"astro", regexp.MustCompile(`(^|\s|/)astro\s+dev\b`), 4321},
	{"angular", regexp.MustCompile(`(^|\s|/)ng\s+serve\b`), 4200},
	{"sveltekit", regexp.MustCompile(`(^|\s|/)svelte-kit\s+dev\b`), 5173},
	{"vite", regexp.MustCompile(`(^|\s|/)vite(\s+(dev|serve))?(\s|$)`), 5173},
	{"gatsby", regexp.MustCompile(`(^|\s|/)gatsby\s+develop\b`), 8000},
	{"vue-cli", regexp.MustCompile(`(^|\s|/)vue-cli-service\s+serve\b`), 8080},
	{"webpack", regexp.MustCompile(`(^|\s|/)(webpack\s+serve|webpack-dev-server)\b`), 8080},
	{"parcel", regexp.MustCompile(`(^|\s|/)parcel(\s+serve)?\s+\S+\.html\b`), 1234},
	{"storybook", regexp.MustCompile(`(^|\s|/)(storybook\s+dev|start-storybook)\b`), 6006},
	{"expo", regexp.MustCompile(`(^|\s|/)expo\s+start\b`), 8081},
	{"django", regexp.MustCompile(`manage\.py\s+runserver\b`), 8000},
	{"flask", regexp.MustCompile(`(^|\s|/)flask\s+run\b`), 5000},
	{"rails", regexp.MustCompile(`(^|\s|/)rails\s+(s|server)\b`), 3000},
	{"hugo", regexp.MustCompile(`(^|\s|/)hugo\s+server\b`), 1313},
	{"jekyll", regexp.MustCompile(`(^|\s|/)jekyll\s+serve\b`), 4000},
	{"express", regexp.MustCompile(`(^|\s|/)(nodemon|node)\s+\S*(server|app|index)\.(c|m)?[jt]s\b`), 3000},
}

// explicitPorts are the forms a command names its own port with, walked
// top-down. A copy of secdast's table of the same name.
var explicitPorts = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|\s)(?:--port|-p|--listen|-l)[=\s]+(\d{2,5})\b`),
	regexp.MustCompile(`(?:^|\s)PORT=(\d{2,5})\b`),
	regexp.MustCompile(`runserver\s+(?:[\w.\[\]:]+:)?(\d{2,5})\b`),
}

// explicitPort returns the port a command names, if any.
func explicitPort(cmd string) (int, bool) {
	for _, re := range explicitPorts {
		if m := re.FindStringSubmatch(cmd); m != nil {
			if p, err := strconv.Atoi(m[1]); err == nil && p >= 1 && p <= 65535 {
				return p, true
			}
		}
	}
	return 0, false
}

// ScriptPort returns the dev server port a package.json script command runs on
// and the name of the table row that recognised it. A copy of
// secdast.ScriptPort.
func ScriptPort(cmd string) (port int, rule string, ok bool) {
	for _, r := range scriptRules {
		if r.re.MatchString(cmd) {
			if p, ok := explicitPort(cmd); ok {
				return p, r.name, true
			}
			return r.port, r.name, true
		}
	}
	return 0, "", false
}

var (
	viteServerPort = regexp.MustCompile(`server\s*:\s*\{[^}]*?\bport\s*:\s*(\d{2,5})`)
	hugoPort       = regexp.MustCompile(`(?m)^\s*port\s*[:=]\s*(\d{2,5})`)
	jekyllPort     = regexp.MustCompile(`(?m)^\s*port\s*:\s*(\d{2,5})`)
	flaskRunPort   = regexp.MustCompile(`(?m)^\s*FLASK_RUN_PORT\s*=\s*(\d{2,5})`)
	railsPort      = regexp.MustCompile(`(?m)^\s*port\s+(?:ENV\.fetch\([^)]*?(\d{2,5})\s*\)|ENV\.fetch\([^)]*\)\s*\{\s*(\d{2,5})\s*\}|(\d{2,5}))`)
)

// splFirstPort returns the first non-empty numeric group re finds in b.
func splFirstPort(re *regexp.Regexp, b []byte) (int, bool) {
	m := re.FindSubmatch(b)
	for i := 1; i < len(m); i++ {
		if len(m[i]) == 0 {
			continue
		}
		if p, err := strconv.Atoi(string(m[i])); err == nil && p >= 1 && p <= 65535 {
			return p, true
		}
	}
	return 0, false
}

// splJekyllSignal reports whether a _config.yml belongs to a Jekyll site.
func splJekyllSignal(b []byte) bool {
	s := string(b)
	return strings.Contains(s, "jekyll") || strings.Contains(s, "theme:") || strings.Contains(s, "permalink:")
}

func splPortCandidate(port int, name, source string) Candidate {
	return Candidate{URL: "http://localhost:" + strconv.Itoa(port) + "/", Name: name, Source: source}
}

// splCandRule is one row of the per-file candidate table: a reader for one
// project file. A copy of secdast's fileTable, with the same rows in the same
// order.
type splCandRule struct {
	match func(rel string) bool
	read  func(data []byte) []Candidate
}

// splCandFiles is THE candidate file table, walked top-down per file.
var splCandFiles = []splCandRule{
	{match: func(rel string) bool { return rel == ".claude/launch.json" }, read: func(b []byte) []Candidate {
		out := LaunchCandidates(b)
		for i := range out {
			out[i].Source = StartSourceLaunchJSON
		}
		return out
	}},
	{match: func(rel string) bool { return rel == "package.json" }, read: splPackageCandidates},
	{match: func(rel string) bool { return strings.HasPrefix(rel, "vite.config.") }, read: func(b []byte) []Candidate {
		if p, ok := splFirstPort(viteServerPort, b); ok {
			return []Candidate{splPortCandidate(p, "vite", StartSourceViteConfig)}
		}
		return nil
	}},
	{match: func(rel string) bool { return rel == "manage.py" }, read: func(b []byte) []Candidate {
		if strings.Contains(string(b), "django") {
			return []Candidate{splPortCandidate(8000, "django", StartSourceDjango)}
		}
		return nil
	}},
	{match: func(rel string) bool { return rel == ".flaskenv" }, read: func(b []byte) []Candidate {
		p, ok := splFirstPort(flaskRunPort, b)
		if !ok {
			p = 5000
		}
		return []Candidate{splPortCandidate(p, "flask", StartSourceFlask)}
	}},
	{match: func(rel string) bool { return rel == "bin/rails" || rel == "config/puma.rb" }, read: func(b []byte) []Candidate {
		if p, ok := splFirstPort(railsPort, b); ok {
			return []Candidate{splPortCandidate(p, "rails", StartSourceRails)}
		}
		return []Candidate{splPortCandidate(3000, "rails", StartSourceRails)}
	}},
	{match: func(rel string) bool { return rel == "hugo.toml" || rel == "hugo.yaml" }, read: func(b []byte) []Candidate {
		p, ok := splFirstPort(hugoPort, b)
		if !ok {
			p = 1313
		}
		return []Candidate{splPortCandidate(p, "hugo", StartSourceHugo)}
	}},
	{match: func(rel string) bool { return rel == "_config.yml" }, read: func(b []byte) []Candidate {
		if !splJekyllSignal(b) {
			return nil
		}
		p, ok := splFirstPort(jekyllPort, b)
		if !ok {
			p = 4000
		}
		return []Candidate{splPortCandidate(p, "jekyll", StartSourceJekyll)}
	}},
}

// splPackageCandidates reads package.json scripts through scriptRules, in
// script-name order so the result is stable.
func splPackageCandidates(b []byte) []Candidate {
	var pj struct {
		Scripts map[string]string `json:"scripts"`
	}
	if json.Unmarshal(b, &pj) != nil {
		return nil
	}
	names := make([]string, 0, len(pj.Scripts))
	for n := range pj.Scripts {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Candidate
	for _, n := range names {
		if p, rule, ok := ScriptPort(pj.Scripts[n]); ok {
			out = append(out, splPortCandidate(p, clean("npm run "+n+" ("+rule+")", 80), StartSourcePackageJSON))
		}
	}
	return out
}

// PlanCandidates returns the target candidates (loopback URLs) from the whole
// dev-server file set, in the order of the files, deduplicated by URL (the
// first source wins), each a target ParseTarget accepts. It is a copy of
// secdast.ProjectCandidates over the files the survey read.
func PlanCandidates(f ProjectFacts) []Candidate {
	seen := map[string]bool{}
	var out []Candidate
	for _, file := range f.src {
		if len(file.Data) == 0 || len(file.Data) > MaxProjectFile {
			continue
		}
		for _, r := range splCandFiles {
			if !r.match(file.Rel) {
				continue
			}
			for _, c := range r.read(file.Data) {
				t, err := ParseTarget(c.URL)
				if err != nil || seen[t.String()] {
					continue
				}
				seen[t.String()] = true
				c.URL = t.String()
				out = append(out, c)
			}
			break
		}
	}
	return out
}

// StartPlan is how the project's development server starts, read from the
// project's own files (never invented): an argv list, not a shell string.
type StartPlan struct {
	Argv    []string   `json:"argv"`
	Cwd     string     `json:"cwd,omitempty"`
	Port    int        `json:"port,omitempty"`
	Source  string     `json:"source"`
	Rule    string     `json:"rule,omitempty"`
	Prepare [][]string `json:"prepare,omitempty"`
	Needs   []string   `json:"needs,omitempty"`
}

// Command is the argv joined by single spaces (what the dialog shows and the
// prompt names).
func (p StartPlan) Command() string { return strings.Join(p.Argv, " ") }

// Choice is the text the plan dialog sends back to choose this plan, and the
// text a run records so a held run starts the same plan: the command alone when
// the plan runs in the project root, else the command and its folder framed as
// "<command> (in <folder>)". A typed start command is split on spaces and
// checked against a closed charset that has no parenthesis, so no typed
// command can ever read as a plan's choice by accident; and two plans that
// differ only by folder have different choices.
func (p StartPlan) Choice() string {
	if p.Cwd == "" {
		return p.Command()
	}
	return p.Command() + startCwdOpen + p.Cwd + startCwdClose
}

// The limits of a start command. The longest valid choice is the longest
// command and the longest folder in the cwd frame (MaxStartChoice); the prompt
// text bounds derive from the same constants, so a record, a validator and a
// prompt cannot disagree about what fits.
const (
	maxStartArgs     = 8
	maxStartArgBytes = 80
	// maxStartCommandBytes bounds the whole command, the words joined by single
	// spaces: real commands are far shorter, and the longer a command the more of
	// the prompt's 22 KiB it uses.
	maxStartCommandBytes = 120
	// maxStartCwdBytes bounds a plan's folder (a launch.json cwd).
	maxStartCwdBytes = 40

	startCwdOpen  = " (in "
	startCwdClose = ")"
)

// MaxStartChoice is the most bytes a valid start choice can have (StartPlan.
// Choice of the longest command in the longest folder). A record that keeps
// the choice for a held run must hold this many bytes and refuse, never cut, a
// longer one.
const MaxStartChoice = maxStartCommandBytes + len(startCwdOpen) + maxStartCwdBytes + len(startCwdClose)

// startArgRune reports whether r is in the closed charset of a start command's
// words: [A-Za-z0-9_./:=@+,-].
func startArgRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("_./:=@+,-", r)
}

// ValidStartArgv checks an argv: at least one and at most 8 elements, each
// non-empty, at most 80 bytes, from the closed charset [A-Za-z0-9_./:=@+,-]
// (a space is not allowed inside an element, nor a quote, $, ; | & backtick,
// redirection, bracket, glob or newline), the whole command (the words joined by
// single spaces) at most 120 bytes, and not the reserved word none in any case
// (StartNone declares that the project has no command, so a command of that
// name could not be told from the choice). The error is a plain sentence for the
// plan dialog.
func ValidStartArgv(argv []string) error {
	if len(argv) == 0 {
		return errors.New("There is no start command. Type the command that starts the application, for example npm run dev.")
	}
	if len(argv) > maxStartArgs {
		return fmt.Errorf("The start command has %d words and at most %d are allowed. A longer command cannot be written here: start it yourself and tell the agent.", len(argv), maxStartArgs)
	}
	for i, a := range argv {
		if a == "" {
			return fmt.Errorf("Word %d of the start command is empty.", i+1)
		}
		if len(a) > maxStartArgBytes {
			return fmt.Errorf("Word %d of the start command is over %d characters.", i+1, maxStartArgBytes)
		}
		for _, r := range a {
			if r == utf8.RuneError || !startArgRune(r) {
				return fmt.Errorf("The start command may use only letters, digits and . _ / : = @ + , - inside a word, and %q is not allowed (word %d). A command that needs quoting, a pipe, a variable or a shell cannot be written here: start it yourself and tell the agent.", r, i+1)
			}
		}
	}
	if n := len(strings.Join(argv, " ")); n > maxStartCommandBytes {
		return fmt.Errorf("The start command is %d characters and at most %d are allowed. A longer command cannot be written here: start it yourself and tell the agent.", n, maxStartCommandBytes)
	}
	if len(argv) == 1 && strings.EqualFold(argv[0], StartNone) {
		return errors.New("The word none is reserved for declaring that there is no start command, so it cannot be the command itself.")
	}
	return nil
}

// ParseStartEdit turns a developer's typed start command into an argv: split on
// runs of spaces and checked by ValidStartArgv. Text around the whole command
// (a pasted trailing newline) is ignored; a tab or newline inside it is not
// allowed.
func ParseStartEdit(s string) ([]string, error) {
	s = strings.TrimSpace(s)
	if len(s) > 2*maxStartCommandBytes {
		return nil, errors.New("The start command is too long. A command this long cannot be written here: start it yourself and tell the agent.")
	}
	var argv []string
	for _, w := range strings.Split(s, " ") {
		if w != "" {
			argv = append(argv, w)
		}
	}
	if err := ValidStartArgv(argv); err != nil {
		return nil, err
	}
	return argv, nil
}

// splCtx is what the start rules read: the facts' files and needs, and the
// count of entries that could not be written as an argv.
type splCtx struct {
	src     []ProjectFile
	needs   []string
	skipped int
}

// file returns the data of the first surveyed file whose path matches.
func (c *splCtx) file(match func(rel string) bool) ([]byte, bool) {
	for _, f := range c.src {
		if match(f.Rel) {
			return f.Data, true
		}
	}
	return nil, false
}

// splPrepare is the table of declared seed or migrate steps: a plan whose rule
// is the row's gets that command as its Prepare step. Only these rows; a step is
// never invented.
var splPrepare = []struct {
	rule string
	argv []string
}{
	{"django", []string{"python", "manage.py", "migrate"}},
	{"rails", []string{"bin/rails", "db:prepare"}},
}

// plan builds one StartPlan, or counts the entry as skipped when its argv
// cannot be written (ValidStartArgv).
func (c *splCtx) plan(source, rule string, argv []string, port int, cwd string) (StartPlan, bool) {
	if ValidStartArgv(argv) != nil {
		c.skipped++
		return StartPlan{}, false
	}
	if port < 1 || port > 65535 {
		port = 0
	}
	p := StartPlan{Argv: argv, Cwd: cwd, Port: port, Source: source, Rule: rule}
	if len(c.needs) > 0 {
		p.Needs = append([]string(nil), c.needs...)
	}
	for _, pr := range splPrepare {
		if pr.rule == rule {
			p.Prepare = append(p.Prepare, append([]string(nil), pr.argv...))
		}
	}
	return p, true
}

// splRule is one row of the start table: the file a source reads and how it
// turns that file into start plans.
type splRule struct {
	match func(rel string) bool
	plans func(c *splCtx, file ProjectFile) []StartPlan
}

func splIs(name string) func(string) bool { return func(rel string) bool { return rel == name } }

// splRules is THE start table, walked top-down (so the plans come most
// specific first): launch.json, package.json scripts, the Procfile, the
// framework files, the Makefile.
var splRules = []splRule{
	{splIs(".claude/launch.json"), splLaunchPlans},
	{splIs("package.json"), splPackagePlans},
	{splIs("Procfile"), splProcfilePlans},
	{splIs("manage.py"), func(c *splCtx, f ProjectFile) []StartPlan {
		if !strings.Contains(string(f.Data), "django") {
			return nil
		}
		return splOne(c.plan(StartSourceDjango, "django", []string{"python", "manage.py", "runserver", "127.0.0.1:8000"}, 8000, ""))
	}},
	{splIs(".flaskenv"), func(c *splCtx, f ProjectFile) []StartPlan {
		p, ok := splFirstPort(flaskRunPort, f.Data)
		if !ok {
			p = 5000
		}
		return splOne(c.plan(StartSourceFlask, "flask", []string{"flask", "run", "--host", "127.0.0.1", "--port", strconv.Itoa(p)}, p, ""))
	}},
	{splIs("bin/rails"), func(c *splCtx, f ProjectFile) []StartPlan {
		p := 3000
		if pb, ok := c.file(splIs("config/puma.rb")); ok {
			if v, ok := splFirstPort(railsPort, pb); ok {
				p = v
			}
		} else if v, ok := splFirstPort(railsPort, f.Data); ok {
			p = v
		}
		return splOne(c.plan(StartSourceRails, "rails", []string{"bin/rails", "server", "-b", "127.0.0.1", "-p", strconv.Itoa(p)}, p, ""))
	}},
	{func(rel string) bool { return rel == "hugo.toml" || rel == "hugo.yaml" }, func(c *splCtx, f ProjectFile) []StartPlan {
		p, ok := splFirstPort(hugoPort, f.Data)
		if !ok {
			p = 1313
		}
		return splOne(c.plan(StartSourceHugo, "hugo", []string{"hugo", "server", "--bind", "127.0.0.1", "--port", strconv.Itoa(p)}, p, ""))
	}},
	{splIs("_config.yml"), func(c *splCtx, f ProjectFile) []StartPlan {
		if !splJekyllSignal(f.Data) {
			return nil
		}
		p, ok := splFirstPort(jekyllPort, f.Data)
		if !ok {
			p = 4000
		}
		return splOne(c.plan(StartSourceJekyll, "jekyll", []string{"bundle", "exec", "jekyll", "serve", "--host", "127.0.0.1", "--port", strconv.Itoa(p)}, p, ""))
	}},
	{splIs("Makefile"), splMakefilePlans},
}

func splOne(p StartPlan, ok bool) []StartPlan {
	if !ok {
		return nil
	}
	return []StartPlan{p}
}

// splPlan walks the start table over the surveyed files and returns the plans
// (deduplicated by command and folder, first source wins; two configurations
// that differ only by folder are two plans) and how many entries could not be
// written as an argv.
func splPlan(f ProjectFacts) (plans []StartPlan, skipped int) {
	c := &splCtx{src: f.src}
	seenSvc := map[string]bool{}
	for _, n := range f.Needs {
		if n.From == "compose" && n.Service != "" && !seenSvc[n.Service] {
			seenSvc[n.Service] = true
			c.needs = append(c.needs, n.Service)
		}
	}
	seen := map[string]bool{}
	for _, r := range splRules {
		for _, file := range f.src {
			if len(file.Data) == 0 || len(file.Data) > MaxProjectFile || !r.match(file.Rel) {
				continue
			}
			for _, p := range r.plans(c, file) {
				if seen[p.Choice()] {
					continue
				}
				seen[p.Choice()] = true
				plans = append(plans, p)
			}
		}
	}
	return plans, c.skipped
}

// PlanStarts returns the start plans the project's files name, most likely
// first: .claude/launch.json, package.json scripts (dev, start, serve), the
// Procfile, the framework files and the Makefile; deduplicated by command and
// folder (StartPlan.Choice). A
// ProjectFacts that did not come from AnalyzeProject has no files and plans
// nothing.
func PlanStarts(f ProjectFacts) []StartPlan {
	plans, _ := splPlan(f)
	return plans
}

// splMaxLaunchConfigs bounds how many launch.json entries are read.
const splMaxLaunchConfigs = 50

// splLaunchPlans reads .claude/launch.json: a configuration's
// runtimeExecutable and runtimeArgs, with its port (or url, or the port the
// command itself names). An entry that cannot be written as an argv is skipped
// and counted; one with no executable has nothing to start.
func splLaunchPlans(c *splCtx, file ProjectFile) []StartPlan {
	if len(file.Data) > MaxLaunchJSON {
		return nil
	}
	var lf struct {
		Configurations []struct {
			RuntimeExecutable string            `json:"runtimeExecutable"`
			RuntimeArgs       []json.RawMessage `json:"runtimeArgs"`
			Port              json.RawMessage   `json:"port"`
			URL               string            `json:"url"`
			Cwd               string            `json:"cwd"`
		} `json:"configurations"`
	}
	if json.Unmarshal(file.Data, &lf) != nil {
		return nil
	}
	var out []StartPlan
	for i, cfg := range lf.Configurations {
		if i == splMaxLaunchConfigs {
			break
		}
		exe := strings.TrimSpace(cfg.RuntimeExecutable)
		if exe == "" {
			continue
		}
		argv := []string{exe}
		valid := true
		for _, raw := range cfg.RuntimeArgs {
			var s string
			if json.Unmarshal(raw, &s) != nil {
				var n json.Number
				if json.Unmarshal(raw, &n) != nil {
					valid = false
					break
				}
				s = n.String()
			}
			argv = append(argv, s)
		}
		cwd, cwdOK := splCwd(cfg.Cwd)
		if !valid || !cwdOK {
			c.skipped++
			continue
		}
		port, rule := splCmdPort(strings.Join(argv, " "))
		if p, ok := launchPort(cfg.Port); ok {
			port = p
		} else if cfg.URL != "" {
			if t, err := ParseTarget(cfg.URL); err == nil {
				port = t.PortNumber()
			}
		}
		if p, ok := c.plan(StartSourceLaunchJSON, rule, argv, port, cwd); ok {
			out = append(out, p)
		}
	}
	return out
}

// splCwd accepts a launch.json cwd that is a clean project-relative path ("" is
// the project root); an absolute path, a ".." segment, an odd character or a
// path over 48 bytes fails (the entry is then skipped and counted, never cut).
func splCwd(cwd string) (string, bool) {
	cwd = strings.TrimSpace(cwd)
	if cwd == "" || cwd == "." || cwd == "./" {
		return "", true
	}
	cwd = strings.TrimPrefix(cwd, "./")
	if !projStrict(cwd) || len(cwd) > maxStartCwdBytes || strings.HasPrefix(cwd, "/") {
		return "", false
	}
	cwd = strings.TrimSuffix(cwd, "/")
	for _, seg := range strings.Split(cwd, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return "", false
		}
	}
	return cwd, true
}

// splScripts are the package.json scripts that start a development server, in
// the order they are offered. The plan runs the script by name (npm run <name>):
// the script's body is never put into an argv.
var splScripts = []string{"dev", "start", "serve"}

// splPortRefine are the rows that refine a script's table port from another
// project file: a Vite script that names no port of its own runs on the port
// vite.config sets.
var splPortRefine = map[string]func(c *splCtx) (int, bool){
	"vite": func(c *splCtx) (int, bool) {
		b, ok := c.file(func(rel string) bool { return strings.HasPrefix(rel, "vite.config.") })
		if !ok {
			return 0, false
		}
		return splFirstPort(viteServerPort, b)
	},
}

func splPackagePlans(c *splCtx, file ProjectFile) []StartPlan {
	var pj struct {
		Scripts map[string]json.RawMessage `json:"scripts"`
	}
	if json.Unmarshal(file.Data, &pj) != nil {
		return nil
	}
	var out []StartPlan
	for _, name := range splScripts {
		var cmd string
		raw, ok := pj.Scripts[name]
		if !ok || json.Unmarshal(raw, &cmd) != nil || len(cmd) > projMaxLineBytes {
			continue
		}
		port, rule := splCmdPort(cmd)
		if refine, ok := splPortRefine[rule]; ok {
			if _, explicit := explicitPort(cmd); !explicit {
				if p, ok := refine(c); ok {
					port = p
				}
			}
		}
		if p, ok := c.plan(StartSourcePackageJSON, rule, []string{"npm", "run", name}, port, ""); ok {
			out = append(out, p)
		}
	}
	return out
}

var procfileWeb = regexp.MustCompile(`^web\s*:\s*(\S.*)$`)

// splProcfilePlans reads the "web:" line of a Procfile, split on spaces. A
// command that cannot be written as an argv (a $PORT variable, a quote, a pipe)
// is skipped and counted.
func splProcfilePlans(c *splCtx, file ProjectFile) []StartPlan {
	var out []StartPlan
	for _, ln := range projLines(file.Data) {
		m := procfileWeb.FindStringSubmatch(strings.TrimSpace(ln))
		if m == nil {
			continue
		}
		cmd := strings.TrimSpace(m[1])
		port, rule := splCmdPort(cmd)
		if p, ok := c.plan(StartSourceProcfile, rule, strings.Fields(cmd), port, ""); ok {
			out = append(out, p)
		}
		break
	}
	return out
}

// splMakeTargets are the Makefile targets that run the application, in the
// order they are offered.
var splMakeTargets = []string{"run", "dev", "serve"}

var makeTargetLine = regexp.MustCompile(`^([A-Za-z0-9_-]+)\s*:($|[^=])`)

// splMakefilePlans offers "make <target>" for a run, dev or serve target; the
// port is read from the target's own recipe through the same port table.
func splMakefilePlans(c *splCtx, file ProjectFile) []StartPlan {
	recipes := map[string][]string{}
	cur := ""
	for _, ln := range projLines(file.Data) {
		switch {
		case strings.HasPrefix(ln, "\t"):
			if cur != "" {
				recipes[cur] = append(recipes[cur], strings.TrimLeft(ln, "\t @-+"))
			}
		case strings.TrimSpace(ln) == "" || strings.HasPrefix(strings.TrimSpace(ln), "#"):
		default:
			cur = ""
			if m := makeTargetLine.FindStringSubmatch(ln); m != nil && strSliceHas(splMakeTargets, m[1]) {
				if _, seen := recipes[m[1]]; !seen {
					cur = m[1]
					recipes[cur] = []string{}
				}
			}
		}
	}
	var out []StartPlan
	for _, t := range splMakeTargets {
		lines, ok := recipes[t]
		if !ok {
			continue
		}
		port, rule := 0, ""
		for _, l := range lines {
			if p, r := splCmdPort(l); p != 0 {
				port, rule = p, r
				break
			}
		}
		if p, ok := c.plan(StartSourceMakefile, rule, []string{"make", t}, port, ""); ok {
			out = append(out, p)
		}
	}
	return out
}

// splCmdPort returns the port a command line runs a server on and the table
// row that recognised it (""): the row's port, or a port the command names
// itself even when no row knows the command. 0 means no port is known.
func splCmdPort(cmd string) (port int, rule string) {
	if p, r, ok := ScriptPort(cmd); ok {
		return p, r
	}
	if p, ok := explicitPort(cmd); ok {
		return p, ""
	}
	return 0, ""
}
