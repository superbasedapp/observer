package secdast

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// devservers.go finds the dev servers a project is likely to run, from its
// own files only (security coverage gaps plan, item 1): no request is made
// and nothing is resolved here. The caller reads the files (capped at
// MaxProjectFile) and hands them in; ListeningPorts marks which candidate
// ports have a listening socket, where the operating system exposes that
// without a dial.

// MaxProjectFile is the most bytes of one project file the candidate
// readers accept; a larger file is skipped.
const MaxProjectFile = 256 << 10

// Candidate sources, the Candidate.Source values.
const (
	SourceLaunchJSON  = "launch.json"
	SourcePackageJSON = "package.json"
	SourceViteConfig  = "vite.config"
	SourceDjango      = "manage.py"
	SourceFlask       = "flask"
	SourceRails       = "rails"
	SourceHugo        = "hugo"
	SourceJekyll      = "jekyll"
)

// DevServerFiles are the project-relative files the candidate readers
// read, in the order the caller should offer them. A path ending in "*" is
// a prefix: the caller reads every file in the project root that starts
// with it (vite.config.ts, vite.config.mjs, ...).
var DevServerFiles = []string{
	".claude/launch.json", "package.json", "vite.config*", "manage.py", ".flaskenv",
	"bin/rails", "config/puma.rb", "hugo.toml", "hugo.yaml", "_config.yml",
}

// scriptRule is one row of the package.json script table: a script whose
// command matches re runs a dev server on port unless the command names
// its own port.
type scriptRule struct {
	name string
	re   *regexp.Regexp
	port int
}

// scriptRules is THE package.json table, walked top-down; the first row
// whose pattern matches a script's command gives its default port. An
// explicit port in the command (explicitPort) wins over the row.
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
// top-down.
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

// ScriptPort returns the dev server port a package.json script command
// runs on and the name of the table row that recognised it.
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

// fileRule is one row of the per-file table: a reader for one project file.
type fileRule struct {
	// match reports whether the project-relative path is this row's file.
	match func(rel string) bool
	read  func(data []byte) []Candidate
}

var (
	viteServerPort = regexp.MustCompile(`server\s*:\s*\{[^}]*?\bport\s*:\s*(\d{2,5})`)
	hugoPort       = regexp.MustCompile(`(?m)^\s*port\s*[:=]\s*(\d{2,5})`)
	jekyllPort     = regexp.MustCompile(`(?m)^\s*port\s*:\s*(\d{2,5})`)
	flaskRunPort   = regexp.MustCompile(`(?m)^\s*FLASK_RUN_PORT\s*=\s*(\d{2,5})`)
	railsPort      = regexp.MustCompile(`(?m)^\s*port\s+(?:ENV\.fetch\([^)]*?(\d{2,5})\s*\)|ENV\.fetch\([^)]*\)\s*\{\s*(\d{2,5})\s*\}|(\d{2,5}))`)
)

// fileTable is THE candidate file table, walked top-down per file.
var fileTable = []fileRule{
	{match: func(rel string) bool { return rel == ".claude/launch.json" }, read: func(b []byte) []Candidate {
		out := LaunchCandidates(b)
		for i := range out {
			out[i].Source = SourceLaunchJSON
		}
		return out
	}},
	{match: func(rel string) bool { return rel == "package.json" }, read: packageJSONCandidates},
	{match: func(rel string) bool { return strings.HasPrefix(rel, "vite.config.") }, read: func(b []byte) []Candidate {
		if p, ok := firstPort(viteServerPort, b); ok {
			return []Candidate{portCandidate(p, "vite", SourceViteConfig)}
		}
		return nil
	}},
	{match: func(rel string) bool { return rel == "manage.py" }, read: func(b []byte) []Candidate {
		if strings.Contains(string(b), "django") {
			return []Candidate{portCandidate(8000, "django", SourceDjango)}
		}
		return nil
	}},
	{match: func(rel string) bool { return rel == ".flaskenv" }, read: func(b []byte) []Candidate {
		p, ok := firstPort(flaskRunPort, b)
		if !ok {
			p = 5000
		}
		return []Candidate{portCandidate(p, "flask", SourceFlask)}
	}},
	{match: func(rel string) bool { return rel == "bin/rails" || rel == "config/puma.rb" }, read: func(b []byte) []Candidate {
		if p, ok := firstPort(railsPort, b); ok {
			return []Candidate{portCandidate(p, "rails", SourceRails)}
		}
		return []Candidate{portCandidate(3000, "rails", SourceRails)}
	}},
	{match: func(rel string) bool { return rel == "hugo.toml" || rel == "hugo.yaml" }, read: func(b []byte) []Candidate {
		p, ok := firstPort(hugoPort, b)
		if !ok {
			p = 1313
		}
		return []Candidate{portCandidate(p, "hugo", SourceHugo)}
	}},
	{match: func(rel string) bool { return rel == "_config.yml" }, read: func(b []byte) []Candidate {
		s := string(b)
		if !strings.Contains(s, "jekyll") && !strings.Contains(s, "theme:") && !strings.Contains(s, "permalink:") {
			return nil
		}
		p, ok := firstPort(jekyllPort, b)
		if !ok {
			p = 4000
		}
		return []Candidate{portCandidate(p, "jekyll", SourceJekyll)}
	}},
}

// firstPort returns the first non-empty numeric group re finds in b.
func firstPort(re *regexp.Regexp, b []byte) (int, bool) {
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

func portCandidate(port int, name, source string) Candidate {
	return Candidate{URL: "http://localhost:" + strconv.Itoa(port) + "/", Name: name, Source: source}
}

// packageJSONCandidates reads package.json scripts through scriptRules, in
// script-name order so the result is stable.
func packageJSONCandidates(b []byte) []Candidate {
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
			out = append(out, portCandidate(p, clip("npm run "+n+" ("+rule+")", 80), SourcePackageJSON))
		}
	}
	return out
}

// ProjectFile is one project file the caller read for ProjectCandidates.
type ProjectFile struct {
	// Rel is the project-relative path, forward slashes.
	Rel  string
	Data []byte
}

// ProjectCandidates returns the dev server URLs a project's files name,
// deduplicated by URL in the order of files (the first source wins), each
// a loopback target ParseTarget accepts.
func ProjectCandidates(files []ProjectFile) []Candidate {
	seen := map[string]bool{}
	var out []Candidate
	for _, f := range files {
		if len(f.Data) == 0 || len(f.Data) > MaxProjectFile {
			continue
		}
		for _, r := range fileTable {
			if !r.match(f.Rel) {
				continue
			}
			for _, c := range r.read(f.Data) {
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

// CandidatePort returns a candidate URL's port (0 when it has none).
func CandidatePort(u string) int {
	t, err := ParseTarget(u)
	if err != nil {
		return 0
	}
	p, _ := strconv.Atoi(t.Port)
	return p
}

// ListeningPorts parses the bodies of Linux's /proc/net/tcp and
// /proc/net/tcp6 and returns the ports with a socket in LISTEN state on a
// loopback or wildcard address, sorted and deduplicated. Nothing is dialed:
// it is the kernel's own table. Malformed lines are skipped.
func ListeningPorts(bodies ...string) []int {
	set := map[int]bool{}
	for _, body := range bodies {
		for i, line := range strings.Split(body, "\n") {
			if i == 0 {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 4 || f[3] != "0A" {
				continue
			}
			addr, portHex, ok := strings.Cut(f[1], ":")
			if !ok || !localListenAddr(addr) {
				continue
			}
			p, err := strconv.ParseUint(portHex, 16, 16)
			if err != nil || p == 0 {
				continue
			}
			set[int(p)] = true
		}
	}
	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// localListenAddr reports whether a /proc/net/tcp hex address is a wildcard
// or loopback address (a dev server bound to it answers on localhost). IPv4
// is one little-endian 32-bit word; IPv6 is four of them.
func localListenAddr(hex string) bool {
	switch len(hex) {
	case 8:
		if hex == "00000000" {
			return true
		}
		// The first octet is the word's lowest byte: the last two hex digits.
		return strings.EqualFold(hex[6:], "7F")
	case 32:
		if strings.Trim(hex, "0") == "" {
			return true // ::
		}
		// ::1 is the last word 0x01000000 (little-endian 00 00 00 01).
		if hex[:24] == "000000000000000000000000" && strings.EqualFold(hex[24:], "01000000") {
			return true
		}
		// ::ffff:127.x.y.z (an IPv4-mapped loopback).
		if hex[:16] == "0000000000000000" && strings.EqualFold(hex[16:24], "FFFF0000") {
			return strings.EqualFold(hex[30:], "7F")
		}
	}
	return false
}
