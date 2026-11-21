package secdockerfile

import (
	"regexp"
	"strings"
	"time"
)

// The end-of-life data behind S-752 (plan section 4.1 "End-of-life data"):
// a compiled table, refreshed each release. End of life here means no
// security support of any kind from the project any more:
//
//   - Debian: the end of Debian LTS (the "eol" field of endoflife.date's
//     debian data), not the end of the regular security team's support
//     and not Freexian's paid Extended LTS.
//   - Ubuntu: the end of standard security maintenance (the "eol" field),
//     not Ubuntu Pro / ESM, which a stock ubuntu image does not receive
//     without a subscription.
//   - Alpine: the end of the release's security branch.
//   - Python: the end of the release's security fixes.
//   - Node.js: the end of the release line's maintenance.
//
// A cycle the table does not list (a new release, an unknown name) gets no
// S-752: the rule reports what it knows, never a guess.

// eolRow is one release cycle's end of life.
type eolRow struct {
	product  string
	cycle    string
	codename string
	eol      time.Time
}

func day(y int, m time.Month, d int) time.Time { return time.Date(y, m, d, 0, 0, 0, 0, time.UTC) }

// eolTable is THE end-of-life table.
//
// source: endoflife.date, read 2026-11-04 (https://endoflife.date/api/
// debian.json, ubuntu.json, alpine-linux.json, python.json, nodejs.json;
// the "eol" field of each cycle). Node.js LTS codenames are the release
// line names of the Node.js release schedule.
var eolTable = []eolRow{
	// Debian (end of LTS).
	{"debian", "7", "wheezy", day(2018, time.May, 31)},
	{"debian", "8", "jessie", day(2020, time.June, 30)},
	{"debian", "9", "stretch", day(2022, time.July, 1)},
	{"debian", "10", "buster", day(2024, time.June, 30)},
	{"debian", "11", "bullseye", day(2026, time.August, 31)},
	{"debian", "12", "bookworm", day(2028, time.June, 30)},
	{"debian", "13", "trixie", day(2030, time.June, 30)},

	// Ubuntu (end of standard support; ESM not counted).
	{"ubuntu", "14.04", "trusty", day(2019, time.April, 2)},
	{"ubuntu", "16.04", "xenial", day(2021, time.April, 2)},
	{"ubuntu", "18.04", "bionic", day(2023, time.May, 31)},
	{"ubuntu", "18.10", "cosmic", day(2019, time.July, 18)},
	{"ubuntu", "19.04", "disco", day(2020, time.January, 23)},
	{"ubuntu", "19.10", "eoan", day(2020, time.July, 6)},
	{"ubuntu", "20.04", "focal", day(2025, time.May, 31)},
	{"ubuntu", "20.10", "groovy", day(2021, time.July, 22)},
	{"ubuntu", "21.04", "hirsute", day(2022, time.January, 20)},
	{"ubuntu", "21.10", "impish", day(2022, time.July, 14)},
	{"ubuntu", "22.04", "jammy", day(2027, time.June, 1)},
	{"ubuntu", "22.10", "kinetic", day(2023, time.July, 20)},
	{"ubuntu", "23.04", "lunar", day(2024, time.January, 20)},
	{"ubuntu", "23.10", "mantic", day(2024, time.July, 12)},
	{"ubuntu", "24.04", "noble", day(2029, time.May, 31)},
	{"ubuntu", "24.10", "oracular", day(2025, time.July, 10)},
	{"ubuntu", "25.04", "plucky", day(2026, time.January, 17)},
	{"ubuntu", "25.10", "questing", day(2026, time.July, 1)},
	{"ubuntu", "26.04", "resolute", day(2031, time.May, 29)},
	{"ubuntu", "26.10", "stonking", day(2027, time.July, 1)},

	// Alpine Linux (end of the security branch).
	{"alpine", "3.5", "", day(2018, time.November, 1)},
	{"alpine", "3.6", "", day(2019, time.May, 1)},
	{"alpine", "3.7", "", day(2019, time.November, 1)},
	{"alpine", "3.8", "", day(2020, time.May, 1)},
	{"alpine", "3.9", "", day(2020, time.November, 1)},
	{"alpine", "3.10", "", day(2021, time.May, 1)},
	{"alpine", "3.11", "", day(2021, time.November, 1)},
	{"alpine", "3.12", "", day(2022, time.May, 1)},
	{"alpine", "3.13", "", day(2022, time.November, 1)},
	{"alpine", "3.14", "", day(2023, time.May, 1)},
	{"alpine", "3.15", "", day(2023, time.November, 1)},
	{"alpine", "3.16", "", day(2024, time.May, 23)},
	{"alpine", "3.17", "", day(2024, time.November, 22)},
	{"alpine", "3.18", "", day(2025, time.May, 9)},
	{"alpine", "3.19", "", day(2025, time.November, 1)},
	{"alpine", "3.20", "", day(2026, time.April, 1)},
	{"alpine", "3.21", "", day(2026, time.November, 1)},
	{"alpine", "3.22", "", day(2027, time.May, 1)},
	{"alpine", "3.23", "", day(2027, time.November, 1)},
	{"alpine", "3.24", "", day(2028, time.June, 1)},

	// Python (end of security fixes).
	{"python", "2.7", "", day(2020, time.January, 1)},
	{"python", "3.5", "", day(2020, time.September, 30)},
	{"python", "3.6", "", day(2021, time.December, 23)},
	{"python", "3.7", "", day(2023, time.June, 27)},
	{"python", "3.8", "", day(2024, time.October, 7)},
	{"python", "3.9", "", day(2025, time.October, 31)},
	{"python", "3.10", "", day(2026, time.October, 1)},
	{"python", "3.11", "", day(2027, time.October, 31)},
	{"python", "3.12", "", day(2028, time.October, 31)},
	{"python", "3.13", "", day(2029, time.October, 31)},
	{"python", "3.14", "", day(2030, time.October, 31)},
	{"python", "3.15", "", day(2031, time.October, 31)},

	// Node.js (end of maintenance).
	{"node", "4", "argon", day(2018, time.April, 30)},
	{"node", "5", "", day(2016, time.June, 30)},
	{"node", "6", "boron", day(2019, time.April, 30)},
	{"node", "7", "", day(2017, time.June, 30)},
	{"node", "8", "carbon", day(2019, time.December, 31)},
	{"node", "9", "", day(2018, time.June, 30)},
	{"node", "10", "dubnium", day(2021, time.April, 30)},
	{"node", "11", "", day(2019, time.June, 30)},
	{"node", "12", "erbium", day(2022, time.April, 30)},
	{"node", "13", "", day(2020, time.June, 1)},
	{"node", "14", "fermium", day(2023, time.April, 30)},
	{"node", "15", "", day(2021, time.June, 1)},
	{"node", "16", "gallium", day(2023, time.September, 11)},
	{"node", "17", "", day(2022, time.June, 1)},
	{"node", "18", "hydrogen", day(2025, time.April, 30)},
	{"node", "19", "", day(2023, time.June, 1)},
	{"node", "20", "iron", day(2026, time.April, 30)},
	{"node", "21", "", day(2024, time.June, 1)},
	{"node", "22", "jod", day(2027, time.April, 30)},
	{"node", "23", "", day(2025, time.June, 1)},
	{"node", "24", "krypton", day(2028, time.April, 30)},
	{"node", "25", "", day(2026, time.June, 1)},
	{"node", "26", "", day(2029, time.April, 30)},
}

// NearEOLWindow is how close to end of life a base turns S-752 on at
// medium severity.
const NearEOLWindow = 90 * 24 * time.Hour

// cycleRef is one (product, cycle) a FROM line's image names.
type cycleRef struct{ product, cycle string }

// lookupCycle finds a cycle by number or by codename.
func lookupCycle(product, token string) (eolRow, bool) {
	for _, r := range eolTable {
		if r.product != product {
			continue
		}
		if r.cycle == token || (r.codename != "" && r.codename == token) {
			return r, true
		}
	}
	return eolRow{}, false
}

// tokenReader turns one tag or name token into a cycle token of a product
// ("" when the token names none of it: a moving name like latest, stable
// or lts reads as nothing).
type tokenReader func(tok string) string

var (
	majorRE      = regexp.MustCompile(`^([0-9]+)(\.[0-9]+)*$`)
	majorMinorRE = regexp.MustCompile(`^([0-9]+\.[0-9]+)(\.[0-9]+)?([a-z]+[0-9]*)?$`)
	alpineSufRE  = regexp.MustCompile(`^alpine([0-9]+\.[0-9]+)$`)
	debianSufRE  = regexp.MustCompile(`^debian([0-9]+)$`)
	nodejsSufRE  = regexp.MustCompile(`^nodejs([0-9]+)$`)
)

// readMajorOrName reads "12", "12.5" (major 12) or a codename.
func readMajorOrName(tok string) string {
	if m := majorRE.FindStringSubmatch(tok); m != nil {
		return m[1]
	}
	return tok
}

// readMajorMinorOrName reads "22.04", "3.18", "3.18.4" (major.minor) or a
// codename; a bare major ("3") is a moving tag and reads as nothing.
func readMajorMinorOrName(tok string) string {
	if m := majorMinorRE.FindStringSubmatch(tok); m != nil {
		return m[1]
	}
	if majorRE.MatchString(tok) {
		return ""
	}
	return tok
}

// tagLeadRule is how an image's first tag token names a cycle.
type tagLeadRule struct {
	product string
	read    tokenReader
}

// suffixRule is a later token naming a distribution release the image is
// built on (python:3.12-slim-bullseye, node:20-alpine3.18).
type suffixRule struct {
	product string
	read    tokenReader
}

// suffixRules are the base-distribution tokens, walked in order.
var suffixRules = []suffixRule{
	{"debian", func(tok string) string {
		if _, ok := lookupCycle("debian", tok); ok && !majorRE.MatchString(tok) {
			return tok // a codename; a bare number is a version, not a distro
		}
		if m := debianSufRE.FindStringSubmatch(tok); m != nil {
			return m[1]
		}
		return ""
	}},
	{"alpine", func(tok string) string {
		if m := alpineSufRE.FindStringSubmatch(tok); m != nil {
			return m[1]
		}
		return ""
	}},
}

// imageRow is one image the end-of-life rule knows.
type imageRow struct {
	// registry is "" for a Docker Hub official image.
	registry string
	// repo is the repository, or a prefix ending in "/" whose next path
	// element is read token by token (distroless names its base there).
	repo string
	// lead reads the tag's first token; nil reads no cycle from the tag.
	lead *tagLeadRule
	// suffixes reads every later tag token through suffixRules.
	suffixes bool
	// nameTokens reads the repository's last element token by token
	// (gcr.io/distroless/static-debian12, nodejs20-debian12).
	nameTokens []suffixRule
}

// imageTable is THE image table, walked top-down; the first match decides.
var imageTable = []imageRow{
	{repo: "debian", lead: &tagLeadRule{"debian", readMajorOrName}},
	{repo: "ubuntu", lead: &tagLeadRule{"ubuntu", readMajorMinorOrName}},
	{repo: "alpine", lead: &tagLeadRule{"alpine", readMajorMinorOrName}},
	{repo: "python", lead: &tagLeadRule{"python", readMajorMinorOrName}, suffixes: true},
	{repo: "node", lead: &tagLeadRule{"node", readMajorOrName}, suffixes: true},
	{registry: "gcr.io", repo: "distroless/", nameTokens: []suffixRule{
		{"debian", func(tok string) string {
			if m := debianSufRE.FindStringSubmatch(tok); m != nil {
				return m[1]
			}
			return ""
		}},
		{"node", func(tok string) string {
			if m := nodejsSufRE.FindStringSubmatch(tok); m != nil {
				return m[1]
			}
			return ""
		}},
	}},
}

// dockerHubHosts are the spellings of Docker Hub's registry.
var dockerHubHosts = map[string]bool{"": true, "docker.io": true, "index.docker.io": true, "registry-1.docker.io": true}

// cyclesOf returns every (product, cycle) the image names that the table
// knows.
func cyclesOf(img imageRef) []eolRow {
	registry := strings.ToLower(img.registry)
	repo := strings.ToLower(img.repo)
	if dockerHubHosts[registry] {
		registry = ""
		repo = strings.TrimPrefix(repo, "library/")
	}
	tag := strings.ToLower(img.tag)
	for _, row := range imageTable {
		if row.registry != registry {
			continue
		}
		var name string
		switch {
		case strings.HasSuffix(row.repo, "/"):
			rest, ok := strings.CutPrefix(repo, row.repo)
			if !ok || rest == "" || strings.Contains(rest, "/") {
				continue
			}
			name = rest
		case row.repo == repo:
		default:
			continue
		}
		var refs []cycleRef
		toks := strings.Split(tag, "-")
		if row.lead != nil && tag != "" {
			if c := row.lead.read(toks[0]); c != "" {
				refs = append(refs, cycleRef{row.lead.product, c})
			}
		}
		if row.suffixes && tag != "" {
			for _, tok := range toks[1:] {
				for _, s := range suffixRules {
					if c := s.read(tok); c != "" {
						refs = append(refs, cycleRef{s.product, c})
					}
				}
			}
		}
		for _, tok := range strings.Split(name, "-") {
			for _, s := range row.nameTokens {
				if c := s.read(tok); c != "" {
					refs = append(refs, cycleRef{s.product, c})
				}
			}
		}
		var out []eolRow
		for _, r := range refs {
			if e, ok := lookupCycle(r.product, r.cycle); ok {
				out = append(out, e)
			}
		}
		return out
	}
	return nil
}

// eolVerdict is S-752's answer for one image.
type eolVerdict struct {
	hit  bool
	past bool
	row  eolRow
}

// judgeEOL picks the worst cycle an image names: past end of life before
// within the window, and the earlier date first.
func judgeEOL(img imageRef, now time.Time) eolVerdict {
	var best eolVerdict
	for _, r := range cyclesOf(img) {
		past := !now.Before(r.eol)
		near := !past && r.eol.Sub(now) <= NearEOLWindow
		if !past && !near {
			continue
		}
		v := eolVerdict{hit: true, past: past, row: r}
		switch {
		case !best.hit:
			best = v
		case v.past && !best.past:
			best = v
		case v.past == best.past && v.row.eol.Before(best.row.eol):
			best = v
		}
	}
	return best
}

// eolDetail is the S-752 finding's detail: table words only.
func eolDetail(v eolVerdict) string {
	name := v.row.product + " " + v.row.cycle
	if v.row.codename != "" && v.row.codename != v.row.cycle {
		name += " (" + v.row.codename + ")"
	}
	when := "end of life on "
	if v.past {
		when = "end of life since "
	}
	return name + ", " + when + v.row.eol.Format("2006-01-02")
}
