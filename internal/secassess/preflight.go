package secassess

import (
	"fmt"
	"sort"
	"strings"
)

// Preflight facts (depth plan W4.2): advice about a pen test or red team before
// it starts, from what the survey saw. Advice only, never a refusal: a note
// that says "likely fails" still lets the developer go on. Every note is one
// honest sentence in plain words, built only from closed ids and strict-charset
// names the facts already carry.

// NoteLevel is how strongly a preflight note speaks.
type NoteLevel string

// The note levels (advice, never a refusal).
const (
	NoteLikelyFails NoteLevel = "likely_fails"
	NoteWarn        NoteLevel = "warn"
	NoteInfo        NoteLevel = "info"
)

// Note is one preflight fact in the dialog's words.
type Note struct {
	ID    string    `json:"id"`
	Level NoteLevel `json:"level"`
	Text  string    `json:"text"`
}

// PreflightInput is what the notes depend on besides the project's files.
type PreflightInput struct {
	// Tier is the sandbox network tier in force ("proxy_only", "internet", "").
	Tier string
	// Start is the start plan chosen for the run (nil: none).
	Start *StartPlan
	// PrepareChosen says the developer ticked the preparation steps of the plan
	// (they run first, once). They run only when it is true; the default is false.
	PrepareChosen bool
	// TargetPort is the port of the target the developer confirmed (0 unknown).
	TargetPort int
}

// pflRule is one row of the preflight table: a rule id and the notes it
// produces (none when the rule does not apply).
type pflRule struct {
	id    string
	notes func(f ProjectFacts, in PreflightInput) []Note
}

// pflRules is THE preflight table (one test row per rule), in rule order; the
// result is ordered by level first and by this order within a level.
var pflRules = []pflRule{
	{"deps_not_installed", pflDepsNotInstalled},
	{"service_needed", pflServiceNeeded},
	{"no_start_command", pflNoStart},
	{"start_port", pflStartPort},
	{"env_files", pflEnvFiles},
	{"no_lockfile", pflNoLockfile},
	{"start_prepare", pflStartPrepare},
	{"api_spec", pflAPISpec},
	{"survey_truncated", pflTruncated},
}

// pflRank orders the levels, most severe first.
var pflRank = map[NoteLevel]int{NoteLikelyFails: 0, NoteWarn: 1, NoteInfo: 2}

// Preflight returns the notes for a pen test or red team of the project, most
// severe first (likely_fails, warn, info), in rule order within a level.
func Preflight(f ProjectFacts, in PreflightInput) []Note {
	var out []Note
	for _, r := range pflRules {
		out = append(out, r.notes(f, in)...)
	}
	sort.SliceStable(out, func(i, j int) bool { return pflRank[out[i].Level] < pflRank[out[j].Level] })
	return out
}

// pflHasDeps reports whether the project's manifests list dependencies in lang.
// A facts value that did not come from AnalyzeProject has no per-language
// count and falls back to the total.
func pflHasDeps(f ProjectFacts, lang string) bool {
	if f.depsByLang != nil {
		return f.depsByLang[lang] > 0
	}
	return f.DepCount > 0 && strSliceHas(f.Languages, lang)
}

// pflInstalls are the ecosystems whose packages are installed into the project
// folder, and the folder that shows it: a missing one means the application
// cannot import its packages. (Go, Ruby and Rust keep their caches outside the
// project, so a missing folder says nothing and has no row.)
var pflInstalls = []struct{ lang, dir, label string }{
	{"node", "node_modules", "node_modules"},
	{"python", "venv", "a venv or .venv folder"},
	{"php", "vendor", "vendor"},
}

func pflDepsNotInstalled(f ProjectFacts, in PreflightInput) []Note {
	var missing []string
	for _, r := range pflInstalls {
		if pflHasDeps(f, r.lang) && !strSliceHas(f.Installed, r.dir) {
			missing = append(missing, r.label)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	level := NoteLikelyFails
	text := "The project's packages do not look installed (no " + pflList(missing) + "). The box cannot install packages while its network is limited to the model proxy: run the installer outside first, or the application will probably not start."
	if in.Tier == "internet" {
		level = NoteWarn
		text = "The project's packages do not look installed (no " + pflList(missing) + "). The box can reach the internet and the agent may install them itself, but that is slow: it is faster to run the installer outside first."
	}
	return []Note{{ID: "deps_not_installed", Level: level, Text: text}}
}

// pflServiceReach says, per sandbox network tier, what the box can do about a
// service the project needs. It never claims what Observer cannot see: whether
// the box holds a container engine is not something the daemon looks at, and a
// remote service may answer when the box has a route out. A tier that is not
// in the table (including "") reads as the narrowest, proxy_only.
var pflServiceReach = map[string]string{
	"internet":   "The box can reach the internet, so a remote one may answer; Observer cannot see a container engine in the box, so do not count on a local one",
	"proxy_only": "The box has no route to one (Observer cannot see a container engine there either)",
}

func pflServiceNeeded(f ProjectFacts, in PreflightInput) []Note {
	var kinds []string
	for _, n := range f.Needs {
		if !strSliceHas(kinds, n.Kind) {
			kinds = append(kinds, n.Kind)
		}
	}
	if len(kinds) == 0 {
		return nil
	}
	reach, ok := pflServiceReach[in.Tier]
	if !ok {
		reach = pflServiceReach["proxy_only"]
	}
	return []Note{{ID: "service_needed", Level: NoteWarn, Text: "The project names " + pflList(kinds) +
		" as a service it needs (a compose file or an example environment file). " + reach + ": the app may fail to start; start it yourself and tell the agent."}}
}

func pflNoStart(f ProjectFacts, in PreflightInput) []Note {
	plans, skipped := splPlan(f)
	if in.Start != nil || len(plans) > 0 {
		return nil
	}
	text := "No start command could be read from the project's files; the agent will look for one or you can type it."
	if skipped > 0 {
		text = "The project's files name " + groundPlural(skipped, "start command", "start commands") +
			", but none that can be written as a plain command (words and flags only: no quotes, pipes, variables or shell); the agent will look for one or you can type it."
	}
	return []Note{{ID: "no_start_command", Level: NoteWarn, Text: text}}
}

// pflStartPort warns when the plan chosen listens on a port other than the
// target's: the agent starts the server where the plan says, polls the target,
// and every dynamic category then reads as not started.
func pflStartPort(_ ProjectFacts, in PreflightInput) []Note {
	if in.Start == nil || in.Start.Port == 0 || in.TargetPort == 0 || in.Start.Port == in.TargetPort {
		return nil
	}
	return []Note{{ID: "start_port", Level: NoteWarn, Text: fmt.Sprintf(
		"The start command is expected to listen on port %d, but the target you chose is on port %d. If the server does not answer on the target's port, every dynamic category reads skipped (not started): choose the target on port %d, or type a start command that listens on port %d.",
		in.Start.Port, in.TargetPort, in.Start.Port, in.TargetPort)}}
}

func pflEnvFiles(f ProjectFacts, _ PreflightInput) []Note {
	n := len(f.EnvFiles)
	if n == 0 {
		return nil
	}
	shown := f.EnvFiles
	if len(shown) > 5 {
		shown = shown[:5]
	}
	names := strings.Join(shown, ", ")
	if n > len(shown) {
		names += fmt.Sprintf(" and %d more", n-len(shown))
	}
	noun, verb, them := "environment files", "are", "them"
	if n == 1 {
		noun, verb, them = "environment file", "is", "it"
	}
	return []Note{{ID: "env_files", Level: NoteWarn, Text: fmt.Sprintf("%d %s (%s) %s in this folder and the box can read %s: the agent is told not to.", n, noun, names, verb, them)}}
}

// pflLocks are the ecosystems that keep a lock file next to the manifest, and
// the file names that count. Python has no row: a pinned requirements.txt is
// its usual lock.
var pflLocks = []struct {
	lang  string
	files []string
}{
	{"node", []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}},
	{"ruby", []string{"Gemfile.lock"}},
	{"php", []string{"composer.lock"}},
	{"rust", []string{"Cargo.lock"}},
	{"go", []string{"go.sum"}},
}

func pflNoLockfile(f ProjectFacts, _ PreflightInput) []Note {
	var langs []string
	for _, r := range pflLocks {
		if !pflHasDeps(f, r.lang) {
			continue
		}
		found := false
		for _, l := range r.files {
			found = found || strSliceHas(f.Lockfiles, l)
		}
		if !found {
			langs = append(langs, r.lang)
		}
	}
	if len(langs) == 0 {
		return nil
	}
	return []Note{{ID: "no_lockfile", Level: NoteInfo, Text: "No lock file was found for the " + pflList(langs) +
		" packages, so a fresh install may pick different versions than the ones you run today."}}
}

// pflStartPrepare is the note about the plan's preparation steps (a Django
// migrate, a Rails db:prepare). They run only when the developer ticks them, so
// a plan that has some and where they were not ticked gets an info note (the
// app may not start without them), and one where they were gets a warning (they
// change local data). The steps are placed through the same helper as the
// prompt's, so what the note shows is what the agent is told, whole or not at
// all.
func pflStartPrepare(_ ProjectFacts, in PreflightInput) []Note {
	if in.Start == nil || len(in.Start.Prepare) == 0 {
		return nil
	}
	var cmds []string
	for _, p := range in.Start.Prepare {
		if len(cmds) == maxPrepareSteps {
			break
		}
		step, ok := ptPlaceText(strings.Join(p, " "), maxPrepareText)
		if !ok {
			step = "a step that cannot be shown here"
		}
		cmds = append(cmds, step)
	}
	steps := strings.Join(cmds, "; ")
	if in.PrepareChosen {
		return []Note{{ID: "start_prepare", Level: NoteWarn, Text: "These steps run first and can change local data in the project, for example its database file: " + steps + "."}}
	}
	return []Note{{ID: "start_prepare", Level: NoteInfo, Text: "The project's files suggest preparation steps (" + steps +
		"). They will not run unless you tick Run the preparation steps first; without them the app may not start."}}
}

func pflAPISpec(f ProjectFacts, _ PreflightInput) []Note {
	if f.SpecPath == "" {
		return nil
	}
	detail := ""
	if f.Spec != nil {
		detail = fmt.Sprintf(", %d operations", f.Spec.Operations)
		if f.Spec.Operations == 1 {
			detail = ", 1 operation"
		}
	}
	return []Note{{ID: "api_spec", Level: NoteInfo, Text: "An API description (" + f.SpecPath + detail + ") is in the project: the agent can use it to plan the API tests."}}
}

func pflTruncated(f ProjectFacts, _ PreflightInput) []Note {
	if !f.Truncated {
		return nil
	}
	return []Note{{ID: "survey_truncated", Level: NoteInfo, Text: "The look at the project's files stopped at a size or time limit, so some of the facts here may be missing."}}
}

// pflList joins words as "a", "a and b", "a, b and c".
func pflList(words []string) string {
	switch len(words) {
	case 0:
		return ""
	case 1:
		return words[0]
	}
	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}
