package secassess

import "strings"

// The start command of a penetration test or red team (depth plan W4.1): the
// plan offers the commands read from the project's files and lets the
// developer type another or declare none. SelectStart turns the developer's
// choice into the command in force, by one ordered table.

// StartNone is the choice that declares no start command (the agent looks for
// one itself). It is reserved: no command can be called none, in any case
// (ValidStartArgv), so the word cannot be told from the choice.
const StartNone = "none"

// StartSourceTyped is the source of a command the developer typed.
const StartSourceTyped = "typed"

// StartSelection is the command in force and how it came about.
type StartSelection struct {
	// Plan is the start plan in force; nil when no command is declared or the
	// typed one was refused.
	Plan *StartPlan
	// Command is the effective command, the argv joined by spaces ("" none). It
	// is the text the prompt shows; the folder it runs in is Cwd.
	Command string
	// Edit is the text for the input: the command in force, or the refused text.
	Edit string
	// Edited says the developer typed the command in force (as against one of
	// the plans the project's files named).
	Edited bool
	// Error is why a typed command was refused, in plain words ("" when none
	// was).
	Error string
	// Choice is the text that gives this selection back to SelectStart: the
	// plan's StartPlan.Choice (the command, and its folder when it has one), the
	// typed command, StartNone for a declared none and "" when nothing is
	// declared or the typed command was refused. It is what a run records and a
	// held run replays: SelectStart(plans, sel.Choice) returns the same selection
	// for every selection that has no Error.
	Choice string
	// Cwd is the project-relative folder the command runs in ("" the project
	// root). A typed command always runs in the root.
	Cwd string
	// Source is where the command in force came from: the plan's source name
	// (StartSourceLaunchJSON, StartSourceProcfile ...), StartSourceTyped for a
	// typed command and "" when none is declared.
	Source string
	// NotPreselected says the project names plans but none was chosen for the
	// developer, because the most likely plan's program is not a well-known
	// runner (startRunners). Nothing is declared until the developer chooses a
	// plan or types a command; the dialog says so and lists the plans.
	NotPreselected bool
}

// startRunner is one row of the runner table: a family of well-known programs
// that start a development server. A plan read from the project's own files is
// pre-selected for the developer only when its program is in this table; any
// other program has to be chosen on purpose.
type startRunner struct {
	family string
	// names are the exact first words of a command (a relative path where the
	// ecosystem's own wrapper is one: ./gradlew, bin/rails).
	names []string
}

// startRunners is THE runner table, one row per family.
var startRunners = []startRunner{
	{"node runtimes and package managers", []string{"node", "nodejs", "npm", "npx", "yarn", "pnpm", "bun", "bunx", "deno", "nodemon", "tsx", "ts-node"}},
	{"javascript dev servers", []string{"next", "nuxt", "nuxi", "vite", "astro", "remix", "ng", "gatsby", "webpack", "webpack-dev-server", "parcel", "storybook", "expo", "react-scripts", "vue-cli-service", "svelte-kit"}},
	{"python interpreters, tools and servers", []string{"python", "python3", "py", "uv", "poetry", "pipenv", "pdm", "uvicorn", "gunicorn", "hypercorn", "daphne", "flask", "fastapi", "django-admin", "streamlit"}},
	{"go", []string{"go", "air"}},
	{"rust", []string{"cargo"}},
	{"dotnet", []string{"dotnet"}},
	{"jvm build tools and runtime", []string{"java", "mvn", "./mvnw", "gradle", "./gradlew", "sbt", "lein"}},
	{"ruby", []string{"ruby", "bundle", "rails", "bin/rails", "rackup", "puma", "rake", "foreman"}},
	{"php", []string{"php", "composer", "symfony"}},
	{"elixir", []string{"mix", "elixir"}},
	{"static site generators", []string{"hugo", "jekyll"}},
	{"build tools", []string{"make", "just", "task"}},
}

// startRunnerKnown reports whether the command's program (its first word) is a
// well-known runner.
func startRunnerKnown(argv []string) bool {
	if len(argv) == 0 {
		return false
	}
	for _, r := range startRunners {
		for _, n := range r.names {
			if argv[0] == n {
				return true
			}
		}
	}
	return false
}

// planSelection is the selection of one plan, as listed or as typed.
func planSelection(pl *StartPlan) StartSelection {
	return StartSelection{
		Plan: pl, Command: pl.Command(), Edit: pl.Command(),
		Choice: pl.Choice(), Cwd: pl.Cwd, Source: pl.Source,
	}
}

// selectStartRow is one row of the table: the first whose test holds decides.
type selectStartRow struct {
	test func(plans []StartPlan, choice string) bool
	pick func(plans []StartPlan, choice string) StartSelection
}

var selectStartRows = []selectStartRow{
	// not chosen: the most likely plan when its program is a well-known runner,
	// else nothing is chosen for the developer (the plans are still listed);
	// none when the project names none
	{func(_ []StartPlan, c string) bool { return c == "" }, func(p []StartPlan, _ string) StartSelection {
		switch {
		case len(p) == 0:
			return StartSelection{}
		case !startRunnerKnown(p[0].Argv):
			return StartSelection{NotPreselected: true}
		}
		return planSelection(&p[0])
	}},
	// declared none
	{func(_ []StartPlan, c string) bool { return c == StartNone }, func([]StartPlan, string) StartSelection {
		return StartSelection{Choice: StartNone}
	}},
	// a choice that spells one of the plans (its command, and its folder when it
	// has one) is that plan
	{func(p []StartPlan, c string) bool { return planByChoice(p, c) != nil }, func(p []StartPlan, c string) StartSelection {
		return planSelection(planByChoice(p, c))
	}},
	// anything else is typed
	{func([]StartPlan, string) bool { return true }, func(_ []StartPlan, c string) StartSelection {
		argv, err := ParseStartEdit(c)
		if err != nil {
			return StartSelection{Edit: c, Edited: true, Error: err.Error()}
		}
		pl := StartPlan{Argv: argv, Source: StartSourceTyped}
		sel := planSelection(&pl)
		sel.Edited = true
		return sel
	}},
}

// planByChoice returns the plan whose StartPlan.Choice is the given text (spaces
// around and between the words are ignored), or nil.
func planByChoice(plans []StartPlan, choice string) *StartPlan {
	choice = strings.Join(strings.Fields(choice), " ")
	for i := range plans {
		if plans[i].Choice() == choice {
			return &plans[i]
		}
	}
	return nil
}

// SelectStart resolves the developer's choice among the plans: not chosen takes
// the most likely plan when its program is a well-known runner (otherwise
// nothing is declared and the selection says NotPreselected), StartNone
// declares no command, a choice that spells one of the plans is that plan, and
// any other text is checked as a typed command (which runs in the project
// root, whatever a plan of the same words says). The plans are not modified.
func SelectStart(plans []StartPlan, choice string) StartSelection {
	choice = strings.TrimSpace(choice)
	for _, r := range selectStartRows {
		if r.test(plans, choice) {
			return r.pick(plans, choice)
		}
	}
	return StartSelection{}
}
