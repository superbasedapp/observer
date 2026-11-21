package secassess

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// MaxPromptBytes bounds the whole prompt (it is passed to the agent on argv).
const MaxPromptBytes = 24 << 10

// PromptInput is what a prompt is built from. Every string is cleaned.
type PromptInput struct {
	Kind        ID
	RunID       string
	ProjectName string
	// Target is the normalized target for a kind that has one.
	Target *Target
	// Relax are the relaxations in force for the run; the prompt says so in
	// words from the relaxation table (plan section 13.10). Empty leaves the
	// prompt exactly as it was.
	Relax []InForce
	// TimeBoxMinutes is the time box the prompt states (0 takes the kind's
	// default; settings may set another).
	TimeBoxMinutes int
	// Frameworks, MethodExtras and Categories are the sets in force for a
	// kind with a model contract (the settings' presets, resolved by the
	// caller); nil takes the defaults named in SchemaInput.
	Frameworks   []string
	MethodExtras []string
	Categories   []string
	// SelfCheck names the self-check command in the prompt, so the agent can
	// check its own assessment.json before it finishes.
	SelfCheck bool
	// Binary is what the caller knows about the daemon's own binary: the
	// self-check line names it by its path when SelfCheckBinary allows (the
	// zero value names the bare command).
	Binary BinaryFacts

	// The fields below belong to threat-model and penetration-test depth (plan
	// W3 and W4). Every one is optional: a zero value leaves the section out or
	// takes the default, so a caller that sets none gets the prompt it always
	// got.

	// Grounding is the rendered grounding digest, already inside its data fence
	// (RenderGrounding); "" leaves the section out. It is placed only for a
	// kind that carries one.
	Grounding string
	// ScopePaths and ScopeNote are the developer's scope for a threat model
	// (NormalizeScope and CleanScopeNote have already run on them).
	ScopePaths []string
	ScopeNote  string
	// AIApp says the project looks like an AI application (the AI frameworks
	// apply).
	AIApp bool
	// Facts are the grounding facts that hold for the project; nil takes every
	// one (the project's shape is not known). SpecSummary is one line about an
	// OpenAPI JSON spec ("" none).
	Facts       []string
	SpecSummary string
	// StartCommand is the start command in force, the argv joined by spaces
	// ("" none: the agent finds one); StartCwd the project-relative folder it
	// runs in ("" the project root) and StartSource where it came from
	// (StartSelection.Source: the prompt says so, and places a command that is
	// repository text inside a data fence).
	StartCommand string
	StartCwd     string
	StartSource  string
	// Prepare are the preparation steps (seed or migrate commands, each joined
	// as text) the developer CHOSE to run first. The caller leaves it empty
	// unless they ticked them; the prompt places them only when it is not empty.
	Prepare []string
	// EnvFiles is how many environment files the project holds at the top level
	// of its folder (nested ones are not counted) and SecretMode the effective
	// workspace_secret_mode.
	EnvFiles   int
	SecretMode string
	// PaceRPS and RequestBudget are the request limits (0 takes the defaults).
	PaceRPS       int
	RequestBudget int
	// Tools says which tools Observer found in the box's standard folders.
	Tools ToolFacts
	// Helper says the request helper (probe.py and probe.json) is in the run
	// directory: the prompt then tells the agent how to use it and the result
	// model asks for the indicator that makes a finding countable.
	Helper bool
	// Objective is the developer's own objective for an exercise (CleanObjective
	// has run on it); "" leaves the section out and the agent states its own.
	// It is read only by a kind that asks for an exercise.
	Objective string
	// Replay is the retest's basis: the findings of the earlier run whose stored
	// requests the task asks the agent to replay. Required for a retest kind and
	// read only by one.
	Replay *RetestBasis
}

// PromptSHA256 is the digest of a prompt: the plan response carries it and the
// launch sends it back, so the developer launches the prompt they read.
func PromptSHA256(prompt string) string {
	sum := sha256.Sum256([]byte(prompt))
	return hex.EncodeToString(sum[:])
}

// SelfCheckCommand is the command the prompt names for a model run, starting with
// the command word bin (SelfCheckBinary's answer; "" is the bare command).
func SelfCheckCommand(bin, runID string) string {
	if bin == "" {
		bin = selfCheckBare
	}
	return bin + " security assess check " + ResultRoot + "/" + runID + "/" + FileAssessment
}

// BuildPrompt renders the task an agent is handed for one assessment. It is
// pure text: the rules, the steps, the result-file contract and the report
// headings come from the kind's row; the project name is cleaned; nothing is
// taken from a client or a repository beyond that.
func BuildPrompt(in PromptInput) (string, error) {
	k, ok := KindByID(string(in.Kind))
	if !ok || !k.Launchable {
		return "", errors.New("secassess.BuildPrompt: not a launchable kind")
	}
	p := ResultPaths(in.RunID)
	if p.Dir == "" {
		return "", errors.New("secassess.BuildPrompt: bad run id")
	}
	if k.Target == TargetRequired && in.Target == nil {
		return "", errors.New("secassess.BuildPrompt: this kind needs a target")
	}
	if k.Retest && (in.Replay == nil || len(in.Replay.Findings) == 0) {
		return "", errors.New("secassess.BuildPrompt: a retest needs findings to replay")
	}
	var b strings.Builder
	writePromptHead(&b, k, in)
	fill := strings.NewReplacer("<run id>", in.RunID, "<run dir>", p.Dir)
	writeBoundaries(&b, k, in, fill)
	writeStepsSection(&b, k, in, fill)
	writeResultFiles(&b, k, p)
	if k.ModelContract() {
		if err := writeModelContract(&b, in, k); err != nil {
			return "", err
		}
	}
	b.WriteString("\nFinish with a short terminal summary: what you did, how many findings, what you could not do.\n")
	out := b.String()
	if len(out) > MaxPromptBytes {
		return "", errors.New("secassess.BuildPrompt: prompt over its cap")
	}
	return out, nil
}

// writePromptHead renders the opening of the task: the title line, the prompt
// version, the role, then the target, the scope and the grounding digest for
// the kinds that carry them.
func writePromptHead(b *strings.Builder, k Kind, in PromptInput) {
	name := clean(in.ProjectName, 80)
	if name == "" {
		name = "this project"
	}
	fmt.Fprintf(b, "SECURITY ASSESSMENT: %s of %q, started by the developer from Observer (run %s).\n", k.Title, name, in.RunID)
	if k.PromptVersion != "" {
		fmt.Fprintf(b, "Prompt version: %s.\n", k.PromptVersion)
	}
	b.WriteString("\n")
	b.WriteString(k.Role + "\n\n")

	if k.Target == TargetRequired {
		b.WriteString("TARGET (confirmed by the developer):\n")
		fmt.Fprintf(b, "  %s\n", in.Target.String())
		b.WriteString("This address is on the sandbox's own loopback; start the project's development server so that it listens there.\n\n")
	}
	if obj := CleanObjective(in.Objective); k.Exercise && obj != "" {
		fmt.Fprintf(b, "OBJECTIVE (developer's words): %q\n\n", obj)
	}
	if k.Scopable {
		writeScope(b, in.ScopePaths, in.ScopeNote)
	}
	if k.Grounded && in.Grounding != "" {
		b.WriteString(in.Grounding)
		if !strings.HasSuffix(in.Grounding, "\n") {
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
}

// writeBoundaries renders the rules that hold for the whole run: the numbered
// boundaries, the time box, the request limits and the relaxed rules when they
// apply, and the setup and tool inventory for a kind that probes a target.
func writeBoundaries(b *strings.Builder, k Kind, in PromptInput, fill *strings.Replacer) {
	b.WriteString("BOUNDARIES (these hold for the whole run):\n")
	n := 0
	for _, line := range append(append([]string(nil), commonBoundary...), k.Boundary...) {
		n++
		fmt.Fprintf(b, "%d. %s\n", n, fill.Replace(line))
	}
	writeTimeBox(b, k, in.TimeBoxMinutes)
	if k.Probing {
		b.WriteString("\nREQUEST LIMITS:\n")
		for _, l := range PentestLimitLines(PTLimitInput{PaceRPS: in.PaceRPS, RequestBudget: in.RequestBudget}) {
			fmt.Fprintf(b, "- %s\n", l)
		}
	}
	if lines := RelaxPromptLines(in.Kind, in.Relax); len(lines) > 0 {
		b.WriteString("\nRELAXED FOR THIS RUN (the developer agreed to each; they end with the run):\n")
		for i, line := range lines {
			fmt.Fprintf(b, "%d. %s\n", i+1, line)
		}
	}
	if k.Probing {
		writeSetup(b, in, fill)
		writeHelper(b, k, in, fill)
		if !k.Retest {
			writeTools(b, in.Tools)
		}
	}
}

// writeStepsSection renders the numbered steps (the threat-model method lines
// when the kind has a method), the risk rating for such a kind, and the
// probing method for a kind that probes.
func writeStepsSection(b *strings.Builder, k Kind, in PromptInput, fill *strings.Replacer) {
	b.WriteString("\nSTEPS:\n")
	steps := k.Steps
	if len(k.Method) > 0 {
		steps = TMMethodLines(TMMethodInput{
			Frameworks: in.Frameworks, MethodExtras: in.MethodExtras, AIApp: in.AIApp, Scoped: k.Scopable && len(in.ScopePaths) > 0,
		})
	}
	for i, s := range steps {
		fmt.Fprintf(b, "%d. %s\n", i+1, fill.Replace(s))
	}
	if len(k.Method) > 0 {
		b.WriteString("\nRISK RATING:\n" + BandMethodText + "\n")
	}
	if k.Probing && !k.Retest {
		writeProbingMethod(b, in)
	}
	if k.Retest {
		b.WriteString("\n" + RenderReplay(*in.Replay))
	}
}

// writeResultFiles renders the result-file contract: the directory, the report
// headings in order, and the line for each other file the kind asks for.
func writeResultFiles(b *strings.Builder, k Kind, p Paths) {
	b.WriteString("\nRESULT FILES (create the directory first; write nothing else outside it):\n")
	fmt.Fprintf(b, "  Directory: %s/ (relative to the project root)\n", p.Dir)
	fmt.Fprintf(b, "  %s: the human report, in Markdown, with these headings in this order:\n", FileReport)
	for _, h := range k.Headings {
		fmt.Fprintf(b, "    - %s\n", h)
	}
	if k.HasFile(FileAssessment) {
		fmt.Fprintf(b, "  %s: the structured result, in JSON, described under RESULT MODEL below.\n", FileAssessment)
	}
	if k.HasFile(FileSARIF) {
		fmt.Fprintf(b, "  %s: SARIF 2.1.0 (version \"2.1.0\") holding the concrete weaknesses only, one result each, with:\n", FileSARIF)
		b.WriteString("    - ruleId: a short identifier you choose, letters, digits, dot, dash or underscore, at most 64 characters (for example weak-session-cookie);\n")
		b.WriteString("    - level: one of error (high impact), warning (medium) or note (low);\n")
		b.WriteString("    - message.text: one short sentence;\n")
		b.WriteString("    - locations[0].physicalLocation: artifactLocation.uri as a path relative to the project root with forward slashes (no leading slash, no ..), and region.startLine.\n")
		b.WriteString("    A weakness that has no single file belongs in the report only. Observer imports this file when the developer asks, as flag-only findings; it never reads your message text, so put the detail in the report.\n")
	}
	if k.HasFile(FileCommands) {
		fmt.Fprintf(b, "  %s: every cloud command you ran, one per line, exactly as you ran it. Observer classifies each line as read-only or not and shows the developer the counts.\n", FileCommands)
	}
}

// writeModelContract renders the result model block and, when asked, the
// self-check line. It fails only when the schema block cannot be built.
func writeModelContract(b *strings.Builder, in PromptInput, k Kind) error {
	block, err := SchemaBlock(SchemaInput{
		Contract: k.Contract, RunID: in.RunID, PromptVersion: k.PromptVersion,
		TargetURL: targetURL(in.Target), Frameworks: in.Frameworks, MethodExtras: in.MethodExtras, Categories: in.Categories,
		Helper: in.Helper, Exercise: k.Exercise,
	})
	if err != nil {
		return err
	}
	b.WriteString("\n" + block)
	if in.SelfCheck {
		bin, _ := SelfCheckBinary(in.Binary)
		fmt.Fprintf(b, "\nSELF-CHECK: before you finish, run `%s` and fix what it names. If it is not found or refused, say so in the report and carry on; do not look for another way.\n", SelfCheckCommand(bin, in.RunID))
	}
	return nil
}

// writeScope renders the developer's scope for a threat model: the SCOPE block
// when they chose places (with the note inside it), and a note of their own on
// a line of its own when they chose none, so the words the run record and the
// dialog show as theirs are in the task. Both are the developer's own words,
// cleaned and %q-quoted; neither is repository text.
func writeScope(b *strings.Builder, paths []string, rawNote string) {
	note := CleanScopeNote(rawNote)
	if len(paths) > 0 {
		b.WriteString("SCOPE (set by the developer for this run; the paths are the folders or files to model):\n")
		for _, p := range paths {
			fmt.Fprintf(b, "  - %s\n", clean(p, 120))
		}
		if note != "" {
			fmt.Fprintf(b, "  The developer's note, in their own words: %q\n", note)
		}
		b.WriteString("\n")
		return
	}
	if note != "" {
		fmt.Fprintf(b, "DEVELOPER NOTE (no folder was chosen, so the whole project is in scope; the note is the developer's own words): %q\n\n", note)
	}
}

// writeSetup renders how to get the target running: the declared start
// command, accounts, the health check and teardown, and the rules about
// environment files (the lines come from PentestSetupLines).
func writeSetup(b *strings.Builder, in PromptInput, fill *strings.Replacer) {
	lines := PentestSetupLines(PTSetupInput{Start: in.StartCommand, Cwd: in.StartCwd, Source: in.StartSource, Prepare: in.Prepare, EnvFiles: in.EnvFiles, SecretMode: in.SecretMode})
	if len(lines) == 0 {
		return
	}
	b.WriteString("\nSETUP (getting the target running, and what to leave alone):\n")
	for _, l := range lines {
		// An item that spans lines (the start command in its data fence) is
		// indented under its bullet.
		fmt.Fprintf(b, "- %s\n", strings.ReplaceAll(fill.Replace(l), "\n", "\n  "))
	}
}

// writeHelper renders the request helper's section when the run has one.
func writeHelper(b *strings.Builder, k Kind, in PromptInput, fill *strings.Replacer) {
	if !in.Helper {
		return
	}
	b.WriteString("\nREQUEST HELPER (Observer wrote it into your run directory):\n")
	lines := PentestHelperLines(ResultPaths(in.RunID).Dir)
	if k.Retest {
		lines = RetestHelperLines(ResultPaths(in.RunID).Dir)
	}
	for _, l := range lines {
		fmt.Fprintf(b, "- %s\n", fill.Replace(l))
	}
}

// writeTools renders the tool inventory.
func writeTools(b *strings.Builder, tools ToolFacts) {
	lines := ToolInventoryLines(tools)
	if len(lines) == 0 {
		return
	}
	b.WriteString("\nTOOLS IN THE SANDBOX:\n")
	for _, l := range lines {
		fmt.Fprintf(b, "- %s\n", l)
	}
}

// writeProbingMethod renders the penetration-test method: the phase order and
// the test categories in force with their pointers.
func writeProbingMethod(b *strings.Builder, in PromptInput) {
	facts := in.Facts
	if facts == nil {
		facts = GroundingFacts
	}
	m := PentestMethod(PTMethodInput{Categories: in.Categories, Facts: facts, SpecSummary: in.SpecSummary})
	if len(m.Phases) > 0 {
		b.WriteString("\nMETHOD (in this order):\n")
		for i, l := range m.Phases {
			fmt.Fprintf(b, "%d. %s\n", i+1, l)
		}
	}
	if len(m.Lines) > 0 {
		b.WriteString("\nTEST CATEGORIES (one coverage entry each in the result model):\n")
		for _, l := range m.Lines {
			b.WriteString(l + "\n")
		}
	}
}

// writeTimeBox renders the time box and the stop conditions of a kind.
func writeTimeBox(b *strings.Builder, k Kind, minutes int) {
	if minutes <= 0 {
		minutes = k.TimeBoxMinutes
	}
	if minutes <= 0 && len(k.StopWhen) == 0 {
		return
	}
	b.WriteString("\nTIME BOX AND STOP CONDITIONS:\n")
	if minutes > 0 {
		fmt.Fprintf(b, "- Time box: %d minutes from the start of this run. Run `date` now and at the start of each phase. When the time is up, stop, write the result files with what you have, and say in the report what you did not get to.\n", minutes)
	}
	if len(k.StopWhen) > 0 {
		b.WriteString("- Stop what you are doing and say so in the report, instead of carrying on, when:\n")
		for _, s := range k.StopWhen {
			fmt.Fprintf(b, "  - %s;\n", s)
		}
	}
}

// targetURL is the target's address for the schema example, "" when the kind
// has none.
func targetURL(t *Target) string {
	if t == nil {
		return ""
	}
	return t.String()
}
