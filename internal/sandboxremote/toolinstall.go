package sandboxremote

import (
	"regexp"
	"strings"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// toolinstall.go decides how the agent tool reaches a hosted box (sandbox
// plan v2 SBX-IMG-1; lane UX, item H4). No agent CLI is uploaded: a template
// the user names holds it, or, on the internet tier, it installs from its
// vendor at first start through one of the tool's grounded install ways
// (the integration registry's InstallHint rows, which the caller maps onto
// InstallOption, so this package names no tool). Two decisions live here:
//
//   - PlanToolInstall, before Start (the daemon's Create and the dialog's
//     per-row notice): whether any install way can work at all, from the
//     template, the tier and what the vendor's default image is known to
//     lack (Vendor.DefaultImageLacks);
//   - PickInstall, in the host helper right after the box is up and before
//     the workspace is uploaded: the first install way whose programs the
//     box has (InstallProbeScript lists them), so a box with no npm uses the
//     vendor's install script instead of failing after the upload (the
//     Daytona live run of 2026-11-18 exited 127 on npm).

// InstallOption is one grounded install of the agent tool as its registry
// row gives it: the channel (the closed InstallHint vocabulary), the argv
// run verbatim, and the programs the command needs beyond its argv[0].
type InstallOption struct {
	Channel  string
	Argv     []string
	Requires []string
}

// InstallChoice is an install way a box can run. Needs are the programs it
// needs on the box's PATH; an entry may name alternatives separated by "|"
// (either one satisfies it).
type InstallChoice struct {
	Channel string   `json:"channel"`
	Argv    []string `json:"argv"`
	Needs   []string `json:"needs"`
}

// boxInstallChannels is the closed channel table: whether a channel's
// command runs inside a plain Linux box, and why. Walked by channel; a
// channel not listed never runs in a box.
var boxInstallChannels = []struct {
	channel string
	inBox   bool
	why     string
}{
	{"npm", true, "the box's own npm installs the package"},
	{"script", true, "the vendor's install script runs with the box's shell and the programs it names (curl, tar, ...)"},
	{"brew", false, "Homebrew is not part of a box image"},
	{"winget", false, "Windows only"},
	{"scoop", false, "Windows only"},
	{"uv", false, "only the npm and script channels run in a box (SBX-IMG-1)"},
}

// channelRunsInBox reports whether channel's command runs in a box.
func channelRunsInBox(channel string) bool {
	for _, c := range boxInstallChannels {
		if c.channel == channel {
			return c.inBox
		}
	}
	return false
}

// installProgramRE is the shape of one program name a box is probed for.
// Names come from compile-time registry constants; anything else is dropped,
// never passed to the box.
var installProgramRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,63}$`)

// validNeed reports whether every alternative of need is a program name.
func validNeed(need string) bool {
	for _, alt := range strings.Split(need, "|") {
		if !installProgramRE.MatchString(alt) {
			return false
		}
	}
	return need != ""
}

// BoxInstallChoices are the install ways of opts a box can run, in the
// registry's order: a channel the box runs, a non-empty argv, and needs made
// of argv[0] and Requires, each a plain program name (an option with any
// other need is dropped).
func BoxInstallChoices(opts []InstallOption) []InstallChoice {
	var out []InstallChoice
	for _, o := range opts {
		if !channelRunsInBox(o.Channel) || len(o.Argv) == 0 {
			continue
		}
		c := InstallChoice{Channel: o.Channel, Argv: append([]string(nil), o.Argv...)}
		ok := true
		seen := map[string]bool{}
		for _, n := range append([]string{o.Argv[0]}, o.Requires...) {
			if !validNeed(n) {
				ok = false
				break
			}
			if !seen[n] {
				seen[n] = true
				c.Needs = append(c.Needs, n)
			}
		}
		if ok {
			out = append(out, c)
		}
	}
	return out
}

// needMet reports whether need is met by have.
func needMet(need string, have func(string) bool) bool {
	for _, alt := range strings.Split(need, "|") {
		if have(alt) {
			return true
		}
	}
	return false
}

// missing lists c's needs have does not meet.
func (c InstallChoice) missing(have func(string) bool) []string {
	var out []string
	for _, n := range c.Needs {
		if !needMet(n, have) {
			out = append(out, n)
		}
	}
	return out
}

// InstallProbeScript prints, one per line, each of its arguments that is a
// program on the box's PATH. Its arguments are InstallProbePrograms (plain
// program names); it never fails.
const InstallProbeScript = `for t in "$@"; do command -v "$t" >/dev/null 2>&1 && echo "$t"; done; exit 0`

// InstallProbePrograms are the distinct programs the choices name, in
// order: the arguments of InstallProbeScript.
func InstallProbePrograms(choices []InstallChoice) []string {
	var out []string
	seen := map[string]bool{}
	for _, c := range choices {
		for _, n := range c.Needs {
			for _, alt := range strings.Split(n, "|") {
				if !seen[alt] {
					seen[alt] = true
					out = append(out, alt)
				}
			}
		}
	}
	return out
}

// ParseInstallProbe reads InstallProbeScript's output into the set of
// programs the box has (only names that were asked for).
func ParseInstallProbe(out string, asked []string) map[string]bool {
	want := map[string]bool{}
	for _, a := range asked {
		want[a] = true
	}
	have := map[string]bool{}
	for _, l := range strings.Split(out, "\n") {
		if l = strings.TrimSpace(l); want[l] {
			have[l] = true
		}
	}
	return have
}

// PickInstall is the first choice whose every need the box has (present),
// and, when none fits, what each choice lacks (one entry per choice, in
// order).
func PickInstall(choices []InstallChoice, present map[string]bool) (InstallChoice, [][]string, bool) {
	have := func(p string) bool { return present[p] }
	var lacks [][]string
	for _, c := range choices {
		m := c.missing(have)
		if len(m) == 0 {
			return c, nil, true
		}
		lacks = append(lacks, m)
	}
	return InstallChoice{}, lacks, false
}

// The closed tool-install refusal codes (each also carries the shared launch
// verdict tool_unavailable_in_image in its technical detail).
const (
	// InstallNoWay: the tool has no install way a box can run.
	InstallNoWay = "no_box_install"
	// InstallTierBlocks: the tier cannot reach the tool's vendor at first
	// start, and no template holds the tool.
	InstallTierBlocks = "tier_blocks_install"
	// InstallImageLacks: every install way needs a program the vendor's
	// default image is known not to have.
	InstallImageLacks = "image_lacks_installer"
	// InstallBoxLacks: the box (as made) has none of what any install way
	// needs (the host helper's check, PickInstall).
	InstallBoxLacks = "box_lacks_installer"
)

// ToolInstallInput is what PlanToolInstall reads.
type ToolInstallInput struct {
	// ToolName is the tool's product name, for the sentences.
	ToolName string
	Vendor   Vendor
	// Template is the provider table's template ("" when none is set).
	Template string
	Tier     vocab.Tier
	Options  []InstallOption
}

// ToolInstallPlan is PlanToolInstall's answer. OK with no Choices means the
// template holds the tool. Not OK carries the closed Code, the plain sentence
// a person reads before Start, and the technical detail.
type ToolInstallPlan struct {
	OK        bool
	Choices   []InstallChoice
	Code      string
	Message   string
	Technical string
}

// toolInstallFacts are the rule table's inputs.
type toolInstallFacts struct {
	in      ToolInstallInput
	choices []InstallChoice
	// usable are the choices the default image is not known to break.
	usable []InstallChoice
	// lacking are the known-lacking programs the choices need.
	lacking []string
}

// toolInstallRules is the ordered table (CLAUDE.md rule 5): the first row
// that matches decides. A row with no code is a pass.
var toolInstallRules = []struct {
	name  string
	match func(toolInstallFacts) bool
	code  string
	say   func(toolInstallFacts) (string, string)
}{
	{"a template holds the tool", func(f toolInstallFacts) bool { return strings.TrimSpace(f.in.Template) != "" }, "", nil},
	{"no install way runs in a box", func(f toolInstallFacts) bool { return len(f.choices) == 0 }, InstallNoWay, func(f toolInstallFacts) (string, string) {
		return "Observer knows no way to install " + f.in.ToolName + " in a hosted box, and no template is set for " + f.in.Vendor.Name + ". " + nameATemplate(f.in, "pick another sandbox"),
			"no grounded Linux npm or script install for the tool; set [terminal.sandbox.hosted.<provider>].template"
	}},
	{"the tier cannot reach the tool's vendor", func(f toolInstallFacts) bool { return f.in.Tier != vocab.TierInternet }, InstallTierBlocks, func(f toolInstallFacts) (string, string) {
		tech := "the " + string(f.in.Tier) + " tier cannot install the tool at first start; set [terminal.sandbox.hosted.<provider>].template or use the internet tier"
		if f.in.Vendor.TemplateRule != "" {
			tech += "; " + f.in.Vendor.TemplateRule
		}
		return "With " + tierWords(f.in.Tier) + " the box cannot download " + f.in.ToolName + " at first start, and no template is set for " + f.in.Vendor.Name + ". " + nameATemplate(f.in, "switch the network setting to internet"), tech
	}},
	{"the default image lacks every installer", func(f toolInstallFacts) bool { return len(f.usable) == 0 }, InstallImageLacks, func(f toolInstallFacts) (string, string) {
		return f.in.Vendor.Name + "'s default image has no " + wordList(f.lacking, "and") + ", which every way Observer knows to install " + f.in.ToolName + " needs, and no template is set. " + nameATemplate(f.in, "pick another sandbox"),
			"the default image lacks " + strings.Join(f.lacking, ", ") + " (" + lackSources(f.in.Vendor, f.lacking) + "); set [terminal.sandbox.hosted.<provider>].template"
	}},
	{"install at first start", func(toolInstallFacts) bool { return true }, "", nil},
}

// PlanToolInstall decides before Start how the agent tool reaches a box with
// no template (see the file comment).
func PlanToolInstall(in ToolInstallInput) ToolInstallPlan {
	f := toolInstallFacts{in: in, choices: BoxInstallChoices(in.Options)}
	known := map[string]bool{}
	for _, p := range in.Vendor.ImageLacks() {
		known[p] = true
	}
	notKnownLacking := func(p string) bool { return !known[p] }
	seen := map[string]bool{}
	for _, c := range f.choices {
		m := c.missing(notKnownLacking)
		if len(m) == 0 {
			f.usable = append(f.usable, c)
			continue
		}
		for _, n := range m {
			if !seen[n] {
				seen[n] = true
				f.lacking = append(f.lacking, n)
			}
		}
	}
	for _, r := range toolInstallRules {
		if !r.match(f) {
			continue
		}
		if r.code == "" {
			if strings.TrimSpace(in.Template) != "" {
				return ToolInstallPlan{OK: true}
			}
			return ToolInstallPlan{OK: true, Choices: f.usable}
		}
		msg, tech := r.say(f)
		return ToolInstallPlan{Code: r.code, Message: msg, Technical: tech}
	}
	return ToolInstallPlan{OK: true}
}

// BoxLacksRefusal is the host helper's sentence when the box has none of
// what any install way needs (PickInstall's lacks), and its technical
// detail.
func BoxLacksRefusal(toolName string, v Vendor, choices []InstallChoice, lacks [][]string) (string, string) {
	var parts, tech []string
	for i, c := range choices {
		if i >= len(lacks) {
			break
		}
		parts = append(parts, "no "+wordList(lacks[i], "or")+" for "+channelWords(c.Channel))
		tech = append(tech, c.Channel+" needs "+strings.Join(lacks[i], ", "))
	}
	return "None of the ways Observer knows to install " + toolName + " can run in this " + v.Name + " box: it has " + strings.Join(parts, ", and ") + ". " +
			nameATemplate(ToolInstallInput{ToolName: toolName, Vendor: v}, "pick another sandbox"),
		InstallBoxLacks + ": " + strings.Join(tech, "; ")
}

// nameATemplate is the shared remedy sentence.
func nameATemplate(in ToolInstallInput, or string) string {
	return "Name a template that holds " + in.ToolName + " for " + in.Vendor.Name + " in Terminals > Settings > Hosted sandboxes, or " + or + "."
}

// tierWords names a tier in plain words.
func tierWords(t vocab.Tier) string {
	switch t {
	case vocab.TierNone:
		return "no network"
	case vocab.TierProxyOnly:
		return "the model proxy as its only network"
	}
	return "the " + string(t) + " network setting"
}

// channelWords names an install channel in plain words.
func channelWords(channel string) string {
	switch channel {
	case "npm":
		return "the npm install"
	case "script":
		return "the vendor's install script"
	}
	return "the " + channel + " install"
}

// wordList joins programs for a sentence ("npm", "curl and tar"); an
// alternative "a|b" reads "a or b".
func wordList(xs []string, conj string) string {
	ws := make([]string, len(xs))
	for i, x := range xs {
		ws[i] = strings.ReplaceAll(x, "|", " or ")
	}
	switch len(ws) {
	case 0:
		return ""
	case 1:
		return ws[0]
	}
	return strings.Join(ws[:len(ws)-1], ", ") + " " + conj + " " + ws[len(ws)-1]
}

// lackSources names where each known-lacking program was seen.
func lackSources(v Vendor, programs []string) string {
	var out []string
	for _, p := range programs {
		for _, f := range v.DefaultImageLacks {
			if f.Program == p {
				out = append(out, p+": "+f.Source)
			}
		}
	}
	return strings.Join(out, "; ")
}
