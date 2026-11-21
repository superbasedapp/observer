package integration

import (
	"strings"
	"testing"
)

// TestUnlaunchablesCoverEveryAdvertisedRowThePickerOmits (T-494, D-160): every
// advertised registry row is either terminal-launchable, an advertised GUI
// row, or listed by Unlaunchables with a reason. Nothing is silently hidden.
func TestUnlaunchablesCoverEveryAdvertisedRowThePickerOmits(t *testing.T) {
	listed := map[string]Unlaunchable{}
	for _, u := range Unlaunchables() {
		if _, dup := listed[u.Tool]; dup {
			t.Errorf("%s listed twice", u.Tool)
		}
		listed[u.Tool] = u
	}
	for _, c := range registry {
		_, isListed := listed[c.Tool]
		guiAdvertised := c.GUI != nil && (GUILaunchable{Spec: *c.GUI, Adapter: c.Tool, Lifecycle: c.Lifecycle}).Advertised()
		switch {
		case !c.Advertised():
			if isListed {
				t.Errorf("%s: an unadvertised (%s) product must not be listed", c.Tool, c.Lifecycle)
			}
		case TerminalLaunchable(c) || guiAdvertised:
			if isListed {
				t.Errorf("%s: already in the picker, must not also be listed as not launchable", c.Tool)
			}
		default:
			if !isListed {
				t.Errorf("%s: advertised, not launchable and not listed: the picker would hide it", c.Tool)
			}
		}
	}
}

// TestUnlaunchableRulesTable: one case per rule row, by capability shape.
func TestUnlaunchableRulesTable(t *testing.T) {
	gui := &GUILaunchSpec{ID: "x-desktop", Label: "X"}
	cases := []struct {
		name string
		f    unlaunchableFacts
		want UnlaunchableKind
	}{
		{"browser extension capture", unlaunchableFacts{c: Capability{Hook: HookSpec{Mechanism: HookBrowserExtension}}}, UnlaunchableBrowser},
		{"hosted by an editor", unlaunchableFacts{c: Capability{}, host: "Visual Studio Code"}, UnlaunchableHosted},
		{"ungrounded desktop app", unlaunchableFacts{c: Capability{GUI: gui}}, UnlaunchableDesktop},
		{"binary row, no launcher", unlaunchableFacts{c: Capability{Binary: &BinaryResolveSpec{Names: BinaryNames{Unix: []string{"x"}}}}}, UnlaunchableCLINoLauncher},
		// FU-148: a CLI binary with an ungrounded desktop row is still a CLI.
		{"binary row and an ungrounded desktop row", unlaunchableFacts{c: Capability{GUI: gui, Binary: &BinaryResolveSpec{Names: BinaryNames{Unix: []string{"x"}}}}}, UnlaunchableCLINoLauncher},
		{"nothing at all", unlaunchableFacts{c: Capability{}}, UnlaunchableNoCLI},
	}
	for _, tc := range cases {
		var got UnlaunchableKind
		var note string
		for _, r := range unlaunchableRules {
			if r.match(tc.f) {
				got, note = r.kind, r.note(tc.f)
				break
			}
		}
		if got != tc.want {
			t.Errorf("%s: kind = %q, want %q", tc.name, got, tc.want)
		}
		if note == "" || !strings.HasSuffix(note, ".") || strings.ContainsAny(note, "\u2013\u2014") {
			t.Errorf("%s: note %q must be a plain sentence with no em or en dash", tc.name, note)
		}
	}
}

// TestUnlaunchablesToday pins the grounded set the picker shows today, so a
// registry change that moves a row in or out is a visible decision.
func TestUnlaunchablesToday(t *testing.T) {
	want := map[string]UnlaunchableKind{
		"chatgpt-web":    UnlaunchableBrowser,
		"claude-web":     UnlaunchableBrowser,
		"copilot-web":    UnlaunchableBrowser,
		"gemini-web":     UnlaunchableBrowser,
		"perplexity-web": UnlaunchableBrowser,
		"cline":          UnlaunchableHosted,
		"copilot":        UnlaunchableHosted,
		"kilo-code":      UnlaunchableHosted,
		"deepseek":       UnlaunchableNoCLI,
		// The 2026-10-21 capture-only wave: grounded CLI binaries, no
		// `observer <verb>` launcher yet.
		"autohand":        UnlaunchableCLINoLauncher,
		"codebuddy":       UnlaunchableCLINoLauncher,
		"cortex-code":     UnlaunchableCLINoLauncher,
		"deepagents-code": UnlaunchableCLINoLauncher,
		"dimcode":         UnlaunchableCLINoLauncher,
		"dirac":           UnlaunchableCLINoLauncher,
		"ibm-bob":         UnlaunchableCLINoLauncher,
		"kimchi":          UnlaunchableCLINoLauncher,
		"stakpak":         UnlaunchableCLINoLauncher,
		"vtcode":          UnlaunchableCLINoLauncher,
		// custom-agent (P-228): the developer's own program, no vendor CLI.
		"custom-agent": UnlaunchableNoCLI,
	}
	got := map[string]UnlaunchableKind{}
	for _, u := range Unlaunchables() {
		got[u.Tool] = u.Kind
		if u.Kind == UnlaunchableHosted && u.Host == "" {
			t.Errorf("%s: hosted row without a host label", u.Tool)
		}
	}
	for tool, k := range want {
		if got[tool] != k {
			t.Errorf("%s: kind = %q, want %q", tool, got[tool], k)
		}
	}
	for tool := range got {
		if _, ok := want[tool]; !ok {
			t.Errorf("%s: newly listed as not launchable (%s); add it here if intended", tool, got[tool])
		}
	}
}
