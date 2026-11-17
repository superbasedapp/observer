package secassess

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// webSource reads a file of the web tree, or skips the test where the tree
// has none (a public checkout without the web sources).
func webSource(t *testing.T, rel ...string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(append([]string{"..", "..", "web"}, rel...)...))
	if err != nil {
		t.Skipf("the web sources are not in this tree: %v", err)
	}
	return string(data)
}

// TestSettingLabelsMatchTheWeb pins the labels this package prints in its
// sentences to the Settings rows the web draws (UX-8): a sentence that names a
// switch by its label is only plain while the row still carries that label.
func TestSettingLabelsMatchTheWeb(t *testing.T) {
	src := webSource(t, "src", "lib", "codeSecuritySettings.ts")
	rowLabel := func(key string) string {
		m := regexp.MustCompile(`key: "security\.assessments\.` + key + `",\s*component: "security",\s*field: "[A-Za-z.]+",\s*label: "([^"]+)"`).FindStringSubmatch(src)
		if m == nil {
			t.Fatalf("the web has no Settings row for %s", key)
		}
		return m[1]
	}
	for _, c := range []struct{ key, label string }{
		{"relax_pentest_local", LabelRelaxPentest},
		{"relax_red_team_local", LabelRelaxRedTeam},
		{"scoped_approval", LabelScopedApproval},
		{"max_network_tier", LabelMaxNetwork},
		{"workspace_secret_mode", LabelEnvFiles},
		{"model_max_mib", LabelModelMaxMiB},
		{"probe_helper", LabelProbeHelper},
	} {
		if got := rowLabel(c.key); got != c.label {
			t.Errorf("%s: the web label is %q, this package says %q", c.key, got, c.label)
		}
	}
	// The value of the maximum-network setting that allows nothing wider.
	if !regexp.MustCompile(`optionLabels: \{ proxy_only: "` + regexp.QuoteMeta(LabelMaxNetworkProxyOnly) + `"`).MatchString(src) {
		t.Errorf("the web has no option labelled %q for the widest-network setting", LabelMaxNetworkProxyOnly)
	}
	// The relaxation switch of each kind is the label the kind's setting carries.
	for _, k := range RelaxKinds() {
		if RelaxSettingLabel(k) == "" {
			t.Errorf("kind %s has relaxation rows and no switch label", k)
		}
	}
	card := webSource(t, "src", "components", "SandboxSettingsCard.tsx")
	for _, label := range []string{LabelHostList} {
		if !strings.Contains(card, `label="`+label+`"`) {
			t.Errorf("the sandbox card has no field labelled %q", label)
		}
	}
	if !regexp.MustCompile(`id="sandbox-network-label"[^>]*>` + LabelSandboxNetwork + `<`).MatchString(card) {
		t.Errorf("the sandbox card has no field labelled %q", LabelSandboxNetwork)
	}
}

// TestRelaxSettingLabelAndTierName: the two lookups, one row each.
func TestRelaxSettingLabelAndTierName(t *testing.T) {
	for _, c := range []struct {
		kind ID
		want string
	}{
		{PentestLocal, LabelRelaxPentest},
		{RedTeamLocal, LabelRelaxRedTeam},
		{ThreatModel, ""},
		{RASP, ""},
	} {
		if got := RelaxSettingLabel(c.kind); got != c.want {
			t.Errorf("RelaxSettingLabel(%s) = %q, want %q", c.kind, got, c.want)
		}
	}
	for _, c := range []struct{ in, want string }{
		{"proxy_only", "proxy only"},
		{"none", "none"},
		{"host", "host"},
		{"internet", "internet"},
		{"", "internet"},
		{"something else", "internet"},
	} {
		if got := TierName(c.in); got != c.want {
			t.Errorf("TierName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// machineWords are the shapes of a name only a developer of Observer reads: a
// config key, a TOML section, a tier or other enum value written as code, a
// guard rule id, a rule row id, a flag, a function name.
var machineWords = []struct {
	name string
	re   *regexp.Regexp
}{
	{"a config key", regexp.MustCompile(`security\.assessments|terminal\.sandbox|egress_allow|workspace_secret_mode|model_max_mib|probe_helper`)},
	{"a TOML section", regexp.MustCompile(`\[(?:terminal|proxy|security|guard|observer)[.\]]`)},
	{"a snake_case value", regexp.MustCompile(`\b[a-z]+(?:_[a-z]+)+\b`)},
	{"a guard rule id", regexp.MustCompile(`\bR-\d{3}\b`)},
	{"an eligibility row id", regexp.MustCompile(`\bE\d{1,2}b?\b(?: to E\d)?`)},
	{"a flag", regexp.MustCompile(`(?:^|[\s(])--[a-z][a-z-]*`)},
	{"a function name", regexp.MustCompile(`\bParseTarget\b`)},
}

// sentenceBook collects a package's user-facing sentences, each with where it
// came from, deduplicated by text.
type sentenceBook struct {
	seen map[string]string
}

func (b *sentenceBook) add(where, s string) {
	if s == "" || s == "-" {
		return
	}
	if b.seen == nil {
		b.seen = map[string]string{}
	}
	if _, ok := b.seen[s]; !ok {
		b.seen[s] = where
	}
}

// userSentences gathers what the pure core says to a person: the relaxation
// rows, every consent reason, every eligibility refusal, the preflight notes,
// the safety table, the environment-file words and the refusals that go with
// them. The prompt builders are not here: a prompt is read by the agent and keeps
// its own words.
func userSentences(t *testing.T) *sentenceBook {
	t.Helper()
	b := &sentenceBook{}
	for _, r := range Relaxations() {
		w := "relaxation " + string(r.Kind) + " " + r.Key
		b.add(w+" title", r.Title)
		b.add(w+" lifts", r.Lifts)
		b.add(w+" why", r.Why)
	}
	// The kinds' own words on the card and the plan.
	for _, k := range Kinds() {
		w := "kind " + string(k.ID)
		b.add(w+" title", k.Title)
		b.add(w+" summary", k.Summary)
		b.add(w+" mode", k.Mode)
		b.add(w+" note", k.Note)
		b.add(w+" reason", k.Reason)
		b.add(w+" pointer", k.Pointer)
	}
	// The consent table: each reason, over every kind and live tier.
	for _, row := range consentRows {
		if row.reason == nil {
			continue
		}
		for _, kind := range []ID{PentestLocal, RedTeamLocal} {
			for _, tier := range []string{"", "none", "host", "internet", "proxy_only"} {
				b.add("consent "+row.ID+" "+row.Name, row.reason(ConsentInput{Row: Relaxation{Kind: kind}, Tier: TierFacts{Live: tier}}))
			}
		}
	}
	for _, kind := range []ID{PentestLocal, RedTeamLocal, ThreatModel} {
		b.add("consent default", kindSwitchOffWords(kind))
	}
	// The eligibility table: the reasons over the combinations of facts that trip a row.
	for _, kind := range []ID{ThreatModel, PentestLocal, RedTeamLocal, RASP} {
		for mask := 0; mask < 1<<6; mask++ {
			for _, tier := range []string{"", "none", "host", "internet", "proxy_only"} {
				for _, target := range []string{"", "http://example.com:80/", "http://localhost:3000/", "http://127.0.0.1:8820/"} {
					for _, backend := range []string{"", "oci-runc", "bwrap"} {
						f, r := goodFacts(), goodRequest(kind)
						f.Tier, r.Target, r.Backend = tier, target, backend
						f.ProjectOnDisk, f.SandboxProbed = mask&1 == 0, mask&2 == 0
						f.ToolSandboxable, f.ToolProxyRouted = mask&4 == 0, mask&8 == 0
						f.SourceLiveAvailable, r.Sandbox = mask&16 == 0, mask&32 == 0
						if mask&1 != 0 {
							f.Backends = f.Backends[:1]
						}
						if mask&2 != 0 {
							r.WorkspaceSource = "clone-local"
						}
						if mask&4 != 0 {
							r.ConfirmTarget = "http://localhost:1/"
						}
						if mask&8 != 0 {
							f.ToolSandboxReason = ""
						}
						b.add("eligibility "+string(kind), Eligible(kind, f, r).Reason)
					}
				}
			}
		}
	}
	// Preflight: the notes that read the tier.
	for _, facts := range []ProjectFacts{
		pfNodeFacts(nil, nil),
		AnalyzeProject(SurveyInput{Files: []ProjectFile{pjFile("compose.yml", "services:\n  db:\n    image: postgres\n")}}),
	} {
		for _, tier := range []string{"", "proxy_only", "internet"} {
			for _, n := range Preflight(facts, PreflightInput{Tier: tier}) {
				b.add("preflight "+n.ID, n.Text)
			}
		}
	}
	// The safety table, with and without the helper and the mask.
	for _, helper := range []bool{true, false} {
		for _, mask := range []bool{true, false} {
			for _, r := range SafetyRowsWith(SafetyFacts{Helper: helper, Mask: mask}) {
				b.add("safety "+r.ID+" rule", r.Rule)
				b.add("safety "+r.ID+" helper", r.Helper)
				b.add("safety "+r.ID+" observer", r.Observer)
			}
		}
	}
	// The environment-file words and the two refusals.
	b.add("env refusal", ReasonSecretFilesOpen)
	b.add("env refusal", ReasonFindingsUnreadable)
	b.add("env tier words", tierWords)
	for _, configured := range []string{SecretOff, SecretWarn, SecretMask, SecretRefuse} {
		for _, mask := range []MaskCapability{MaskNoBackend, MaskCannot, MaskNoReport, MaskCan} {
			for _, files := range []int{0, 1, 3} {
				for _, scan := range []string{"", ScanDone, ScanNever} {
					for _, open := range []bool{false, true} {
						for _, unreadable := range []bool{false, true} {
							for _, tier := range []string{"", "proxy_only", "internet"} {
								m := EffectiveSecretMode(SecretModeInput{Configured: configured, Mask: mask, EnvFiles: files, Scan: scan, LastScan: "2026-11-16", OpenSecret: open, FindingsUnreadable: unreadable, Tier: tier})
								b.add("env words "+configured, m.Words)
								b.add("env tier words", m.TierWords)
							}
						}
					}
				}
			}
		}
	}
	return b
}

// TestUserSentencesNameNoMachineIdentifiers is the pin of the polish round's
// UX-8: no sentence the pure core builds for a person names a config key, a
// TOML section, an enum value in code form, a rule id or a flag. A screen and a
// switch label say where to go, and the machine names stay in the structured
// fields beside the sentence (a relaxation's Key, a refusal's Code and Row).
func TestUserSentencesNameNoMachineIdentifiers(t *testing.T) {
	book := userSentences(t)
	if len(book.seen) < 40 {
		t.Fatalf("only %d sentences were gathered: the walk does not reach the tables", len(book.seen))
	}
	keys := make([]string, 0, len(book.seen))
	for s := range book.seen {
		keys = append(keys, s)
	}
	slices.Sort(keys)
	for _, s := range keys {
		// node_modules is a folder a person sees in their project, not a name of ours.
		checked := strings.ReplaceAll(s, "node_modules", "the packages folder")
		for _, w := range machineWords {
			if loc := w.re.FindString(checked); loc != "" {
				t.Errorf("%s: names %s (%q): %q", book.seen[s], w.name, loc, s)
			}
		}
	}
}

// TestSentencesNameTheScreenAndTheSwitch: the sentences that send a reader to a
// setting say which screen and which label, row by row of the consent table and
// the eligibility refusals that do so.
func TestSentencesNameTheScreenAndTheSwitch(t *testing.T) {
	has := func(t *testing.T, got string, want ...string) {
		t.Helper()
		for _, w := range want {
			if !strings.Contains(got, w) {
				t.Errorf("%q lacks %q", got, w)
			}
		}
	}
	for _, c := range []struct {
		name string
		got  func() string
		want []string
	}{
		{"the pen test switch is off", func() string { return kindSwitchOffWords(PentestLocal) }, []string{`"` + LabelRelaxPentest + `"`, WhereSettings}},
		{"the red team switch is off", func() string { return kindSwitchOffWords(RedTeamLocal) }, []string{`"` + LabelRelaxRedTeam + `"`, WhereSettings}},
		{"a kind with no switch", func() string { return kindSwitchOffWords(ThreatModel) }, []string{"nothing to lift"}},
		{"the scoped approval switch is off", func() string {
			return ConsentRoute(ConsentInput{Row: Relaxation{Kind: PentestLocal, Type: RelaxRule}, Policy: Policy{Relax: map[ID]bool{PentestLocal: true}}}).Reason
		}, []string{`"` + LabelScopedApproval + `"`, WhereSettings}},
		{"the widest network is the model proxy", func() string {
			return ConsentRoute(ConsentInput{Row: Relaxation{Kind: PentestLocal, Type: RelaxTier}, Policy: Policy{Relax: map[ID]bool{PentestLocal: true}, MaxTier: "proxy_only"}, Tier: TierFacts{Live: "internet"}}).Reason
		}, []string{`"` + LabelMaxNetwork + `"`, `"` + LabelMaxNetworkProxyOnly + `"`, WhereSettings}},
		{"a host tier", func() string {
			return ConsentRoute(ConsentInput{Row: Relaxation{Kind: PentestLocal, Type: RelaxTier}, Policy: Policy{Relax: map[ID]bool{PentestLocal: true}, MaxTier: "internet"}, Tier: TierFacts{Live: "host"}}).Reason
		}, []string{"set to host", `Set ` + LabelSandboxNetwork + ` to internet with a list of hosts, or to proxy only`, WhereSandbox}},
		{"no host list", func() string {
			return ConsentRoute(ConsentInput{Row: Relaxation{Kind: PentestLocal, Type: RelaxTier}, Policy: Policy{Relax: map[ID]bool{PentestLocal: true}, MaxTier: "internet"}, Tier: TierFacts{Live: "internet"}}).Reason
		}, []string{`"` + LabelHostList + `"`, WhereSandbox}},
		{"the tier relaxation row", func() string { return relaxations[1].Lifts }, []string{`"` + LabelHostList + `"`, WhereSandbox}},
		{"the size cap of the file", func() string {
			r := Validate(make([]byte, MaxModelBytes+1), ValidateOptions{})
			for _, is := range r.Report.Issues {
				if is.Code == "too_large" {
					return is.Message
				}
			}
			return ""
		}, []string{`"` + LabelModelMaxMiB + `"`, WhereSettings}},
		{"an open secret refuses", func() string { return ReasonSecretFilesOpen }, []string{`"` + LabelEnvFiles + `"`, WhereSettings}},
		{"unreadable findings refuse", func() string { return ReasonFindingsUnreadable }, []string{`"` + LabelEnvFiles + `"`, WhereSettings}},
	} {
		t.Run(c.name, func(t *testing.T) { has(t, c.got(), c.want...) })
	}
}
