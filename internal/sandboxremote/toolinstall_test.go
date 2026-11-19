package sandboxremote

import (
	"reflect"
	"regexp"
	"strings"
	"testing"

	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
)

// The install ways of a tool like OpenCode: npm first, then the vendor's
// script (the registry's grounded Linux rows, 2026-11-18).
var (
	optNPM    = InstallOption{Channel: "npm", Argv: []string{"npm", "install", "-g", "opencode-ai@latest"}}
	optScript = InstallOption{Channel: "script", Argv: []string{"bash", "-lc", "curl -fsSL https://opencode.ai/install | bash"}, Requires: []string{"curl", "tar"}}
	optBrew   = InstallOption{Channel: "brew", Argv: []string{"brew", "install", "x"}}
	optUV     = InstallOption{Channel: "uv", Argv: []string{"uv", "tool", "install", "x"}}
)

// TestBoxInstallChannels walks the channel table, one case per row.
func TestBoxInstallChannels(t *testing.T) {
	for _, c := range boxInstallChannels {
		if got := channelRunsInBox(c.channel); got != c.inBox {
			t.Errorf("%s: runs in box %v, want %v", c.channel, got, c.inBox)
		}
		if c.why == "" {
			t.Errorf("%s: no reason", c.channel)
		}
	}
	if channelRunsInBox("choco") {
		t.Error("an unlisted channel runs in a box")
	}
}

func TestBoxInstallChoices(t *testing.T) {
	got := BoxInstallChoices([]InstallOption{optBrew, optNPM, optUV, optScript, {Channel: "npm"}, {Channel: "script", Argv: []string{"sh"}, Requires: []string{"curl; rm -rf /"}}})
	want := []InstallChoice{
		{Channel: "npm", Argv: optNPM.Argv, Needs: []string{"npm"}},
		{Channel: "script", Argv: optScript.Argv, Needs: []string{"bash", "curl", "tar"}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("choices = %+v, want %+v", got, want)
	}
	alt := BoxInstallChoices([]InstallOption{{Channel: "script", Argv: []string{"bash", "-lc", "x"}, Requires: []string{"curl", "bash", "shasum|sha256sum"}}})
	if !reflect.DeepEqual(alt[0].Needs, []string{"bash", "curl", "shasum|sha256sum"}) {
		t.Errorf("needs = %v (argv[0] first, deduplicated, alternatives kept)", alt[0].Needs)
	}
}

func TestInstallProbe(t *testing.T) {
	choices := BoxInstallChoices([]InstallOption{optNPM, optScript, {Channel: "script", Argv: []string{"bash"}, Requires: []string{"shasum|sha256sum"}}})
	progs := InstallProbePrograms(choices)
	if want := []string{"npm", "bash", "curl", "tar", "shasum", "sha256sum"}; !reflect.DeepEqual(progs, want) {
		t.Fatalf("programs = %v, want %v", progs, want)
	}
	have := ParseInstallProbe("bash\ncurl\n tar \nevil\n", progs)
	if !reflect.DeepEqual(have, map[string]bool{"bash": true, "curl": true, "tar": true}) {
		t.Errorf("have = %v (a name that was not asked for is ignored)", have)
	}
	if !strings.Contains(InstallProbeScript, `"$@"`) || strings.Contains(InstallProbeScript, "eval") {
		t.Error("the probe script must take the programs as arguments, never as text")
	}
}

// TestPickInstall: one case per outcome.
func TestPickInstall(t *testing.T) {
	choices := BoxInstallChoices([]InstallOption{optNPM, optScript})
	cases := []struct {
		name    string
		present []string
		channel string
		lacks   [][]string
	}{
		{"npm present: the registry's first way", []string{"npm", "bash", "curl", "tar"}, "npm", nil},
		{"no npm (Daytona's default image): the vendor script", []string{"bash", "curl", "tar"}, "script", nil},
		{"neither", []string{"bash"}, "", [][]string{{"npm"}, {"curl", "tar"}}},
	}
	for _, c := range cases {
		p := map[string]bool{}
		for _, x := range c.present {
			p[x] = true
		}
		got, lacks, ok := PickInstall(choices, p)
		if ok != (c.channel != "") || got.Channel != c.channel || !reflect.DeepEqual(lacks, c.lacks) {
			t.Errorf("%s: got %q %v %v", c.name, got.Channel, lacks, ok)
		}
	}
	alt := BoxInstallChoices([]InstallOption{{Channel: "script", Argv: []string{"bash"}, Requires: []string{"shasum|sha256sum"}}})
	if _, _, ok := PickInstall(alt, map[string]bool{"bash": true, "sha256sum": true}); !ok {
		t.Error("an alternative need is met by either program")
	}
}

// TestPlanToolInstallRules: one case per row of toolInstallRules.
func TestPlanToolInstallRules(t *testing.T) {
	daytona, _ := VendorFor(VendorDaytona)
	e2b, _ := VendorFor(VendorE2B)
	vercel, _ := VendorFor(VendorVercel)
	cases := []struct {
		row      string
		in       ToolInstallInput
		code     string
		channels []string
		says     []string
	}{
		{"a template holds the tool", ToolInstallInput{ToolName: "Codex", Vendor: daytona, Template: "my-snapshot", Tier: vocab.TierNone, Options: []InstallOption{optNPM}}, "", nil, nil},
		{"no install way runs in a box", ToolInstallInput{ToolName: "Zed", Vendor: e2b, Tier: vocab.TierInternet, Options: []InstallOption{optBrew}}, InstallNoWay, nil, []string{"knows no way to install Zed", "Name a template"}},
		{"the tier cannot reach the tool's vendor", ToolInstallInput{ToolName: "Codex", Vendor: vercel, Tier: vocab.TierProxyOnly, Options: []InstallOption{optNPM}}, InstallTierBlocks, nil, []string{"model proxy as its only network", "Codex", "internet"}},
		{"the default image lacks every installer", ToolInstallInput{ToolName: "Codex", Vendor: daytona, Tier: vocab.TierInternet, Options: []InstallOption{optNPM}}, InstallImageLacks, nil, []string{"Daytona's default image has no npm", "Codex", "Name a template"}},
		{"install at first start (Daytona drops the npm way)", ToolInstallInput{ToolName: "OpenCode", Vendor: daytona, Tier: vocab.TierInternet, Options: []InstallOption{optNPM, optScript}}, "", []string{"script"}, nil},
		{"install at first start (E2B keeps both, in order)", ToolInstallInput{ToolName: "OpenCode", Vendor: e2b, Tier: "", Options: []InstallOption{optNPM, optScript}}, "", []string{"npm", "script"}, nil},
	}
	// The empty tier is not internet: the launch resolves it first (the
	// hosted tier default); the plan takes the resolved tier.
	cases[5].in.Tier = vocab.TierInternet
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.row] = true
		p := PlanToolInstall(c.in)
		if p.Code != c.code || p.OK != (c.code == "") {
			t.Errorf("%s: code %q ok %v, want %q", c.row, p.Code, p.OK, c.code)
			continue
		}
		var ch []string
		for _, x := range p.Choices {
			ch = append(ch, x.Channel)
		}
		if !reflect.DeepEqual(ch, c.channels) {
			t.Errorf("%s: channels %v, want %v", c.row, ch, c.channels)
		}
		for _, w := range c.says {
			if !strings.Contains(p.Message, w) {
				t.Errorf("%s: message %q lacks %q", c.row, p.Message, w)
			}
		}
		if c.code != "" && p.Technical == "" {
			t.Errorf("%s: no technical detail", c.row)
		}
	}
	for _, r := range toolInstallRules {
		found := false
		for k := range seen {
			if strings.HasPrefix(k, r.name) {
				found = true
			}
		}
		if !found {
			t.Errorf("rule %q has no case", r.name)
		}
	}
}

// internalWordRE finds a config key, a snake_case code or a CLI command.
var internalWordRE = regexp.MustCompile(`\[terminal\.|[a-z]+_[a-z_]+|observer sandbox`)

// TestToolInstallMessagesArePlain: the sentences a person reads carry no
// internal name; those stay in the technical detail.
func TestToolInstallMessagesArePlain(t *testing.T) {
	daytona, _ := VendorFor(VendorDaytona)
	vercel, _ := VendorFor(VendorVercel)
	var msgs []string
	for _, in := range []ToolInstallInput{
		{ToolName: "Zed", Vendor: daytona, Tier: vocab.TierInternet, Options: []InstallOption{optBrew}},
		{ToolName: "Codex", Vendor: vercel, Tier: vocab.TierNone, Options: []InstallOption{optNPM}},
		{ToolName: "Codex", Vendor: daytona, Tier: vocab.TierInternet, Options: []InstallOption{optNPM}},
	} {
		msgs = append(msgs, PlanToolInstall(in).Message)
	}
	choices := BoxInstallChoices([]InstallOption{optNPM, optScript})
	_, lacks, _ := PickInstall(choices, map[string]bool{"bash": true})
	msg, tech := BoxLacksRefusal("OpenCode", daytona, choices, lacks)
	msgs = append(msgs, msg)
	for _, m := range msgs {
		if m == "" || internalWordRE.MatchString(m) || strings.ContainsAny(m, "–—") {
			t.Errorf("not plain: %q", m)
		}
	}
	if !strings.Contains(msg, "no npm for the npm install, and no curl or tar for the vendor's install script") {
		t.Errorf("box refusal: %q", msg)
	}
	if !strings.HasPrefix(tech, InstallBoxLacks+": npm needs npm; script needs curl, tar") {
		t.Errorf("box refusal technical: %q", tech)
	}
}

// TestDefaultImageLacksGrounded: every image fact names its program and a
// dated source.
func TestDefaultImageLacksGrounded(t *testing.T) {
	dated := regexp.MustCompile(`20[0-9]{2}-[0-9]{2}-[0-9]{2}`)
	for _, id := range VendorIDs() {
		v, _ := VendorFor(id)
		for _, f := range v.DefaultImageLacks {
			if !installProgramRE.MatchString(f.Program) || !dated.MatchString(f.Source) {
				t.Errorf("%s: ungrounded image fact %+v", id, f)
			}
		}
	}
	d, _ := VendorFor(VendorDaytona)
	if !reflect.DeepEqual(d.ImageLacks(), []string{"npm"}) {
		t.Errorf("Daytona's default image facts = %v", d.ImageLacks())
	}
}
