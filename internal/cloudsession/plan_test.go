package cloudsession

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/golden")

// testKey is a fixed non-zero 32-byte key (base64) for golden output.
const testKey = "npbhJUUL/Zy088BDnuqYRDqjjQtlyF9/eVcWFOCzj2g="

// testPins are fixed npm integrity pins (sha512 of "golden-x64" and
// "golden-arm64") for golden output.
var testPins = []NpmPin{
	{Arch: "x64", Integrity: "sha512-LIIunlMeQQrBAdEFZnDbFyLWHT4fcP8huXGMHwo/VnPBkvd0hgKj2ejuG9gWnIJ4WjQwpCuR/I1P6+5A/1dFMw=="},
	{Arch: "arm64", Integrity: "sha512-9AHuuQkK7EnVnrWzxYhOyvb6J+LPeZVt8ADKhQtsrETYgHbXRl18ILcmKyONSBV7O7CQce7nHt2lr+7wXHtYbg=="},
}

func testOpts(agent string) PlanOptions {
	return PlanOptions{
		Agent:           agent,
		Destination:     DestOrg,
		DestinationURL:  "https://org.example.com",
		ObserverVersion: "v1.37.0",
		VendorKeys:      []string{testKey},
		NpmPins:         testPins,
	}
}

// memRepo is an in-memory repository for the planner.
type memRepo map[string]string

func (m memRepo) read(path string) (string, bool, error) {
	c, ok := m[path]
	return c, ok, nil
}

// apply writes a plan into the repo.
func (m memRepo) apply(p RepoPlan) {
	for _, c := range p.Changes {
		if c.Delete {
			delete(m, c.Path)
			continue
		}
		if c.Changed() {
			m[c.Path] = c.After
		}
	}
}

func (m memRepo) clone() memRepo {
	out := memRepo{}
	for k, v := range m {
		out[k] = v
	}
	return out
}

// TestPlanInitGolden pins the exact files init writes for each supported
// agent into an empty repository.
func TestPlanInitGolden(t *testing.T) {
	for _, agent := range []string{"claude-code", "copilot"} {
		t.Run(agent, func(t *testing.T) {
			plan, err := PlanInit(testOpts(agent), memRepo{}.read)
			if err != nil {
				t.Fatal(err)
			}
			if len(plan.Changes) == 0 {
				t.Fatal("no changes planned")
			}
			for _, c := range plan.Changes {
				golden := filepath.Join("testdata", "golden", agent, goldenName(c.Path))
				if *update {
					if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(golden, []byte(c.After), 0o644); err != nil {
						t.Fatal(err)
					}
					continue
				}
				want, err := os.ReadFile(golden)
				if err != nil {
					t.Fatalf("read golden (run with -update): %v", err)
				}
				if c.After != string(want) {
					t.Errorf("%s differs from %s:\n%s", c.Path, golden, c.After)
				}
			}
		})
	}
}

// goldenName maps a repository path to its golden file: a leading dot of a
// segment becomes "_", so .claude and .github trees are not hidden from git
// (the repository ignores **/.claude/*).
func goldenName(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if strings.HasPrefix(p, ".") {
			parts[i] = "_" + p[1:]
		}
	}
	return filepath.Join(parts...)
}

// TestPlanInitIsIdempotent: a second init over the first changes nothing.
func TestPlanInitIsIdempotent(t *testing.T) {
	for _, agent := range []string{"claude-code", "copilot"} {
		repo := memRepo{}
		p1, err := PlanInit(testOpts(agent), repo.read)
		if err != nil {
			t.Fatal(err)
		}
		repo.apply(p1)
		p2, err := PlanInit(testOpts(agent), repo.read)
		if err != nil {
			t.Fatal(err)
		}
		if p2.Changed() {
			t.Errorf("%s: second init changes files:\n%s", agent, p2.Diff())
		}
	}
}

const teamSettings = `{
  "permissions": {
    "allow": [
      "Bash(go test:*)"
    ]
  },
  "hooks": {
    "PostToolUse": [
      {
        "matcher": "Edit",
        "hooks": [
          {
            "type": "command",
            "command": "gofmt -l ."
          }
        ]
      }
    ]
  },
  "env": {
    "FOO": "<bar>"
  }
}
`

// TestRemoveRestoresBytes: init then remove gives back the original bytes,
// for a repository with and without the team's own settings.
func TestRemoveRestoresBytes(t *testing.T) {
	cases := []struct {
		name  string
		agent string
		start memRepo
	}{
		{"claude empty repo", "claude-code", memRepo{}},
		{"claude team settings", "claude-code", memRepo{ClaudeSettingsPath: teamSettings, "README.md": "hi\n"}},
		{"claude settings without trailing newline", "claude-code", memRepo{ClaudeSettingsPath: strings.TrimSuffix(teamSettings, "\n")}},
		{"copilot empty repo", "copilot", memRepo{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := tc.start.clone()
			p, err := PlanInit(testOpts(tc.agent), repo.read)
			if err != nil {
				t.Fatal(err)
			}
			repo.apply(p)
			r, err := PlanRemove(tc.agent, repo.read)
			if err != nil {
				t.Fatal(err)
			}
			repo.apply(r)
			if len(repo) != len(tc.start) {
				t.Errorf("files after remove = %v, want %v", keys(repo), keys(tc.start))
			}
			for k, v := range tc.start {
				if repo[k] != v {
					t.Errorf("%s not restored byte-for-byte:\n got %q\nwant %q", k, repo[k], v)
				}
			}
		})
	}
}

func keys(m memRepo) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// TestInitKeepsTeamHooks: the team's own hook group survives, Observer's
// groups come after it.
func TestInitKeepsTeamHooks(t *testing.T) {
	repo := memRepo{ClaudeSettingsPath: teamSettings}
	p, err := PlanInit(testOpts("claude-code"), repo.read)
	if err != nil {
		t.Fatal(err)
	}
	after := p.Changes[0].After
	if !strings.Contains(after, `"command": "gofmt -l ."`) {
		t.Fatal("team hook lost")
	}
	if strings.Index(after, "gofmt") > strings.Index(after, OwnerTag) {
		t.Error("Observer's group was not appended after the team's")
	}
	if !strings.Contains(after, `"FOO": "<bar>"`) {
		t.Error("HTML-sensitive characters were escaped")
	}
}

// TestInitRefusesNonCanonicalJSON: a settings file in another layout is not
// edited unless --reformat.
func TestInitRefusesNonCanonicalJSON(t *testing.T) {
	repo := memRepo{ClaudeSettingsPath: `{"hooks":{}}`}
	if _, err := PlanInit(testOpts("claude-code"), repo.read); err == nil || !strings.Contains(err.Error(), "--reformat") {
		t.Fatalf("err = %v, want a refusal naming --reformat", err)
	}
	opts := testOpts("claude-code")
	opts.Reformat = true
	p, err := PlanInit(opts, repo.read)
	if err != nil {
		t.Fatal(err)
	}
	if p.Changes[0].Note == "" {
		t.Error("a reformat must be reported")
	}
	if _, err := PlanInit(testOpts("claude-code"), memRepo{ClaudeSettingsPath: "[1]\n"}.read); err == nil {
		t.Error("a non-object settings file must be refused")
	}
}

// TestCopilotKeepsExistingSetupWorkflow: an existing workflow is never
// edited; the step to add is reported.
func TestCopilotKeepsExistingSetupWorkflow(t *testing.T) {
	existing := "name: mine\njobs:\n  copilot-setup-steps:\n    runs-on: ubuntu-latest\n"
	repo := memRepo{CopilotSetupStepsPath: existing}
	p, err := PlanInit(testOpts("copilot"), repo.read)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range p.Changes {
		if c.Path == CopilotSetupStepsPath && c.Changed() {
			t.Fatal("existing workflow edited")
		}
	}
	found := false
	for _, m := range p.Manual {
		if strings.Contains(m, "sudo sh "+SetupScriptPath) {
			found = true
		}
	}
	if !found {
		t.Errorf("manual step missing: %v", p.Manual)
	}
	repo.apply(p)
	r, err := PlanRemove("copilot", repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(r)
	if repo[CopilotSetupStepsPath] != existing {
		t.Error("remove touched the team's workflow")
	}
}

// TestGeneratedFileOwnership: an edited generated file is neither
// overwritten by init nor deleted by remove; a foreign file blocks init.
func TestGeneratedFileOwnership(t *testing.T) {
	repo := memRepo{}
	p, err := PlanInit(testOpts("claude-code"), repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(p)
	repo[SetupScriptPath] += "echo local edit\n"
	if _, err := PlanInit(testOpts("claude-code"), repo.read); err == nil {
		t.Error("init overwrote an edited setup script")
	}
	r, err := PlanRemove("claude-code", repo.read)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Changes {
		if c.Path == SetupScriptPath && (c.Delete || c.Changed()) {
			t.Error("remove deleted an edited setup script")
		}
	}
	if _, err := PlanInit(testOpts("claude-code"), memRepo{SetupScriptPath: "#!/bin/sh\necho mine\n"}.read); err == nil {
		t.Error("init overwrote a foreign file")
	}
}

// TestRemoveKeepsSharedSetupScript: removing one agent keeps the setup
// script while another agent still uses it.
func TestRemoveKeepsSharedSetupScript(t *testing.T) {
	repo := memRepo{}
	for _, a := range []string{"claude-code", "copilot"} {
		p, err := PlanInit(testOpts(a), repo.read)
		if err != nil {
			t.Fatal(err)
		}
		repo.apply(p)
	}
	r, err := PlanRemove("claude-code", repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(r)
	if _, ok := repo[SetupScriptPath]; !ok {
		t.Fatal("setup script removed while copilot still uses it")
	}
	if _, ok := repo[ClaudeSettingsPath]; ok {
		t.Error("claude settings not removed")
	}
	r, err = PlanRemove("copilot", repo.read)
	if err != nil {
		t.Fatal(err)
	}
	repo.apply(r)
	if len(repo) != 0 {
		t.Errorf("files left after removing both: %v", keys(repo))
	}
}

func TestPlanInitValidation(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*PlanOptions)
		want   string
	}{
		{"unknown agent", func(o *PlanOptions) { o.Agent = "nope" }, "unknown agent"},
		{"unsupported agent", func(o *PlanOptions) { o.Agent = "cursor" }, "not supported yet"},
		{"file destination", func(o *PlanOptions) { o.Destination = DestFile }, "org or node"},
		{"dev version", func(o *PlanOptions) { o.ObserverVersion = "dev" }, "release tag"},
		{"no keys", func(o *PlanOptions) { o.VendorKeys = nil }, "no vendor verification key"},
		{"zero key", func(o *PlanOptions) { o.VendorKeys = []string{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="} }, "placeholder"},
		{"http url", func(o *PlanOptions) { o.DestinationURL = "http://org.example.com" }, "https"},
		{"relative install dir", func(o *PlanOptions) { o.InstallDir = "bin" }, "absolute"},
		{"http mirror", func(o *PlanOptions) { o.InstallSource, o.ReleaseBaseURL = InstallRelease, "http://mirror" }, "https"},
		{"unknown install source", func(o *PlanOptions) { o.InstallSource = "curl-bash" }, "--install-source"},
		{"no npm pins", func(o *PlanOptions) { o.NpmPins = nil }, "dist.integrity"},
		{"sha1 pin", func(o *PlanOptions) { o.NpmPins = []NpmPin{{Arch: "x64", Integrity: "sha1-AAAA"}} }, "sha512"},
		{"short pin", func(o *PlanOptions) { o.NpmPins = []NpmPin{{Arch: "x64", Integrity: "sha512-AAAA"}} }, "64-byte"},
		{"unknown arch", func(o *PlanOptions) { o.NpmPins = []NpmPin{{Arch: "riscv64", Integrity: testPins[0].Integrity}} }, "unknown architecture"},
		{"duplicate arch", func(o *PlanOptions) { o.NpmPins = []NpmPin{testPins[0], testPins[0]} }, "two npm pins"},
		{"http registry", func(o *PlanOptions) { o.NpmRegistry = "http://registry.example" }, "--npm-registry"},
		{"registry with shell", func(o *PlanOptions) { o.NpmRegistry = "https://r.example/$(id)" }, "--npm-registry"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := testOpts("claude-code")
			tc.mutate(&o)
			_, err := PlanInit(o, memRepo{}.read)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}

// TestHookCommandsAreGated: every committed command tests the cloud marker
// and the binary before running anything, ends with the owner tag, and
// never carries a token.
func TestHookCommandsAreGated(t *testing.T) {
	for _, a := range Agents() {
		if !a.Supported() {
			continue
		}
		for _, b := range plannedHooks(a, testOpts(a.ID)) {
			cmd, err := hookCommand(a, b, testOpts(a.ID))
			if err != nil {
				t.Fatal(err)
			}
			gate := markerGate(a)
			if !strings.HasPrefix(cmd, gate+" && [ -x /usr/local/bin/observer ] && exec /usr/local/bin/observer ") {
				t.Errorf("%s %s: command not gated: %s", a.ID, b.Event, cmd)
			}
			if !strings.HasSuffix(cmd, "; exit 0 "+OwnerTag) {
				t.Errorf("%s %s: command does not end with the owner tag: %s", a.ID, b.Event, cmd)
			}
			if strings.Contains(strings.ToLower(cmd), "token") {
				t.Errorf("%s %s: command mentions a token: %s", a.ID, b.Event, cmd)
			}
		}
	}
}

func TestDiffRendersEveryChange(t *testing.T) {
	p, err := PlanInit(testOpts("copilot"), memRepo{}.read)
	if err != nil {
		t.Fatal(err)
	}
	d := p.Diff()
	for _, f := range []string{CopilotHooksPath, SetupScriptPath, CopilotSetupStepsPath} {
		if !strings.Contains(d, "+++ b/"+f) {
			t.Errorf("diff missing %s:\n%s", f, d)
		}
	}
}

// TestResolveShare pins decision CA-D19's posture table: the node
// destination defaults to full content, the org and file destinations to
// metadata only, an explicit posture wins, and anything else is refused.
func TestResolveShare(t *testing.T) {
	cases := []struct {
		dest    DestinationKind
		in      SharePosture
		want    SharePosture
		wantErr bool
	}{
		{DestNode, "", ShareFullContent, false},
		{DestOrg, "", ShareMetadataOnly, false},
		{DestFile, "", ShareMetadataOnly, false},
		{DestOrg, ShareFullContent, ShareFullContent, false},
		{DestNode, ShareMetadataOnly, ShareMetadataOnly, false},
		{DestOrg, "everything", "", true},
		{"elsewhere", "", "", true},
	}
	for _, tc := range cases {
		got, err := ResolveShare(tc.dest, tc.in)
		if (err != nil) != tc.wantErr || got != tc.want {
			t.Errorf("ResolveShare(%s, %q) = %q, %v; want %q (err %v)", tc.dest, tc.in, got, err, tc.want, tc.wantErr)
		}
	}
}

// TestPlanInitBakesShare pins that the resolved posture is written into every
// committed flush command, and that a bad --share is refused before
// rendering.
func TestPlanInitBakesShare(t *testing.T) {
	base := PlanOptions{
		Agent: "claude-code", Destination: DestOrg, DestinationURL: "https://org.example.com",
		ObserverVersion: "v1.37.0", VendorKeys: []string{testKey}, NpmPins: testPins,
	}
	empty := func(string) (string, bool, error) { return "", false, nil }
	for _, tc := range []struct {
		name  string
		dest  DestinationKind
		share SharePosture
		want  string
	}{
		{"org default", DestOrg, "", "--share metadata_only"},
		{"org managed member", DestOrg, ShareFullContent, "--share full_content"},
		{"node default", DestNode, "", "--share full_content"},
	} {
		o := base
		o.Destination, o.Share = tc.dest, tc.share
		plan, err := PlanInit(o, empty)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		flushes := 0
		for _, c := range plan.Changes {
			flushes += strings.Count(c.After, "cloud-session flush")
			if strings.Contains(c.After, "cloud-session flush") && strings.Count(c.After, "cloud-session flush") != strings.Count(c.After, tc.want) {
				t.Errorf("%s: %s has a flush without %q", tc.name, c.Path, tc.want)
			}
		}
		if flushes == 0 {
			t.Fatalf("%s: no flush command rendered", tc.name)
		}
	}
	o := base
	o.Share = "all-of-it"
	if _, err := PlanInit(o, empty); err == nil {
		t.Fatal("an unknown --share was accepted")
	}
}

// plannedHooks returns the bindings opts plans for a (feature-tagged ones
// only while their feature is on).
func plannedHooks(a Agent, opts PlanOptions) []HookBinding {
	var out []HookBinding
	for _, b := range a.Hooks {
		if opts.enabled(b.Feature) {
			out = append(out, b)
		}
	}
	return out
}
