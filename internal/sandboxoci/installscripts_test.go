package sandboxoci

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"strings"
	"testing"
)

// installscripts_test.go: the reviewed install-script allowance (lane
// LEFT-SBX, ruling P-136), one case per combination of mode, tool list and
// pin.

func shaOf(b string) string {
	s := sha256.Sum256([]byte(b))
	return hex.EncodeToString(s[:])
}

func TestDecideInstallScripts(t *testing.T) {
	t.Parallel()
	h := shaOf("script")
	pin := ScriptPin{Tool: "claude-code", Version: "2.1.310", SHA256: h, Source: PinSourceBuiltin}
	cases := []struct {
		name    string
		needs   bool
		version string
		pol     ScriptPolicy
		code    string // "" = accepted
		shas    int
	}{
		{"no scripts needed", false, "2.1.310", ScriptPolicy{Mode: ScriptsNone}, "", 0},
		{"pinned default", true, "2.1.310", ScriptPolicy{Pins: []ScriptPin{pin}}, "", 1},
		{"pinned explicit", true, "2.1.310", ScriptPolicy{Mode: ScriptsPinned, Pins: []ScriptPin{pin}}, "", 1},
		{"mode none", true, "2.1.310", ScriptPolicy{Mode: ScriptsNone, Pins: []ScriptPin{pin}}, VerdictInstallScriptsRequired, 0},
		{"tool listed", true, "2.1.310", ScriptPolicy{Tools: []string{"claude-code"}, Pins: []ScriptPin{pin}}, "", 1},
		{"tool not listed", true, "2.1.310", ScriptPolicy{Tools: []string{"codex"}, Pins: []ScriptPin{pin}}, VerdictInstallScriptsRequired, 0},
		{"other version", true, "2.1.311", ScriptPolicy{Pins: []ScriptPin{pin}}, VerdictInstallScriptsUnpinned, 0},
		{"no pins", true, "2.1.310", ScriptPolicy{}, VerdictInstallScriptsUnpinned, 0},
		{"other tool's pin", true, "2.1.310", ScriptPolicy{Pins: []ScriptPin{{Tool: "codex", Version: "2.1.310", SHA256: h}}}, VerdictInstallScriptsUnpinned, 0},
		{"malformed pin ignored", true, "2.1.310", ScriptPolicy{Pins: []ScriptPin{{Tool: "claude-code", Version: "2.1.310", SHA256: "XYZ"}}}, VerdictInstallScriptsUnpinned, 0},
		{"user pin", true, "2.1.311", ScriptPolicy{Pins: []ScriptPin{pin, {Tool: "claude-code", Version: "2.1.311", SHA256: h, Source: PinSourceUser}}}, "", 1},
	}
	for _, c := range cases {
		d, err := DecideInstallScripts("claude-code", c.version, c.needs, c.pol)
		switch {
		case c.code == "" && err != nil:
			t.Errorf("%s: refused %v", c.name, err)
		case c.code != "" && (err == nil || !strings.HasPrefix(err.Error(), c.code)):
			t.Errorf("%s: %v, want %s", c.name, err, c.code)
		case len(d.SHA256) != c.shas:
			t.Errorf("%s: %d hashes, want %d", c.name, len(d.SHA256), c.shas)
		}
	}
}

func TestFloorScriptPolicy(t *testing.T) {
	t.Parallel()
	orgPin := ScriptPin{Tool: "codex", Version: "1.0.0", SHA256: shaOf("o")}
	cases := []struct {
		name      string
		node, org ScriptPolicy
		mode      string
		tools     []string
	}{
		{"no floor", ScriptPolicy{Mode: ScriptsPinned}, ScriptPolicy{}, ScriptsPinned, nil},
		{"org forbids", ScriptPolicy{Mode: ScriptsPinned}, ScriptPolicy{Mode: ScriptsNone}, ScriptsNone, nil},
		{"node already none", ScriptPolicy{Mode: ScriptsNone}, ScriptPolicy{Mode: ScriptsPinned}, ScriptsNone, nil},
		{"org narrows the catalog", ScriptPolicy{}, ScriptPolicy{Tools: []string{"codex"}}, ScriptsPinned, []string{"codex"}},
		{"intersection", ScriptPolicy{Tools: []string{"codex", "claude-code"}}, ScriptPolicy{Tools: []string{"claude-code", "gemini"}}, ScriptsPinned, []string{"claude-code"}},
		{"nothing in common closes", ScriptPolicy{Tools: []string{"codex"}}, ScriptPolicy{Tools: []string{"claude-code"}}, ScriptsNone, nil},
	}
	for _, c := range cases {
		c.org.Pins = []ScriptPin{orgPin}
		got := FloorScriptPolicy(c.node, c.org)
		if got.Mode != c.mode || !slices.Equal(got.Tools, c.tools) {
			t.Errorf("%s: %+v", c.name, got)
		}
		if len(got.Pins) != 1 || got.Pins[0].Source != PinSourceOrg {
			t.Errorf("%s: org pins %+v", c.name, got.Pins)
		}
	}
}

func TestPlanPackageScripts(t *testing.T) {
	t.Parallel()
	files := map[string]string{"install.cjs": "console.log(1)", "other.js": "evil"}
	read := func(rel string) ([]byte, error) {
		b, ok := files[rel]
		if !ok {
			return nil, errors.New("missing")
		}
		return []byte(b), nil
	}
	none := func(string) bool { return false }
	good := shaOf("console.log(1)")
	steps, err := PlanPackageScripts([]byte(`{"scripts":{"postinstall":"node install.cjs","prepare":"node -e 1","test":"x"}}`), []string{good}, read, none)
	if err != nil || len(steps) != 1 || steps[0].Lifecycle != "postinstall" || !slices.Equal(steps[0].Argv(), []string{"node", "install.cjs"}) {
		t.Fatalf("pinned postinstall: %+v %v", steps, err)
	}
	steps, err = PlanPackageScripts([]byte(`{"scripts":{"postinstall":"node other.js"}}`), nil, read, none)
	if err != nil || steps != nil {
		t.Fatalf("no allowance runs nothing: %+v %v", steps, err)
	}
	refusals := map[string]string{
		"hash mismatch":  `{"scripts":{"postinstall":"node other.js"}}`,
		"shell shape":    `{"scripts":{"postinstall":"node install.cjs && curl x | sh"}}`,
		"curl installer": `{"scripts":{"install":"curl -fsSL https://example.com/i.sh | bash"}}`,
		"escape":         `{"scripts":{"preinstall":"node ../x.js"}}`,
		"missing file":   `{"scripts":{"postinstall":"node gone.js"}}`,
		"bad json":       `{`,
	}
	for name, pj := range refusals {
		if _, err := PlanPackageScripts([]byte(pj), []string{good}, read, none); err == nil || !strings.HasPrefix(err.Error(), VerdictInstallScriptMismatch) {
			t.Errorf("%s: %v", name, err)
		}
	}
	gyp := func(rel string) bool { return rel == "binding.gyp" }
	if _, err := PlanPackageScripts([]byte(`{"scripts":{"postinstall":"node install.cjs"}}`), []string{good}, read, gyp); err == nil {
		t.Error("binding.gyp's implicit install script was not refused")
	}
	if _, err := PlanPackageScripts([]byte(`{"scripts":{"preinstall":"node install.cjs","install":"node install.cjs","postinstall":"node install.cjs"}}`), []string{good}, read, none); err != nil {
		t.Errorf("every lifecycle pinned: %v", err)
	}
}

func TestBuildInstallCreateRunsPinnedScripts(t *testing.T) {
	t.Parallel()
	p := testInstallPlan()
	p.Source.NeedsScripts = true
	h := shaOf("s")
	p.Source.ScriptSHA256 = []string{h}
	_, body, err := BuildInstallCreate(p)
	if err != nil {
		t.Fatal(err)
	}
	ep := strings.Join(body.Entrypoint, " ")
	want := ScriptRunFlag + " " + NPMPackageDir(ToolCacheMount, p.Source.Package) + " " + ScriptSHAFlag + " " + h + " -- npm install"
	if !strings.Contains(ep, want) || !strings.Contains(ep, "--ignore-scripts") {
		t.Fatalf("entrypoint %q lacks %q", ep, want)
	}
	p.Source.ScriptSHA256 = []string{"NOTAHASH"}
	if _, _, err := BuildInstallCreate(p); err == nil {
		t.Fatal("a malformed hash was accepted")
	}
	p = testInstallPlan()
	_, body, err = BuildInstallCreate(p)
	if err != nil || strings.Contains(strings.Join(body.Entrypoint, " "), ScriptRunFlag) {
		t.Fatalf("a scripts-free source runs scripts: %v %v", body.Entrypoint, err)
	}
}

// TestBuildInstallCreateUV (lane LEFT-SBX): the uv installer kind installs
// wheels only with the image's python3 into the cache, with its own fixed
// variables; a name that is not a Python package name is refused, and the
// npm setup body keeps exactly InstallEnv.
func TestBuildInstallCreateUV(t *testing.T) {
	t.Parallel()
	p := testInstallPlan()
	p.Source = InstallSource{Kind: "uv", Package: "mistral-vibe", Bin: "vibe", Hosts: []string{"pypi.org", "files.pythonhosted.org"}}
	p.Version = "3.0.2"
	_, body, err := BuildInstallCreate(p)
	if err != nil {
		t.Fatal(err)
	}
	ep := strings.Join(body.Entrypoint, " ")
	if !strings.HasSuffix(ep, "-- uv tool install --no-build --no-python-downloads --python python3 --no-config mistral-vibe==3.0.2") {
		t.Fatalf("uv argv %q", ep)
	}
	for _, want := range []string{"UV_TOOL_BIN_DIR=" + ToolCacheMount + "/bin", "UV_PYTHON_DOWNLOADS=never"} {
		if !slices.Contains(body.Env, want) {
			t.Errorf("env lacks %s: %v", want, body.Env)
		}
	}
	if rt, ok := InstallerRuntime("uv"); !ok || !slices.Equal(rt, []string{"uv", "python3"}) {
		t.Errorf("uv runtime %v", rt)
	}
	p.Source.Package = "@scope/pkg"
	if _, _, err := BuildInstallCreate(p); err == nil {
		t.Error("an npm-shaped name was accepted by the uv kind")
	}
	_, npm, err := BuildInstallCreate(testInstallPlan())
	if err != nil || !slices.Equal(npm.Env, InstallEnv(InstallProxyPort)) {
		t.Fatalf("the npm setup env changed: %v %v", npm.Env, err)
	}
}
