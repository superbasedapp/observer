package agentconfig

import (
	"reflect"
	"strings"
	"testing"
)

// TestLayerFindingRules has one case per layerFindingRules row (pinned by
// the count check), each matching that row and no earlier one.
func TestLayerFindingRules(t *testing.T) {
	fam := func(c Concern, obs, off string) Family {
		return Family{ID: "t/" + string(c), Concern: c, ObserverClass: obs, OffClass: off}
	}
	user, proj := SourceRef{FileID: "t/user"}, SourceRef{FileID: "t/project"}
	in := func(f Family, class string, winProject bool, shadow ...string) findingInput {
		fi := findingInput{f: f, res: EffectiveResult{EffectiveClass: class, Winning: user}, shadowClass: map[string]bool{}, winProject: winProject}
		for _, s := range shadow {
			fi.shadowClass[s] = true
			fi.res.Shadowed = append(fi.res.Shadowed, proj)
		}
		return fi
	}
	userPolicy := func(userSet bool) findingInput {
		fi := in(fam(ConcernUserPolicy, "", ""), classSet, false)
		fi.userSet = userSet
		return fi
	}
	route := fam(ConcernRoute, classLoopback, "")
	hooks := fam(ConcernHooksOff, classOn, classOff)
	cases := []struct {
		name string
		in   findingInput
		want FindingCode
	}{
		{"a project file routes elsewhere", in(route, classVendorHost, true), FindingProjectRouteOverride},
		{"a higher layer shadows Observer's route", in(route, classOtherHost, false, classLoopback), FindingRouteShadowed},
		{"the IDE hands the agent another host", in(fam(ConcernIDERoute, classLoopback, ""), classVendorHost, false), FindingIDERouteOverride},
		{"a project file turns hooks off", in(hooks, classOff, true), FindingProjectHooksDisabled},
		{"a user or managed file turns hooks off", in(hooks, classOff, false), FindingHooksDisabled},
		{"a higher file turns a lower off switch back on", in(hooks, classOn, true, classOff), FindingHooksOffOverridden},
		{"a higher hook array drops Observer's group", in(fam(ConcernHookArray, classWithObserver, ""), classEmpty, true, classWithObserver), FindingHookArrayReplaced},
		{"a layer drop is set", in(fam(ConcernLayerDrop, "", classOn), classOn, true), FindingLayersDropped},
		{"the first MCP file hides the others", in(fam(ConcernMCP, "", ""), classPresent, true, classPresent), FindingMCPFirstFileOnly},
		{"a saved sign-in pins the vendor host", in(fam(ConcernAuth, classAPIKey, ""), classGoogleSignIn, false), FindingAuthPinsVendorHost},
		{"another provider is active", in(fam(ConcernProvider, classRouted, ""), classOther, false), FindingInactiveProvider},
		{"an unverified provider is active", in(fam(ConcernProvider, classRouted, ""), classUnverified, false), FindingProviderUnverified},
		{"a user-writable preferences domain sets a policy key", userPolicy(true), FindingUserPolicyOverride},
	}
	if len(cases) != len(layerFindingRules) {
		t.Fatalf("%d cases for %d layerFindingRules rows: add one case per row", len(cases), len(layerFindingRules))
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if layerFindingRules[i].code != tc.want {
				t.Fatalf("row %d is %s, the case expects %s: keep cases in row order", i, layerFindingRules[i].code, tc.want)
			}
			got, ok := findingCode(tc.in)
			if !ok || got != tc.want {
				t.Fatalf("findingCode = %q, %v; want %q", got, ok, tc.want)
			}
		})
	}
	// Observer's own value is never a finding.
	for _, fi := range []findingInput{in(route, classLoopback, true), in(hooks, classOn, true), in(fam(ConcernProvider, classRouted, ""), classRouted, false), userPolicy(false)} {
		if c, ok := findingCode(fi); ok {
			t.Errorf("%s with Observer's class %s gave %s", fi.f.Concern, fi.res.EffectiveClass, c)
		}
	}
}

// lf builds a LayerFile for a real catalogue row.
func lf(t *testing.T, id, project string, tree map[string]any) LayerFile {
	t.Helper()
	row, ok := fileRowsByID()[id]
	if !ok {
		t.Fatalf("no catalogue row %s", id)
	}
	return LayerFile{Row: row, Project: project, Tree: tree}
}

// own stands in for internal/hook.IsObserverHookCommand.
func own(c string) bool { return strings.Contains(c, "observer hook") }

// briefFinding is what the real-catalogue cases compare.
type briefFinding struct {
	Family  string
	Code    FindingCode
	Project string
	Class   string
	Winning string
}

func brief(fs []LayerFinding) []briefFinding {
	var out []briefFinding
	for _, f := range fs {
		out = append(out, briefFinding{f.Family, f.Code, f.Project, f.Class, f.Winning.String()})
	}
	return out
}

func env(k, v string) map[string]any { return map[string]any{"env": map[string]any{k: v}} }

// TestEvaluateLayersRealCatalogue runs EvaluateLayers on the real catalogue
// rows, one case per finding the lane closes (each fails on the old code,
// which had no families beyond claude-code/env and no finding producer).
func TestEvaluateLayersRealCatalogue(t *testing.T) {
	const p = "/w/app"
	loop, vendor, other := "http://127.0.0.1:8820", "https://api.anthropic.com", "https://llm.example.com/v1"
	vtArr := func(cmd string) map[string]any {
		return map[string]any{"hooks": map[string]any{"lifecycle": map[string]any{"pre_tool_use": []any{
			map[string]any{"matcher": "*", "hooks": []any{map[string]any{"type": "command", "command": cmd}}},
		}}}}
	}
	cases := []struct {
		name    string
		fam     string
		files   []LayerFile
		runtime []RuntimeTree
		want    []briefFinding
	}{
		{
			name: "CC-4/OBS-9: .claude/settings.local.json sends the route to the vendor", fam: "claude-code/env",
			files: []LayerFile{
				lf(t, "claude-code/user-settings", "", env("ANTHROPIC_BASE_URL", loop)),
				lf(t, "claude-code/project-local-settings", p, env("ANTHROPIC_BASE_URL", vendor)),
			},
			want: []briefFinding{{"claude-code/env", FindingProjectRouteOverride, p, classVendorHost, "claude-code/project-local-settings"}},
		},
		{
			name: "CC-1: the launch environment shadows every settings file", fam: "claude-code/env",
			files:   []LayerFile{lf(t, "claude-code/user-settings", "", env("ANTHROPIC_BASE_URL", loop))},
			runtime: []RuntimeTree{{Tool: "claude-code", Layer: RuntimeLaunchEnv, Tree: env("ANTHROPIC_BASE_URL", vendor)}},
			want:    []briefFinding{{"claude-code/env", FindingRouteShadowed, "", classVendorHost, "runtime:launch_env"}},
		},
		{
			name: "CC-4: the env block's credentials are never observed", fam: "claude-code/env",
			files: []LayerFile{lf(t, "claude-code/project-settings", p, env("ANTHROPIC_API_KEY", "sk-not-a-url"))},
		},
		{
			name: "CC-4/CLI-5: a project disableAllHooks", fam: "claude-code/disableAllHooks",
			files: []LayerFile{lf(t, "claude-code/project-local-settings", p, map[string]any{"disableAllHooks": true})},
			want:  []briefFinding{{"claude-code/disableAllHooks", FindingProjectHooksDisabled, p, classOff, "claude-code/project-local-settings"}},
		},
		{
			name: "CLI-5: a project re-enables what the user file switched off", fam: "claude-code/disableAllHooks",
			files: []LayerFile{
				lf(t, "claude-code/user-settings", "", map[string]any{"disableAllHooks": true}),
				lf(t, "claude-code/project-settings", p, map[string]any{"disableAllHooks": false}),
			},
			want: []briefFinding{
				{"claude-code/disableAllHooks", FindingHooksDisabled, "", classOff, "claude-code/user-settings"},
				{"claude-code/disableAllHooks", FindingHooksOffOverridden, p, classOn, "claude-code/project-settings"},
			},
		},
		{
			name: "CLI-5: the Gemini system file wins over the user file", fam: "gemini-cli/hooksConfig.enabled",
			files: []LayerFile{
				lf(t, "gemini-cli/user-settings", "", map[string]any{"hooksConfig": map[string]any{"enabled": true}}),
				lf(t, "gemini-cli/system-settings", "", map[string]any{"hooksConfig": map[string]any{"enabled": false}}),
			},
			want: []briefFinding{{"gemini-cli/hooksConfig.enabled", FindingHooksDisabled, "", classOff, "gemini-cli/system-settings"}},
		},
		{
			name: "FU-38: Factory's org hooksDisabled is only a default", fam: "droid/hooksDisabled",
			files: []LayerFile{
				lf(t, "droid/system-settings", "", map[string]any{"hooksDisabled": true}),
				lf(t, "droid/user-settings", "", map[string]any{"hooksDisabled": false}),
			},
			want: []briefFinding{{"droid/hooksDisabled", FindingHooksOffOverridden, "", classOn, "droid/user-settings"}},
		},
		{
			name: "S-18/FU-38: Command Code mods.disabled names Observer's mod in the project", fam: "command-code/mods.disabled",
			files: []LayerFile{
				lf(t, "command-code/user-settings", "", map[string]any{"mods": map[string]any{"disabled": []any{"titling"}}}),
				lf(t, "command-code/project-local-settings", p, map[string]any{"mods": map[string]any{"disabled": []any{"observer-guard"}}}),
			},
			want: []briefFinding{{"command-code/mods.disabled", FindingProjectHooksDisabled, p, classOff, "command-code/project-local-settings"}},
		},
		{
			name: "S-18: a Command Code disable in the user file wins over a project file", fam: "command-code/mods.disableAll",
			files: []LayerFile{
				lf(t, "command-code/user-settings", "", map[string]any{"mods": map[string]any{"disableAll": true}}),
				lf(t, "command-code/project-settings", p, map[string]any{"mods": map[string]any{"disableAll": false}}),
			},
			want: []briefFinding{{"command-code/mods.disableAll", FindingHooksDisabled, "", classOff, "command-code/user-settings"}},
		},
		{
			name: "CLI-2: a project qwen settings file shadows the user route", fam: "qwen-code/model.baseUrl",
			files: []LayerFile{
				lf(t, "qwen-code/user-settings", "", map[string]any{"model": map[string]any{"baseUrl": loop + "/v1"}}),
				lf(t, "qwen-code/project-settings", p, map[string]any{"model": map[string]any{"baseUrl": other}}),
			},
			want: []briefFinding{{"qwen-code/model.baseUrl", FindingProjectRouteOverride, p, classOtherHost, "qwen-code/project-settings"}},
		},
		{
			name: "CLI-2: a project crush.json shadows the user route", fam: "crush/providers.openai.base_url",
			files: []LayerFile{
				lf(t, "crush/user-json", "", map[string]any{"providers": map[string]any{"openai": map[string]any{"base_url": loop + "/v1"}}}),
				lf(t, "crush/project-json", p, map[string]any{"providers": map[string]any{"openai": map[string]any{"base_url": "https://api.openai.com/v1"}}}),
			},
			want: []briefFinding{{"crush/providers.openai.base_url", FindingProjectRouteOverride, p, classVendorHost, "crush/project-json"}},
		},
		{
			name: "CLI-2: a project opencode.json beats OPENAI_BASE_URL", fam: "opencode/provider.openai.options.baseURL",
			files:   []LayerFile{lf(t, "opencode/project-config", p, map[string]any{"provider": map[string]any{"openai": map[string]any{"options": map[string]any{"baseURL": other}}}})},
			runtime: []RuntimeTree{{Tool: "opencode", Layer: RuntimeLaunchEnv, Tree: map[string]any{"provider": map[string]any{"openai": map[string]any{"options": map[string]any{"baseURL": loop + "/v1"}}}}}},
			want:    []briefFinding{{"opencode/provider.openai.options.baseURL", FindingProjectRouteOverride, p, classOtherHost, "opencode/project-config"}},
		},
		{
			name: "CLI-2/CLI-3: OPENCODE_CONFIG_CONTENT carries the route past the project file", fam: "opencode/provider.openai.options.baseURL",
			files:   []LayerFile{lf(t, "opencode/project-config", p, map[string]any{"provider": map[string]any{"openai": map[string]any{"options": map[string]any{"baseURL": other}}}})},
			runtime: []RuntimeTree{{Tool: "opencode", Layer: RuntimeConfigContent, Tree: map[string]any{"provider": map[string]any{"openai": map[string]any{"options": map[string]any{"baseURL": loop + "/v1"}}}}}},
		},
		{
			name: "CLI-3: crush's large model talks to another provider", fam: "crush/models.large.provider",
			files: []LayerFile{lf(t, "crush/user-json", "", map[string]any{"models": map[string]any{"large": map[string]any{"provider": "anthropic"}}})},
			want:  []briefFinding{{"crush/models.large.provider", FindingInactiveProvider, "", classOther, "crush/user-json"}},
		},
		{
			name: "CLI-3: qwen on qwen-oauth is unverified", fam: "qwen-code/security.auth.selectedType",
			files: []LayerFile{lf(t, "qwen-code/user-settings", "", map[string]any{"security": map[string]any{"auth": map[string]any{"selectedType": "qwen-oauth"}}})},
			want:  []briefFinding{{"qwen-code/security.auth.selectedType", FindingProviderUnverified, "", classUnverified, "qwen-code/user-settings"}},
		},
		{
			name: "CLI-6: Gemini saved on Google sign-in", fam: "gemini-cli/security.auth.selectedType",
			files: []LayerFile{lf(t, "gemini-cli/user-settings", "", map[string]any{"security": map[string]any{"auth": map[string]any{"selectedType": "oauth-personal"}}})},
			want:  []briefFinding{{"gemini-cli/security.auth.selectedType", FindingAuthPinsVendorHost, "", classGoogleSignIn, "gemini-cli/user-settings"}},
		},
		{
			name: "CLI-6: an administrator enforces Vertex AI", fam: "gemini-cli/security.auth.enforcedType",
			files: []LayerFile{lf(t, "gemini-cli/system-settings", "", map[string]any{"security": map[string]any{"auth": map[string]any{"enforcedType": "vertex-ai"}}})},
			want:  []briefFinding{{"gemini-cli/security.auth.enforcedType", FindingAuthPinsVendorHost, "", classVertex, "gemini-cli/system-settings"}},
		},
		{
			name: "CLI-7: aider's .env overrides the launcher route", fam: "aider/openai-api-base",
			runtime: []RuntimeTree{
				{Tool: "aider", Layer: RuntimeLaunchEnv, Tree: map[string]any{"openai-api-base": loop + "/v1"}},
				{Tool: "aider", Layer: RuntimeDotenv, Tree: map[string]any{"openai-api-base": other}},
			},
			want: []briefFinding{{"aider/openai-api-base", FindingRouteShadowed, "", classOtherHost, "runtime:dotenv"}},
		},
		{
			name: "CLI-7: a project .env sets OPENAI_API_BASE (key presence only)", fam: "aider/openai-api-base",
			runtime: []RuntimeTree{
				{Tool: "aider", Layer: RuntimeLaunchEnv, Tree: map[string]any{"openai-api-base": loop + "/v1"}},
				{Tool: "aider", Layer: RuntimeDotenv, Project: p, Tree: map[string]any{"openai-api-base": KeyPresent{}}},
			},
			want: []briefFinding{{"aider/openai-api-base", FindingProjectRouteOverride, p, classSet, "runtime:dotenv"}},
		},
		{
			name: "CLI-7: a project .aider.conf.yml sets openai-api-base", fam: "aider/openai-api-base",
			files:   []LayerFile{lf(t, "aider/project-conf", p, map[string]any{"openai-api-base": other})},
			runtime: []RuntimeTree{{Tool: "aider", Layer: RuntimeLaunchEnv, Tree: map[string]any{"openai-api-base": loop + "/v1"}}},
			want:    []briefFinding{{"aider/openai-api-base", FindingProjectRouteOverride, p, classOtherHost, "aider/project-conf"}},
		},
		{
			name: "W-6: an empty workspace pre_tool_use array drops Observer's group", fam: "vtcode/hooks.lifecycle.pre_tool_use",
			files: []LayerFile{
				lf(t, "vtcode/user-config", "", vtArr("/usr/local/bin/observer hook vtcode PreToolUse")),
				lf(t, "vtcode/workspace-config", p, map[string]any{"hooks": map[string]any{"lifecycle": map[string]any{"pre_tool_use": []any{}}}}),
			},
			want: []briefFinding{{"vtcode/hooks.lifecycle.pre_tool_use", FindingHookArrayReplaced, p, classEmpty, "vtcode/workspace-config"}},
		},
		{
			name: "W-6: a workspace array without Observer's command replaces it", fam: "vtcode/hooks.lifecycle.pre_tool_use",
			files: []LayerFile{
				lf(t, "vtcode/user-config", "", vtArr("observer hook vtcode PreToolUse")),
				lf(t, "vtcode/workspace-root-config", p, vtArr("./lint.sh")),
			},
			want: []briefFinding{{"vtcode/hooks.lifecycle.pre_tool_use", FindingHookArrayReplaced, p, classWithout, "vtcode/workspace-root-config"}},
		},
		{
			name: "W-6/FU-51: use_root_config drops the user layer", fam: "",
			files: []LayerFile{
				lf(t, "vtcode/user-config", "", vtArr("observer hook vtcode PreToolUse")),
				lf(t, "vtcode/workspace-root-config", p, map[string]any{"workspace": map[string]any{"use_root_config": true}}),
			},
			want: []briefFinding{{"vtcode/workspace.use_root_config", FindingLayersDropped, p, classOn, "vtcode/workspace-root-config"}},
		},
		{
			name: "S-22: Stakpak reads only the first MCP file it finds", fam: "stakpak/mcp",
			files: []LayerFile{
				lf(t, "stakpak/user-mcp-json", "", map[string]any{"mcpServers": map[string]any{}}),
				lf(t, "stakpak/project-mcp-toml", p, map[string]any{}),
			},
			want: []briefFinding{{"stakpak/mcp", FindingMCPFirstFileOnly, p, classPresent, "stakpak/project-mcp-toml"}},
		},
		{
			name: "IDE-3: VS Code hands Claude Code the vendor host", fam: "copilot/claudeCode.environmentVariables",
			files: []LayerFile{lf(t, "copilot/user-settings", "", map[string]any{"claudeCode.environmentVariables": []any{
				map[string]any{"name": "ANTHROPIC_BASE_URL", "value": vendor},
			}})},
			want: []briefFinding{{"copilot/claudeCode.environmentVariables", FindingIDERouteOverride, "", classVendorHost, "copilot/user-settings"}},
		},
		{
			name: "IDE-3: a workspace value replaces the user array", fam: "copilot/claudeCode.environmentVariables",
			files: []LayerFile{
				lf(t, "copilot/user-settings", "", map[string]any{"claudeCode.environmentVariables": []any{map[string]any{"name": "ANTHROPIC_BASE_URL", "value": vendor}}}),
				lf(t, "copilot/workspace-settings", p, map[string]any{"claudeCode.environmentVariables": []any{map[string]any{"name": "OTHER", "value": "x"}}}),
			},
			want: []briefFinding{{"copilot/claudeCode.environmentVariables", FindingIDERouteOverride, "", classVendorHost, "copilot/user-settings"}},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := LayerInput{Files: tc.files, Runtime: tc.runtime, Projects: []string{p}, Classify: ClassifyContext{OwnHookCommand: own}}
			if tc.fam != "" {
				f, ok := FamilyByID(tc.fam)
				if !ok {
					t.Fatalf("no family %s", tc.fam)
				}
				in.Families = []Family{f}
			}
			got, err := EvaluateLayers(in)
			if err != nil {
				t.Fatal(err)
			}
			if b := brief(got); !reflect.DeepEqual(b, tc.want) {
				t.Errorf("got  %+v\nwant %+v", b, tc.want)
			}
		})
	}
}

// TestShadowedRoutes pins the RouteShadowed shape (CLI-2): the file the tool
// uses instead of Observer's route.
func TestShadowedRoutes(t *testing.T) {
	fs := []LayerFinding{
		{Tool: "qwen-code", Code: FindingProjectRouteOverride, Project: "/w", Key: KeyPath{"model", "baseUrl"}, Class: classOtherHost, Winning: SourceRef{FileID: "qwen-code/project-settings"}},
		{Tool: "claude-code", Code: FindingRouteShadowed, Key: KeyPath{"env", "ANTHROPIC_BASE_URL"}, Class: classVendorHost, Winning: SourceRef{Runtime: RuntimeLaunchEnv}},
		{Tool: "gemini-cli", Code: FindingHooksDisabled},
	}
	want := []RouteShadowed{
		{Tool: "qwen-code", FileRowID: "qwen-code/project-settings", Project: "/w", Key: KeyPath{"model", "baseUrl"}, Class: classOtherHost},
		{Tool: "claude-code", Runtime: RuntimeLaunchEnv, Key: KeyPath{"env", "ANTHROPIC_BASE_URL"}, Class: classVendorHost},
	}
	if got := ShadowedRoutes(fs); !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// TestURLClass pins the URL classes.
func TestURLClass(t *testing.T) {
	for in, want := range map[string]string{
		"http://127.0.0.1:8820":        classLoopback,
		"http://localhost:8820/v1":     classLoopback,
		"http://[::1]:8820":            classLoopback,
		"https://api.anthropic.com":    classVendorHost,
		"https://API.OPENAI.COM/v1":    classVendorHost,
		"https://gateway.example.com":  classOtherHost,
		"":                             classEmpty,
		"not a url":                    classValue,
		"ftp://127.0.0.1":              classValue,
		"http://127.0.0.1.example.com": classOtherHost,
	} {
		if got := urlClass(in); got != want {
			t.Errorf("urlClass(%q) = %s, want %s", in, got, want)
		}
	}
}
