package integration

import (
	"reflect"
	"regexp"
	"testing"
)

// TestClassifyHostedRouteRules pins the ordered hosted-route table: one case
// per rule, plus the ordering cases that make the table's precedence visible.
func TestClassifyHostedRouteRules(t *testing.T) {
	childEnv := WrapSpec{Kind: WrapChildEnv, Env: []WrapEnvVar{
		{Name: "ANTHROPIC_BASE_URL"}, {Name: "OPENAI_BASE_URL", Suffix: "/v1"},
	}}
	tests := []struct {
		name string
		in   HostedRouteInput
		want HostedRoute
	}{
		{
			name: "own product with no wrap outranks the CLI's persisted route",
			in: HostedRouteInput{
				Cap:        Capability{Proxy: &ProxyRoute{Kind: RouteProviderJSON}, Routability: RouteStatusRoutableNow},
				Wrap:       WrapSpec{Kind: WrapNone, Reason: "hosted gateway"},
				OwnProduct: true,
			},
			want: HostedRouteLauncherOnly,
		},
		{
			name: "own product WITH a wrap keeps its persisted route",
			in: HostedRouteInput{
				Cap:        Capability{Proxy: &ProxyRoute{Kind: RouteProviderJSON}},
				Wrap:       WrapSpec{Kind: WrapConfigWrite, ConfigTool: "x"},
				OwnProduct: true,
			},
			want: HostedRoutePersisted,
		},
		{
			name: "persisted env-settings route",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteEnvSettings, EnvVar: "ANTHROPIC_BASE_URL"}}, Wrap: childEnv},
			want: HostedRoutePersisted,
		},
		{
			name: "persisted config-file route",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteConfigFile}}},
			want: HostedRoutePersisted,
		},
		{
			name: "launcher env var exported by the wrap with the same suffix",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteLauncher, EnvVar: "OPENAI_BASE_URL", Suffix: "/v1"}}, Wrap: childEnv},
			want: HostedRouteLaunchEnv,
		},
		{
			name: "same env var but a different suffix is not an export",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteLauncher, EnvVar: "OPENAI_BASE_URL"}}, Wrap: childEnv},
			want: HostedRouteLauncherOnly,
		},
		{
			name: "launcher env var the wrap does not export",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteLauncher, EnvVar: "COPILOT_PROVIDER_BASE_URL", Suffix: "/v1"}}, Wrap: childEnv},
			want: HostedRouteLauncherOnly,
		},
		{
			name: "launcher route under a WrapNone host",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteLauncher, EnvVar: "OPENAI_BASE_URL", Suffix: "/v1"}}, Wrap: WrapSpec{Reason: "r"}},
			want: HostedRouteLauncherOnly,
		},
		{
			name: "manual-kind proxy route",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteManual}}},
			want: HostedRouteManual,
		},
		{
			name: "vscode-settings-kind proxy route",
			in:   HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: RouteVSCodeSettings}}},
			want: HostedRouteManual,
		},
		{
			name: "routable_now knob with no driven route",
			in:   HostedRouteInput{Cap: Capability{Routability: RouteStatusRoutableNow}},
			want: HostedRouteManual,
		},
		{
			name: "probe_required",
			in:   HostedRouteInput{Cap: Capability{Routability: RouteStatusProbeRequired}},
			want: HostedRouteUnproven,
		},
		{
			name: "after_upstream",
			in:   HostedRouteInput{Cap: Capability{Routability: RouteStatusAfterUpstream}},
			want: HostedRouteUnproven,
		},
		{
			name: "after_bridge",
			in:   HostedRouteInput{Cap: Capability{Routability: RouteStatusAfterBridge}},
			want: HostedRouteUnproven,
		},
		{
			name: "native_exempt",
			in:   HostedRouteInput{Cap: Capability{Routability: RouteStatusNativeExempt}},
			want: HostedRouteNotRoutable,
		},
		{
			name: "unclassified zero value claims nothing",
			in:   HostedRouteInput{},
			want: HostedRouteUnclassified,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyHostedRoute(tt.in); got != tt.want {
				t.Errorf("ClassifyHostedRoute = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestEveryRouteKindHasAWrappedOutcome pins that no RouteKind falls through
// the hosted-route table: whatever mechanism a future registry row declares,
// a wrapped IDE launch has a defined, non-zero answer for it.
func TestEveryRouteKindHasAWrappedOutcome(t *testing.T) {
	want := map[RouteKind][]HostedRoute{
		RouteLauncher:       {HostedRouteLaunchEnv, HostedRouteLauncherOnly},
		RouteEnvSettings:    {HostedRoutePersisted},
		RouteConfigFile:     {HostedRoutePersisted},
		RouteProviderJSON:   {HostedRoutePersisted},
		RouteVSCodeSettings: {HostedRouteManual},
		RouteManual:         {HostedRouteManual},
	}
	if len(want) != len(AllRouteKinds()) {
		t.Fatalf("AllRouteKinds has %d kinds, the expectation table %d - add the new kind here", len(AllRouteKinds()), len(want))
	}
	wrap := WrapSpec{Kind: WrapChildEnv, Env: []WrapEnvVar{{Name: "X_BASE_URL"}}}
	for _, k := range AllRouteKinds() {
		allowed, ok := want[k]
		if !ok {
			t.Errorf("RouteKind %q has no expected wrapped outcome", k)
			continue
		}
		for _, exported := range []bool{true, false} {
			env := "Y_BASE_URL"
			if exported {
				env = "X_BASE_URL"
			}
			got := ClassifyHostedRoute(HostedRouteInput{Cap: Capability{Proxy: &ProxyRoute{Kind: k, EnvVar: env}}, Wrap: wrap})
			found := false
			for _, a := range allowed {
				if got == a {
					found = true
				}
			}
			if !found {
				t.Errorf("RouteKind %q (exported=%v) -> %q, want one of %v", k, exported, got, allowed)
			}
		}
	}
}

// TestEveryGUIRowHasAWrappedLaunchOutcome sweeps the live GUI table: every
// offered row resolves to its `observer ide <id>` wrapped command, every
// hosted agent gets a classified outcome, and no row claims traffic proof
// without dated evidence.
func TestEveryGUIRowHasAWrappedLaunchOutcome(t *testing.T) {
	datedProof := regexp.MustCompile(`^\d{4}-\d{2}-\d{2}: \S`)
	for _, g := range GUILaunchables() {
		id := g.Spec.ID
		for _, r := range HostedRoutes(g) {
			if r.Outcome == HostedRouteUnclassified {
				t.Errorf("GUI row %q: hosted agent %q has no classified wrapped-launch outcome (Routability %q)",
					id, r.Tool, r.Routability)
			}
		}
		if p := g.Spec.Wrap.TrafficProof; p != "" {
			if g.Spec.Wrap.Kind != WrapChildEnv {
				t.Errorf("GUI row %q: TrafficProof set on a %q wrap - only an injected wrap can be traffic-proven", id, g.Spec.Wrap.Kind)
			}
			if !datedProof.MatchString(p) {
				t.Errorf("GUI row %q: TrafficProof %q must start with the dated evidence \"YYYY-MM-DD: ...\"", id, p)
			}
		}
		for _, seg := range g.Spec.Wrap.HandoffPathSegments {
			if g.Spec.Wrap.Kind != WrapChildEnv {
				t.Errorf("GUI row %q: HandoffPathSegments on a %q wrap - only an injected wrap can be defeated by a hand-off", id, g.Spec.Wrap.Kind)
			}
			if seg == "" || regexp.MustCompile(`[/\\]`).MatchString(seg) {
				t.Errorf("GUI row %q: hand-off segment %q must be one non-empty path segment", id, seg)
			}
		}
		w, ok := WrappedCommandFor(id)
		if ok != g.Advertised() {
			t.Errorf("GUI row %q: WrappedCommandFor ok=%v, want %v (advertised)", id, ok, g.Advertised())
			continue
		}
		if !ok {
			continue
		}
		if w.Kind != LaunchKindGUI || !reflect.DeepEqual(w.Args, []string{GUILaunchVerb, id}) {
			t.Errorf("GUI row %q: wrapped command = %+v, want kind gui args [%s %s]", id, w, GUILaunchVerb, id)
		}
		if w.Routes != (g.Spec.Wrap.Kind == WrapChildEnv) {
			t.Errorf("GUI row %q: Routes = %v but wrap kind is %q", id, w.Routes, g.Spec.Wrap.Kind)
		}
		if w.TrafficProven != (g.Spec.Wrap.TrafficProof != "" && w.Routes) {
			t.Errorf("GUI row %q: TrafficProven = %v disagrees with TrafficProof %q", id, w.TrafficProven, g.Spec.Wrap.TrafficProof)
		}
	}
}

// TestGUILaunchVerbDisjointFromToolVerbs pins that `observer ide` can never
// shadow (or be shadowed by) a CLI adapter's launcher verb or tool key.
func TestGUILaunchVerbDisjointFromToolVerbs(t *testing.T) {
	if _, ok := ToolForLaunchSubcommand(GUILaunchVerb); ok {
		t.Fatalf("GUILaunchVerb %q collides with a registry Handoff.Launch.Subcommand", GUILaunchVerb)
	}
	if _, ok := registry[GUILaunchVerb]; ok {
		t.Fatalf("GUILaunchVerb %q collides with a registry tool key", GUILaunchVerb)
	}
}

// TestWrappedCommandFor pins the item-7 seam on representative rows of each
// shape.
func TestWrappedCommandFor(t *testing.T) {
	tests := []struct {
		id         string
		wantOK     bool
		wantKind   LaunchKind
		wantArgs   []string
		wantRoutes bool
		wantProven bool
	}{
		{"claude-code", true, LaunchKindTerminal, []string{"claude"}, true, true},
		{"vscode", true, LaunchKindGUI, []string{GUILaunchVerb, "vscode"}, true, false},
		{"cursor-ide", true, LaunchKindGUI, []string{GUILaunchVerb, "cursor-ide"}, false, false},
		{"hermes-desktop", false, "", nil, false, false}, // ungrounded, never offered
		{"cline", false, "", nil, false, false},          // an extension has no launch row
		{"no-such-id", false, "", nil, false, false},
	}
	for _, tt := range tests {
		t.Run(tt.id, func(t *testing.T) {
			w, ok := WrappedCommandFor(tt.id)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tt.wantOK)
			}
			if !ok {
				return
			}
			if w.Kind != tt.wantKind || !reflect.DeepEqual(w.Args, tt.wantArgs) ||
				w.Routes != tt.wantRoutes || w.TrafficProven != tt.wantProven {
				t.Errorf("got %+v, want kind=%q args=%q routes=%v proven=%v",
					w, tt.wantKind, tt.wantArgs, tt.wantRoutes, tt.wantProven)
			}
			if len(w.Replaces.Unix) == 0 && len(w.Replaces.Windows) == 0 {
				t.Errorf("Replaces is empty - the wrapped form must name the vendor spelling it stands in for")
			}
		})
	}
}

// TestGUIRowForID pins the id ladder `observer ide` accepts: a GUI id, or an
// adapter key whose adapter carries a GUI row.
func TestGUIRowForID(t *testing.T) {
	tests := []struct {
		id     string
		wantID string
		wantOK bool
	}{
		{"vscode", "vscode", true},
		{"cursor-ide", "cursor-ide", true},
		{"cursor", "cursor-ide", true},
		{"claude-code", "", false}, // no GUI row of its own
		{"nope", "", false},
	}
	for _, tt := range tests {
		g, ok := GUIRowForID(tt.id)
		if ok != tt.wantOK || (ok && g.Spec.ID != tt.wantID) {
			t.Errorf("GUIRowForID(%q) = (%q, %v), want (%q, %v)", tt.id, g.Spec.ID, ok, tt.wantID, tt.wantOK)
		}
	}
}

// TestDocumentedIDEHostMatrix pins the two editor-host rows' per-agent
// outcomes, which docs/proxy-wrappers.md ("`observer ide`") renders as the
// operator matrix. A registry change that moves a cell must update that doc.
func TestDocumentedIDEHostMatrix(t *testing.T) {
	want := map[string]map[string]HostedRoute{
		"vscode": {
			"claude-code": HostedRoutePersisted, "codex": HostedRoutePersisted,
			"cline": HostedRouteManual, "kilo-code": HostedRouteManual,
			"kilo-code-cli": HostedRouteNotRoutable, "copilot": HostedRouteUnproven,
			"gemini-cli": HostedRouteLaunchEnv, "qwen-code": HostedRoutePersisted,
			"kimi-code": HostedRoutePersisted, "mistral-code": HostedRouteUnproven,
			"droid": HostedRouteUnproven, "opencode": HostedRouteLaunchEnv,
			"command-code": HostedRouteUnproven,
		},
		"jetbrains-idea": {
			"junie": HostedRouteUnproven, "claude-code": HostedRoutePersisted,
			"codex": HostedRoutePersisted, "kimi-code": HostedRoutePersisted,
			"qwen-code": HostedRoutePersisted, "mistral-code": HostedRouteUnproven,
			"droid": HostedRouteUnproven, "grok": HostedRouteLauncherOnly,
			"copilot-cli": HostedRouteLauncherOnly,
		},
	}
	for id, cells := range want {
		g, ok := GUILaunchFor(id)
		if !ok {
			t.Fatalf("GUI row %q missing", id)
		}
		got := map[string]HostedRoute{}
		for _, r := range HostedRoutes(g) {
			got[r.Tool] = r.Outcome
		}
		if !reflect.DeepEqual(got, cells) {
			t.Errorf("GUI row %q hosted matrix drifted (update docs/proxy-wrappers.md):\n got %v\nwant %v", id, got, cells)
		}
	}
}
