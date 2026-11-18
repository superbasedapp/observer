package settingslink

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPlaceTable is one case per row: the path the SPA routes and the name
// the dashboard shows. A changed SPA route fails here first.
func TestPlaceTable(t *testing.T) {
	cases := []struct {
		place Place
		href  string
		label string
	}{
		{Components, "/settings/components", "Settings > Components"},
		{TerminalLaunchPolicy, "/terminals?tab=settings#launch-policy", "Terminals > Settings > Fresh-agent launch policy"},
		{SessionAttach, "/settings?section=terminal", "Settings > Session attach"},
		{OTelExport, "/settings?section=otel", "Settings > OTel export"},
		{RemoteAccess, "/remote", "Remote"},
		{Account, "/settings?section=enrolment", "Settings > Account"},
		{ProcessCapture, "/settings?section=process", "Settings > Process capture"},
		{GuardNetwork, "/security?tab=mcp", "Security > MCP > Network features"},
		{TerminalSandbox, "/terminals?tab=settings#sandbox-backends", "Terminals > Settings > Sandbox isolation"},
		{TeamSummaries, "/settings?section=intel", "Settings > Team AI summaries"},
		{TerminalRemoteSystems, "/terminals?tab=settings#remote-systems", "Terminals > Settings > Remote systems (SSH)"},
		{ConnectedTools, "/settings?section=tools", "Settings > Connected tools"},
		{RoutingSettings, "/settings?section=routing", "Settings > Routing"},
		{GuardSettings, "/settings?section=guard", "Settings > Guard"},
		{ObservabilitySettings, "/settings?section=observability", "Settings > Observability"},
		{IntelligenceSettings, "/settings?section=intelligence", "Settings > Intelligence"},
		{SecurityMode, "/security?tab=overview", "Security > Overview > Mode"},
	}
	if len(cases) != len(Places()) {
		t.Fatalf("table has %d places, test covers %d: add a case for the new row", len(Places()), len(cases))
	}
	for _, tc := range cases {
		t.Run(string(tc.place), func(t *testing.T) {
			l, ok := For(tc.place)
			if !ok {
				t.Fatalf("For(%q) not found", tc.place)
			}
			if l.Href != tc.href || l.Label != tc.label {
				t.Fatalf("For(%q) = %+v, want %q %q", tc.place, l, tc.href, tc.label)
			}
		})
	}
}

// TestEveryPlaceIsAnInAppPath pins the shape every client relies on: a
// same-origin path (one leading slash), never a scheme or a protocol-relative
// URL, and a plain label with no dash characters.
func TestEveryPlaceIsAnInAppPath(t *testing.T) {
	seen := map[Place]bool{}
	for _, p := range Places() {
		if seen[p] {
			t.Fatalf("place %q listed twice", p)
		}
		seen[p] = true
		l, _ := For(p)
		if !strings.HasPrefix(l.Href, "/") || strings.HasPrefix(l.Href, "//") || strings.Contains(l.Href, "://") {
			t.Fatalf("%s: %q is not an in-app path", p, l.Href)
		}
		if l.Label == "" || strings.ContainsAny(l.Label, "–—") {
			t.Fatalf("%s: bad label %q", p, l.Label)
		}
	}
}

func TestUnknownPlaceHasNoLink(t *testing.T) {
	if _, ok := For("nope"); ok {
		t.Fatal("an unknown place resolved")
	}
	b := Needs("x_off", "X is off.", "nope")
	if b.Settings != "" || b.SettingsLabel != "" {
		t.Fatalf("unknown place produced a link: %+v", b)
	}
}

func TestComponentLink(t *testing.T) {
	cases := []struct {
		id, href string
	}{
		{"remote", "/settings/components?component=remote"},
		{"terminals.sandbox", "/settings/components?component=terminals.sandbox"},
		{"", "/settings/components"},
		{"a b&c", "/settings/components?component=" + url.QueryEscape("a b&c")},
	}
	for _, tc := range cases {
		if got := Component(tc.id); got.Href != tc.href || got.Label != "Settings > Components" {
			t.Fatalf("Component(%q) = %+v, want %q", tc.id, got, tc.href)
		}
	}
	if got := ComponentCommand("remote"); got != "observer components add remote --yes" {
		t.Fatalf("ComponentCommand = %q", got)
	}
}

// TestBodyShape pins the JSON a client reads: the code and message stay,
// the link fields are added, and a body with no link adds nothing.
func TestBodyShape(t *testing.T) {
	cases := []struct {
		name string
		body Body
		want string
	}{
		{
			"place",
			Needs("guided_install_off", "Guided install is off.", TerminalLaunchPolicy),
			`{"error":"guided_install_off","message":"Guided install is off.","settings":"/terminals?tab=settings#launch-policy","settings_label":"Terminals > Settings > Fresh-agent launch policy"}`,
		},
		{
			"component",
			NeedsComponent("component_not_installed", "Remote dashboard is off.", "remote"),
			`{"error":"component_not_installed","message":"Remote dashboard is off.","settings":"/settings/components?component=remote","settings_label":"Settings > Components","command":"observer components add remote --yes"}`,
		},
		{
			"no link",
			Body{Error: "x", Message: "y"},
			`{"error":"x","message":"y"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := marshalPlain(t, tc.body)
			if raw != tc.want {
				t.Fatalf("got  %s\nwant %s", raw, tc.want)
			}
		})
	}
}

// TestOrgPlaceTable is one case per team-dashboard row: web2's route and
// the name the node shows.
func TestOrgPlaceTable(t *testing.T) {
	cases := []struct {
		place OrgPlace
		href  string
		label string
	}{
		{OrgSessionEnrichment, "https://org.example/intelligence?tab=session-enrichment", "Intelligence > Session enrichment"},
	}
	if len(cases) != len(OrgPlaces()) {
		t.Fatalf("org table has %d places, test covers %d: add a case for the new row", len(OrgPlaces()), len(cases))
	}
	for _, tc := range cases {
		l, ok := OrgFor("https://org.example/", tc.place)
		if !ok || l.Href != tc.href || l.Label != tc.label {
			t.Fatalf("OrgFor(%q) = %+v %v, want %q %q", tc.place, l, ok, tc.href, tc.label)
		}
	}
	if _, ok := OrgFor("https://org.example", "nope"); ok {
		t.Fatal("an unknown org place resolved")
	}
}

// TestOrgDashboardBase pins which org server addresses a button may open.
// Anything else keeps the place's name and drops the URL.
func TestOrgDashboardBase(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://org.example", "https://org.example"},
		{"https://org.example:8443/some/path?q=1", "https://org.example:8443"},
		{" https://org.example/ ", "https://org.example"},
		{"http://127.0.0.1:8443", "http://127.0.0.1:8443"},
		{"http://localhost:9000", "http://localhost:9000"},
		{"http://[::1]:9000", "http://[::1]:9000"},
		{"http://org.example", ""},
		{"https://user:pw@org.example", ""},
		{"javascript:alert(1)", ""},
		{"ftp://org.example", ""},
		{"", ""},
		{"not a url", ""},
	}
	for _, tc := range cases {
		if got := OrgDashboardBase(tc.in); got != tc.want {
			t.Fatalf("OrgDashboardBase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
	l, ok := OrgFor("http://org.example", OrgSessionEnrichment)
	if !ok || l.Href != "" || l.Label == "" {
		t.Fatalf("unsafe base kept a URL: %+v", l)
	}
	if raw := marshalPlain(t, l.Fields()); raw != `{"org_settings_label":"Intelligence > Session enrichment"}` {
		t.Fatalf("org fields = %s", raw)
	}
}

// TestWebPlacesMirrorTheTable keeps web/src/lib/settingsPlaces.ts (the
// dashboard's counterpart for statuses it computes itself) equal to these
// tables, row for row.
func TestWebPlacesMirrorTheTable(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "web", "src", "lib", "settingsPlaces.ts"))
	if err != nil {
		t.Fatalf("read the web table: %v", err)
	}
	re := regexp.MustCompile(`(?m)^\s+([a-z_]+): \{ href: "([^"]+)", label: "([^"]+)" \},$`)
	web := map[string][2]string{}
	for _, m := range re.FindAllStringSubmatch(string(raw), -1) {
		web[m[1]] = [2]string{m[2], m[3]}
	}
	want := map[string][2]string{}
	for _, p := range Places() {
		l, _ := For(p)
		want[string(p)] = [2]string{l.Href, l.Label}
	}
	for _, r := range orgPlaces {
		want[string(r.place)] = [2]string{r.href, r.label}
	}
	for id, w := range want {
		if got, ok := web[id]; !ok || got != w {
			t.Errorf("settingsPlaces.ts row %q = %v, want %v", id, got, w)
		}
	}
	for id := range web {
		if _, ok := want[id]; !ok {
			t.Errorf("settingsPlaces.ts has %q, which the Go tables do not", id)
		}
	}
}

// marshalPlain encodes v without HTML escaping, so a label's ">" reads as
// written (json.Marshal would spell it \u003e; a JSON client reads both).
func marshalPlain(t *testing.T, v any) string {
	t.Helper()
	var b strings.Builder
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(b.String(), "\n")
}
