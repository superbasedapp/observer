package settingsgate

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/configschema"
)

// planeAKeyExceptions are the Plane A keys that lack a UI, CLI or MCP write
// path on purpose, each with its reason (principle 10's allow-list). A key
// here still READS everywhere (Settings shows it read-only, `observer config
// get|list`, MCP get_settings).
var planeAKeyExceptions = map[string]string{
	"observability.admission.criterion":          "a compound table of admission rules (name, prompt, threshold, action); edited in config.toml, the generic editor renders no table rows",
	"observability.alerts.rules":                 "a compound table of alert rules; edited in config.toml, the generic editor renders no table rows",
	"observability.alerts.pagerduty_routing_key": "a T2 secret, a PagerDuty Events API v2 routing key (lane C9, ALERT-PD-2): written only by the owner-local PUT /api/obs/alerts/pagerduty and `observer obs alerts pagerduty set` (stdin), refused by the generic editor and `observer config set`, and never offered to MCP, where a coding agent would hold the credential; it reads redacted",
	"observability.alerts.slack_webhook_url":     "a T2 secret, a bearer webhook URL (lane B9, ALERT-SLACK-2): written only by the owner-local PUT /api/obs/alerts/slack and `observer obs alerts slack set` (stdin), refused by the generic editor and `observer config set`, and never offered to MCP, where a coding agent would hold the credential; it reads redacted",
	"observability.egress.rules":                 "a compound table of first-match egress rules; edited in config.toml, the generic editor renders no table rows",
	"observability.egress.targets":               "a compound table of typed upstream targets; edited in config.toml, the generic editor renders no table rows",
}

// isPlaneAKey is the Plane A scope of the parity rule: the observability
// block (D18's [observability.sdk] included).
func isPlaneAKey(l configschema.Leaf) bool {
	return l.Block == "observability"
}

// webSettingsSections reads the node dashboard's SectionId union, the
// sections whose keys the Settings page renders (schema-driven SchemaSection
// for every section without a bespoke page).
func webSettingsSections(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("../../web/src/pages/Settings.tsx")
	if err != nil {
		t.Fatalf("read the node Settings page: %v", err)
	}
	m := regexp.MustCompile(`(?s)type SectionId =(.*?);`).FindSubmatch(src)
	if m == nil {
		t.Fatal("SectionId union not found in web/src/pages/Settings.tsx")
	}
	out := map[string]bool{}
	for _, q := range regexp.MustCompile(`"([a-z0-9-]+)"`).FindAllSubmatch(m[1], -1) {
		out[string(q[1])] = true
	}
	return out
}

// sampleValue is a value the gate is asked about: for the destination the
// one that needs the most (online); otherwise any value (the gate's verdict
// for a non-destination key does not depend on it).
func sampleValue(l configschema.Leaf) string {
	if l.Path == "observability.sdk.destination" {
		return "online"
	}
	return "x"
}

// TestEveryPlaneAKeyIsReachableFromUICLIAndMCP is principle 10's parity
// gate: every Plane A config key has a dashboard control (its Settings
// section renders it), a CLI write (`observer config set` accepts it) and
// an MCP path (set_setting applies or proposes it, never refuses), or a
// reasoned exception above.
func TestEveryPlaneAKeyIsReachableFromUICLIAndMCP(t *testing.T) {
	sections := webSettingsSections(t)
	seen := map[string]bool{}
	var missing []string
	for _, l := range configschema.Leaves() {
		if !isPlaneAKey(l) {
			continue
		}
		seen[l.Path] = true
		c := configschema.CheckKey(l.Path, nil)
		ui := l.Section != "" && sections[l.Section] && c.Verdict == configschema.KeyOK && l.Kind.Writable()
		cli := c.Verdict == configschema.KeyOK && l.Kind.Writable()
		mcp := Decide(l.Path, sampleValue(l), nil).Verdict != Refuse
		_, excepted := planeAKeyExceptions[l.Path]
		switch {
		case ui && cli && mcp && excepted:
			t.Errorf("%s is reachable everywhere now; delete its exception", l.Path)
		case !(ui && cli && mcp) && !excepted:
			missing = append(missing, l.Path+" (ui="+yes(ui)+" cli="+yes(cli)+" mcp="+yes(mcp)+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf("Plane A key %s lacks a UI, CLI or MCP path and has no reasoned exception (principle 10)", m)
	}
	for k := range planeAKeyExceptions {
		if !seen[k] {
			t.Errorf("exception %s names no Plane A key", k)
		}
	}
}

func yes(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

// TestTheDestinationIsGatedByValue pins D19's carve-out: only destination
// local applies; the default ("", which a signed-in machine resolves to both,
// review finding R-B02), online and both are proposals, and the gateway
// override is one.
func TestTheDestinationIsGatedByValue(t *testing.T) {
	for v, want := range map[string]Verdict{"local": Apply, " local ": Apply, "": Propose, "  ": Propose, "online": Propose, "both": Propose, "Local": Propose} {
		if got := Decide("observability.sdk.destination", v, nil).Verdict; got != want {
			t.Errorf("destination %q: %s, want %s", v, got, want)
		}
	}
	if !strings.HasPrefix(Decide("observability.sdk.gateway_url", "https://gw", nil).Reason, "it sends") {
		t.Error("the gateway override is a destination proposal")
	}
}
