package orgcontract

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeSecurityManagedPolicy(t *testing.T) {
	good := `{"version":1,"components":["security.deps","security.trust"],"drivers":["scalibr"],"scanner_source":"org_mirror","scan_schedule":"daily","org_dedupe_key":"acme-2026","custom_manifests":["sha256:` + strings.Repeat("e", 64) + `"],"online_checks":"on","finding_share":"findings","feedback":"off","ai_change_record":"org","defaults":{"cpu_priority":"low","pause_on_battery":true,"statusline_segment":false,"mcp_tools":true,"notify_critical":false}}`
	p, ok, err := DecodeSecurityManagedPolicy([]byte(good))
	if err != nil || !ok || len(p.Components) != 2 || p.Defaults == nil {
		t.Fatalf("good body: %+v %v %v", p, ok, err)
	}
	for _, none := range []string{`{}`, `null`, ``, "  "} {
		if _, ok, err := DecodeSecurityManagedPolicy([]byte(none)); ok || err != nil {
			t.Errorf("%q: the kit's none must decode to nothing, got ok=%v err=%v", none, ok, err)
		}
	}
}

// TestSecurityManagedPolicyRefusals is one refusal per thing the body may
// never carry, and per closed vocabulary.
func TestSecurityManagedPolicyRefusals(t *testing.T) {
	cases := map[string]string{
		// No credential, executable path or argument has a field.
		"credential field":       `{"version":1,"token":"s3cr3t"}`,
		"api key field":          `{"version":1,"relay":{"api_key":"k"}}`,
		"executable path field":  `{"version":1,"scanner_path":"/usr/bin/osv-scanner"}`,
		"arguments field":        `{"version":1,"args":["--online"]}`,
		"path as a driver":       `{"version":1,"drivers":["/opt/evil/scan"]}`,
		"argument as a driver":   `{"version":1,"drivers":["osv --download"]}`,
		"path as a manifest":     `{"version":1,"custom_manifests":["/etc/manifest.json"]}`,
		"key material as dedupe": `{"version":1,"org_dedupe_key":"-----BEGIN PRIVATE KEY-----"}`,
		// Never git hooks (PR11).
		"git hooks": `{"version":1,"components":["security.githooks"]}`,
		// Closed vocabularies.
		"vendor source":     `{"version":1,"scanner_source":"vendor_release"}`,
		"unknown schedule":  `{"version":1,"scan_schedule":"weekly"}`,
		"unknown component": `{"version":1,"components":["guard"]}`,
		"empty list":        `{"version":1,"drivers":[]}`,
		"bad share":         `{"version":1,"finding_share":"content"}`,
		"bad default":       `{"version":1,"defaults":{"cpu_priority":"high"}}`,
		"unknown default":   `{"version":1,"defaults":{"shell":"bash"}}`,
		"wrong version":     `{"version":2}`,
		"missing version":   `{"components":["security.trust"]}`,
		"trailing data":     `{"version":1} {}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeSecurityManagedPolicy([]byte(body)); !errors.Is(err, ErrSecurityManagedPolicy) {
				t.Fatalf("err = %v, want a refusal", err)
			}
		})
	}
}

func TestCanonicalSecurityManagedPolicy(t *testing.T) {
	a, err := CanonicalSecurityManagedPolicy(SecurityManagedPolicyV1{Version: 1, Components: []string{"security.trust", "security.deps", "security.trust"}})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := CanonicalSecurityManagedPolicy(SecurityManagedPolicyV1{Version: 1, Components: []string{"security.deps", "security.trust"}})
	if string(a) != string(b) {
		t.Fatalf("not canonical: %s vs %s", a, b)
	}
	if _, err := CanonicalSecurityManagedPolicy(SecurityManagedPolicyV1{Version: 1, ScannerSource: "user_installed"}); err == nil {
		t.Fatal("canonical must validate")
	}
}

func TestSecurityManagedPolicyEnables(t *testing.T) {
	if why := SecurityManagedPolicyEnables(SecurityManagedPolicyV1{Version: 1, ScanSchedule: "daily", FindingShare: "posture"}); len(why) != 0 {
		t.Fatalf("a schedule and a share level enable nothing: %v", why)
	}
	if why := SecurityManagedPolicyEnables(SecurityManagedPolicyV1{Version: 1, OnlineChecks: "on"}); len(why) != 1 {
		t.Fatalf("online on: %v", why)
	}
	if why := SecurityManagedPolicyEnables(SecurityManagedPolicyV1{Version: 1, Components: []string{"security.trust"}, Drivers: []string{"osv"}}); len(why) != 2 {
		t.Fatalf("components and drivers: %v", why)
	}
}
