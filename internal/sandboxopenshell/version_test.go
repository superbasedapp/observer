package sandboxopenshell

import (
	"strings"
	"testing"
)

func TestParseVersion(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"openshell 0.1.6", "0.1.6", true},
		{"openshell-gateway 0.1.6\n", "0.1.6", true},
		{"0.1.6", "0.1.6", true},
		{"v0.1.6", "0.1.6", true},
		{"openshell 0.1.7-rc.1", "0.1.7-rc.1", true},
		{"openshell 0.1.6 (3a5dfcd)", "0.1.6", true},
		{"openshell 0.1.6+local", "0.1.6+local", true},
		{"openshell 0.1.7-rc.1+dirty.2", "0.1.7-rc.1+dirty.2", true},
		{"openshell", "", false},
		{"", "", false},
		{"build 10.2", "", false},
	}
	for _, tc := range cases {
		v, err := ParseVersion(tc.in)
		if (err == nil) != tc.ok {
			t.Errorf("%q: err %v, want ok %v", tc.in, err, tc.ok)
			continue
		}
		if tc.ok && v.String() != tc.want {
			t.Errorf("%q: %s, want %s", tc.in, v, tc.want)
		}
	}
}

// TestCheckVersionTable: one case per row of the version table, in order.
func TestCheckVersionTable(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		f       VersionFacts
		verdict string
		reason  string
	}{
		{"cli unreadable", VersionFacts{CLI: "garbage", Gateway: "0.1.6"}, VerdictVersionUnknown, "CLI"},
		{"gateway unreadable", VersionFacts{CLI: "openshell 0.1.6", Gateway: ""}, VerdictVersionUnknown, "gateway"},
		{"pin unreadable", VersionFacts{CLI: "openshell 0.1.6", Gateway: "0.1.6", Pin: "latest"}, VerdictVersionUnknown, "version is not a version"},
		{"cli and gateway differ", VersionFacts{CLI: "openshell 0.1.5", Gateway: "0.1.6"}, VerdictVersionMismatch, "same version"},
		{"below the floor", VersionFacts{CLI: "openshell 0.1.5", Gateway: "0.1.5"}, VerdictVersionTooOld, "floor 0.1.6"},
		{"pin differs", VersionFacts{CLI: "openshell 0.1.6", Gateway: "0.1.6", Pin: "0.1.7"}, VerdictVersionPinMismatch, "pins 0.1.7"},
		{"newer untested", VersionFacts{CLI: "openshell 0.1.7", Gateway: "0.1.7"}, VerdictVersionUntested, "tested: 0.1.6"},
		{"pre-release untested", VersionFacts{CLI: "openshell 0.1.6-rc.2", Gateway: "0.1.6-rc.2"}, VerdictVersionUntested, "not a tested version"},
		{"build metadata untested", VersionFacts{CLI: "openshell 0.1.6+local", Gateway: "0.1.6+local"}, VerdictVersionUntested, "0.1.6+local is not a tested version"},
		{"build metadata on one side only", VersionFacts{CLI: "openshell 0.1.6+local", Gateway: "0.1.6"}, VerdictVersionMismatch, "same version"},
		{"tested", VersionFacts{CLI: "openshell 0.1.6", Gateway: "0.1.6"}, "", ""},
		{"tested with matching pin", VersionFacts{CLI: "openshell 0.1.6", Gateway: "v0.1.6", Pin: "v0.1.6"}, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := CheckVersion(tc.f)
			if r.Verdict != tc.verdict || !strings.Contains(r.Reason, tc.reason) {
				t.Fatalf("got %+v, want verdict %q reason containing %q", r, tc.verdict, tc.reason)
			}
			if r.Verdict == "" && r.Row.Receipt == "" {
				t.Fatalf("a usable version without its tested row: %+v", r)
			}
		})
	}
}

// TestTestedVersionTableIsGrounded: every row cites a receipt, carries its
// not-found text, and is at or above the floor.
func TestTestedVersionTableIsGrounded(t *testing.T) {
	t.Parallel()
	rows := TestedVersions()
	if len(rows) == 0 {
		t.Fatal("no tested version")
	}
	for _, r := range rows {
		if r.Version.less(FloorVersion) || r.Version.Pre != "" || r.Version.Build != "" {
			t.Errorf("%s: below the floor, a pre-release or a build with metadata", r.Version)
		}
		if !strings.Contains(r.Receipt, "_spikes/openshell/receipts/") || r.NotFoundText == "" {
			t.Errorf("%s: receipt %q not-found %q", r.Version, r.Receipt, r.NotFoundText)
		}
	}
	if rows[0].Version != FloorVersion {
		t.Errorf("the first tested version %s is not the floor %s", rows[0].Version, FloorVersion)
	}
}
