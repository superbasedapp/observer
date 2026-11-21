package sandboxremote

import (
	"strings"
	"testing"
)

// TestConsentLinesForAnOrgPublishedVendor (FX1 item 8, live finding
// F-L3-7): the org-hosted row's consent screen says the box runs on the
// organization's machines (not "on <row label>'s machines") and gives no
// estimate with empty fields; a priced vendor keeps both lines as before.
func TestConsentLinesForAnOrgPublishedVendor(t *testing.T) {
	line := func(scr ConsentScreen, label string) string {
		for _, l := range scr.Lines {
			if l.Label == label {
				return l.Value
			}
		}
		t.Fatalf("no %q line", label)
		return ""
	}
	org, _ := VendorFor(VendorOpenShellOrg)
	f := ConsentFacts{Provider: org.ID, Region: RegionOrgPublished, Endpoint: "https://sandbox.example.com", Tier: "proxy_only", Capture: "full"}
	scr := BuildConsentScreen(org, f, Manifest{Root: "/home/dev/app"}, org.EstimateCost(60))
	if got := line(scr, "Where the box runs"); !strings.HasPrefix(got, "on your organization's machines") || strings.Contains(got, org.Name) {
		t.Errorf("where: %q", got)
	}
	if got := line(scr, "Estimated cost"); strings.Contains(got, "estimate: ,") || strings.Contains(got, "list price read ;") || !strings.Contains(got, "organization's compute") {
		t.Errorf("cost: %q", got)
	}
	e2b, _ := VendorFor(VendorE2B)
	scr = BuildConsentScreen(e2b, ConsentFacts{Provider: e2b.ID, Region: "us"}, Manifest{}, e2b.EstimateCost(60))
	if got := line(scr, "Where the box runs"); !strings.HasPrefix(got, "on "+e2b.Name+"'s machines") {
		t.Errorf("e2b where: %q", got)
	}
	if got := line(scr, "Estimated cost"); !strings.Contains(got, "list price read "+e2b.Price.Date) || e2b.Price.Date == "" {
		t.Errorf("e2b cost: %q", got)
	}
}
