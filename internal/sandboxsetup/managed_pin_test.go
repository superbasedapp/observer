package sandboxsetup

import (
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
)

// managed_pin_test.go pins D-L7-1 (fix round 3, item 8): on a managed node
// with no org mirror a grounded pinned download reads the mirror sentence,
// never fetches from the vendor, and stays runnable from a file the person
// names; an ungrounded pin keeps reading pin_unavailable; an individual
// node is unchanged.
func TestManagedPinnedDownload(t *testing.T) {
	grounded := Pin{ID: "cloud-hypervisor", Version: "54.0", GOOS: "linux", GOARCH: "amd64", URL: "https://example.invalid/ch", SHA256: strings.Repeat("a", 64), Size: 4 << 20, Status: PinGrounded}
	owed := grounded
	owed.Status = PinOwed
	cases := []struct {
		name       string
		managed    bool
		source     string
		pin        Pin
		wantRun    bool
		wantReason string
		wantSource string
		wantURL    bool
	}{
		{"managed with a grounded pin", true, "", grounded, true, reasonManagedNoMirror, SourceFromFile, false},
		{"managed with an ungrounded pin", true, "", owed, false, reasonPinUnavailable, "", false},
		{"individual with a grounded pin", false, SourceVendorRelease, grounded, true, "", SourceVendorRelease, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withPins(t, tc.pin)
			in := base(t, sandboxbackend.BackendCloudHypervisor)
			in.Managed, in.DownloadSource = tc.managed, tc.source
			in.Facts = map[string]Fact{"cloud-hypervisor": {Checked: true}}
			st := stepOf(t, Build(in), "cloud-hypervisor")
			if st.CanRun != tc.wantRun {
				t.Fatalf("can_run = %v, want %v (%+v)", st.CanRun, tc.wantRun, st)
			}
			if tc.wantReason != "" && !strings.Contains(st.Reason, tc.wantReason) {
				t.Errorf("reason = %q, want it to hold %q", st.Reason, tc.wantReason)
			}
			if tc.wantReason == "" && (strings.Contains(st.Reason, reasonManagedNoMirror) || strings.Contains(st.Reason, reasonPinUnavailable)) {
				t.Errorf("an individual node's step reads %q", st.Reason)
			}
			if tc.wantSource == "" {
				if st.Consent != nil {
					t.Errorf("consent = %+v, want none", st.Consent)
				}
				return
			}
			if st.Consent == nil || st.Consent.Source != tc.wantSource || st.Consent.SHA256 != grounded.SHA256 || (st.Consent.URL != "") != tc.wantURL {
				t.Errorf("consent = %+v, want source %s url %v", st.Consent, tc.wantSource, tc.wantURL)
			}
		})
	}
}
