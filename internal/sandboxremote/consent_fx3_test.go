package sandboxremote

import (
	"strings"
	"testing"
)

// TestRemoteCloneScope (FX3 item 3): the one scope-key owner round-trips,
// and the consent screen of a box-side clone names the URL in full and no
// upload.
func TestRemoteCloneScope(t *testing.T) {
	const url = "https://git.example.com/acme/app.git"
	k := RemoteCloneScopeKey(url)
	if got, ok := RemoteCloneURL(k); !ok || got != url || k != "remote_clone:"+url {
		t.Fatalf("scope %q -> %q %v", k, got, ok)
	}
	if _, ok := RemoteCloneURL(ScopeKey("/w", true, ManifestLimits{})); ok {
		t.Error("an upload scope read as a clone")
	}
	v, _ := VendorFor(VendorE2B)
	scr := BuildConsentScreen(v, ConsentFacts{Provider: v.ID, ScopeKey: k}, Manifest{Root: "/w", ScopeKey: k}, Estimate{})
	if l := scr.Lines[2]; l.Label != "What is uploaded" || !strings.Contains(l.Value, url) || !strings.HasPrefix(l.Value, "nothing from this machine") {
		t.Errorf("upload line %+v", l)
	}
}

// TestSetConsentLineIsByLabel (FX3-A9): the remote-clone upload line is
// found by its label, wherever it sits.
func TestSetConsentLineIsByLabel(t *testing.T) {
	lines := []ConsentLine{{"Endpoint", "e"}, {"Provider", "p"}, {"Capture", "c"}, {"What is uploaded", "files"}}
	setConsentLine(lines, "What is uploaded", "nothing")
	if lines[3].Value != "nothing" || lines[2].Value != "c" {
		t.Fatalf("lines %v", lines)
	}
	setConsentLine(lines, "Absent", "x")
	for _, l := range lines {
		if l.Value == "x" {
			t.Fatalf("an absent label changed a line: %v", lines)
		}
	}
}
