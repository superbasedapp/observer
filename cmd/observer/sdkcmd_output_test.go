package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
)

// TestSDKStatusShowsTheWorkspaceAndCaptureLevel pins review L-23: `observer
// sdk status` names the key's workspace and that workspace's capture level.
func TestSDKStatusShowsTheWorkspaceAndCaptureLevel(t *testing.T) {
	var out bytes.Buffer
	printSDKStatus(&out, sdkcredsvc.Discovery{
		Destination: "both", Source: "default_signed_in", SignedIn: true,
		Online: sdkcredsvc.DiscoveryOnline{CredentialPresent: true, KeyID: "ik_1", WorkspaceID: "default", CaptureLevel: sdkcredsvc.CaptureMetadataOnly},
	})
	if !strings.Contains(out.String(), "workspace:   default, capture level L0, metadata only") {
		t.Fatalf("status output:\n%s", out.String())
	}
	out.Reset()
	printSDKWorkspace(&out, "the key sends to workspace ", "", "")
	if got := out.String(); !strings.Contains(got, "(not reported), capture level not reported") {
		t.Fatalf("unknown workspace and level: %q", got)
	}
}
