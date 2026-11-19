//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestParseSandboxCLISourceFlags (F-L3R-1): the source and remote flags are
// Observer's, stripped from the inner launch, validated against the closed
// source set; one case per row.
func TestParseSandboxCLISourceFlags(t *testing.T) {
	for _, tc := range []struct {
		name           string
		args           []string
		ok, wantErr    bool
		source, remote string
		rest           []string
	}{
		{"spaced source", []string{"observer", "claude", "--observer-sandbox", "openshell-org", "--observer-sandbox-source", "clone-local", "-p", "hi"}, true, false, "clone-local", "", []string{"-p", "hi"}},
		{"equals source", []string{"observer", "claude", "--observer-sandbox-source=live", "--observer-sandbox=auto"}, true, false, "live", "", nil},
		{"clone-remote with its repository", []string{"observer", "claude", "--observer-sandbox", "openshell-org", "--observer-sandbox-source", "clone-remote", "--observer-sandbox-remote=https://git.example.com/a/b.git"}, true, false, "clone-remote", "https://git.example.com/a/b.git", nil},
		{"after -- it is the tool's", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--", "--observer-sandbox-source", "x"}, true, false, "", "", []string{"--", "--observer-sandbox-source", "x"}},
		{"missing value", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--observer-sandbox-source"}, true, true, "", "", nil},
		{"flag-shaped value", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--observer-sandbox-source", "--model"}, true, true, "", "", nil},
		{"empty equals value", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--observer-sandbox-source="}, true, true, "", "", nil},
		{"unknown source", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--observer-sandbox-source", "copy"}, true, true, "", "", nil},
		{"clone-remote without a repository", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--observer-sandbox-source", "clone-remote"}, true, true, "", "", nil},
		{"a repository without clone-remote", []string{"observer", "claude", "--observer-sandbox", "bwrap", "--observer-sandbox-remote", "https://git.example.com/a.git"}, true, true, "", "", nil},
		{"a source without a sandbox", []string{"observer", "claude", "--observer-sandbox-source", "live"}, true, true, "", "", nil},
	} {
		got, ok, err := parseSandboxCLI(tc.args)
		if ok != tc.ok || (err != nil) != tc.wantErr {
			t.Errorf("%s: ok %v err %v", tc.name, ok, err)
			continue
		}
		if err != nil {
			continue
		}
		if got.Source != tc.source || got.Remote != tc.remote || !reflect.DeepEqual(got.Rest, tc.rest) {
			t.Errorf("%s: %+v", tc.name, got)
		}
	}
}

// TestSandboxCLIWorkspaceSource (F-L3R-1): the flag wins; a row that
// declares no deliveries, or one that can share the live tree, keeps live;
// a row whose deliveries cannot carry live takes the first source its first
// declared delivery carries and says so; a row with no flag-free source
// refuses with the flag to pass. One case per row of the rule.
func TestSandboxCLIWorkspaceSource(t *testing.T) {
	org, ok := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	if !ok || len(org.Deliveries) == 0 {
		t.Fatal("the org row declares no deliveries")
	}
	for _, tc := range []struct {
		name       string
		flag       string
		deliveries []string
		want       workspace.Source
		noted      bool
		refusal    string
	}{
		{"the flag wins", "clone-remote", org.Deliveries, workspace.SourceCloneRemote, false, ""},
		{"no deliveries keeps live", "", nil, workspace.SourceLive, false, ""},
		{"a shared tree keeps live", "", []string{"sync", "bind_same_path"}, workspace.SourceLive, false, ""},
		{"the org row takes clone-local", "", org.Deliveries, workspace.SourceCloneLocal, true, ""},
		{"a remote-clone-only row needs the flag", "", []string{"remote_clone"}, "", false, "--observer-sandbox-source clone-remote"},
	} {
		got, note, err := sandboxCLIWorkspaceSource(tc.flag, tc.deliveries)
		if tc.refusal != "" {
			if err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Errorf("%s: err %v, want %q", tc.name, err, tc.refusal)
			}
			continue
		}
		if err != nil || got != tc.want || (note != "") != tc.noted {
			t.Errorf("%s: %q %q %v", tc.name, got, note, err)
		}
		if tc.noted && !strings.Contains(note, string(tc.want)) {
			t.Errorf("%s: the note does not name the source: %q", tc.name, note)
		}
	}
}

// TestSandboxCLIOrgLaunchIsDelivered (F-L3R-1, the live refusal): the
// source the CLI used to send (live) is refused by the org row's delivery
// rule with source_unsupported; the source the CLI now picks for that row
// with no flag is delivered.
func TestSandboxCLIOrgLaunchIsDelivered(t *testing.T) {
	org, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	cfg := config.TerminalSandboxConfig{}
	if _, err := hostedSourceDelivery(context.Background(), org, termsvc.PrepareRequest{WorkspaceSource: string(workspace.SourceLive)}, sandboxvocab.TierInternet, cfg); err == nil || !strings.Contains(err.Error(), "source_unsupported") {
		t.Fatalf("live on the org row: %v", err)
	}
	src, _, err := sandboxCLIWorkspaceSource("", sandboxCLIRowDeliveries(sandboxremote.VendorOpenShellOrg))
	if err != nil {
		t.Fatal(err)
	}
	d, err := hostedSourceDelivery(context.Background(), org, termsvc.PrepareRequest{WorkspaceSource: string(src)}, sandboxvocab.TierInternet, cfg)
	if err != nil || d.Delivery != workspace.DeliverySync {
		t.Fatalf("the CLI's default on the org row: %+v %v", d, err)
	}
	if got := sandboxCLIRowDeliveries("bwrap"); len(got) != 0 {
		t.Fatalf("a local row declares deliveries: %v", got)
	}
}
