//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/termsvc"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// TestHostedSourceDelivery (lane G4, design 4.1 and 4.3; lane CLONE): one
// case per source on the org row and on a vendor row, the remote-clone
// gates in their order (switch, tier, host list, URL), and the remote-URL
// attack shapes refused.
func TestHostedSourceDelivery(t *testing.T) {
	org, _ := sandboxremote.VendorFor(sandboxremote.VendorOpenShellOrg)
	e2b, _ := sandboxremote.VendorFor(sandboxremote.VendorE2B)
	daytona, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona)
	cfg := config.TerminalSandboxConfig{AllowRemoteClone: true, RemoteAllowedHosts: []string{"git.example.com", "github.com"}}
	// box pins the clone location in the box (lane CLONE2), so the vendor
	// rows' cases below are the box-side clone's own gates; auto and home
	// are TestHostedSourceDeliveryCloneWhere.
	box := func(c config.TerminalSandboxConfig) config.TerminalSandboxConfig {
		c.Hosted.CloneWhere = "box"
		return c
	}
	const gh = "https://github.com/acme/app.git"
	net := vocab.TierInternet
	cases := []struct {
		name     string
		v        sandboxremote.Vendor
		src, url string
		tier     vocab.Tier
		cfg      config.TerminalSandboxConfig
		want     workspace.Delivery
		refusal  string
	}{
		{"vendor row, default is the live upload", e2b, "", "", net, cfg, workspace.DeliveryUploadSnapshot, ""},
		{"vendor row, live", e2b, "live", "", vocab.TierNone, cfg, workspace.DeliveryUploadSnapshot, ""},
		{"vendor row, clone-local refused", e2b, "clone-local", "", net, cfg, "", "source_unsupported"},
		{"vendor row, worktree refused", e2b, "worktree", "", net, cfg, "", "source_unsupported"},
		{"vendor row, clone-remote is the box clone", daytona, "clone-remote", gh, net, box(cfg), workspace.DeliveryRemoteClone, ""},
		{"vendor row, clone-remote switch off", daytona, "clone-remote", gh, net, box(config.TerminalSandboxConfig{RemoteAllowedHosts: []string{"github.com"}}), "", "allow_remote_clone"},
		{"vendor row, clone-remote on proxy_only", daytona, "clone-remote", gh, vocab.TierProxyOnly, box(cfg), "", "remote_clone_needs_egress"},
		{"vendor row, clone-remote on none", daytona, "clone-remote", gh, vocab.TierNone, box(cfg), "", "remote_clone_needs_egress"},
		{"vendor row, clone-remote with an empty host list", daytona, "clone-remote", gh, net, box(config.TerminalSandboxConfig{AllowRemoteClone: true}), "", "remote_clone_hosts_missing"},
		{"vendor row, ssh needs a key the box lacks", daytona, "clone-remote", "git@github.com:acme/app.git", net, box(cfg), "", "clone_url_invalid"},
		{"vendor row, token in the URL", daytona, "clone-remote", "https://x:ghp_t@github.com/acme/app.git", net, box(cfg), "", "clone_url_invalid"},
		{"vendor row, host not listed", daytona, "clone-remote", "https://gitlab.com/acme/app.git", net, box(cfg), "", "clone_url_invalid"},
		{"org row, default is clone-local", org, "", "", net, cfg, workspace.DeliverySync, ""},
		{"org row, clone-local", org, "clone-local", "", net, cfg, workspace.DeliverySync, ""},
		{"org row, live refused with the next step", org, "live", "", net, cfg, "", "clone-local"},
		{"org row, worktree refused", org, "worktree", "", net, cfg, "", "source_unsupported"},
		{"org row, clone-remote", org, "clone-remote", "https://git.example.com/acme/app.git", net, cfg, workspace.DeliveryRemoteClone, ""},
		{"org row, scp form kept", org, "clone-remote", "git@git.example.com:acme/app.git", net, cfg, workspace.DeliveryRemoteClone, ""},
		{"org row, clone-remote on proxy_only", org, "clone-remote", "https://git.example.com/acme/app.git", vocab.TierProxyOnly, cfg, "", "remote_clone_needs_egress"},
		{"clone-remote without allow_remote_clone", org, "clone-remote", "https://git.example.com/acme/app.git", net, config.TerminalSandboxConfig{RemoteAllowedHosts: []string{"git.example.com"}}, "", "allow_remote_clone"},
		{"clone-remote with an empty host list", org, "clone-remote", "https://git.example.com/acme/app.git", net, config.TerminalSandboxConfig{AllowRemoteClone: true}, "", "remote_clone_hosts_missing"},
		{"another host", org, "clone-remote", "https://evil.example.net/x.git", net, cfg, "", "clone_url_invalid"},
		{"ext transport", org, "clone-remote", "ext::sh -c touch% /tmp/pwned", net, cfg, "", "clone_url_invalid"},
		{"file url", org, "clone-remote", "file:///etc", net, cfg, "", "clone_url_invalid"},
		{"leading dash", org, "clone-remote", "--upload-pack=touch /tmp/x", net, cfg, "", "clone_url_invalid"},
		{"upload-pack embedded", org, "clone-remote", "https://git.example.com/a.git --upload-pack=x", net, cfg, "", "clone_url_invalid"},
	}
	for _, tc := range cases {
		got, err := hostedSourceDelivery(context.Background(), tc.v, termsvc.PrepareRequest{WorkspaceSource: tc.src, WorkspaceRemote: tc.url, ProjectRoot: "/home/dev/app"}, tc.tier, tc.cfg)
		if tc.refusal != "" {
			if err == nil || !strings.Contains(err.Error(), tc.refusal) {
				t.Errorf("%s: err %v, want %q", tc.name, err, tc.refusal)
			}
			var step *dashapi.SandboxStepRefusal
			if err != nil && (!errors.As(err, &step) || step.Message == "" || strings.Contains(step.Message, "_")) {
				t.Errorf("%s: not a plain typed refusal: %v", tc.name, err)
			}
			continue
		}
		if err != nil || got.Delivery != tc.want {
			t.Errorf("%s: %+v %v", tc.name, got, err)
		}
		if got.Delivery == workspace.DeliveryRemoteClone && (got.CloneURL != tc.url || got.uploads()) {
			t.Errorf("%s: a remote clone uploads or lost its URL: %+v", tc.name, got)
		}
	}
}

// TestHostedDeliveryTiers: one case per row of the tier x delivery table.
func TestHostedDeliveryTiers(t *testing.T) {
	cases := []struct {
		d    workspace.Delivery
		tier vocab.Tier
		runs bool
	}{
		{workspace.DeliveryRemoteClone, vocab.TierInternet, true},
		{workspace.DeliveryRemoteClone, vocab.TierProxyOnly, false},
		{workspace.DeliveryRemoteClone, vocab.TierNone, false},
		{workspace.DeliveryUploadSnapshot, vocab.TierNone, true},
		{workspace.DeliverySync, vocab.TierProxyOnly, true},
	}
	for _, c := range cases {
		if got := hostedDeliveryRunsOn(c.d, c.tier); got != c.runs {
			t.Errorf("%s on %s: %v, want %v", c.d, c.tier, got, c.runs)
		}
	}
	if len(hostedDeliveryTiers) != 3 {
		t.Errorf("the table has %d rows; give a new row its case here", len(hostedDeliveryTiers))
	}
}

// TestHostedAcceptedSourcesNotes (lane CLONE): the dialog's source list
// leaves a vendor row's box clone out, with a plain note, exactly when a
// gate refuses it before Start; a source the row never takes has no note.
func TestHostedAcceptedSourcesNotes(t *testing.T) {
	open := config.TerminalSandboxConfig{AllowRemoteClone: true, RemoteAllowedHosts: []string{"github.com"}}
	// With the clone pinned in the box (lane CLONE2), its gates leave the
	// source out; with auto (the default) or home, a clone made on this
	// machine takes it on every tier and with no host list.
	pin := func(c config.TerminalSandboxConfig, where string) config.TerminalSandboxConfig {
		c.Hosted.CloneWhere = where
		return c
	}
	cases := []struct {
		name   string
		tier   vocab.Tier
		cfg    config.TerminalSandboxConfig
		listed bool
		note   string
	}{
		{"internet, gates open", vocab.TierInternet, pin(open, "box"), true, ""},
		{"switch off", vocab.TierInternet, pin(config.TerminalSandboxConfig{RemoteAllowedHosts: []string{"github.com"}}, "box"), false, "switched off"},
		{"proxy_only", vocab.TierProxyOnly, pin(open, "box"), false, "needs internet access"},
		{"none", vocab.TierNone, pin(open, "box"), false, "needs internet access"},
		{"no hosts listed", vocab.TierInternet, pin(config.TerminalSandboxConfig{AllowRemoteClone: true}, "box"), false, "git hosts"},
		{"auto, proxy_only: cloned here", vocab.TierProxyOnly, open, true, ""},
		{"auto, none: cloned here", vocab.TierNone, open, true, ""},
		{"auto, no hosts listed: cloned here", vocab.TierInternet, config.TerminalSandboxConfig{AllowRemoteClone: true}, true, ""},
		{"auto, switch off", vocab.TierInternet, config.TerminalSandboxConfig{RemoteAllowedHosts: []string{"github.com"}}, false, "switched off"},
		{"home, none", vocab.TierNone, pin(open, "home"), true, ""},
		{"home, switch off", vocab.TierNone, pin(config.TerminalSandboxConfig{}, "home"), false, "switched off"},
	}
	for _, c := range cases {
		srcs, notes, ok := hostedAcceptedSources(sandboxremote.VendorDaytona, c.tier, c.cfg)
		if !ok {
			t.Fatal("no list")
		}
		has := strings.Contains(strings.Join(srcs, ","), "clone-remote")
		if has != c.listed || !strings.Contains(notes["clone-remote"], c.note) || (c.note == "") != (notes["clone-remote"] == "") {
			t.Errorf("%s: listed %v (want %v), note %q (want %q)", c.name, srcs, c.listed, notes["clone-remote"], c.note)
		}
		if notes["clone-local"] != "" || notes["worktree"] != "" || !strings.HasPrefix(strings.Join(srcs, ","), "live") {
			t.Errorf("%s: sources %v notes %v", c.name, srcs, notes)
		}
	}
}
