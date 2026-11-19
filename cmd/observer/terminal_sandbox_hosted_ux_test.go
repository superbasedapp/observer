//go:build !sbo_omit_terminals_sandbox && !sbo_omit_isolation && !sbo_omit_terminals

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/integration"
	"github.com/marmutapp/superbased-observer/internal/sandboxbackend"
	"github.com/marmutapp/superbased-observer/internal/sandboxremote"
	"github.com/marmutapp/superbased-observer/internal/sandboxselect"
	vocab "github.com/marmutapp/superbased-observer/internal/sandboxvocab"
	"github.com/marmutapp/superbased-observer/internal/settingslink"
	"github.com/marmutapp/superbased-observer/internal/workspace"
)

// The lane UX items (H4, H5, H8, H9, H10): what the New Terminal dialog
// learns before Start, served on the hosted rows' probe entries.

// TestHostedSourceDeliveries (H5): every source a hosted row takes, with
// every gate open, is mapped to the delivery the launch resolves for it; the
// vendor rows' live source is an upload (upload_snapshot), so the dialog never
// calls it the live directory.
func TestHostedSourceDeliveries(t *testing.T) {
	open := config.TerminalSandboxConfig{AllowRemoteClone: true, RemoteAllowedHosts: []string{"github.com"}}
	for _, id := range sandboxremote.VendorIDs() {
		got, ok := hostedSourceDeliveries(id)
		srcs, _, _ := hostedAcceptedSources(id, vocab.TierInternet, open)
		if !ok {
			t.Errorf("%s: no deliveries", id)
			continue
		}
		v, _ := sandboxremote.VendorFor(id)
		for _, s := range srcs {
			want, err := workspace.DeliveryFor(workspace.Source(s), hostedRowModes(v))
			if err != nil || got[s] != string(want) {
				t.Errorf("%s %s: delivery %q, want %q (%v)", id, s, got[s], want, err)
			}
		}
		if slices.Contains(srcs, "live") && got["live"] == string(workspace.DeliveryBindSamePath) {
			t.Errorf("%s: a hosted row's live source is a live bind", id)
		}
	}
	if _, ok := hostedSourceDeliveries(sandboxbackend.BackendBwrap); ok {
		t.Error("a local row has hosted deliveries")
	}
}

// TestHostedToolNoticesMatchTheLaunch (H4): the probe's per-tool notice for
// a row is exactly what hostedToolDelivery would refuse at launch, for every
// sandbox-launchable tool, on every hosted row and tier.
func TestHostedToolNoticesMatchTheLaunch(t *testing.T) {
	var cfg config.TerminalSandboxConfig
	for _, id := range sandboxremote.VendorIDs() {
		v, _ := sandboxremote.VendorFor(id)
		for _, tier := range []vocab.Tier{vocab.TierInternet, vocab.TierProxyOnly, vocab.TierNone} {
			notices := hostedToolNotices(id, cfg, tier)
			for _, c := range integration.Capabilities() {
				if !integration.TerminalLaunchable(c) || len(c.Sandbox.StateRW) == 0 {
					continue
				}
				_, err := hostedToolDelivery(c.Tool, "", tier, v)
				n, listed := notices[c.Tool]
				if listed != (err != nil) {
					t.Errorf("%s %s %s: notice %v, launch error %v", id, tier, c.Tool, listed, err)
					continue
				}
				var step *dashapi.SandboxStepRefusal
				if err != nil && (!errors.As(err, &step) || step.Message != n.Message || step.Code != sandboxselect.VerdictToolUnavailableInImage) {
					t.Errorf("%s %s %s: the launch's refusal %v is not the notice %q", id, tier, c.Tool, err, n.Message)
				}
				// The fix is the row's template, typed on Hosted sandboxes:
				// the dialog links there, not to Sandbox isolation.
				if listed && n.Place != settingslink.TerminalSandboxHosted {
					t.Errorf("%s %s %s: notice place %q, want %q", id, tier, c.Tool, n.Place, settingslink.TerminalSandboxHosted)
				}
			}
		}
	}
	// The live finding: OpenCode on Daytona's default image is not refused
	// (its vendor script remains); Codex, npm only, is.
	d := hostedToolNotices(sandboxremote.VendorDaytona, cfg, vocab.TierInternet)
	if _, ok := d["opencode"]; ok {
		t.Errorf("OpenCode refused on Daytona: %+v", d["opencode"])
	}
	if n, ok := d["codex"]; !ok || !strings.Contains(n.Message, "has no npm") || strings.Contains(n.Message, "tool_unavailable") {
		t.Errorf("Codex on Daytona: %+v", n)
	}
	got, _ := hostedToolDelivery("opencode", "", vocab.TierInternet, func() sandboxremote.Vendor { v, _ := sandboxremote.VendorFor(sandboxremote.VendorDaytona); return v }())
	if len(got) != 1 || got[0].Channel != "script" {
		t.Errorf("OpenCode on Daytona installs by %+v, want the vendor script only", got)
	}
	// A template set on the row's own table lifts every notice.
	cfg.Hosted.Daytona.Template = "my-snapshot"
	if n := hostedToolNotices(sandboxremote.VendorDaytona, cfg, vocab.TierNone); len(n) != 0 {
		t.Errorf("notices with a template: %v", n)
	}
}

// TestHostedFillProbeRow (H5, H4, H10): a hosted row's entry carries its
// sources, deliveries, tool notices and network notes; a local row's none.
func TestHostedFillProbeRow(t *testing.T) {
	var cfg config.TerminalSandboxConfig
	row, _ := sandboxbackend.Get(sandboxbackend.BackendE2B)
	var e dashapi.SandboxBackendAvail
	hostedFillProbeRow(&e, row, cfg, vocab.TierInternet)
	if !reflect.DeepEqual(e.WorkspaceSources, []string{"live"}) || e.SourceDeliveries["live"] != string(workspace.DeliveryUploadSnapshot) {
		t.Errorf("sources %v deliveries %v", e.WorkspaceSources, e.SourceDeliveries)
	}
	// The box-side clone the row delivers is not taken with the remote-clone
	// switch off, and the entry says why (H7).
	if e.SourceDeliveries["clone-remote"] != string(workspace.DeliveryRemoteClone) || e.WorkspaceSourceNotes["clone-remote"] == "" {
		t.Errorf("clone-remote: delivery %q note %q", e.SourceDeliveries["clone-remote"], e.WorkspaceSourceNotes["clone-remote"])
	}
	if len(e.NetworkNotes) < 2 || !strings.Contains(e.NetworkNotes[0], "cloud metadata address") || !strings.Contains(strings.Join(e.NetworkNotes, " "), "169.254.169.254") {
		t.Errorf("network notes %v", e.NetworkNotes)
	}
	var none dashapi.SandboxBackendAvail
	hostedFillProbeRow(&none, row, cfg, vocab.TierNone)
	for _, n := range none.NetworkNotes {
		if strings.Contains(n, "cloud metadata address or private") {
			t.Errorf("a blocked tier is called unrefused: %q", n)
		}
	}
	local, _ := sandboxbackend.Get(sandboxbackend.BackendBwrap)
	var l dashapi.SandboxBackendAvail
	hostedFillProbeRow(&l, local, cfg, vocab.TierInternet)
	if l.WorkspaceSources != nil || l.SourceDeliveries != nil || l.ToolNotices != nil || l.NetworkNotes != nil {
		t.Errorf("a local row got hosted facts: %+v", l)
	}
}

// TestHostedRowsDiscloseNoHookGating (H9): every hosted row serves the
// no-hook disclosure with the consent screen's sentence.
func TestHostedRowsDiscloseNoHookGating(t *testing.T) {
	for _, id := range sandboxremote.VendorIDs() {
		row, ok := sandboxbackend.Get(id)
		if !ok {
			continue
		}
		found := false
		for _, d := range sandboxDisclosuresFor(row, "") {
			found = found || (d.ID == string(sandboxbackend.DiscloseNoHookGating) && d.Text == sandboxremote.HostedHookNote)
		}
		if !found {
			t.Errorf("%s does not disclose that guard does not gate the box", id)
		}
	}
}

// TestHostedWorkspaceRoute (H8): the route answers the launch's own root
// rules for a folder, before Start; a bad folder is a 400.
func TestHostedWorkspaceRoute(t *testing.T) {
	repo, plain := t.TempDir(), t.TempDir()
	sub := filepath.Join(repo, "sub")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	old := hostedWorkspaceFacts
	t.Cleanup(func() { hostedWorkspaceFacts = old })
	hostedWorkspaceFacts = func(_ context.Context, dir string) (sandboxremote.UploadRootFacts, string) {
		f := sandboxremote.UploadRootFacts{Root: filepath.ToSlash(dir), Home: "/nonexistent-home"}
		if strings.HasPrefix(dir, repo) {
			f.IsRepository, f.RepositoryTop = true, filepath.ToSlash(repo)
		}
		return f, dir
	}
	cases := []struct {
		dir    string
		status int
		code   string
	}{
		{repo, http.StatusOK, ""},
		{sub, http.StatusOK, sandboxremote.ErrScopeInsideRepository},
		// SBXD-8: under the shipped defaults a plain folder uploads, with
		// a note (TestHostedWorkspaceRouteNonGitOff pins the refusal).
		{plain, http.StatusOK, sandboxremote.UploadNonRepositoryNote},
		{"relative/dir", http.StatusBadRequest, ""},
		{filepath.Join(plain, "missing"), http.StatusBadRequest, ""},
	}
	for _, c := range cases {
		w := httptest.NewRecorder()
		hostedWorkspaceHandler(w, httptest.NewRequest(http.MethodGet, "/api/terminal/sandbox/hosted/workspace?dir="+url.QueryEscape(c.dir), nil))
		if w.Code != c.status {
			t.Errorf("%s: status %d", c.dir, w.Code)
			continue
		}
		if c.status != http.StatusOK {
			continue
		}
		var v hostedWorkspaceView
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		if v.Code != c.code || v.OK != (c.code == "" || c.code == sandboxremote.UploadNonRepositoryNote) || (c.code != "" && v.Message == "") {
			t.Errorf("%s: %+v", c.dir, v)
		}
	}
	found := false
	for _, f := range hostedExtraDashboardRoutes {
		for _, r := range f("", func(h http.HandlerFunc) http.HandlerFunc { return h }) {
			if r.Pattern == hostedWorkspaceRoute {
				found = r.Capability == dashapi.CapabilityLocal
			}
		}
	}
	if !found {
		t.Error("the workspace route is not registered as a Local hosted route")
	}
}
