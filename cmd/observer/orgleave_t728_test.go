package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/govern"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
)

// T-728 (D-542): after Leave the operator's config.toml still said
// [org_client] enabled = true with the URL of a retired server, a re-enrol
// never rewrote an existing block, and the plan said nothing about the
// machine key left in the org-bearer store.

const t728Block = "[observer]\nlog_level = \"warn\"\n\n" +
	"[org_client]\n" +
	"# my own note about sharing\n" +
	"enabled = true  # keep me\n" +
	"org_server_url = \"https://retired.example\"\n" +
	"max_push_bytes = 1048576  # 1 MiB\n\n" +
	"[org_client.share]\n" +
	"full_content = false\n"

// TestT728OrgClientConfigEdgeRows pins orgClientCfgRows edge by edge: only
// the named lines change, every comment and other line stays, and a file
// without the table (or without the file) is never written.
func TestT728OrgClientConfigEdgeRows(t *testing.T) {
	for _, tc := range []struct {
		name    string
		body    string
		edge    orgClientCfgEdge
		url     string
		want    string
		noBlock bool
		wantErr bool
	}{
		{
			name: "leave turns the push switch off, keeps the address and comments",
			body: t728Block, edge: orgClientCfgLeave,
			want: strings.Replace(t728Block, "enabled = true  # keep me", "enabled = false # keep me", 1),
		},
		{
			name: "re-enrol turns it on and rewrites the address",
			body: strings.Replace(t728Block, "enabled = true  # keep me", "enabled = false # keep me", 1),
			edge: orgClientCfgEnrol, url: "https://org.new.example",
			want: strings.Replace(strings.Replace(t728Block, "enabled = true  # keep me", "enabled = true # keep me", 1),
				"https://retired.example", "https://org.new.example", 1),
		},
		{
			name: "re-enrol inserts a missing address into the block",
			body: "[org_client]\nenabled = false\n",
			edge: orgClientCfgEnrol, url: "https://org.new.example",
			want: "[org_client]\nenabled = true\norg_server_url = \"https://org.new.example\"\n",
		},
		{
			name: "no [org_client] table: nothing written",
			body: "[observer]\nlog_level = \"warn\"\n", edge: orgClientCfgLeave,
			want: "[observer]\nlog_level = \"warn\"\n", noBlock: true,
		},
		{
			name: "a value the line editor cannot rewrite: error, nothing written",
			body: "[org_client]\nenabled = [true]\n", edge: orgClientCfgLeave,
			want: "[org_client]\nenabled = [true]\n", wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.toml")
			if err := os.WriteFile(path, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			got, err := applyOrgClientConfigEdge(path, tc.edge, tc.url)
			if tc.wantErr != (err != nil) {
				t.Fatalf("err = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr && !errors.Is(err, config.ErrNotSurgical) {
				t.Errorf("err = %v, want ErrNotSurgical", err)
			}
			if got.NoBlock != tc.noBlock {
				t.Errorf("NoBlock = %v, want %v", got.NoBlock, tc.noBlock)
			}
			after, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatal(rerr)
			}
			if string(after) != tc.want {
				t.Fatalf("file after edit:\n%s\nwant:\n%s", after, tc.want)
			}
		})
	}
	// A missing file stays missing.
	missing := filepath.Join(t.TempDir(), "absent.toml")
	if got, err := applyOrgClientConfigEdge(missing, orgClientCfgLeave, ""); err != nil || !got.NoBlock {
		t.Fatalf("missing file: (%+v, %v)", got, err)
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatal("a missing config.toml was created")
	}
}

// TestT728LeavePlanNamesConfigAndMachineKey pins the two plan rows T-728 adds:
// the push switch retired after the walk, and the machine key kept with its
// reason.
func TestT728LeavePlanNamesConfigAndMachineKey(t *testing.T) {
	rows := map[string]string{}
	for _, s := range unenrolPlanRows() {
		rows[s.ID] = s.Phase
	}
	if rows["org_client_enabled"] != "after" {
		t.Errorf("org_client_enabled phase = %q, want after", rows["org_client_enabled"])
	}
	if rows["machine_key"] != "kept" {
		t.Errorf("machine_key phase = %q, want kept", rows["machine_key"])
	}
	last := unenrolPlanRows()[len(unenrolPlanRows())-1]
	if last.Phase != "kept" {
		t.Errorf("the plan no longer ends with what is kept: %+v", last)
	}
}

// TestT728DashboardLeaveAndReEnrolEditTheBlock is the operator path end to
// end: enrol from the dashboard, the block points somewhere stale by hand,
// Leave turns sharing off (comments kept) and says so, a re-enrol turns it
// back on and rewrites the address.
func TestT728DashboardLeaveAndReEnrolEditTheBlock(t *testing.T) {
	ctx := context.Background()
	org := newEnrolFakeOrg(t, orgcontract.TenancyManaged, []string{govern.AuthorityDashboardVisibility, govern.AuthorityEnforceBudget})
	d, _, cfgPath := testEnrolDashboard(t)
	link := dashapi.EnrolRequest{Method: "link", Link: org.url + "/enrol/" + idpTestEnrolCode}

	out, err := d.Enrol(ctx, link)
	if err != nil {
		t.Fatalf("first Enrol: %v", err)
	}
	if out.PendingGrant != nil {
		if _, err := d.DecideGrant(ctx, out.PendingGrant.OfferID, true); err != nil {
			t.Fatalf("DecideGrant: %v", err)
		}
	}
	body, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "org_server_url = \""+org.url+"\"") {
		t.Fatalf("first enrol wrote no org_server_url:\n%s", body)
	}
	// The operator's node: the address points at a retired server.
	stale := strings.Replace(string(body), org.url, "https://retired.example", 1)
	if err := os.WriteFile(cfgPath, []byte(stale), 0o600); err != nil {
		t.Fatal(err)
	}

	lv, err := d.Leave(ctx, dashapi.SwitchOptions{})
	if err != nil || !lv.WasEnrolled {
		t.Fatalf("Leave = (%+v, %v)", lv, err)
	}
	cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("config.Load after Leave: %v", err)
	}
	if cfg.OrgClient.Enabled {
		t.Fatal("Leave left [org_client] enabled = true")
	}
	after, _ := os.ReadFile(cfgPath)
	if !strings.Contains(string(after), "# enabled = true means observer start ships") {
		t.Fatalf("Leave dropped the block's comments:\n%s", after)
	}
	var saidConfig, saidKey bool
	for _, n := range lv.Notes {
		saidConfig = saidConfig || strings.Contains(n.Text, "enabled = false")
		saidKey = saidKey || strings.Contains(n.Text, "machine key")
	}
	if !saidConfig || !saidKey {
		t.Fatalf("Leave notes do not name the config edit and the kept machine key: %+v", lv.Notes)
	}

	again, err := d.Enrol(ctx, link)
	if err != nil {
		t.Fatalf("re-enrol: %v", err)
	}
	cfg, err = config.Load(config.LoadOptions{GlobalPath: cfgPath})
	if err != nil {
		t.Fatalf("config.Load after re-enrol: %v", err)
	}
	if !cfg.OrgClient.Enabled || cfg.OrgClient.OrgServerURL != org.url {
		t.Fatalf("re-enrol left enabled=%v org_server_url=%q, want true and %q", cfg.OrgClient.Enabled, cfg.OrgClient.OrgServerURL, org.url)
	}
	var saidUpdate bool
	for _, n := range again.Notes {
		saidUpdate = saidUpdate || strings.Contains(n.Text, "Updated the existing [org_client] block")
	}
	if !saidUpdate {
		t.Fatalf("re-enrol notes do not say the block was updated: %+v", again.Notes)
	}
}
