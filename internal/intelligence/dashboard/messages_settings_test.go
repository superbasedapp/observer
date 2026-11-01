package dashboard

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/marmutapp/superbased-observer/internal/store"
)

// The developer edits [messages] from Settings (T-854, the no config-file
// dead end rule): PUT /api/config/section/messages runs through the one
// section save pipeline, and GET /api/messages/summary says when read
// receipts are fixed on by a managed enrolment.

func TestConfigSection_MessagesSavesEveryKey(t *testing.T) {
	s, path := newSecretTestServer(t, keysCorpus)
	body := `{"Toast": false, "VSCode": true, "Statusline": false, "Desktop": true, "AlertsOnly": true, "ReadReceipts": false}`

	dry := putSection(t, s, "messages?dry_run=1", body, false)
	if dry.Code != http.StatusOK {
		t.Fatalf("dry run: %d %s", dry.Code, dry.Body.String())
	}
	keys := strings.Join(strs(decodeMap(t, dry)["changed_keys"]), ",")
	for _, k := range []string{"messages.toast", "messages.statusline", "messages.desktop", "messages.alerts_only", "messages.read_receipts"} {
		if !strings.Contains(keys, k) {
			t.Fatalf("changed_keys %q is missing %s", keys, k)
		}
	}

	rr := putSection(t, s, "messages", body, true)
	if rr.Code != http.StatusOK {
		t.Fatalf("save: %d %s", rr.Code, rr.Body.String())
	}
	cfg, err := loadConfigForDashboard(path)
	if err != nil {
		t.Fatal(err)
	}
	m := cfg.Messages
	if m.Toast || !m.VSCode || m.Statusline || !m.Desktop || !m.AlertsOnly || m.ReadReceipts {
		t.Fatalf("saved [messages] = %+v", m)
	}

	var sum messagesSummaryResponse
	getModelJSON(t, s, "/api/messages/summary", &sum)
	if sum.Surfaces.Toast || !sum.Surfaces.Desktop || !sum.Surfaces.AlertsOnly || sum.Surfaces.ReadReceipts {
		t.Fatalf("the summary must read the saved choice at once (no restart): %+v", sum.Surfaces)
	}
}

func TestMessagesSurfacesReadReceiptsLockedOnManagedEnrolment(t *testing.T) {
	cases := []struct {
		name    string
		tenancy string
		want    bool
	}{
		{"individual enrolment: the developer decides", "individual", false},
		{"managed enrolment: always sent", "managed", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := newMessagesServer(t, true)
			if err := store.New(s.opts.DB).WriteEnrolment(context.Background(), store.Enrolment{
				OrgID: "org-1", OrgServerURL: "https://org.example", UserID: "u-1", Tenancy: tc.tenancy,
			}); err != nil {
				t.Fatal(err)
			}
			var sum messagesSummaryResponse
			getModelJSON(t, s, "/api/messages/summary", &sum)
			if sum.Surfaces.ReadReceiptsLocked != tc.want {
				t.Fatalf("summary read_receipts_locked = %v, want %v", sum.Surfaces.ReadReceiptsLocked, tc.want)
			}
			var page messagesPageResponse
			getModelJSON(t, s, "/api/messages", &page)
			if page.Surfaces.ReadReceiptsLocked != tc.want {
				t.Fatalf("page read_receipts_locked = %v, want %v", page.Surfaces.ReadReceiptsLocked, tc.want)
			}
		})
	}

	// Not enrolled: nothing is locked.
	s, _ := newMessagesServer(t, false)
	var sum messagesSummaryResponse
	getModelJSON(t, s, "/api/messages/summary", &sum)
	if sum.Surfaces.ReadReceiptsLocked {
		t.Fatal("an unenrolled machine has no managed enrolment")
	}
}
