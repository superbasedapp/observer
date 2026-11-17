package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/managedconfig"
	"github.com/marmutapp/superbased-observer/internal/orgcontract"
	"github.com/marmutapp/superbased-observer/internal/pairing"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// TestConnectPairingCodeReachesTheEnrolmentExchange runs the real
// composition, `observer connect` -> `observer enroll` -> orgclient, against
// a fake org server: the pairing code from SBO_PAIR_CODE arrives as the
// exchange's one-time token, the machine is enrolled, and connect closes
// with the one sentence built from the new enrolment.
func TestConnectPairingCodeReachesTheEnrolmentExchange(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	code := testPairCode(t)
	var got orgcontract.EnrollRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/agent/enroll" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			http.Error(w, "bad", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orgcontract.EnrollResponse{
			Bearer: "bearer-xyz", BearerExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339),
			OrgID: "org-a", OrgName: "Acme", UserID: "u-1", UserEmail: "dev@acme.example",
			Tenancy: orgcontract.TenancyIndividual,
		})
	}))
	t.Cleanup(srv.Close)

	st := idpTestStore(t)
	client := idpTestOrgClient(t, st)
	cfgPath := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(cfgPath, []byte("[observer]\nlog_level = \"warn\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h := newConnectHarness()
	h.env[pairing.EnvVar] = code
	deps := h.deps()
	deps.loadEnrolment = func(ctx context.Context, _ string) (*store.Enrolment, error) { return st.LoadEnrolment(ctx) }
	deps.runEnroll = func(cmd *cobra.Command, args []string, stdin io.Reader) error {
		enroll := newEnrollCmdWith(enrolCmdDeps{
			attachPolicy: func() managedconfig.AttachResult {
				return managedconfig.AttachResult{Status: managedconfig.AttachStatusNone}
			},
			bundle: func(context.Context, string) (orgBundle, error) {
				cfg, err := config.Load(config.LoadOptions{GlobalPath: cfgPath})
				if err != nil {
					return orgBundle{}, err
				}
				return orgBundle{client: client, store: st, cfg: cfg, cleanup: func() {}}, nil
			},
		})
		return runSubcommand(cmd, enroll, args, stdin)
	}
	cmd := newConnectCmdWith(deps)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetIn(strings.NewReader(""))
	cmd.SetArgs([]string{srv.URL, "--config", cfgPath, "--wire-clients=false"})
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	if err := cmd.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("connect: %v\n%s", err, out.String())
	}
	if got.OneTimeToken != code || got.AgentPublicKey == "" {
		t.Fatalf("the exchange got token %q key %q, want the pairing code", got.OneTimeToken, got.AgentPublicKey)
	}
	enr, err := st.LoadEnrolment(context.Background())
	if err != nil || enr == nil || enr.OrgID != "org-a" || enr.UserEmail != "dev@acme.example" {
		t.Fatalf("enrolment = %+v (%v)", enr, err)
	}
	for _, want := range []string{"Enrolled in Acme", "Now: Acme (individual) as dev@acme.example"} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("output lacks %q:\n%s", want, out.String())
		}
	}
	if strings.Contains(out.String(), code) {
		t.Fatal("the pairing code was printed")
	}
}
