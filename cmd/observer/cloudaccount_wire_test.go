package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/marmutapp/superbased-observer/internal/cloudcred"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/intelligence/dashboard"
)

// TestCloudAccountProbeUsesResolvedHost exercises the real credential lookup:
// login writes host-scoped records, and dashboard completion must read the same
// scope, respecting the CLI's config/env/default endpoint resolution.
func TestCloudAccountProbeUsesResolvedHost(t *testing.T) {
	for _, tc := range []struct {
		name, configURL, envURL, storedHost string
		wantPresent                         bool
	}{
		{"configured host", "https://Configured.Example/", "", "configured.example", true},
		{"environment overrides config", "https://configured.example", " https://env.example/ ", "env.example", true},
		{"built-in host", "", "", "cloud.superbased.app", true},
		{"different host stays signed out", "https://configured.example", "https://env.example", "configured.example", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(cloudBaseURLEnv, tc.envURL)
			cfgPath, _, dir := writeCloudTestConfig(t)
			body, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			body = append(body, []byte(fmt.Sprintf("\n[cloud]\nbase_url = %q\n", tc.configURL))...)
			if err := os.WriteFile(cfgPath, body, 0o600); err != nil {
				t.Fatal(err)
			}
			cred := cloudcred.OpenForHost(dir, tc.storedHost, slog.New(slog.NewTextHandler(io.Discard, nil)))
			if cred.Backend() != "file" {
				t.Skip("requires the isolated file fallback; never seed the user's OS keychain")
			}
			if err := cred.SaveAPIToken("fixture-api"); err != nil {
				t.Fatal(err)
			}
			if err := cred.SaveWorkOSRefresh("fixture-refresh"); err != nil {
				t.Fatal(err)
			}
			got, err := probeCloudSignIn(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			if got.APITokenPresent != tc.wantPresent || got.WorkOSSignInPresent != tc.wantPresent {
				t.Fatalf("API/refresh presence = %t/%t, want %t/%t", got.APITokenPresent, got.WorkOSSignInPresent, tc.wantPresent, tc.wantPresent)
			}
		})
	}
}

// TestResolveWorkOSClientIDPrecedence pins env > [cloud].workos_client_id >
// the compiled default (config.DefaultCloudWorkOSClientID).
func TestResolveWorkOSClientIDPrecedence(t *testing.T) {
	cfg := config.Default()
	t.Setenv(cloudWorkOSClientIDEnv, "")
	if got := resolveWorkOSClientID(cfg); got != config.DefaultCloudWorkOSClientID {
		t.Fatalf("unconfigured → %q, want compiled default %q", got, config.DefaultCloudWorkOSClientID)
	}
	cfg.Cloud.WorkOSClientID = " client_cfg "
	if got := resolveWorkOSClientID(cfg); got != "client_cfg" {
		t.Fatalf("config only → %q, want client_cfg (trimmed)", got)
	}
	t.Setenv(cloudWorkOSClientIDEnv, "client_env")
	if got := resolveWorkOSClientID(cfg); got != "client_env" {
		t.Fatalf("env must win over config, got %q", got)
	}
}

// TestCloudCommandArgs pins the child argv the dashboard runner spawns — the
// same shape defaultCloudSyncSpawner uses: `cloud <verb> <args...> [--config
// <path>]`, the config path always LAST.
func TestCloudCommandArgs(t *testing.T) {
	if got := cloudCommandArgs("login", nil, ""); len(got) != 2 || got[0] != "cloud" || got[1] != "login" {
		t.Fatalf("no args, no config → %v", got)
	}
	got := cloudCommandArgs("logout", nil, "/x/config.toml")
	if len(got) != 4 || got[2] != "--config" || got[3] != "/x/config.toml" {
		t.Fatalf("no args, with config → %v", got)
	}
	got = cloudCommandArgs("consent", []string{"grant", "--purpose", "structural_activity_insights", "--yes"}, "/x/config.toml")
	want := []string{"cloud", "consent", "grant", "--purpose", "structural_activity_insights", "--yes", "--config", "/x/config.toml"}
	if len(got) != len(want) {
		t.Fatalf("with args and config → %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("with args and config → %v, want %v", got, want)
		}
	}
}

// TestCloudAccountWireRunInvalidatesProbeCache pins that a login/logout run
// drops the probe cache so the next status poll re-reads the credential store,
// and that the runner streams the child's output to the caller.
func TestCloudAccountWireRunInvalidatesProbeCache(t *testing.T) {
	var spawned [][]string
	w := &cloudAccountWire{
		configPath: "/x/config.toml",
		spawn: func(_ context.Context, argv []string, out io.Writer) error {
			spawned = append(spawned, argv)
			_, _ = io.WriteString(out, "https://auth.example/authorize\n")
			return nil
		},
	}
	// Seed a fresh cache entry BY HAND (never call the real probe here — it
	// opens the host's credential store), then run: the run must clear it.
	w.cachedAt = time.Now()
	w.cached = dashboard.CloudSignInState{APITokenPresent: true}
	if st, _ := w.probe(); !st.APITokenPresent {
		t.Fatal("a fresh cache entry must be served without re-probing")
	}
	var out bytes.Buffer
	if err := w.run(context.Background(), "login", nil, &out); err != nil {
		t.Fatal(err)
	}
	if !w.cachedAt.IsZero() {
		t.Fatal("run must invalidate the probe cache")
	}
	if out.String() != "https://auth.example/authorize\n" {
		t.Fatalf("child output not streamed: %q", out.String())
	}
	if len(spawned) != 1 || spawned[0][1] != "login" || spawned[0][3] != "/x/config.toml" {
		t.Fatalf("spawned = %v", spawned)
	}
}

// TestCloudAccountWireRunInvalidatesProbeCacheOnDeleteAccount pins that the
// wire's run() drops the probe cache for delete-account too — not just
// login/logout — since a local-only delete-account clears the same
// credentials login/logout do.
func TestCloudAccountWireRunInvalidatesProbeCacheOnDeleteAccount(t *testing.T) {
	w := &cloudAccountWire{
		configPath: "/x/config.toml",
		spawn:      func(_ context.Context, _ []string, _ io.Writer) error { return nil },
	}
	w.cachedAt = time.Now()
	w.cached = dashboard.CloudSignInState{APITokenPresent: true}
	if err := w.run(context.Background(), "delete-account", []string{"--yes", "--local-only"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !w.cachedAt.IsZero() {
		t.Fatal("run must invalidate the probe cache after delete-account")
	}
}

// TestCloudGrantableProbe pins cloudGrantableProbe's shape against the known
// internal/cloudgateway purpose-rule table: structural_activity_insights is
// standing-grantable, bounded_context_enrichment is not (per-session only, no
// schema-level grant in this release), and the bootstrap-lane purpose
// (account_device_operations) is skipped entirely — mirroring
// cloudconsent.go's cloudPrintGrantableHelp exactly.
func TestCloudGrantableProbe(t *testing.T) {
	rows := cloudGrantableProbe()
	byPurpose := map[string]dashboard.CloudGrantable{}
	for _, r := range rows {
		byPurpose[r.Purpose] = r
	}
	if _, ok := byPurpose["account_device_operations"]; ok {
		t.Fatalf("bootstrap-lane purpose must be skipped, rows = %+v", rows)
	}
	structural, ok := byPurpose["structural_activity_insights"]
	if !ok || !structural.OK || structural.Reason != "" {
		t.Fatalf("structural_activity_insights = %+v, want ok=true reason=\"\"", structural)
	}
	bounded, ok := byPurpose["bounded_context_enrichment"]
	if !ok || bounded.OK || bounded.Reason == "" {
		t.Fatalf("bounded_context_enrichment = %+v, want ok=false with a reason", bounded)
	}
}
