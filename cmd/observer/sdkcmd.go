package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"slices"

	"github.com/spf13/cobra"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/sdkcredsvc"
	"github.com/marmutapp/superbased-observer/internal/store"
)

// `observer sdk` (Plane A build-out W2-7, ruling D18): where this machine
// tells the superbased SDKs to send an app's data, and the SDK key that lets
// them send it to your organization. The destination itself is the setting
// observability.sdk.destination (`observer config set`); sign-in and
// sign-out manage the key. The contract is
// docs/plans/plane-a-sdk-buildout/contracts/destination.md.

// sdkCredentialService opens the machine's SDK key holder for cfg.
func sdkCredentialService(cfg config.Config, logger *slog.Logger) sdkcredsvc.Service {
	dir := sdkcredsvc.DefaultDir(filepath.Dir(cfg.Observer.DBPath))
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	return sdkcredsvc.Service{
		Dir:             dir,
		Keychain:        keystore.Open(sdkcredsvc.KeystoreService, dir, logger),
		Logger:          logger,
		GatewayOverride: cfg.Observability.SDK.GatewayURL,
	}
}

// sdkKeyCheckName is the `observer doctor` row for the SDK key (review E-59).
const sdkKeyCheckName = "sdk.key"

// sdkKeyDoctorCheck is the sdk.key doctor row: FAIL when the key expired,
// WARN within 14 days of expiry or when the key file does not read back,
// OK otherwise.
func sdkKeyDoctorCheck(cfg config.Config) diag.Check {
	kc := sdkcredsvc.DoctorCheck(sdkCredentialService(cfg, nil).Status())
	status, ok := map[string]diag.Status{"ok": diag.StatusOK, "warn": diag.StatusWarn, "fail": diag.StatusFail}[kc.Level]
	if !ok {
		status = diag.StatusWarn
	}
	return diag.Check{Name: sdkKeyCheckName, Status: status, Message: kc.Message, Details: kc.Details}
}

// sdkMinter is this machine's org client for the SDK key rail.
func sdkMinter(cfg config.Config, st *store.Store) sdkcredsvc.Minter {
	bs := orgclient.OpenBearerStoreQuiet(cfg.OrgClient.KeychainID, filepath.Dir(cfg.Observer.DBPath))
	return orgclient.New(cfg.OrgClient, st, bs, version, nil, nil)
}

func newSDKCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sdk",
		Short: "Where the superbased SDKs send your apps' data, and your SDK key",
		Long: "The superbased SDKs send an app's spans to this machine (local), to your\n" +
			"organization's gateway (online) or to both. Without an init() option or\n" +
			"SUPERBASED_DESTINATION they ask this machine for its default:\n" +
			"local when you are not signed in, both when you are.\n\n" +
			"  observer sdk status                  what an SDK on this machine would do\n" +
			"  observer sdk sign-in                 get your SDK key from your organization\n" +
			"  observer sdk sign-out                revoke it and remove it from this machine\n" +
			"  observer sdk sign-out --all          revoke every SDK key you have, on every machine\n" +
			"  observer config set observability.sdk.destination local|online|both --yes",
	}
	cmd.AddCommand(newSDKStatusCmd(), newSDKSignInCmd(), newSDKSignOutCmd())
	return cmd
}

func newSDKStatusCmd() *cobra.Command {
	var (
		configPath string
		asJSON     bool
	)
	cmd := &cobra.Command{
		Use:   "status",
		Short: "Show the SDK destination this machine hands out and whether it holds an SDK key",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := loadConfigFile(configPath)
			if err != nil {
				return err
			}
			st := sdkCredentialService(cfg, nil).Status()
			d := sdkcredsvc.BuildDiscovery(cfg, st, "http://"+dashboardLoopbackAddr(cfg))
			if asJSON {
				return writeJSONOut(cmd.OutOrStdout(), d)
			}
			printSDKStatus(cmd.OutOrStdout(), d)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the discovery body the SDKs read (never the key)")
	return cmd
}

func printSDKStatus(out io.Writer, d sdkcredsvc.Discovery) {
	fmt.Fprintf(out, "destination: %s (%s)\n", d.Destination, d.Source)
	fmt.Fprintf(out, "signed in:   %v\n", d.SignedIn)
	fmt.Fprintf(out, "local:       %s (observability on: %v)\n", d.Local.OTLPTracesURL, d.Local.Enabled)
	gw := d.Online.GatewayURL
	if gw == "" {
		gw = "(none known)"
	}
	fmt.Fprintf(out, "gateway:     %s\n", gw)
	if d.Online.CredentialPresent {
		fmt.Fprintf(out, "SDK key:     %s (%s), file %s\n", d.Online.KeyID, joinOrNone(d.Online.Scopes), d.Online.CredentialFile)
		printSDKWorkspace(out, "workspace:   ", d.Online.WorkspaceID, d.Online.CaptureLevel)
	}
	for _, w := range d.Warnings {
		fmt.Fprintln(out, "warning:     "+w)
	}
}

// printSDKWorkspace prints the key's workspace and the capture level the
// organization applies to it (review L-23): a key that keeps no content or
// end user says so.
func printSDKWorkspace(out io.Writer, label, workspace, level string) {
	if workspace == "" {
		workspace = "(not reported)"
	}
	fmt.Fprintf(out, "%s%s, capture level %s\n", label, workspace, sdkcredsvc.CaptureLevelText(level))
}

func joinOrNone(s []string) string {
	if len(s) == 0 {
		return "no scopes"
	}
	out := s[0]
	for _, x := range s[1:] {
		out += "," + x
	}
	return out
}

func newSDKSignInCmd() *cobra.Command {
	var configPath string
	cmd := &cobra.Command{
		Use:   "sign-in",
		Short: "Get your own SDK key from your organization and keep it on this machine",
		Long: "Asks the organization this machine is signed in to for your own SDK key\n" +
			"(it replaces any earlier one) and keeps it in this machine's keychain and in\n" +
			"a file only you can read, where the superbased SDKs find it. The key is\n" +
			"never printed and no route on this machine hands it out. After signing in,\n" +
			"an SDK's default destination is both (this machine and your organization)\n" +
			"unless you chose another.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSDKSignIn(cmd, configPath)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	return cmd
}

func newSDKSignOutCmd() *cobra.Command {
	var (
		configPath string
		all, yes   bool
	)
	cmd := &cobra.Command{
		Use:   "sign-out",
		Short: "Revoke your SDK key on your organization and remove it from this machine",
		Long: "Revokes the SDK key this machine holds on your organization and removes\n" +
			"every local copy. Your other machines keep their keys. When this machine\n" +
			"holds no key, nothing is revoked at your organization.\n\n" +
			"--all revokes every SDK key you have, on every machine (it asks first;\n" +
			"--yes answers for a script).",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if all && !yes && !confirmOnTTY(cmd, "Revoke every SDK key you have, on every machine? Apps on your other machines stop sending online until you sign in there again.") {
				return errors.New("not confirmed; nothing was revoked (pass --yes to revoke every SDK key without asking)")
			}
			return runSDKSignOut(cmd, configPath, all)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&all, "all", false, "Revoke every SDK key you have on your organization, on every machine")
	cmd.Flags().BoolVar(&yes, "yes", false, "With --all: do not ask for confirmation")
	return cmd
}

func runSDKSignIn(cmd *cobra.Command, configPath string) error {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	st := store.New(database)
	svc := sdkCredentialService(cfg, nil)
	out := cmd.OutOrStdout()
	status, err := sdkSignIn(cmd.Context(), svc, sdkMinter(cfg, st))
	if err != nil {
		return err
	}
	fmt.Fprintf(out, "signed in: SDK key %s saved to %s (readable by you only)\n", status.KeyID, status.CredentialFile)
	if status.KeyGatewayURL != "" {
		fmt.Fprintf(out, "apps send it only to: %s\n", status.KeyGatewayURL)
	}
	printSDKWorkspace(out, "the key sends to workspace ", status.WorkspaceID, status.CaptureLevel)
	d := sdkcredsvc.BuildDiscovery(cfg, status, "http://"+dashboardLoopbackAddr(cfg))
	fmt.Fprintf(out, "an SDK on this machine now sends to: %s (%s)\n", d.Destination, d.Source)
	for _, w := range d.Warnings {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
	}
	return nil
}

// runSDKSignOut revokes this machine's key (or, with all, every key of the
// member) and removes the local copies. With no held key and no --all,
// nothing is revoked at the organization (review E-28).
func runSDKSignOut(cmd *cobra.Command, configPath string, all bool) error {
	cfg, database, cleanup, err := loadConfigAndDB(cmd.Context(), configPath)
	if err != nil {
		return err
	}
	defer cleanup()
	svc := sdkCredentialService(cfg, nil)
	out := cmd.OutOrStdout()
	n, err := svc.SignOut(cmd.Context(), sdkMinter(cfg, store.New(database)), all)
	if errors.Is(err, sdkcredsvc.ErrNoHeldKey) {
		fmt.Fprintln(out, "signed out: "+err.Error())
		return nil
	}
	fmt.Fprintf(out, "signed out: %d SDK key(s) revoked on your organization; local copies removed\n", n)
	return err
}

// sdkSignIn is the one sign-in path (CLI and dashboard).
func sdkSignIn(ctx context.Context, svc sdkcredsvc.Service, m sdkcredsvc.Minter) (sdkcredsvc.Status, error) {
	status, err := svc.SignIn(ctx, m)
	switch {
	case err == nil:
		return status, nil
	case errors.Is(err, orgclient.ErrNotEnrolled):
		return status, fmt.Errorf("this machine is not signed in to an organization; run `observer org enroll` first (without an organization, SDKs send to this machine only)")
	default:
		return status, err
	}
}

// appObsCompiledIn reports whether this build includes AI Apps on the
// machine: the obs component compiled in and offered by the distro (review
// E-29's "compiled in" input to discovery and the trace handler).
func appObsCompiledIn() bool {
	return slices.Contains(components.Compiled(components.BinaryNode), "obs")
}

// dashboardLoopbackAddr is the dashboard's local address for the discovery
// body's admission URL (flag-less: env, then config, then the default).
func dashboardLoopbackAddr(cfg config.Config) string {
	return resolveDashboardAddr("", cfg.Dashboard.Addr, "127.0.0.1:8081")
}

// sdkDashboardSeams wires the dashboard's SDK routes to the same holder and
// org client the CLI uses.
func sdkDashboardSeams(cfg config.Config, st *store.Store) dashapi.SDKSeams {
	svc := sdkCredentialService(cfg, nil)
	return dashapi.SDKSeams{
		Status: svc.Status,
		SignIn: func(ctx context.Context) (sdkcredsvc.Status, error) {
			return sdkSignIn(ctx, svc, sdkMinter(cfg, st))
		},
		// The dashboard never revokes every key: with no held key it revokes
		// nothing at the org and says so (review E-28).
		SignOut: func(ctx context.Context) (int, error) {
			return svc.SignOut(ctx, sdkMinter(cfg, st), false)
		},
		Receiver: func() (dashapi.OTLPReceiverState, bool) {
			rs, ok, err := loadOTLPReceiverStatus(cfg)
			if err != nil || !ok {
				return dashapi.OTLPReceiverState{}, false
			}
			return dashapi.OTLPReceiverState{State: rs.State, GRPCAddr: rs.GRPCAddr, HTTPAddr: rs.HTTPAddr, Error: rs.Error, At: rs.At}, true
		},
	}
}
