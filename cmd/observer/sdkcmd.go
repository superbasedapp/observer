package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/marmutapp/superbased-observer/internal/components"
	"github.com/marmutapp/superbased-observer/internal/config"
	"github.com/marmutapp/superbased-observer/internal/dashapi"
	"github.com/marmutapp/superbased-observer/internal/diag"
	"github.com/marmutapp/superbased-observer/internal/keystore"
	"github.com/marmutapp/superbased-observer/internal/orgclient"
	"github.com/marmutapp/superbased-observer/internal/pastedsecret"
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
			"  observer sdk use-key --gateway-url <address>\n" +
			"                                       install an SDK key an admin issued you (read from stdin)\n" +
			"  observer sdk sign-out                revoke it and remove it from this machine\n" +
			"                                       (an admin-issued key is removed, never revoked)\n" +
			"  observer sdk sign-out --all          revoke every SDK key you have, on every machine\n" +
			"  observer config set observability.sdk.destination local|online|both --yes",
	}
	cmd.AddCommand(newSDKStatusCmd(), newSDKSignInCmd(), newSDKUseKeyCmd(), newSDKSignOutCmd())
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
			d := sdkcredsvc.BuildDiscoveryWithOrg(cfg, st, "http://"+dashboardLoopbackAddr(cfg), sdkOrgDashboard(cmd.Context(), cfg))
			held := sdkHeldFile(st.Usable())
			if asJSON {
				return writeJSONOut(cmd.OutOrStdout(), sdkStatusJSON{Discovery: d, SDKHeldFile: held})
			}
			printSDKStatus(cmd.OutOrStdout(), d)
			printSDKHeldFile(cmd.OutOrStdout(), held)
			return nil
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().BoolVar(&asJSON, "json", false, "Print the discovery body the SDKs read, and the SDK-held file's state (never a key)")
	return cmd
}

// sdkStatusJSON is `observer sdk status --json`: the discovery body the
// SDKs read, plus (additive, beside it) the SDK-held file's state.
type sdkStatusJSON struct {
	sdkcredsvc.Discovery
	SDKHeldFile sdkcredsvc.HeldFile `json:"sdk_held_file"`
}

// sdkOrgDashboard reads the enrolment's dashboard facts for the discovery
// body's online.dashboard_url, the same facts the dashboard's discovery
// route uses. It never creates the database: with none, or not enrolled,
// the field stays "".
func sdkOrgDashboard(ctx context.Context, cfg config.Config) sdkcredsvc.OrgDashboard {
	if inRelayBox() {
		return sdkcredsvc.OrgDashboard{}
	}
	if _, err := os.Stat(cfg.Observer.DBPath); err != nil {
		return sdkcredsvc.OrgDashboard{}
	}
	_, database, cleanup, err := openNodeDB(ctx, cfg, cfg.Observer.DBPath)
	if err != nil {
		return sdkcredsvc.OrgDashboard{}
	}
	defer cleanup()
	enr, err := store.New(database).LoadEnrolment(ctx)
	if err != nil || enr == nil {
		return sdkcredsvc.OrgDashboard{}
	}
	return sdkcredsvc.OrgDashboardFrom(enr.OrgID, enr.OnlineURL, enr.OrgServerURL)
}

// sdkHeldFile reports the SDK-held credential file the SDK's `setup` writes
// (SDK quickstart plan 3.4, destination.md section 6a), from a stat of it:
// never opened, never read, so the key in it is never seen. machineKeyUsable
// is whether this machine offers the SDKs its own key, which wins the
// credential (ruling R10).
func sdkHeldFile(machineKeyUsable bool) sdkcredsvc.HeldFile {
	home, _ := os.UserHomeDir() //nolint:errcheck // no home: the ladder names no path and says so
	p, src := sdkcredsvc.SDKHeldFilePath(runtime.GOOS, os.Getenv, home)
	facts := sdkHeldFileFacts(p)
	if facts.Exists {
		abs, err := filepath.Abs(p)
		if err != nil {
			abs = p
		}
		facts.OutsideLocalAppData = sdkcredsvc.HeldFileOutsideLocalAppData(runtime.GOOS, abs, os.Getenv("LOCALAPPDATA"))
	}
	return sdkcredsvc.DescribeHeldFile(runtime.GOOS, p, src, facts, machineKeyUsable)
}

// sdkHeldFileFacts stats path without following a link and without opening
// it.
func sdkHeldFileFacts(path string) sdkcredsvc.HeldFileFacts {
	if path == "" {
		return sdkcredsvc.HeldFileFacts{}
	}
	fi, err := os.Lstat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return sdkcredsvc.HeldFileFacts{}
	case err != nil:
		return sdkcredsvc.HeldFileFacts{StatErr: err.Error()}
	}
	link := fi.Mode()&fs.ModeSymlink != 0
	if runtime.GOOS == "windows" {
		// A junction or another reparse point reads as irregular.
		link = link || fi.Mode()&fs.ModeIrregular != 0
	}
	return sdkcredsvc.HeldFileFacts{
		Exists:  true,
		Link:    link,
		Regular: fi.Mode().IsRegular(),
		Size:    fi.Size(),
		// Windows has no group or other bits; its reader checks the folder
		// and the owner SID instead (destination.md section 6a, ruling R4).
		OpenToOthers: runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0,
		ForeignOwner: sdkHeldFileForeignOwner(fi),
	}
}

// printSDKHeldFile prints the SDK-held file's line of `observer sdk status`.
func printSDKHeldFile(out io.Writer, h sdkcredsvc.HeldFile) {
	if h.Path == "" {
		fmt.Fprintln(out, "SDK file:    "+h.Text)
		return
	}
	fmt.Fprintf(out, "SDK file:    %s: %s\n", h.Path, h.Text)
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
		if d.Online.KeyOrigin == sdkcredsvc.KeyOriginAdminIssued {
			// An installed admin key's scopes and workspace are the admin's
			// to know (Machine identities); the key itself does not say.
			fmt.Fprintf(out, "SDK key:     %s (%s), file %s\n", d.Online.KeyID, sdkcredsvc.Meta{Origin: d.Online.KeyOrigin}.KeyOriginText(), d.Online.CredentialFile)
			fmt.Fprintln(out, "             its scopes and workspace are on Machine identities, in your organization's dashboard settings")
		} else {
			fmt.Fprintf(out, "SDK key:     %s (%s), file %s\n", d.Online.KeyID, joinOrNone(d.Online.Scopes), d.Online.CredentialFile)
			printSDKWorkspace(out, "workspace:   ", d.Online.WorkspaceID, d.Online.CaptureLevel)
		}
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

// sdkUseKeyArgsRefusal is what `observer sdk use-key` says to anything on
// its command line. It never repeats the argument: a key typed there is
// already in the shell history, and must not also reach a terminal log.
const sdkUseKeyArgsRefusal = "observer sdk use-key reads the key from stdin only, never from the command line (a key there lands in your shell history and the process list); nothing was stored. Run it with no argument and paste the key when asked, or pipe it in"

func newSDKUseKeyCmd() *cobra.Command {
	var configPath, gatewayURL string
	cmd := &cobra.Command{
		Use:   "use-key --gateway-url <address>",
		Short: "Install an SDK key an admin issued you, so your apps send to your organization",
		Long: "For an organization that does not give members their own SDK keys (a hosted\n" +
			"organization today): an admin mints a key under Machine identities, in the\n" +
			"organization's dashboard settings, and gives it to you with the organization's\n" +
			"gateway address. This command keeps it\n" +
			"the way `observer sdk sign-in` keeps a key: in this machine's keychain and in a\n" +
			"file only you can read, with the gateway address beside it, where the superbased\n" +
			"SDKs find it. After it, an SDK's default destination is both (this machine and\n" +
			"your organization) unless you chose another.\n\n" +
			"The key is read from stdin only: paste it when asked (it is not shown), or pipe\n" +
			"it in. It is never taken from the command line, never printed and never logged.\n" +
			"--gateway-url is the address the admin's dialog shows (SUPERBASED_ORG_URL); it\n" +
			"must be https (plain http only to this machine). Without it, the setting\n" +
			"observability.sdk.gateway_url is used.\n\n" +
			"`observer sdk sign-out` removes the key from this machine; it does not revoke it\n" +
			"(the key is the admin's), so ask an admin to revoke it when you are done.\n\n" +
			"Without Observer on the machine, an app can carry the key itself instead:\n" +
			"SUPERBASED_API_KEY=<key>, SUPERBASED_ORG_URL=<address> and\n" +
			"SUPERBASED_DESTINATION=both (or online) in the app's environment.",
		Example: "  observer sdk use-key --gateway-url https://acme.superbased.app\n" +
			"  observer sdk use-key --gateway-url https://gw.example.com:4318 < key.txt",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) > 0 {
				return errors.New(sdkUseKeyArgsRefusal)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSDKUseKey(cmd, configPath, gatewayURL)
		},
	}
	cmd.Flags().StringVar(&configPath, "config", "", "Path to config.toml (defaults to ~/.observer/config.toml)")
	cmd.Flags().StringVar(&gatewayURL, "gateway-url", "", "The organization's gateway address the key is sent to (https; the admin's dialog shows it)")
	return cmd
}

// runSDKUseKey reads the key and installs it through sdkcredsvc.InstallKey.
// It needs no database and no organization call.
func runSDKUseKey(cmd *cobra.Command, configPath, gatewayURL string) error {
	cfg, err := loadConfigFile(configPath)
	if err != nil {
		return err
	}
	svc := sdkCredentialService(cfg, nil)
	// Everything that does not need the key is checked before asking for it.
	if _, err := svc.CheckInstall(gatewayURL); err != nil {
		return err
	}
	key, err := sdkReadKey(cmd.InOrStdin(), cmd.ErrOrStderr())
	if err != nil {
		return fmt.Errorf("read the SDK key from stdin: %w; nothing was stored", err)
	}
	status, err := sdkUseKey(svc, sdkcredsvc.InstallInput{Compound: key, GatewayURL: gatewayURL})
	if err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "installed: SDK key %s (%s) saved to %s (readable by you only)\n", status.KeyID, status.KeyOriginText(), status.CredentialFile)
	fmt.Fprintf(out, "apps send it only to: %s\n", status.KeyGatewayURL)
	d := sdkcredsvc.BuildDiscovery(cfg, status, "http://"+dashboardLoopbackAddr(cfg))
	fmt.Fprintf(out, "an SDK on this machine now sends to: %s (%s)\n", d.Destination, d.Source)
	fmt.Fprintln(out, "restart your apps to pick it up; `observer sdk sign-out` removes it from this machine (it does not revoke it)")
	for _, w := range d.Warnings {
		fmt.Fprintln(cmd.ErrOrStderr(), "warning: "+w)
	}
	return nil
}

// sdkUseKey is the one install path (CLI and dashboard).
func sdkUseKey(svc sdkcredsvc.Service, in sdkcredsvc.InstallInput) (sdkcredsvc.Status, error) {
	return svc.InstallKey(in)
}

// sdkPasteTries is how many times the terminal read asks again when a read
// brings nothing (D9: through wsl.exe from Windows PowerShell an Enter could
// arrive before the paste did).
const sdkPasteTries = 3

// sdkReadKey reads the SDK key: without echo from a terminal, else one line
// of stdin (8 KiB at most). The prompt goes to prompt (stderr), so a script
// that captures stdout sees only the result.
var sdkReadKey = func(in io.Reader, prompt io.Writer) (string, error) {
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) { //nolint:gosec // G115: a descriptor number
		return sdkReadPasted(prompt, func() ([]byte, error) {
			return term.ReadPassword(int(f.Fd())) //nolint:gosec // G115: a descriptor number
		})
	}
	line, err := bufio.NewReader(io.LimitReader(in, 8<<10)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if pastedsecret.Clean(line) == "" {
		return "", errors.New("no SDK key on stdin (paste it when asked, or pipe it in)")
	}
	return line, nil
}

// sdkReadPasted prompts and reads one pasted key without echo, asking again
// (up to sdkPasteTries) while a read brings nothing once a paste's wrappers
// are removed.
func sdkReadPasted(out io.Writer, read func() ([]byte, error)) (string, error) {
	prompt := "Paste the SDK key your admin gave you (not shown): "
	var last string
	for range sdkPasteTries {
		fmt.Fprint(out, prompt)
		b, err := read()
		fmt.Fprintln(out)
		if err != nil {
			return "", err
		}
		last = string(b)
		if pastedsecret.Clean(last) != "" {
			return last, nil
		}
		prompt = "Nothing was read (the paste may not have arrived yet). Paste the SDK key again (not shown): "
	}
	return last, nil
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
			"holds no key, nothing is revoked at your organization. A key an admin issued\n" +
			"you (`observer sdk use-key`) is removed from this machine but never revoked:\n" +
			"it is the admin's, so ask an admin to revoke it on Machine identities.\n\n" +
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
	if errors.Is(err, sdkcredsvc.ErrAdminIssuedKeyKept) {
		// An admin-issued key: removed here, never revoked (it is the
		// admin's). With --all the member's own keys were still revoked.
		if all {
			fmt.Fprintf(out, "signed out: %d SDK key(s) of yours revoked on your organization\n", n)
		}
		fmt.Fprintln(out, "removed: "+sdkcredsvc.ErrAdminIssuedKeyKept.Error())
		return withoutErr(err, sdkcredsvc.ErrAdminIssuedKeyKept)
	}
	fmt.Fprintf(out, "signed out: %d SDK key(s) revoked on your organization; local copies removed\n", n)
	return err
}

// withoutErr is err with every target taken out of an errors.Join tree, nil
// when nothing else is left (a notice the caller already printed).
func withoutErr(err, target error) error {
	if err == nil || err == target { //nolint:errorlint // identity: the target itself is dropped
		return nil
	}
	j, ok := err.(interface{ Unwrap() []error }) //nolint:errorlint // only an errors.Join node is split
	if !ok {
		return err
	}
	var rest []error
	for _, e := range j.Unwrap() {
		if e = withoutErr(e, target); e != nil {
			rest = append(rest, e)
		}
	}
	return errors.Join(rest...)
}

// sdkSignIn is the one sign-in path (CLI and dashboard).
func sdkSignIn(ctx context.Context, svc sdkcredsvc.Service, m sdkcredsvc.Minter) (sdkcredsvc.Status, error) {
	status, err := svc.SignIn(ctx, m)
	switch {
	case err == nil:
		return status, nil
	case errors.Is(err, orgclient.ErrNotEnrolled):
		return status, fmt.Errorf("this machine is not signed in to an organization; run `observer org enroll` first (without an organization, SDKs send to this machine only)")
	case errors.Is(err, orgclient.ErrSDKCredentialNotSupported):
		// SR-9: a hosted organization issues no member keys; say what to do
		// with the key an admin issues instead.
		return status, errors.New(sdkAdminKeyHelp)
	default:
		return status, err
	}
}

// sdkAdminKeyHelp is what a member of an organization that issues no member
// SDK keys is told (SR-9): where the key comes from and the two supported
// ways to use it. One sentence set, shared by sign-in's refusal.
const sdkAdminKeyHelp = "this organization does not give members their own SDK keys yet; ask an admin for an SDK key (Machine identities, in the organization's dashboard settings) and its gateway address, then install it on this machine with `observer sdk use-key --gateway-url <address>` (paste the key when asked; it is read from stdin only), or give it to one app as SUPERBASED_API_KEY with SUPERBASED_ORG_URL=<address> and SUPERBASED_DESTINATION=both. Until then, your apps' data does not reach the organization"

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
		// "Use an SDK key from my admin": the same install as `observer sdk
		// use-key`, the key from the request body.
		InstallKey: func(compound, gatewayURL string) (sdkcredsvc.Status, error) {
			return sdkUseKey(svc, sdkcredsvc.InstallInput{Compound: compound, GatewayURL: gatewayURL})
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
